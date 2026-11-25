<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\Http\RequestInfo;
use SecureNow\Http\Transport;
use SecureNow\Net\Ip;
use SecureNow\Net\IpSet;
use SecureNow\Telemetry\Exporter;
use SecureNow\Util;

/**
 * Layer 1 of the SecureNow firewall, in the app: decides before the framework boots whether a
 * request is answered with 403 (blocklist, allowlist, user-agent rule, scoped rule), a
 * proof-of-work challenge, or 429 (rate limit). The order and the responses are the Node SDK's.
 */
final class Firewall
{
    public static function active(): bool
    {
        return Config::apiKey() !== null;
    }

    /** @return array<string,mixed>|null */
    private static function policy(): ?array
    {
        $state = State::load();
        if ($state === null) {
            Sync::initial();
            $state = State::load(true);
        }
        return $state;
    }

    /**
     * @param array<string,mixed> $ipDetails ClientIp::resolve()
     */
    public static function check(RequestInfo $request, array $ipDetails): ?Verdict
    {
        if (!self::active()) {
            return null;
        }
        $state = self::policy();
        $ip = (string) ($ipDetails['ip'] ?? '');

        if ($state === null) {
            // No policy and none could be fetched: open lets traffic through, closed blocks it.
            if (strtolower((string) Config::get('firewall.failMode', 'open')) === 'closed') {
                return self::block($request, $ip, 'blocklist', '', 'fail-closed', false);
            }
            return null;
        }
        // The dashboard / CLI switch wins over everything.
        if (($state['remoteEnabled'] ?? true) === false) {
            return null;
        }

        // SecureNow's own solve endpoint, before any rule: a challenged visitor can always answer.
        if ($request->path === Challenge::INTERNAL_PATH) {
            return self::handleChallengeSolve($request, $ip, $state);
        }

        $allowlist = IpSet::import($state['al'] ?? null);
        if ($allowlist->total() > 0) {
            if (!$allowlist->contains($ip)) {
                self::log("blocked $ip via HTTP (not in allowlist)");
                return self::block($request, $ip, 'allowlist', '', '');
            }
            return null;
        }

        if (State::blocklistContains($state['bl'] ?? null, $ip)) {
            self::log("blocked $ip via HTTP");
            return self::block($request, $ip, 'blocklist', '', $ip);
        }

        $uaRule = UserAgentRules::match($state['ua'] ?? null, $request->header('user-agent'), $ip);
        if ($uaRule !== null) {
            self::log("blocked $ip via HTTP (user agent rule={$uaRule['id']})");
            return self::block($request, $ip, 'blocklist', $uaRule['id'], 'ua:' . $uaRule['id']);
        }

        $parsed = Ip::parse($ip);
        $now = time();

        $rule = self::firstMatch($state['blRules'] ?? [], $request, $ip, $parsed, $now);
        if ($rule !== null) {
            $ruleId = self::ruleId($rule);
            self::log("blocked $ip via HTTP (rule=" . ($ruleId !== '' ? $ruleId : 'scoped') . ')');
            return self::block($request, $ip, 'blocklist', $ruleId, (string) ($rule['ip'] ?? $ip));
        }

        // Between hard block and rate limit: an uncleared visitor gets the interstitial and does
        // not use up a rate-limit bucket.
        $challenge = $state['challenge'] ?? null;
        if (!empty($state['chRules']) && is_array($challenge) && !empty($challenge['secret'])) {
            $rule = self::firstMatch($state['chRules'], $request, $ip, $parsed, $now);
            if ($rule !== null && !self::hasClearance($request, $ip, (string) $challenge['secret'])) {
                self::log("challenged $ip via HTTP (rule=" . (self::ruleId($rule) ?: 'scoped') . ')');
                return self::challenge($request, $ip, $rule, $challenge);
            }
        }

        return self::rateLimit($request, $ip, $parsed, $state['rlRules'] ?? [], $now);
    }

    private static function log(string $message): void
    {
        if (Config::bool('firewall.log', false)) {
            @error_log('[securenow] Firewall: ' . $message);
        } else {
            Diag::debug('Firewall: ' . $message);
        }
    }

    /** @param array<string,mixed> $rule */
    private static function ruleId(array $rule): string
    {
        return (string) ($rule['id'] ?? $rule['_id'] ?? '');
    }

    /** @param array<string,mixed> $rule */
    private static function ruleExpired(array $rule, int $now): bool
    {
        if (empty($rule['expiresAt'])) {
            return false;
        }
        $at = strtotime((string) $rule['expiresAt']);
        return $at !== false && $at <= $now;
    }

    /**
     * @param array<string,mixed> $rule
     * @param array<string,mixed>|null $parsed
     */
    private static function ruleApplies(array $rule, RequestInfo $request, string $ip, ?array $parsed, int $now): bool
    {
        if (self::ruleExpired($rule, $now)) {
            return false;
        }
        $method = strtoupper((string) ($rule['method'] ?? 'ALL')) ?: 'ALL';
        if ($method !== 'ALL' && $method !== $request->method) {
            return false;
        }
        if (!Ip::entryMatches((string) ($rule['ip'] ?? ''), $parsed, $ip)) {
            return false;
        }
        return Paths::ruleMatches($rule, $request->path);
    }

    /**
     * @param array<int,mixed> $rules
     * @param array<string,mixed>|null $parsed
     * @return array<string,mixed>|null
     */
    private static function firstMatch(array $rules, RequestInfo $request, string $ip, ?array $parsed, int $now): ?array
    {
        foreach ($rules as $rule) {
            if (is_array($rule) && self::ruleApplies($rule, $request, $ip, $parsed, $now)) {
                return $rule;
            }
        }
        return null;
    }

    /** @param array<string,mixed> $event */
    private static function report(RequestInfo $request, array $event): void
    {
        Exporter::addFirewallEvent($event + [
            'applicationKey' => Config::appKey(),
            'environment' => Config::environment(),
            'action' => 'blocked',
            'statusCode' => Config::int('firewall.statusCode', 403, 100),
            'occurredAt' => gmdate('Y-m-d\TH:i:s.v\Z'),
            'method' => $request->method,
            'path' => $request->target,
            'userAgent' => $request->header('user-agent'),
        ]);
    }

    private static function wantsHtml(RequestInfo $request): bool
    {
        return strpos($request->header('accept'), 'text/html') !== false;
    }

    private static function block(RequestInfo $request, string $ip, string $source, string $ruleId, string $matchedEntry, bool $report = true): Verdict
    {
        $status = Config::int('firewall.statusCode', 403, 100);
        if ($report) {
            self::report($request, ['source' => $source, 'ip' => $ip, 'ruleId' => $ruleId, 'matchedEntry' => $matchedEntry]);
        }
        $verdict = self::wantsHtml($request)
            ? new Verdict('blocked', $status, ['Content-Type' => 'text/html; charset=utf-8'], Pages::blocked($ip, $status))
            : new Verdict('blocked', $status, ['Content-Type' => 'application/json'], Util::json(['error' => 'Forbidden', 'ip' => $ip]));
        $verdict->headers['Cache-Control'] = 'no-store';
        $verdict->attributes = ['securenow.firewall.action' => 'blocked', 'securenow.firewall.source' => $source];
        if ($ruleId !== '') {
            $verdict->attributes['securenow.firewall.rule_id'] = $ruleId;
        }
        return $verdict;
    }

    // ---- rate limits ----

    /** @param array<string,mixed> $rule */
    private static function rateLimitSubject(array $rule, string $ip, RequestInfo $request): string
    {
        $keyBy = (string) ($rule['keyBy'] ?? 'ip');
        if ($keyBy === 'global') {
            return 'global';
        }
        if ($keyBy === 'header' || $keyBy === 'cookie') {
            $name = trim((string) ($rule['keyName'] ?? ''));
            $value = trim($keyBy === 'header' ? $request->header($name) : $request->cookie($name));
            if ($value !== '') {
                // Hashed: no raw credential is kept or sent to a shared store.
                return $keyBy . ':' . substr(hash('sha256', $value), 0, 24);
            }
        }
        return $ip;
    }

    /**
     * @param array<string,mixed>|null $parsed
     * @param array<int,mixed> $rules
     */
    private static function rateLimit(RequestInfo $request, string $ip, ?array $parsed, array $rules, int $now): ?Verdict
    {
        if (!$rules) {
            return null;
        }
        $nowMs = Util::nowMs();
        foreach ($rules as $rule) {
            if (!is_array($rule) || !self::ruleApplies($rule, $request, $ip, $parsed, $now)) {
                continue;
            }
            $limit = max(1, (int) ($rule['limit'] ?? 1));
            $windowSeconds = max(1, (int) ($rule['windowSeconds'] ?? 60));
            $ruleId = self::ruleId($rule);
            $bucket = ($ruleId !== '' ? $ruleId : (($rule['ip'] ?? '*') . ':' . ($rule['method'] ?? 'ALL') . ':' . ($rule['pathPattern'] ?? '*')))
                . '|' . self::rateLimitSubject($rule, $ip, $request);
            // Windows aligned to the clock, so every worker and server agrees on the bucket.
            $windowMs = $windowSeconds * 1000;
            $windowIndex = intdiv($nowMs, $windowMs);
            $count = RateLimiter::hit($bucket, $windowIndex, $windowSeconds);
            if ($count === null || $count <= $limit) {
                continue;
            }
            $retryAfter = max(1, (int) ceil((($windowIndex + 1) * $windowMs - $nowMs) / 1000));
            self::log("rate-limited $ip via HTTP (rule=" . ($ruleId !== '' ? $ruleId : 'unknown') . ')');
            self::report($request, [
                'action' => 'rate_limited',
                'source' => 'rate_limit',
                'statusCode' => 429,
                'ip' => $ip,
                'ruleId' => $ruleId,
                'keyBy' => (string) ($rule['keyBy'] ?? 'ip'),
                'matchedEntry' => $ruleId,
                'path' => $request->path,
            ]);
            $headers = [
                'Retry-After' => (string) $retryAfter,
                'X-RateLimit-Limit' => (string) $limit,
                'X-RateLimit-Window' => (string) $windowSeconds,
                'X-SecureNow-Rate-Limit-Rule' => $ruleId,
            ];
            $verdict = self::wantsHtml($request)
                ? new Verdict('rate_limited', 429, $headers + ['Content-Type' => 'text/html; charset=utf-8'], Pages::rateLimited())
                : new Verdict('rate_limited', 429, $headers + ['Content-Type' => 'application/json'], Util::json(['error' => 'Too Many Requests', 'ip' => $ip, 'retryAfter' => $retryAfter]));
            $verdict->attributes = ['securenow.firewall.action' => 'rate_limited', 'securenow.firewall.source' => 'rate_limit', 'securenow.firewall.rule_id' => $ruleId];
            return $verdict;
        }
        return null;
    }

    // ---- challenge (proof of work) ----

    private static function hasClearance(RequestInfo $request, string $ip, string $secret): bool
    {
        $cookie = $request->cookie(Challenge::CLEARANCE_COOKIE);
        return $cookie !== '' && Challenge::verifyClearance($secret, $cookie, $ip, $request->header('user-agent'));
    }

    /**
     * @param array<string,mixed>|null $rule
     * @param array<string,mixed> $config
     */
    private static function clearanceTtl(?array $rule, array $config): int
    {
        $ttl = (int) ($rule['clearanceTtlSeconds'] ?? 0);
        if ($ttl >= 30) {
            return $ttl;
        }
        $ttl = (int) ($config['clearanceTtl'] ?? 0);
        return $ttl >= 30 ? $ttl : Challenge::DEFAULT_CLEARANCE_TTL;
    }

    /**
     * @param array<string,mixed> $rule
     * @param array<string,mixed> $config
     */
    private static function challenge(RequestInfo $request, string $ip, array $rule, array $config): Verdict
    {
        $difficulty = (int) ($rule['difficulty'] ?? 0);
        if ($difficulty < 4 || $difficulty > 28) {
            $difficulty = (int) ($config['difficulty'] ?? 0);
            if ($difficulty < 4) {
                $difficulty = Challenge::DEFAULT_DIFFICULTY;
            }
        }
        $ruleId = self::ruleId($rule);
        $rid = $ruleId !== '' ? $ruleId : '*';
        $token = Challenge::signChallenge((string) $config['secret'], $ip, $difficulty, $rid, (int) ($config['challengeTtl'] ?? 0));
        self::report($request, [
            'action' => 'captcha_challenged',
            'source' => 'challenge',
            'statusCode' => 403,
            'ip' => $ip,
            'ruleId' => $ruleId,
            'matchedEntry' => $rid,
            'path' => $request->path,
        ]);
        $headers = ['X-SecureNow-Challenge' => 'required', 'Cache-Control' => 'no-store'];
        $verdict = self::wantsHtml($request)
            ? new Verdict('challenged', 403, $headers + ['Content-Type' => 'text/html; charset=utf-8'], Pages::challenge($token, $difficulty, Challenge::INTERNAL_PATH, $request->target, $ip))
            : new Verdict('challenged', 403, $headers + ['Content-Type' => 'application/json'], Util::json([
                'error' => 'challenge_required',
                'challenge' => ['token' => $token, 'alg' => Challenge::ALG_POW, 'difficulty' => $difficulty, 'submit' => Challenge::INTERNAL_PATH],
            ]));
        $verdict->attributes = ['securenow.firewall.action' => 'challenged', 'securenow.firewall.source' => 'challenge', 'securenow.firewall.rule_id' => $ruleId];
        return $verdict;
    }

    /**
     * POST /__securenow/challenge: verify the proof of work (locally with the app's secret, or
     * through the API) and set the clearance cookie.
     *
     * @param array<string,mixed> $state
     */
    private static function handleChallengeSolve(RequestInfo $request, string $ip, array $state): Verdict
    {
        $json = ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'];
        if ($request->method !== 'POST') {
            return new Verdict('challenge_failed', 405, $json + ['Allow' => 'POST'], '{"ok":false,"reason":"method_not_allowed"}');
        }
        $raw = $request->body(8193);
        $body = ($raw !== null && strlen($raw) <= 8192) ? json_decode($raw === '' ? '{}' : $raw, true) : null;
        if (!is_array($body) || empty($body['token']) || !is_string($body['token'])) {
            return new Verdict('challenge_failed', 400, $json, '{"ok":false,"reason":"bad_request"}');
        }
        $config = is_array($state['challenge'] ?? null) ? $state['challenge'] : [];
        $secret = (string) ($config['secret'] ?? '');
        $ua = $request->header('user-agent');
        $rid = is_string($body['rid'] ?? null) && $body['rid'] !== '' ? $body['rid'] : '*';
        $nonce = is_scalar($body['nonce'] ?? null) ? (string) $body['nonce'] : '';

        $rule = null;
        if ($rid !== '*') {
            foreach (($state['chRules'] ?? []) as $candidate) {
                if (is_array($candidate) && self::ruleId($candidate) === $rid) {
                    $rule = $candidate;
                    break;
                }
            }
        }
        $ttl = self::clearanceTtl($rule, $config);
        $clearance = null;
        $reason = 'verification_failed';

        if (($config['verify'] ?? 'auto') === 'proxy' || $secret === '') {
            $query = http_build_query(array_filter(['app' => Config::appKey(), 'env' => Config::environment()]));
            $response = Transport::request(
                'POST',
                rtrim(Config::firewallApiUrl(), '/') . '/api/v1/firewall/verify-challenge' . ($query !== '' ? '?' . $query : ''),
                Exporter::controlHeaders() + ['content-type' => 'application/json'],
                Util::json(['token' => $body['token'], 'nonce' => $nonce, 'ip' => $ip, 'ua' => $ua, 'rid' => $rid, 'clearanceTtl' => $ttl]),
                8000
            );
            $parsed = $response['status'] === 200 ? json_decode($response['body'], true) : null;
            if ($response['status'] !== 200) {
                $reason = 'proxy_unreachable';
            } elseif (!is_array($parsed)) {
                $reason = 'proxy_bad_response';
            } elseif (!empty($parsed['ok']) && !empty($parsed['clearance']['value'])) {
                $clearance = ['value' => (string) $parsed['clearance']['value'], 'maxAge' => (int) ($parsed['clearance']['maxAge'] ?? $ttl)];
            } else {
                $reason = (string) ($parsed['reason'] ?? $reason);
            }
        } else {
            $result = Challenge::verifySolution($secret, $body['token'], $nonce, $ip);
            if ($result['ok']) {
                $clearance = Challenge::issueClearance($secret, $ip, $ua, $rid, $ttl);
            } else {
                $reason = (string) ($result['reason'] ?? $reason);
            }
        }

        if ($clearance === null) {
            self::report($request, [
                'action' => 'captcha_failed', 'source' => 'challenge', 'statusCode' => 400,
                'ip' => $ip, 'matchedEntry' => $reason, 'method' => 'POST', 'path' => Challenge::INTERNAL_PATH,
            ]);
            return new Verdict('challenge_failed', 400, $json, Util::json(['ok' => false, 'reason' => $reason]));
        }

        self::report($request, [
            'action' => 'captcha_passed', 'source' => 'challenge', 'statusCode' => 204,
            'ip' => $ip, 'matchedEntry' => $rid, 'method' => 'POST', 'path' => Challenge::INTERNAL_PATH,
        ]);
        $verdict = new Verdict('challenge_passed', 204, ['Cache-Control' => 'no-store'], '');
        $secure = $request->https || strtolower(trim(explode(',', $request->header('x-forwarded-proto'))[0])) === 'https';
        $verdict->cookies[] = Challenge::CLEARANCE_COOKIE . '=' . $clearance['value'] . '; Max-Age=' . max(1, (int) $clearance['maxAge'])
            . '; Path=/; HttpOnly; SameSite=Lax' . ($secure ? '; Secure' : '');
        return $verdict;
    }

    /** For `securenow status` and `securenow firewall:check`. @return array<string,mixed> */
    public static function stats(): array
    {
        $state = State::load(true);
        $meta = State::meta();
        return [
            'synced' => $state !== null,
            'remoteEnabled' => $state['remoteEnabled'] ?? null,
            'blocklist' => State::blocklistTotal($state['bl'] ?? null),
            'blocklistRules' => count($state['blRules'] ?? []),
            'allowlist' => IpSet::import($state['al'] ?? null)->total(),
            'rateLimitRules' => count($state['rlRules'] ?? []),
            'challengeRules' => count($state['chRules'] ?? []),
            'userAgentRules' => count($state['ua']['rules'] ?? []),
            'userAgentAllowRules' => count($state['ua']['allow'] ?? []),
            'syncedAt' => $state['syncedAt'] ?? null,
            'checkedAt' => isset($meta['checkedAt']) ? intdiv((int) $meta['checkedAt'], 1000) : null,
            'consecutiveErrors' => (int) ($meta['errors'] ?? 0),
            'lastError' => $meta['lastError'] ?? null,
            'apiUrl' => ($meta['apiUrl'] ?? '') !== '' ? $meta['apiUrl'] : Config::firewallApiUrl(),
        ];
    }
}
