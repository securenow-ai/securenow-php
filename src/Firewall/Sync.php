<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\Http\Transport;
use SecureNow\Net\IpSet;
use SecureNow\Store\Store;
use SecureNow\Telemetry\Exporter;
use SecureNow\Util;

/**
 * Pulls the firewall policy from SecureNow: one request to /api/v1/firewall/sync with the
 * versions already held; the API answers 304, or only what changed (the Node SDK's unified sync).
 *
 * There is no timer in PHP-FPM. After a response is sent, the request that finds the policy
 * older than config.firewall.versionCheckInterval (10 s) and takes the sync lock does the check;
 * the others carry on. `securenow agent` does it on a timer instead when it runs.
 * Failures back off (doubling, up to 2 minutes) and the last good policy keeps being enforced.
 */
final class Sync
{
    private const CIRCUIT_THRESHOLD = 5;
    private const CIRCUIT_COOLDOWN_MS = 120000;

    /** Post-response hook: check for a newer policy when one is due. */
    public static function maybe(bool $detached = true): void
    {
        if (Config::apiKey() === null || Store::dir() === null || Exporter::agentAlive()) {
            return;
        }
        $meta = State::meta();
        $now = Util::nowMs();
        if ($now < (int) ($meta['nextCheck'] ?? 0)) {
            return;
        }
        // Without fastcgi_finish_request the visitor would wait for this check: only the PHP-FPM
        // path, the built-in dev server and the first sync do it inline.
        if (!$detached && PHP_SAPI !== 'cli-server' && State::load() !== null && ($now - (int) ($meta['checkedAt'] ?? 0)) < 60000) {
            return;
        }
        $lock = Store::lock('sync');
        if ($lock === null) {
            return;
        }
        try {
            $meta = State::meta();
            if (Util::nowMs() < (int) ($meta['nextCheck'] ?? 0)) {
                return;
            }
            self::run();
        } finally {
            Store::unlock($lock);
        }
    }

    /** First request of a fresh install: fetch the policy before deciding, once. */
    public static function initial(): void
    {
        if (Config::apiKey() === null || Store::dir() === null) {
            return;
        }
        $meta = State::meta();
        if (Util::nowMs() < (int) ($meta['nextCheck'] ?? 0)) {
            return;
        }
        $lock = Store::lock('sync');
        if ($lock === null) {
            return;
        }
        try {
            if (State::load(true) === null) {
                self::run(false, 4000);
            }
        } finally {
            Store::unlock($lock);
        }
    }

    /**
     * One sync. $full asks for everything again (the hourly safety net, `securenow sync`).
     *
     * @return array{ok:bool,status:int,changed:array<string,bool>,error:?string,ips?:string[]}
     */
    public static function run(bool $full = false, int $timeoutMs = 8000, bool $wantIps = false, int $wait = 0): array
    {
        $meta = State::meta();
        $state = State::load(true);
        $now = Util::nowMs();
        $result = ['ok' => false, 'status' => 0, 'changed' => [], 'error' => null];

        if (!$full) {
            if ($now < (int) ($meta['retryAfterUntil'] ?? 0)) {
                return ['error' => 'backing off (429)'] + $result;
            }
            $opened = (int) ($meta['circuitOpenedAt'] ?? 0);
            if ($opened > 0 && $now - $opened < self::CIRCUIT_COOLDOWN_MS) {
                return ['error' => 'circuit open'] + $result;
            }
        }

        $interval = Config::int('firewall.versionCheckInterval', 10, 1);
        $syncInterval = Config::int('firewall.syncInterval', 3600, 1);
        if (!$full && $state !== null && (time() - (int) ($state['fullAt'] ?? 0)) >= $syncInterval) {
            $full = true;
        }

        $headers = Exporter::controlHeaders();
        if ($state !== null && !$full) {
            $versions = $state['versions'] ?? [];
            foreach (['bl' => 'x-blocklist-version', 'al' => 'x-allowlist-version', 'rl' => 'x-rate-limit-version', 'ch' => 'x-challenge-version'] as $key => $header) {
                if (!empty($versions[$key])) {
                    $headers[$header] = (string) $versions[$key];
                }
            }
            if (!empty($state['etag'])) {
                $headers['if-none-match'] = (string) $state['etag'];
            }
            // Long-poll (the agent): the API holds the answer while nothing changed and answers as
            // soon as something does, so a block arrives when it is made.
            if ($wait > 0) {
                $headers['x-firewall-wait'] = (string) $wait;
                $timeoutMs = $wait * 1000 + 15000;
            }
        }

        $query = http_build_query(array_filter(['app' => Config::appKey(), 'env' => Config::environment()]));
        $bases = array_merge([Config::firewallApiUrl()], Config::firewallApiFallbacks());
        $preferred = (string) ($meta['apiUrl'] ?? '');
        if ($preferred !== '' && in_array($preferred, $bases, true)) {
            $bases = array_values(array_unique(array_merge([$preferred], $bases)));
        }

        $response = null;
        $usedBase = $bases[0];
        foreach ($bases as $base) {
            $usedBase = $base;
            $url = rtrim($base, '/') . '/api/v1/firewall/sync' . ($query !== '' ? '?' . $query : '');
            $response = Transport::request('GET', $url, $headers, null, $timeoutMs);
            // Only an unreachable host moves on to the fallback: never a URL the app did not configure.
            if ($response['status'] !== 0) {
                break;
            }
        }

        $meta['checkedAt'] = Util::nowMs();
        $status = (int) $response['status'];
        // The longest wait the API offers, 0 when it does not long-poll.
        $offered = (string) ($response['headers']['x-firewall-long-poll'] ?? '');
        $meta['longPoll'] = ($status === 200 || $status === 304) && preg_match('/^\d{1,6}$/', $offered) ? min(25, (int) $offered) : 0;
        $result['status'] = $status;

        if ($status === 304) {
            self::succeeded($meta, $usedBase, $interval);
            if ($state !== null && !empty($response['headers']['etag'])) {
                $state['etag'] = $response['headers']['etag'];
            }
            $result['ok'] = true;
            return $result;
        }

        if ($status === 200) {
            $body = $response['body'];
            $ips = self::extractStringArray($body, 'blocklistIps');
            $data = json_decode($body, true);
            unset($body);
            if (!is_array($data)) {
                return self::failed($meta, $result, 'unreadable sync answer', $interval, $state);
            }
            if ($ips === null && isset($data['blocklistIps']) && is_array($data['blocklistIps'])) {
                $ips = array_values(array_filter($data['blocklistIps'], 'is_string'));
            }
            $changed = self::apply($state, $data, $ips, $response['headers']['etag'] ?? null, $full || $state === null, $wantIps, $result);
            $result['changed'] = $changed;
            $result['ok'] = true;
            self::succeeded($meta, $usedBase, $interval);
            return $result;
        }

        if ($status === 429) {
            $retry = (int) ($response['headers']['retry-after'] ?? 0);
            if ($retry > 0 && $retry <= 300) {
                $meta['retryAfterUntil'] = Util::nowMs() + $retry * 1000;
            }
        }
        $error = $status === 0 ? (string) $response['error'] : 'API returned ' . $status . ': ' . substr($response['body'], 0, 200);
        return self::failed($meta, $result, $error, $interval, $state);
    }

    /** @param array<string,mixed> $meta */
    private static function succeeded(array $meta, string $base, int $interval): void
    {
        $meta['errors'] = 0;
        $meta['circuitOpenedAt'] = 0;
        $meta['retryAfterUntil'] = 0;
        $meta['lastError'] = null;
        $meta['apiUrl'] = $base;
        $meta['okAt'] = Util::nowMs();
        $meta['nextCheck'] = Util::nowMs() + (int) ($interval * 1000 * (0.8 + mt_rand(0, 400) / 1000));
        State::saveMeta($meta);
    }

    /**
     * @param array<string,mixed> $meta
     * @param array<string,mixed> $result
     * @param array<string,mixed>|null $state
     * @return array{ok:bool,status:int,changed:array<string,bool>,error:?string}
     */
    private static function failed(array $meta, array $result, string $error, int $interval, ?array $state): array
    {
        $errors = (int) ($meta['errors'] ?? 0) + 1;
        $meta['errors'] = $errors;
        $meta['lastError'] = $error;
        $meta['apiUrl'] = '';
        if ($errors >= self::CIRCUIT_THRESHOLD && empty($meta['circuitOpenedAt'])) {
            $meta['circuitOpenedAt'] = Util::nowMs();
        } elseif ($errors > self::CIRCUIT_THRESHOLD) {
            // Half-open probe failed: stay open for another cooldown.
            $meta['circuitOpenedAt'] = Util::nowMs();
        }
        $backoff = min($interval * 1000 * (2 ** min($errors, 8)), 120000);
        $meta['nextCheck'] = Util::nowMs() + (int) ($backoff * (0.8 + mt_rand(0, 400) / 1000));
        State::saveMeta($meta);
        Diag::warn('Firewall: sync failed (' . ($state === null ? 'no policy yet' : 'using the last policy') . '): ' . $error);
        $result['error'] = $error;
        return $result;
    }

    /**
     * @param array<string,mixed>|null $state
     * @param array<string,mixed> $data
     * @param string[]|null $ips
     * @param array<string,mixed> $result
     * @return array<string,bool>
     */
    private static function apply(?array $state, array $data, ?array $ips, ?string $etag, bool $wasFull, bool $wantIps, array &$result): array
    {
        $state = $state ?? [
            'versions' => [],
            'remoteEnabled' => true,
            'bl' => null,
            'blRules' => [],
            'al' => null,
            'rlRules' => [],
            'chRules' => [],
            'challenge' => null,
            'ua' => null,
        ];
        $changed = [];

        if (isset($data['app']) && is_array($data['app'])) {
            if (is_bool($data['app']['firewallEnabled'] ?? null)) {
                if (($state['remoteEnabled'] ?? true) !== $data['app']['firewallEnabled']) {
                    Diag::info('Firewall: remote toggle -> ' . ($data['app']['firewallEnabled'] ? 'ENABLED' : 'DISABLED'));
                }
                $state['remoteEnabled'] = $data['app']['firewallEnabled'];
            }
            if (isset($data['app']['challenge']) && is_array($data['app']['challenge'])) {
                $state['challenge'] = $data['app']['challenge'];
            }
        }
        foreach (['blocklist' => 'bl', 'allowlist' => 'al', 'rateLimits' => 'rl', 'challenges' => 'ch'] as $field => $key) {
            if (isset($data[$field]['version'])) {
                $state['versions'][$key] = (string) $data[$field]['version'];
            }
        }

        if ($ips !== null || isset($data['blocklistRules'])) {
            $generation = Util::randomHex(6);
            $set = IpSet::fromList($ips ?? []);
            $state['bl'] = State::packBlocklist($set, $generation);
            $state['blRules'] = self::normalizeBlocklistRules($data['blocklistRules'] ?? []);
            $state['gen'] = $generation;
            $changed['blocklist'] = true;
            if ($wantIps) {
                $result['ips'] = $ips ?? [];
            }
            Diag::info(sprintf(
                'Firewall: synced %d global blocked IPs (%d exact + %d CIDR ranges) and %d scoped block rules',
                $set->total(),
                $set->exact,
                $set->cidr,
                count($state['blRules'])
            ));
        }
        if (isset($data['allowlistIps']) && is_array($data['allowlistIps'])) {
            $state['al'] = IpSet::fromList($data['allowlistIps'])->export();
            $changed['allowlist'] = true;
        }
        if (isset($data['rateLimitRules']) && is_array($data['rateLimitRules'])) {
            $state['rlRules'] = self::cleanRules($data['rateLimitRules']);
            $changed['rateLimits'] = true;
        }
        if (isset($data['challengeRules']) && is_array($data['challengeRules'])) {
            $state['chRules'] = self::cleanRules($data['challengeRules']);
            $changed['challenges'] = true;
        }

        // Every full answer carries the whole user-agent rule set; one without it means none apply.
        $ua = UserAgentRules::compile($data['userAgentRules'] ?? null);
        if (($state['ua']['fingerprint'] ?? null) !== $ua['fingerprint']) {
            $changed['userAgentRules'] = true;
            if ($ua['skipped'] > 0) {
                Diag::warn('Firewall: skipped ' . $ua['skipped'] . ' user-agent rule(s): invalid, unsafe, duplicate or over the limit');
            }
        }
        $state['ua'] = $ua;

        if ($etag !== null && $etag !== '') {
            $state['etag'] = $etag;
        }
        $state['syncedAt'] = time();
        if ($wasFull) {
            $state['fullAt'] = time();
        }
        State::save($state);
        if (!empty($changed['blocklist']) && isset($state['gen'])) {
            State::removeOldBlocklists((string) $state['gen']);
        }
        if (mt_rand(1, 50) === 1) {
            RateLimiter::collectGarbage();
        }
        return $changed;
    }

    /**
     * Takes a large array of strings out of the JSON text before decoding it, so a blocklist of
     * hundreds of thousands of addresses never becomes a PHP array of zvals twice.
     *
     * @return string[]|null null when the key is absent
     */
    private static function extractStringArray(string &$body, string $key): ?array
    {
        $needle = '"' . $key . '":[';
        $start = strpos($body, $needle);
        if ($start === false) {
            return null;
        }
        $open = $start + strlen($needle);
        $close = strpos($body, ']', $open);
        if ($close === false) {
            return null;
        }
        $segment = substr($body, $open, $close - $open);
        $body = substr($body, 0, $open) . substr($body, $close);
        if (trim($segment) === '') {
            return [];
        }
        // Some JSON encoders write "/" as "\/".
        if (strpos($segment, '\\') !== false) {
            $segment = str_replace('\\/', '/', $segment);
        }
        $out = [];
        $token = strtok($segment, ',');
        while ($token !== false) {
            $value = trim($token, " \t\r\n\"");
            if ($value !== '') {
                $out[] = $value;
            }
            $token = strtok(',');
        }
        return $out;
    }

    /**
     * @param mixed $rules
     * @return array<int,array<string,mixed>>
     */
    private static function cleanRules($rules): array
    {
        $out = [];
        foreach (is_array($rules) ? $rules : [] as $rule) {
            if (is_array($rule)) {
                $out[] = $rule;
            }
        }
        return $out;
    }

    /**
     * @param mixed $rules
     * @return array<int,array<string,mixed>>
     */
    private static function normalizeBlocklistRules($rules): array
    {
        $out = [];
        foreach (is_array($rules) ? $rules : [] as $rule) {
            if (!is_array($rule) || empty($rule['ip'])) {
                continue;
            }
            $mode = strtolower((string) ($rule['pathMatchMode'] ?? ''));
            if (!in_array($mode, ['exact', 'prefix', 'regex'], true)) {
                $mode = 'prefix';
            }
            $rule['ip'] = trim((string) $rule['ip']);
            $rule['method'] = strtoupper((string) ($rule['method'] ?? 'ALL')) ?: 'ALL';
            $rule['pathMatchMode'] = $mode;
            $rule['pathPattern'] = $mode === 'prefix'
                ? Paths::normalizePrefix((string) ($rule['pathPattern'] ?? ''))
                : trim((string) ($rule['pathPattern'] ?? ''));
            $out[] = $rule;
        }
        return $out;
    }
}
