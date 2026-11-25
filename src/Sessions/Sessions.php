<?php

declare(strict_types=1);

namespace SecureNow\Sessions;

use SecureNow\Config;
use SecureNow\Events\Events;
use SecureNow\Firewall\Verdict;
use SecureNow\Http\RequestInfo;
use SecureNow\Http\Transport;
use SecureNow\Store\Store;
use SecureNow\Telemetry\Exporter;
use SecureNow\Util;

/**
 * Session and user revocation: the "kill the stolen session" half of account-takeover response
 * (the Node SDK's securenow/sessions).
 *
 *   // no code: "sessions": { "guard": true, "capture": true } in .securenow/runtime.json
 *   // or in your own auth check:
 *   if (SecureNow::checkSession()['revoked']) { /* answer 401 *\/ }
 *
 * The SDK pulls active revocations from SecureNow (outbound, ETag-cached) and checks each
 * request locally. Fail-open: a SecureNow or network outage never blocks traffic.
 * A session id is the SHA-256 of the Bearer token or session cookie; a user id is the JWT `sub`.
 */
final class Sessions
{
    private const STATE = 'rev.state';
    private const META = 'rev.meta';
    private const SYNC_INTERVAL_MS = 30000;
    private const CAPTURE_WINDOW_SECONDS = 300;

    /** A trailing * matches a prefix (WordPress adds a site hash to its cookie names). */
    private const SESSION_COOKIES = [
        '__Secure-next-auth.session-token',
        '__Host-next-auth.session-token',
        'next-auth.session-token',
        'connect.sid',
        'PHPSESSID',
        'wordpress_logged_in_*',
        'session',
        'sid',
    ];

    /** @var array<string,int>|null "type:value" => expiry in ms (0 = never) */
    private static ?array $entries = null;

    public static function reset(): void
    {
        self::$entries = null;
    }

    public static function sha256(string $value): string
    {
        return hash('sha256', $value);
    }

    /** @return string[] */
    public static function cookieNames(): array
    {
        return array_merge(Config::list('sessions.cookieNames'), self::SESSION_COOKIES);
    }

    /**
     * The session and user a request carries, with no app code.
     *
     * @return array{sessionId:?string,userId:?string}
     */
    public static function identify(RequestInfo $request): array
    {
        $sessionId = null;
        $userId = null;
        $auth = $request->header('authorization');
        if ($auth !== '' && preg_match('/^Bearer\s+(\S+)/i', $auth, $m)) {
            $token = trim($m[1]);
            if ($token !== '') {
                $sessionId = self::sha256($token);
                $segments = explode('.', $token);
                if (count($segments) >= 2) {
                    $payload = json_decode(Util::b64urlDecode($segments[1]), true);
                    if (is_array($payload) && isset($payload['sub']) && is_scalar($payload['sub']) && (string) $payload['sub'] !== '') {
                        $userId = (string) $payload['sub'];
                    }
                }
            }
        }
        if ($sessionId === null) {
            $cookies = $request->cookies();
            if ($cookies) {
                foreach (self::cookieNames() as $name) {
                    if (substr($name, -1) === '*') {
                        $prefix = substr($name, 0, -1);
                        foreach ($cookies as $cookieName => $value) {
                            if ($value !== '' && strncmp((string) $cookieName, $prefix, strlen($prefix)) === 0) {
                                $sessionId = self::sha256($value);
                                break 2;
                            }
                        }
                    } elseif (!empty($cookies[$name])) {
                        $sessionId = self::sha256($cookies[$name]);
                        break;
                    }
                }
            }
        }
        return ['sessionId' => $sessionId, 'userId' => $userId];
    }

    /** @return array<string,int> */
    private static function entries(): array
    {
        if (self::$entries !== null) {
            return self::$entries;
        }
        $state = Store::readArray(self::STATE);
        if ($state === null) {
            // First use on this machine: fetch once, now, so a revocation applies from the first request.
            self::sync(false, 2500);
            $state = Store::readArray(self::STATE);
        } else {
            self::markUsed();
        }
        self::$entries = is_array($state['entries'] ?? null) ? $state['entries'] : [];
        return self::$entries;
    }

    /** Sessions are in use: keep the revocation list fresh after responses. */
    private static function markUsed(): void
    {
        Exporter::addTask([self::class, 'syncMaybe']);
    }

    public static function isRevoked(?string $sessionId, ?string $userId): bool
    {
        if (Config::apiKey() === null || Config::appKey() === null) {
            return false;
        }
        $entries = self::entries();
        if (!$entries) {
            return false;
        }
        $now = Util::nowMs();
        foreach (['session' => $sessionId, 'user' => $userId] as $type => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $key = $type . ':' . $value;
            if (isset($entries[$key]) && ($entries[$key] === 0 || $now <= $entries[$key])) {
                return true;
            }
        }
        return false;
    }

    /** session.seen, at most once per session and address every 5 minutes: feeds session-theft detection. */
    public static function seen(?string $sessionId, ?string $userId, string $ip): void
    {
        if (($sessionId === null || $sessionId === '') && ($userId === null || $userId === '')) {
            return;
        }
        $key = sha1(($sessionId ?? '') . '|' . $ip);
        if (Store::apcu()) {
            if (!@apcu_add('securenow:seen:' . $key, 1, self::CAPTURE_WINDOW_SECONDS)) {
                return;
            }
        } else {
            $dir = Store::path('seen');
            if ($dir !== null) {
                if (!@is_dir($dir)) {
                    @mkdir($dir, 0700, true);
                }
                $file = $dir . DIRECTORY_SEPARATOR . $key;
                $mtime = @filemtime($file);
                if ($mtime !== false && (time() - $mtime) < self::CAPTURE_WINDOW_SECONDS) {
                    return;
                }
                @touch($file);
                if (mt_rand(1, 200) === 1) {
                    self::collectSeen($dir);
                }
            }
        }
        $props = ['ip' => $ip];
        if ($sessionId !== null && $sessionId !== '') {
            $props['sessionId'] = $sessionId;
        }
        if ($userId !== null && $userId !== '') {
            $props['userId'] = $userId;
        }
        Events::track('session.seen', $props);
    }

    private static function collectSeen(string $dir): void
    {
        $cutoff = time() - self::CAPTURE_WINDOW_SECONDS * 2;
        $n = 0;
        foreach ((array) @scandir($dir) as $name) {
            if (!is_string($name) || $name === '.' || $name === '..') {
                continue;
            }
            $mtime = @filemtime($dir . DIRECTORY_SEPARATOR . $name);
            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($dir . DIRECTORY_SEPARATOR . $name);
            }
            if (++$n > 20000) {
                break;
            }
        }
    }

    /**
     * Is this session or user revoked? Feeds session-theft detection unless $capture is false.
     *
     * @return array{revoked:bool,sessionId:?string,userId:?string}
     */
    public static function check(?string $sessionId, ?string $userId, string $ip, bool $capture = true): array
    {
        try {
            if ($capture) {
                self::seen($sessionId, $userId, $ip);
            }
            return ['revoked' => self::isRevoked($sessionId, $userId), 'sessionId' => $sessionId, 'userId' => $userId];
        } catch (\Throwable $e) {
            return ['revoked' => false, 'sessionId' => $sessionId, 'userId' => $userId];
        }
    }

    /** Zero-code guard (config.sessions.guard / config.sessions.capture), run before the app. */
    public static function guard(RequestInfo $request, string $ip): ?Verdict
    {
        $enforce = Config::bool('sessions.guard', false);
        $capture = Config::bool('sessions.capture', false);
        if ((!$enforce && !$capture) || Config::apiKey() === null) {
            return null;
        }
        try {
            $identity = self::identify($request);
            if ($identity['sessionId'] === null && $identity['userId'] === null) {
                return null;
            }
            if ($capture) {
                self::seen($identity['sessionId'], $identity['userId'], $ip);
            }
            if ($enforce && self::isRevoked($identity['sessionId'], $identity['userId'])) {
                return self::revokedVerdict($request);
            }
        } catch (\Throwable $e) {
            // fail-open
        }
        return null;
    }

    /** The 401 the guard answers with: session cookies cleared, a JSON body. */
    public static function revokedVerdict(RequestInfo $request): Verdict
    {
        $verdict = new Verdict(
            'session_revoked',
            401,
            ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'],
            '{"error":"Session revoked. Please sign in again.","code":"session_revoked"}'
        );
        $present = $request->cookies();
        foreach (self::cookieNames() as $name) {
            if (substr($name, -1) === '*') {
                $prefix = substr($name, 0, -1);
                foreach ($present as $cookieName => $_) {
                    if (strncmp((string) $cookieName, $prefix, strlen($prefix)) === 0) {
                        $verdict->cookies[] = $cookieName . '=; Path=/; Max-Age=0; HttpOnly';
                    }
                }
            } else {
                $verdict->cookies[] = $name . '=; Path=/; Max-Age=0; HttpOnly';
            }
        }
        $verdict->attributes = ['securenow.session.revoked' => true];
        return $verdict;
    }

    /** Post-response hook. */
    public static function syncMaybe(bool $detached = true): void
    {
        if (Config::apiKey() === null || Store::dir() === null || Exporter::agentAlive()) {
            return;
        }
        $meta = Store::readArray(self::META) ?? [];
        if (Util::nowMs() < (int) ($meta['nextCheck'] ?? 0)) {
            return;
        }
        if (!$detached && PHP_SAPI !== 'cli-server') {
            return;
        }
        self::sync();
    }

    /** One revocation sync. @return bool whether SecureNow answered */
    public static function sync(bool $force = false, int $timeoutMs = 5000): bool
    {
        $apiKey = Config::apiKey();
        $appKey = Config::appKey();
        if ($apiKey === null || $appKey === null || Store::dir() === null) {
            return false;
        }
        $lock = Store::lock('rev');
        if ($lock === null) {
            return false;
        }
        try {
            $state = Store::readArray(self::STATE);
            $meta = Store::readArray(self::META) ?? [];
            $meta['nextCheck'] = Util::nowMs() + self::SYNC_INTERVAL_MS;
            Store::writeArray(self::META, $meta);

            $headers = Exporter::controlHeaders() + ['x-securenow-app-key' => $appKey];
            if (!$force && $state !== null && !empty($state['etag'])) {
                $headers['if-none-match'] = (string) $state['etag'];
            }
            $url = rtrim(Config::firewallApiUrl(), '/') . '/api/v1/revocations/sync?' . http_build_query(['app' => $appKey, 'env' => Config::environment()]);
            $response = Transport::request('GET', $url, $headers, null, $timeoutMs);
            if ($response['status'] === 304) {
                return true;
            }
            if ($response['status'] < 200 || $response['status'] >= 300) {
                return false;
            }
            $body = json_decode($response['body'], true);
            if (!is_array($body)) {
                return false;
            }
            $entries = [];
            foreach (($body['revocations']['entries'] ?? []) as $entry) {
                if (!is_array($entry) || empty($entry['type']) || empty($entry['value'])) {
                    continue;
                }
                $expiry = 0;
                if (!empty($entry['expiresAt'])) {
                    $time = strtotime((string) $entry['expiresAt']);
                    $expiry = $time === false ? 0 : $time * 1000;
                }
                $entries[$entry['type'] . ':' . $entry['value']] = $expiry;
            }
            Store::writeArray(self::STATE, ['etag' => $response['headers']['etag'] ?? null, 'entries' => $entries, 'syncedAt' => time()]);
            self::$entries = $entries;
            return true;
        } finally {
            Store::unlock($lock);
        }
    }

    /** @return array<string,mixed> */
    public static function stats(): array
    {
        $state = Store::readArray(self::STATE);
        return ['synced' => $state !== null, 'revocations' => count($state['entries'] ?? []), 'syncedAt' => $state['syncedAt'] ?? null];
    }
}
