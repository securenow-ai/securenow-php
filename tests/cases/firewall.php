<?php

declare(strict_types=1);

use SecureNow\Firewall\Challenge;
use SecureNow\Firewall\Firewall;
use SecureNow\Firewall\State;
use SecureNow\Firewall\Sync;
use SecureNow\Http\Transport;
use SecureNow\Net\ClientIp;
use SecureNow\SecureNow;
use SecureNow\Sessions\Sessions;
use SecureNow\Telemetry\Exporter;

/**
 * A fake SecureNow backend behind Transport::fake(): records every call, answers the firewall
 * sync with $policy, and accepts telemetry.
 */
final class FakeBackend
{
    /** @var array<int,array<string,mixed>> */
    public static array $calls = [];
    /** @var array<string,mixed> */
    public static array $policy = [];
    public static int $syncStatus = 200;
    /** @var array<int,array<string,string>> */
    public static array $revocations = [];

    /** @param array<string,mixed> $policy */
    public static function install(array $policy = []): void
    {
        self::$calls = [];
        self::$syncStatus = 200;
        self::$revocations = [];
        self::$policy = $policy + [
            'blocklist' => ['version' => 'bl1', 'count' => 0],
            'allowlist' => ['version' => 'al1', 'count' => 0],
            'rateLimits' => ['version' => 'rl1', 'count' => 0],
            'challenges' => ['version' => 'ch1', 'count' => 0],
            'environment' => 'production',
            'userAgentRules' => ['version' => 'ua1', 'rules' => [], 'exemptIps' => [], 'allow' => []],
            'app' => ['key' => 'app', 'firewallEnabled' => true, 'challenge' => ['secret' => 'challenge-secret', 'difficulty' => 4, 'challengeTtl' => 120, 'clearanceTtl' => 1800, 'verify' => 'auto']],
            'blocklistIps' => [],
            'blocklistRules' => [],
            'allowlistIps' => [],
            'rateLimitRules' => [],
            'challengeRules' => [],
        ];
        Transport::fake(static function (array $request): array {
            FakeBackend::$calls[] = $request;
            $url = (string) $request['url'];
            if (strpos($url, '/firewall/sync') !== false) {
                if (FakeBackend::$syncStatus !== 200) {
                    return ['status' => FakeBackend::$syncStatus, 'headers' => [], 'body' => '', 'error' => FakeBackend::$syncStatus === 0 ? 'connection refused' : null];
                }
                $etag = '"' . sha1(json_encode(FakeBackend::$policy)) . '|ua:ua1"';
                if (($request['headers']['if-none-match'] ?? '') === $etag) {
                    return ['status' => 304, 'headers' => ['etag' => $etag], 'body' => ''];
                }
                return ['status' => 200, 'headers' => ['etag' => $etag], 'body' => json_encode(FakeBackend::$policy)];
            }
            if (strpos($url, '/revocations/sync') !== false) {
                return ['status' => 200, 'headers' => ['etag' => '"r1"'], 'body' => json_encode(['revocations' => ['entries' => FakeBackend::$revocations]])];
            }
            return ['status' => 200, 'headers' => [], 'body' => '{"ok":true}'];
        });
    }

    /** @return array<int,array<string,mixed>> */
    public static function callsTo(string $fragment): array
    {
        return array_values(array_filter(self::$calls, static function (array $call) use ($fragment): bool {
            return strpos((string) $call['url'], $fragment) !== false;
        }));
    }
}

/** @param array<string,string> $headers */
function fw_check(string $method, string $target, string $ip, array $headers = [], ?string $body = null): ?\SecureNow\Firewall\Verdict
{
    State::reset();
    $request = T::request($method, $target, $headers, $ip, $body);
    return Firewall::check($request, ClientIp::resolve($request));
}

return [
    'first request syncs the policy, then blocks a listed address' => static function (): void {
        T::boot();
        FakeBackend::install(['blocklistIps' => ['203.0.113.7', '198.18.0.0/15', '2001:db8:bad::/48']]);
        $verdict = fw_check('GET', '/', '203.0.113.7', ['accept' => 'text/html']);
        T::ok($verdict !== null, 'blocked');
        T::eq(403, $verdict->status);
        T::eq('blocked', $verdict->action);
        T::contains('Access Blocked', $verdict->body);
        T::contains('203.0.113.7', $verdict->body);

        $json = fw_check('GET', '/api', '198.19.4.4', ['accept' => 'application/json']);
        T::eq('{"error":"Forbidden","ip":"198.19.4.4"}', $json->body);
        T::ok(fw_check('GET', '/', '2001:db8:bad::1') !== null, 'ipv6 range');
        T::eq(null, fw_check('GET', '/', '203.0.113.8'));

        $sync = FakeBackend::callsTo('/firewall/sync');
        T::eq(1, count($sync), 'one sync for all those requests');
        T::contains('https://ingest.securenow.ai/api/v1/firewall/sync?app=11111111-2222-3333-4444-555555555555&env=production', (string) $sync[0]['url']);
        T::eq('Bearer snk_live_testkey0123456789', $sync[0]['headers']['authorization']);
    },

    'blocked requests are reported once, coalesced' => static function (): void {
        T::boot();
        FakeBackend::install(['blocklistIps' => ['203.0.113.7']]);
        fw_check('GET', '/a', '203.0.113.7');
        fw_check('GET', '/a', '203.0.113.7');
        fw_check('GET', '/a', '203.0.113.7');
        Exporter::finish();
        Exporter::flush(false, true);
        $posts = FakeBackend::callsTo('/firewall/events');
        T::eq(1, count($posts));
        $events = json_decode((string) $posts[0]['body'], true)['events'];
        T::eq(1, count($events));
        T::eq(3, $events[0]['count']);
        T::eq('blocklist', $events[0]['source']);
        T::eq('203.0.113.7', $events[0]['ip']);
    },

    'an allowlist lets only listed addresses through' => static function (): void {
        T::boot();
        FakeBackend::install(['allowlistIps' => ['198.51.100.0/24'], 'blocklistIps' => ['198.51.100.5']]);
        T::eq(null, fw_check('GET', '/', '198.51.100.5'), 'allowlisted wins');
        $verdict = fw_check('GET', '/', '203.0.113.1');
        T::eq(403, $verdict->status);
        T::eq('allowlist', $verdict->attributes['securenow.firewall.source']);
    },

    'the dashboard switch turns enforcement off' => static function (): void {
        T::boot();
        FakeBackend::install(['blocklistIps' => ['203.0.113.7'], 'app' => ['firewallEnabled' => false]]);
        T::eq(null, fw_check('GET', '/', '203.0.113.7'));
    },

    'user-agent rules block scrapers from any address' => static function (): void {
        T::boot();
        FakeBackend::install(['userAgentRules' => [
            'version' => 'ua2',
            'rules' => [['id' => 'gptbot', 'pattern' => 'GPTBot', 'category' => 'ai'], ['id' => 'evil', 'pattern' => '(a+)+$', 'category' => 'x']],
            'allow' => [['id' => 'ok', 'pattern' => 'FriendlyBot']],
            'exemptIps' => ['198.51.100.200'],
        ]]);
        $verdict = fw_check('GET', '/', '198.51.100.9', ['user-agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2)']);
        T::eq(403, $verdict->status);
        T::eq('gptbot', $verdict->attributes['securenow.firewall.rule_id']);
        T::eq(null, fw_check('GET', '/', '198.51.100.9', ['user-agent' => 'Mozilla/5.0 Chrome/120']));
        T::eq(null, fw_check('GET', '/', '198.51.100.9', ['user-agent' => 'GPTBot FriendlyBot']), 'allow wins');
        T::eq(null, fw_check('GET', '/', '198.51.100.200', ['user-agent' => 'GPTBot']), 'exempt address');
        T::eq(1, count(State::load()['ua']['rules']), 'the unsafe pattern was dropped');
    },

    'route-scoped block rules follow method, path and expiry' => static function (): void {
        T::boot();
        FakeBackend::install(['blocklistRules' => [
            ['id' => 'r1', 'ip' => '198.51.100.9', 'method' => 'POST', 'pathPattern' => '/api/login', 'pathMatchMode' => 'exact'],
            ['id' => 'r2', 'ip' => '198.51.100.0/24', 'method' => 'ALL', 'pathPattern' => '/admin*', 'pathMatchMode' => 'prefix'],
            ['id' => 'r3', 'ip' => '198.51.100.9', 'method' => 'ALL', 'pathPattern' => '/old', 'expiresAt' => '2020-01-01T00:00:00Z'],
        ]]);
        T::eq('r1', fw_check('POST', '/api/login', '198.51.100.9')->attributes['securenow.firewall.rule_id']);
        T::eq('r1', fw_check('POST', '/API/Login/', '198.51.100.9')->attributes['securenow.firewall.rule_id'], 'canonical alias');
        T::eq(null, fw_check('GET', '/api/login', '198.51.100.9'), 'other method');
        T::eq(null, fw_check('POST', '/api/login', '198.51.100.10'), 'other address');
        T::eq('r2', fw_check('GET', '/admin/users', '198.51.100.77')->attributes['securenow.firewall.rule_id']);
        T::eq(null, fw_check('GET', '/old', '198.51.100.9'), 'expired');
    },

    'rate limits answer 429 with Retry-After, per address' => static function (): void {
        T::boot();
        FakeBackend::install(['rateLimitRules' => [
            ['id' => 'rl-login', 'ip' => '', 'method' => 'POST', 'pathPattern' => '/login', 'pathMatchMode' => 'exact', 'limit' => 3, 'windowSeconds' => 3600, 'keyBy' => 'ip'],
        ]]);
        for ($i = 0; $i < 3; $i++) {
            T::eq(null, fw_check('POST', '/login', '198.51.100.31'), "request $i passes");
        }
        $verdict = fw_check('POST', '/login', '198.51.100.31');
        T::eq(429, $verdict->status);
        T::eq('3', $verdict->headers['X-RateLimit-Limit']);
        T::eq('rl-login', $verdict->headers['X-SecureNow-Rate-Limit-Rule']);
        T::ok((int) $verdict->headers['Retry-After'] >= 1);
        T::eq(null, fw_check('POST', '/login', '198.51.100.32'), 'another address has its own bucket');
        T::eq(null, fw_check('GET', '/login', '198.51.100.31'), 'another method is not limited');
    },

    'rate limits can count per header value' => static function (): void {
        T::boot();
        FakeBackend::install(['rateLimitRules' => [
            ['id' => 'rl-key', 'ip' => '', 'method' => 'ALL', 'pathPattern' => '/api', 'limit' => 2, 'windowSeconds' => 3600, 'keyBy' => 'header', 'keyName' => 'X-Api-Key'],
        ]]);
        T::eq(null, fw_check('GET', '/api/a', '198.51.100.41', ['x-api-key' => 'k1']));
        T::eq(null, fw_check('GET', '/api/a', '198.51.100.42', ['x-api-key' => 'k1']));
        T::eq(429, fw_check('GET', '/api/a', '198.51.100.43', ['x-api-key' => 'k1'])->status, 'same key from a third address');
        T::eq(null, fw_check('GET', '/api/a', '198.51.100.43', ['x-api-key' => 'k2']));
    },

    'a challenge is served, solved, and cleared' => static function (): void {
        T::boot();
        FakeBackend::install(['challengeRules' => [['id' => 'ch-1', 'ip' => '', 'method' => 'ALL', 'pathPattern' => '/shop', 'difficulty' => 6]]]);
        $ip = '198.51.100.50';
        $ua = 'Mozilla/5.0 Test';
        $page = fw_check('GET', '/shop/cart?x=1', $ip, ['accept' => 'text/html', 'user-agent' => $ua]);
        T::eq(403, $page->status);
        T::eq('required', $page->headers['X-SecureNow-Challenge']);
        T::contains('Verifying your browser', $page->body);
        T::contains('"ret":"/shop/cart?x=1"', $page->body);

        $api = fw_check('GET', '/shop/cart', $ip, ['accept' => 'application/json', 'user-agent' => $ua]);
        $challenge = json_decode($api->body, true)['challenge'];
        T::eq('pow-sha256', $challenge['alg']);
        T::eq(6, $challenge['difficulty']);
        $nonce = 0;
        while (Challenge::leadingZeroBits(hash('sha256', $challenge['token'] . '.' . $nonce, true)) < 6) {
            $nonce++;
        }

        $wrong = fw_check('POST', Challenge::INTERNAL_PATH, $ip, ['user-agent' => $ua], json_encode(['token' => $challenge['token'], 'nonce' => 'nope']));
        T::eq(400, $wrong->status);
        T::eq(405, fw_check('GET', Challenge::INTERNAL_PATH, $ip)->status);

        $solved = fw_check('POST', Challenge::INTERNAL_PATH, $ip, ['user-agent' => $ua], json_encode(['token' => $challenge['token'], 'nonce' => (string) $nonce]));
        T::eq(204, $solved->status);
        T::eq(1, count($solved->cookies));
        T::contains('__sn_clearance=k1.', $solved->cookies[0]);
        T::contains('HttpOnly; SameSite=Lax', $solved->cookies[0]);
        $cookie = explode(';', $solved->cookies[0])[0];

        T::eq(null, fw_check('GET', '/shop/cart', $ip, ['user-agent' => $ua, 'cookie' => "a=b; $cookie"]), 'cleared');
        T::eq(403, fw_check('GET', '/shop/cart', '198.51.100.51', ['user-agent' => $ua, 'cookie' => $cookie])->status, 'clearance is bound to the address');
        T::eq(null, fw_check('GET', '/other', $ip, ['user-agent' => $ua]), 'unmatched path');
    },

    'the agent long-polls when the API offers it' => static function (): void {
        T::boot();
        FakeBackend::install();
        $seen = [];
        Transport::fake(static function (array $request) use (&$seen): array {
            $seen[] = $request;
            return ['status' => 200, 'headers' => ['etag' => '"e1"', 'x-firewall-long-poll' => '25'], 'body' => json_encode(FakeBackend::$policy)];
        });
        T::ok(Sync::run()['ok']);
        T::eq(25, State::meta()['longPoll']);
        T::ok(!isset($seen[0]['headers']['x-firewall-wait']), 'no wait without a policy to compare');
        Sync::run(false, 8000, false, 5);
        T::eq('5', $seen[1]['headers']['x-firewall-wait']);
        T::eq(20000, $seen[1]['timeoutMs'], 'the request outlives the wait');
        Sync::run(true, 8000, false, 5);
        T::ok(!isset($seen[2]['headers']['x-firewall-wait']), 'a full sync never waits');
    },

    'an unchanged policy is answered 304 and failures back off' => static function (): void {
        T::boot();
        FakeBackend::install(['blocklistIps' => ['203.0.113.7']]);
        T::ok(Sync::run()['ok']);
        $second = Sync::run();
        T::eq(304, $second['status']);
        $headers = FakeBackend::callsTo('/firewall/sync')[1]['headers'];
        T::eq('bl1', $headers['x-blocklist-version']);
        T::ok(isset($headers['if-none-match']));

        FakeBackend::$syncStatus = 500;
        $failed = Sync::run();
        T::eq(false, $failed['ok']);
        $meta = State::meta();
        T::eq(1, $meta['errors']);
        T::ok($meta['nextCheck'] > \SecureNow\Util::nowMs() + 10000, 'backs off');
        T::ok(fw_check('GET', '/', '203.0.113.7') !== null, 'the last policy is still enforced');
    },

    'an unreachable gateway falls back to the API host' => static function (): void {
        T::boot();
        FakeBackend::install();
        Transport::fake(static function (array $request): array {
            FakeBackend::$calls[] = $request;
            if (strpos((string) $request['url'], 'ingest.securenow.ai') !== false) {
                return ['status' => 0, 'headers' => [], 'body' => '', 'error' => 'could not resolve host'];
            }
            return ['status' => 200, 'headers' => ['etag' => '"x"'], 'body' => json_encode(FakeBackend::$policy)];
        });
        T::ok(Sync::run()['ok']);
        T::contains('https://api.securenow.ai/api/v1/firewall/sync', (string) FakeBackend::$calls[1]['url']);
    },

    'fail mode: open lets traffic through without a policy, closed blocks it' => static function (): void {
        T::boot();
        FakeBackend::install();
        FakeBackend::$syncStatus = 0;
        T::eq(null, fw_check('GET', '/', '198.51.100.60'));
        T::boot(['firewall' => ['failMode' => 'closed']]);
        FakeBackend::install();
        FakeBackend::$syncStatus = 0;
        T::eq(403, fw_check('GET', '/', '198.51.100.60')->status);
    },

    'without a runtime key the firewall is off and nothing is called' => static function (): void {
        T::boot([], false);
        FakeBackend::install(['blocklistIps' => ['203.0.113.7']]);
        T::eq(null, fw_check('GET', '/', '203.0.113.7'));
        T::eq(0, count(FakeBackend::$calls));
    },

    'a large blocklist is stored in files and still matches' => static function (): void {
        $dir = T::boot();
        $ips = [];
        for ($i = 0; $i < 12000; $i++) {
            $ips[] = '100.' . intdiv($i, 65536) . '.' . (intdiv($i, 256) % 256) . '.' . ($i % 256);
        }
        $ips[] = '2001:db8::99';
        FakeBackend::install(['blocklistIps' => $ips]);
        T::ok(fw_check('GET', '/', '100.0.46.223') !== null, 'last listed');
        T::ok(fw_check('GET', '/', '100.0.0.0') !== null, 'first listed');
        T::eq(null, fw_check('GET', '/', '100.0.47.0'));
        T::ok(fw_check('GET', '/', '2001:db8::99') !== null);
        T::ok(count(glob($dir . '/bl-*.v4') ?: []) === 1, 'blocklist file written');
        T::ok(filesize($dir . '/fw.state') < 20000, 'the state file stays small');
    },

    'the session guard answers 401 for a revoked session' => static function (): void {
        T::boot(['sessions' => ['guard' => true, 'capture' => true]]);
        FakeBackend::install();
        $token = 'header.' . rtrim(strtr(base64_encode('{"sub":"user-42"}'), '+/', '-_'), '=') . '.sig';
        FakeBackend::$revocations = [
            ['type' => 'session', 'value' => hash('sha256', 'stolen-cookie-value')],
            ['type' => 'user', 'value' => 'user-42'],
            ['type' => 'session', 'value' => hash('sha256', 'expired'), 'expiresAt' => '2020-01-01T00:00:00Z'],
        ];
        $revoked = Sessions::guard(T::request('GET', '/', ['cookie' => 'PHPSESSID=stolen-cookie-value']), '198.51.100.70');
        T::eq(401, $revoked->status);
        T::contains('session_revoked', $revoked->body);
        T::ok(in_array('PHPSESSID=; Path=/; Max-Age=0; HttpOnly', $revoked->cookies, true));
        T::eq(401, Sessions::guard(T::request('GET', '/', ['authorization' => "Bearer $token"]), '198.51.100.70')->status, 'revoked user (JWT sub)');
        T::eq(null, Sessions::guard(T::request('GET', '/', ['cookie' => 'PHPSESSID=fine']), '198.51.100.70'));
        T::eq(null, Sessions::guard(T::request('GET', '/', ['cookie' => 'PHPSESSID=expired']), '198.51.100.70'));
        T::eq(null, Sessions::guard(T::request('GET', '/'), '198.51.100.70'), 'no session, nothing to check');

        Exporter::finish();
        Exporter::flush(false, true);
        $events = json_decode((string) FakeBackend::callsTo('/v1/events')[0]['body'], true)['events'];
        T::eq('session.seen', $events[0]['type']);
        T::eq('198.51.100.70', $events[0]['ip']);
        T::eq(hash('sha256', 'stolen-cookie-value'), $events[0]['session_id']);
    },

    'a worker runtime drives requests: a verdict is a firewall hit, a passed request a trace' => static function (): void {
        T::boot();
        FakeBackend::install(['blocklistIps' => ['203.0.113.7']]);
        T::ok(SecureNow::start());
        $verdict = SecureNow::beginRequest(T::request('GET', '/pricing?plan=pro', ['accept' => 'application/json'], '203.0.113.7'));
        T::eq(403, $verdict->status);
        SecureNow::endRequest($verdict->status);
        Exporter::flush(false, true);

        // A request the firewall answered is a firewall hit, not a trace.
        T::eq(0, count(FakeBackend::callsTo('/v1/traces')));
        $hits = json_decode((string) FakeBackend::callsTo('/firewall/events')[0]['body'], true)['events'];
        T::eq('203.0.113.7', $hits[0]['ip']);
        T::eq('/pricing?plan=pro', $hits[0]['path']);
        $syncHeaders = FakeBackend::callsTo('/firewall/sync')[0]['headers'];
        T::eq('8.28.0', $syncHeaders['x-securenow-sdk-version']);
        T::eq('securenow-php/' . \SecureNow\Version::SDK, $syncHeaders['x-securenow-sdk']);

        // The next request of the same worker is independent, and traced.
        T::eq(null, SecureNow::beginRequest(T::request('GET', '/pricing?plan=pro', [], '198.51.100.80')));
        T::eq('198.51.100.80', SecureNow::clientIp());
        SecureNow::endRequest(200);
        Exporter::flush(false, true);
        $traces = FakeBackend::callsTo('/v1/traces');
        T::eq(1, count($traces));
        T::eq('11111111-2222-3333-4444-555555555555', $traces[0]['headers']['x-securenow-app-key']);
        $span = json_decode((string) $traces[0]['body'], true)['resourceSpans'][0]['scopeSpans'][0]['spans'][0];
        $attrs = [];
        foreach ($span['attributes'] as $attribute) {
            $attrs[$attribute['key']] = current($attribute['value']);
        }
        T::eq(2, $span['kind']);
        T::eq('198.51.100.80', $attrs['http.client_ip']);
        T::eq('200', $attrs['http.status_code']);
        T::eq('/pricing?plan=pro', $attrs['http.target']);
    },
];
