<?php

declare(strict_types=1);

use SecureNow\Firewall\Challenge;
use SecureNow\Firewall\Paths;
use SecureNow\Firewall\UserAgentRules;
use SecureNow\Net\ClientIp;
use SecureNow\Net\IpSet;
use SecureNow\Redaction\Redactor;

// Every case replays inputs through the PHP port and expects what the Node SDK produced
// (tests/fixtures/node-parity.json, written by tests/tools/gen-fixtures.js).

return [
    'value redaction matches Node' => static function (): void {
        foreach (T::fixtures()['values'] as $case) {
            T::eq($case['out'], Redactor::redactValue($case['in']), 'value ' . substr($case['in'], 0, 40));
        }
    },

    'body redaction matches Node' => static function (): void {
        $f = T::fixtures();
        $redactor = new Redactor($f['customFields']);
        foreach ($f['bodies'] as $case) {
            $result = null;
            try {
                $result = $redactor->redactBodyText($case['body'], $case['contentType']);
            } catch (Throwable $e) {
                $result = ['error' => true];
            }
            if ($case['result'] === null || isset($case['result']['error'])) {
                T::eq($case['result'], $result, 'body ' . $case['body']);
                continue;
            }
            T::eq($case['result']['type'], $result['type'] ?? null, 'type of ' . $case['body']);
            // Compare as data: key order and number formatting are the encoder's business.
            if ($case['result']['type'] === 'graphql') {
                T::eq($case['result']['body'], $result['body'], 'graphql ' . $case['body']);
            } else {
                T::eq(json_decode($case['result']['body'], true), json_decode($result['body'], true), 'body ' . $case['body']);
            }
        }
    },

    'captured JSON keeps slashes and unicode as written' => static function (): void {
        $redactor = new Redactor();
        $result = $redactor->redactBodyText('{"path":"../../etc/passwd","html":"<script>","u":"héllo"}', 'application/json');
        T::eq('{"path":"../../etc/passwd","html":"<script>","u":"héllo"}', $result['body']);
    },

    'sensitive header names match Node' => static function (): void {
        $f = T::fixtures();
        $redactor = new Redactor($f['headerCustom']);
        foreach ($f['headers'] as $case) {
            T::eq($case['sensitive'], $redactor->isSensitiveHeader($case['name']), 'header ' . $case['name']);
        }
    },

    'log redaction matches Node' => static function (): void {
        foreach (T::fixtures()['logs'] as $case) {
            T::eq($case['out'], Redactor::redactLogText($case['in']), 'log ' . $case['in']);
        }
    },

    'query redaction matches Node' => static function (): void {
        foreach (T::fixtures()['searches'] as $case) {
            T::eq($case['out'], Redactor::redactSearch($case['in']), 'search ' . $case['in']);
        }
    },

    'OTP field detection matches Node' => static function (): void {
        foreach (T::fixtures()['otpFields'] as $case) {
            T::eq($case['otp'], Redactor::isOtpCodeField($case['key']), 'otp ' . $case['key']);
        }
    },

    'path rules match Node' => static function (): void {
        foreach (T::fixtures()['pathCases'] as $case) {
            T::eq($case['match'], Paths::ruleMatches($case['rule'], $case['path']), json_encode($case['rule']) . ' vs ' . $case['path']);
        }
    },

    'canonical paths match Node' => static function (): void {
        foreach (T::fixtures()['canonical'] as $case) {
            T::eq($case['plain'], Paths::canonical($case['path']), 'canonical ' . $case['path']);
            T::eq($case['stripped'], Paths::canonical($case['path'], true), 'stripped ' . $case['path']);
        }
    },

    'user-agent pattern safety matches Node' => static function (): void {
        foreach (T::fixtures()['uaProblems'] as $case) {
            T::eq($case['refused'], UserAgentRules::patternProblem($case['pattern']) !== '', 'pattern ' . substr($case['pattern'], 0, 40));
        }
    },

    'user-agent matching matches Node' => static function (): void {
        $f = T::fixtures();
        $compiled = UserAgentRules::compile($f['uaRuleSet']);
        foreach ($f['uaMatches'] as $case) {
            $rule = UserAgentRules::match($compiled, $case['ua'], $case['ip']);
            T::eq($case['rule'], $rule['id'] ?? null, 'ua ' . $case['ua'] . ' from ' . $case['ip']);
        }
    },

    'IP and CIDR matching matches Node' => static function (): void {
        $f = T::fixtures();
        $set = IpSet::fromList($f['ipList']);
        foreach ($f['ipMatches'] as $case) {
            T::eq($case['blocked'], $set->contains($case['ip']), 'ip ' . $case['ip']);
        }
    },

    'IP set survives export/import and file search' => static function (): void {
        $f = T::fixtures();
        $set = IpSet::import(IpSet::fromList($f['ipList'])->export());
        $file = tempnam(sys_get_temp_dir(), 'snip');
        file_put_contents($file, $set->v4);
        foreach ($f['ipMatches'] as $case) {
            T::eq($case['blocked'], $set->contains($case['ip']), 'imported ' . $case['ip']);
            $parsed = \SecureNow\Net\Ip::parse($case['ip']);
            if ($parsed !== null && $parsed['f'] === 4) {
                T::eq($case['blocked'], IpSet::searchFile($file, 4, $parsed['bin']), 'file ' . $case['ip']);
            }
        }
        unlink($file);
    },

    'a large blocklist is searched correctly' => static function (): void {
        $list = [];
        mt_srand(42);
        for ($i = 0; $i < 20000; $i++) {
            $list[] = mt_rand(1, 223) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255);
        }
        $set = IpSet::fromList($list);
        foreach ([0, 77, 9999, 19999] as $i) {
            T::ok($set->contains($list[$i]), 'listed ' . $list[$i]);
        }
        T::ok(!$set->contains('224.0.0.1'));
        T::eq(20000, $set->total());
    },

    'a challenge solved against Node verifies in PHP' => static function (): void {
        $f = T::fixtures();
        $c = $f['challenge'];
        $result = Challenge::verifySolution($f['secret'], $c['token'], $c['nonce'], $c['ip']);
        T::eq(true, $result['ok'], 'node token: ' . ($result['reason'] ?? ''));
        T::eq('ip_mismatch', Challenge::verifySolution($f['secret'], $c['token'], $c['nonce'], '198.51.100.99')['reason']);
        T::eq('bad_signature', Challenge::verifySolution('other-secret', $c['token'], $c['nonce'], $c['ip'])['reason']);
        T::eq('insufficient_work', Challenge::verifySolution($f['secret'], $c['token'], 'x', $c['ip'])['reason'] ?? 'ok');
        T::ok(Challenge::verifyClearance($f['secret'], $c['clearance'], $c['ip'], $c['ua']), 'node clearance');
        T::ok(!Challenge::verifyClearance($f['secret'], $c['clearance'], $c['ip'], 'Other UA'), 'ua bound');
        T::ok(!Challenge::verifyClearance($f['secret'], $c['clearance'], '198.51.100.99', $c['ua']), 'ip bound');
    },

    'PHP mints tokens for Node to verify' => static function (): void {
        $f = T::fixtures();
        $ip = '198.51.100.23';
        $ua = 'Mozilla/5.0 Test';
        $token = Challenge::signChallenge($f['secret'], $ip, 10, 'rule-1', 3600);
        $nonce = 0;
        while (Challenge::leadingZeroBits(hash('sha256', $token . '.' . $nonce, true)) < 10) {
            $nonce++;
        }
        T::ok(Challenge::verifySolution($f['secret'], $token, (string) $nonce, $ip)['ok']);
        $clearance = Challenge::issueClearance($f['secret'], $ip, $ua, 'rule-1', 3600);
        T::ok(Challenge::verifyClearance($f['secret'], $clearance['value'], $ip, $ua));
        @mkdir(dirname(__DIR__) . '/out');
        file_put_contents(dirname(__DIR__) . '/out/php-tokens.json', json_encode([
            'ip' => $ip, 'ua' => $ua, 'challenge' => ['token' => $token, 'nonce' => (string) $nonce], 'clearance' => $clearance['value'],
        ]));
    },

    'client IP resolution matches Node' => static function (): void {
        T::boot();
        foreach (T::fixtures()['ipCases'] as $case) {
            $details = ClientIp::resolve(T::request('GET', '/', $case['headers'], $case['remote']));
            T::eq($case['ip'], $details['ip'], 'ip for ' . json_encode($case));
            T::eq($case['source'], $details['source'], 'source for ' . json_encode($case));
            T::eq($case['trustedProxy'], $details['trustedProxy'], 'trusted for ' . json_encode($case));
        }
    },

    'a configured proxy and the cloudflare preset are trusted' => static function (): void {
        T::boot(['networking' => ['trustedProxies' => ['cloudflare', '203.0.113.50']]]);
        $viaCf = ClientIp::resolve(T::request('GET', '/', ['x-forwarded-for' => '198.51.100.1'], '173.245.48.9'));
        T::eq('198.51.100.1', $viaCf['ip']);
        $viaListed = ClientIp::resolve(T::request('GET', '/', ['x-forwarded-for' => '198.51.100.2'], '203.0.113.50'));
        T::eq('198.51.100.2', $viaListed['ip']);
        $spoofed = ClientIp::resolve(T::request('GET', '/', ['x-forwarded-for' => '198.51.100.3'], '203.0.113.51'));
        T::eq('203.0.113.51', $spoofed['ip']);
    },
];
