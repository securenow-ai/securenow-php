<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Util;

/**
 * SecureNow challenge protocol (v1 = invisible proof-of-work), wire-compatible with the Node SDK
 * (challenge.js) and the API (challengeCrypto.js): a challenge minted on one side verifies on the
 * other. Stateless: a challenge token and a clearance cookie are HMAC-signed envelopes.
 */
final class Challenge
{
    public const CHALLENGE_PREFIX = 'c1';
    public const CLEARANCE_PREFIX = 'k1';
    public const ALG_POW = 'pow-sha256';
    public const CLEARANCE_COOKIE = '__sn_clearance';
    public const INTERNAL_PATH = '/__securenow/challenge';

    public const DEFAULT_DIFFICULTY = 14;
    public const DEFAULT_CHALLENGE_TTL = 120;
    public const DEFAULT_CLEARANCE_TTL = 1800;

    private static function hmac(string $secret, string $data): string
    {
        return Util::b64urlEncode(hash_hmac('sha256', $data, $secret, true));
    }

    private static function normIp(string $ip): string
    {
        return trim(preg_replace('/^::ffff:/i', '', $ip) ?? $ip);
    }

    private static function uaHash(string $ua): string
    {
        return substr(hash('sha256', $ua), 0, 16);
    }

    public static function leadingZeroBits(string $digest): int
    {
        $bits = 0;
        $length = strlen($digest);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($digest[$i]);
            if ($byte === 0) {
                $bits += 8;
                continue;
            }
            for ($mask = 0x80; $mask > 0 && !($byte & $mask); $mask >>= 1) {
                $bits++;
            }
            break;
        }
        return $bits;
    }

    /** @return array{body:string,payload:array<string,mixed>,sig:string}|null */
    private static function parseSigned(string $prefix, string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] !== $prefix) {
            return null;
        }
        $payload = json_decode(Util::b64urlDecode($parts[1]), true);
        if (!is_array($payload)) {
            return null;
        }
        return ['body' => $parts[0] . '.' . $parts[1], 'payload' => $payload, 'sig' => $parts[2]];
    }

    public static function signChallenge(string $secret, string $ip, int $difficulty, string $rid, int $ttl): string
    {
        $iat = time();
        $payload = [
            'ip' => self::normIp($ip),
            'alg' => self::ALG_POW,
            'diff' => max(1, $difficulty),
            'rid' => $rid !== '' ? $rid : '*',
            'iat' => $iat,
            'exp' => $iat + ($ttl > 0 ? $ttl : self::DEFAULT_CHALLENGE_TTL),
        ];
        $body = self::CHALLENGE_PREFIX . '.' . Util::b64urlEncode(Util::json($payload));
        return $body . '.' . self::hmac($secret, $body);
    }

    /** @return array{ok:bool,reason?:string,payload?:array<string,mixed>} */
    public static function verifySolution(string $secret, string $token, string $nonce, string $ip): array
    {
        $parsed = self::parseSigned(self::CHALLENGE_PREFIX, $token);
        if ($parsed === null) {
            return ['ok' => false, 'reason' => 'malformed'];
        }
        if (!hash_equals(self::hmac($secret, $parsed['body']), $parsed['sig'])) {
            return ['ok' => false, 'reason' => 'bad_signature'];
        }
        $p = $parsed['payload'];
        if (!empty($p['exp']) && time() > (int) $p['exp']) {
            return ['ok' => false, 'reason' => 'expired'];
        }
        if ($ip !== '' && self::normIp($ip) !== (string) ($p['ip'] ?? '')) {
            return ['ok' => false, 'reason' => 'ip_mismatch'];
        }
        if (($p['alg'] ?? '') !== self::ALG_POW) {
            return ['ok' => false, 'reason' => 'unsupported_alg'];
        }
        if ($nonce === '') {
            return ['ok' => false, 'reason' => 'missing_nonce'];
        }
        $digest = hash('sha256', $token . '.' . $nonce, true);
        if (self::leadingZeroBits($digest) < max(0, (int) ($p['diff'] ?? 0))) {
            return ['ok' => false, 'reason' => 'insufficient_work'];
        }
        return ['ok' => true, 'payload' => $p];
    }

    /** @return array{value:string,maxAge:int,exp:int} */
    public static function issueClearance(string $secret, string $ip, string $ua, string $rid, int $ttl): array
    {
        $iat = time();
        $ttl = $ttl > 0 ? $ttl : self::DEFAULT_CLEARANCE_TTL;
        $payload = [
            'ip' => self::normIp($ip),
            'uah' => self::uaHash($ua),
            'rid' => $rid !== '' ? $rid : '*',
            'iat' => $iat,
            'exp' => $iat + $ttl,
        ];
        $body = self::CLEARANCE_PREFIX . '.' . Util::b64urlEncode(Util::json($payload));
        return ['value' => $body . '.' . self::hmac($secret, $body), 'maxAge' => $ttl, 'exp' => $payload['exp']];
    }

    public static function verifyClearance(string $secret, string $cookie, string $ip, string $ua): bool
    {
        $parsed = self::parseSigned(self::CLEARANCE_PREFIX, $cookie);
        if ($parsed === null || !hash_equals(self::hmac($secret, $parsed['body']), $parsed['sig'])) {
            return false;
        }
        $p = $parsed['payload'];
        if (!empty($p['exp']) && time() > (int) $p['exp']) {
            return false;
        }
        if ($ip !== '' && self::normIp($ip) !== (string) ($p['ip'] ?? '')) {
            return false;
        }
        if ($ua !== '' && self::uaHash($ua) !== (string) ($p['uah'] ?? '')) {
            return false;
        }
        return true;
    }
}
