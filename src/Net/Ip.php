<?php

declare(strict_types=1);

namespace SecureNow\Net;

/**
 * IP parsing and CIDR math on packed binary addresses (inet_pton), IPv4 and IPv6. No regex on the
 * address itself. An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is treated as the IPv4 address it carries.
 */
final class Ip
{
    private const MAPPED_PREFIX = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

    /** '::ffff:1.2.3.4', '[2001:db8::1]', '1.2.3.4:5678' -> the bare address. */
    public static function normalize(?string $value): string
    {
        $ip = trim((string) $value);
        if ($ip === '') {
            return '';
        }
        if (strncasecmp($ip, '::ffff:', 7) === 0 && strpos($ip, '.') !== false) {
            $ip = substr($ip, 7);
        }
        if ($ip[0] === '[') {
            $end = strpos($ip, ']');
            if ($end !== false) {
                $ip = substr($ip, 1, $end - 1);
            }
        } elseif (preg_match('/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/', $ip)) {
            $ip = substr($ip, 0, (int) strrpos($ip, ':'));
        }
        return $ip;
    }

    /**
     * @return array{f:int,bin:string,key:string}|null family (4 or 6), packed address, canonical text
     */
    public static function parse(?string $ip): ?array
    {
        $s = trim((string) $ip);
        if ($s === '' || strlen($s) > 64) {
            return null;
        }
        if ($s[0] === '[' && substr($s, -1) === ']') {
            $s = substr($s, 1, -1);
        }
        $zone = strpos($s, '%');
        if ($zone !== false) {
            $s = substr($s, 0, $zone);
        }
        if (filter_var($s, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $bin = @inet_pton($s);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && strncmp($bin, self::MAPPED_PREFIX, 12) === 0) {
            $bin = substr($bin, 12);
        }
        $key = @inet_ntop($bin);
        if ($key === false) {
            return null;
        }
        return ['f' => strlen($bin) === 4 ? 4 : 6, 'bin' => $bin, 'key' => $key];
    }

    private static function mask(int $bytes, int $bits): string
    {
        $full = intdiv($bits, 8);
        $rem = $bits % 8;
        $mask = str_repeat("\xff", $full);
        if ($full < $bytes) {
            $mask .= chr((0xff << (8 - $rem)) & 0xff);
            $mask = str_pad($mask, $bytes, "\x00");
        }
        return $mask;
    }

    /**
     * '10.0.0.0/8', '2001:db8::/32' -> the first and last address of the range.
     *
     * @return array{f:int,start:string,end:string,bits:int}|null
     */
    public static function cidr(string $cidr): ?array
    {
        $slash = strpos($cidr, '/');
        if ($slash === false) {
            return null;
        }
        $suffix = trim(substr($cidr, $slash + 1));
        if (!preg_match('/^\d{1,3}$/', $suffix)) {
            return null;
        }
        $bits = (int) $suffix;
        $addr = trim(substr($cidr, 0, $slash));
        if ($addr !== '' && $addr[0] === '[' && substr($addr, -1) === ']') {
            $addr = substr($addr, 1, -1);
        }
        if (filter_var($addr, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $bin = @inet_pton($addr);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 4) {
            if ($bits > 32) {
                return null;
            }
        } else {
            if ($bits > 128) {
                return null;
            }
            // ::ffff:0:0/96 and narrower are IPv4 ranges written in IPv6 form.
            if ($bits >= 96 && strncmp($bin, self::MAPPED_PREFIX, 12) === 0) {
                $bin = substr($bin, 12);
                $bits -= 96;
            }
        }
        $bytes = strlen($bin);
        $mask = self::mask($bytes, $bits);
        $start = $bin & $mask;
        $end = $start | ~$mask;
        return ['f' => $bytes === 4 ? 4 : 6, 'start' => $start, 'end' => $end, 'bits' => $bits];
    }

    /** Does a rule's IP or CIDR cover this (already parsed) address? */
    public static function entryMatches(string $entry, ?array $parsed, string $rawIp): bool
    {
        $entry = trim($entry);
        if ($entry === '') {
            return true;
        }
        if (strpos($entry, '/') !== false) {
            if ($parsed === null) {
                return false;
            }
            $range = self::cidr($entry);
            if ($range === null || $range['f'] !== $parsed['f']) {
                return false;
            }
            return strcmp($parsed['bin'], $range['start']) >= 0 && strcmp($parsed['bin'], $range['end']) <= 0;
        }
        $target = self::parse($entry);
        if ($target === null || $parsed === null) {
            return $entry === trim($rawIp);
        }
        return $target['bin'] === $parsed['bin'];
    }

    public static function isLoopback(string $ip): bool
    {
        return (bool) preg_match('/^(127\.|::1$|::ffff:127\.)/', $ip);
    }

    public static function isPrivate(string $ip): bool
    {
        return (bool) preg_match(
            '/^(127\.|::1$|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|f[cd][0-9a-f]{2}:)/i',
            $ip
        );
    }
}
