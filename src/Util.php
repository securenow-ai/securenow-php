<?php

declare(strict_types=1);

namespace SecureNow;

final class Util
{
    /** JSON the way JSON.stringify writes it: slashes and unicode as they are, so detection rules match the same text. */
    public const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR;

    /** @param mixed $value */
    public static function json($value): string
    {
        $out = json_encode($value, self::JSON_FLAGS);
        return $out === false ? 'null' : $out;
    }

    /** @param mixed $value */
    public static function isList($value): bool
    {
        if (!is_array($value)) {
            return false;
        }
        $i = 0;
        foreach ($value as $key => $_) {
            if ($key !== $i++) {
                return false;
            }
        }
        return true;
    }

    public static function b64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function b64urlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), false);
        return $decoded === false ? '' : $decoded;
    }

    public static function randomHex(int $bytes): string
    {
        try {
            return bin2hex(random_bytes($bytes));
        } catch (\Throwable $e) {
            $out = '';
            for ($i = 0; $i < $bytes; $i++) {
                $out .= sprintf('%02x', mt_rand(0, 255));
            }
            return $out;
        }
    }

    public static function uuid(): string
    {
        $hex = self::randomHex(16);
        $hex[12] = '4';
        $hex[16] = dechex((hexdec($hex[16]) & 0x3) | 0x8);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20, 12);
    }

    /** Wall-clock nanoseconds since the Unix epoch (microsecond precision). */
    public static function nowNs(): int
    {
        return self::floatSecondsToNs(microtime(true));
    }

    public static function floatSecondsToNs(float $seconds): int
    {
        return ((int) round($seconds * 1000000)) * 1000;
    }

    public static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }

    public static function startsWith(string $haystack, string $needle): bool
    {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }

    public static function lower(string $value): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
    }

    /** Cut to a byte length without leaving half a UTF-8 character at the end. */
    public static function truncate(string $value, int $max): string
    {
        if (strlen($value) <= $max) {
            return $value;
        }
        if (function_exists('mb_strcut')) {
            return mb_strcut($value, 0, $max, 'UTF-8');
        }
        return substr($value, 0, $max);
    }
}
