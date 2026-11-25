<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Util;

/**
 * Route matching for block, rate-limit and challenge rules (firewall-paths.js). A rule matches
 * the raw path and its canonical form (percent-decoded, lower-case, duplicate slashes collapsed;
 * exact rules also ignore a trailing slash), so /API/Login/ cannot walk past a rule on /api/login.
 */
final class Paths
{
    private const MAX_REGEX_LENGTH = 500;
    private const MAX_TESTED_PATH = 4096;

    public static function normalizePrefix(string $pattern): string
    {
        $value = trim($pattern);
        return $value !== '' && substr($value, -1) === '*' ? substr($value, 0, -1) : $value;
    }

    public static function canonical(string $path, bool $stripTrailingSlash = false): string
    {
        $value = $path === '' ? '/' : $path;
        // decodeURIComponent keeps the raw spelling when the encoding is malformed.
        if (strpos($value, '%') !== false && !preg_match('/%(?![0-9A-Fa-f]{2})/', $value)) {
            $decoded = rawurldecode($value);
            if (preg_match('//u', $decoded)) {
                $value = $decoded;
            }
        }
        $value = Util::lower($value);
        $value = preg_replace('~/{2,}~', '/', $value) ?? $value;
        if ($stripTrailingSlash && strlen($value) > 1) {
            $value = rtrim($value, '/');
            if ($value === '') {
                $value = '/';
            }
        }
        return $value === '' ? '/' : $value;
    }

    /** Why a path regex is refused, or '' when it compiles and is safe. */
    public static function regexProblem(string $pattern): string
    {
        if (strlen($pattern) > self::MAX_REGEX_LENGTH) {
            return 'longer than ' . self::MAX_REGEX_LENGTH . ' characters';
        }
        if (preg_match('/([+*]|\{\d+,\d*\})\s*\)([+*?]|\{\d+,\d*\})/', $pattern)) {
            return 'nested quantifiers can backtrack catastrophically';
        }
        if (@preg_match(self::delimit($pattern), '') === false) {
            return 'invalid';
        }
        return '';
    }

    /** A JavaScript-style regex source as a PCRE pattern. \x01 never appears in a rule. */
    public static function delimit(string $source, string $flags = ''): string
    {
        return "\x01" . str_replace("\x01", '', $source) . "\x01" . $flags;
    }

    /** @param array<string,mixed> $rule */
    public static function ruleMatches(array $rule, string $path): bool
    {
        $pattern = trim((string) ($rule['pathPattern'] ?? ''));
        if ($pattern === '') {
            return true;
        }
        $mode = strtolower((string) ($rule['pathMatchMode'] ?? 'prefix')) ?: 'prefix';
        if ($mode === 'regex') {
            if (self::regexProblem($pattern) !== '') {
                return false;
            }
            $tested = substr($path, 0, self::MAX_TESTED_PATH);
            $regex = self::delimit($pattern);
            return @preg_match($regex, $tested) === 1 || @preg_match($regex, self::canonical($tested, true)) === 1;
        }
        if ($mode === 'exact') {
            return $path === $pattern || self::canonical($path, true) === self::canonical($pattern, true);
        }
        $prefix = self::normalizePrefix($pattern);
        return Util::startsWith($path, $prefix) || Util::startsWith(self::canonical($path), self::canonical($prefix));
    }
}
