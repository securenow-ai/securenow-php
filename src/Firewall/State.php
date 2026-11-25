<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Net\Ip;
use SecureNow\Net\IpSet;
use SecureNow\Store\Store;

/**
 * The synced firewall policy as each request reads it: one small serialized file in the cache
 * folder (rules, allowlist, user-agent rules, challenge settings), and the blocklist as packed
 * binary ranges, inline when small, in its own files when large, searched without loading it.
 */
final class State
{
    private const FILE = 'fw.state';
    private const META = 'fw.meta';
    private const INLINE_MAX_BYTES = 65536;

    /** @var array<string,mixed>|null */
    private static ?array $cached = null;
    private static bool $loaded = false;

    public static function reset(): void
    {
        self::$cached = null;
        self::$loaded = false;
    }

    /** @return array<string,mixed>|null null until the first successful sync */
    public static function load(bool $fresh = false): ?array
    {
        if (self::$loaded && !$fresh) {
            return self::$cached;
        }
        self::$loaded = true;
        $state = Store::readArray(self::FILE);
        self::$cached = (is_array($state) && ($state['v'] ?? 0) === 1) ? $state : null;
        return self::$cached;
    }

    /** @param array<string,mixed> $state */
    public static function save(array $state): bool
    {
        $state['v'] = 1;
        $ok = Store::writeArray(self::FILE, $state);
        if ($ok) {
            self::$cached = $state;
            self::$loaded = true;
        }
        return $ok;
    }

    /** A policy for this process only (the CLI's dry run): nothing is written. @param array<string,mixed> $state */
    public static function useInMemory(array $state): void
    {
        self::$cached = $state;
        self::$loaded = true;
    }

    /** @return array<string,mixed> */
    public static function meta(): array
    {
        return Store::readArray(self::META) ?? [];
    }

    /** @param array<string,mixed> $meta */
    public static function saveMeta(array $meta): void
    {
        Store::writeArray(self::META, $meta);
    }

    /**
     * Stores a blocklist: inline in the state when small, as files when large.
     *
     * @return array<string,mixed> what goes in the state under "bl"
     */
    public static function packBlocklist(IpSet $set, string $generation): array
    {
        $packed = ['other' => $set->other, 'exact' => $set->exact, 'cidr' => $set->cidr];
        if (strlen($set->v4) + strlen($set->v6) <= self::INLINE_MAX_BYTES) {
            return $packed + ['v4' => $set->v4, 'v6' => $set->v6];
        }
        foreach (['v4' => $set->v4, 'v6' => $set->v6] as $family => $data) {
            if ($data === '') {
                continue;
            }
            $name = 'bl-' . $generation . '.' . $family;
            if (Store::write($name, $data)) {
                $packed['file' . $family] = $name;
            }
        }
        return $packed;
    }

    /** Blocklist files of earlier generations. */
    public static function removeOldBlocklists(string $keepGeneration): void
    {
        foreach (Store::glob('bl-*.v[46]') as $path) {
            if (strpos(basename($path), 'bl-' . $keepGeneration . '.') !== 0 && (time() - (int) @filemtime($path)) > 60) {
                @unlink($path);
            }
        }
    }

    /** @param array<string,mixed>|null $packed */
    public static function blocklistContains(?array $packed, string $ip): bool
    {
        if (!$packed || $ip === '') {
            return false;
        }
        $parsed = Ip::parse($ip);
        if ($parsed === null) {
            return isset($packed['other'][trim($ip)]);
        }
        $family = $parsed['f'] === 4 ? 'v4' : 'v6';
        $width = $parsed['f'] === 4 ? 4 : 16;
        if (isset($packed[$family]) && is_string($packed[$family]) && $packed[$family] !== '') {
            return IpSet::searchString($packed[$family], $width, $parsed['bin']);
        }
        if (!empty($packed['file' . $family])) {
            $path = Store::path((string) $packed['file' . $family]);
            return $path !== null && IpSet::searchFile($path, $width, $parsed['bin']);
        }
        return false;
    }

    /** @param array<string,mixed>|null $packed */
    public static function blocklistTotal(?array $packed): int
    {
        return $packed ? (int) ($packed['exact'] ?? 0) + (int) ($packed['cidr'] ?? 0) : 0;
    }
}
