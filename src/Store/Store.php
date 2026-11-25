<?php

declare(strict_types=1);

namespace SecureNow\Store;

use SecureNow\Config;

/**
 * PHP-FPM keeps nothing in memory between requests, so what the Node SDK holds in the process
 * (synced firewall rules, revocations, counters, telemetry waiting to be sent) lives here: a
 * private folder (0700) with atomic writes, plus APCu for counters when it is loaded.
 *
 * Folder: config.runtime.cacheDir, or SECURENOW_CACHE_DIR, or a per-app folder in the system
 * temp directory.
 */
final class Store
{
    private static ?string $dir = null;
    private static bool $resolved = false;

    /** @var array{0:int,1:int}|null uid and gid the files belong to, when root works on a web user's behalf */
    private static ?array $owner = null;

    public static function reset(): void
    {
        self::$dir = null;
        self::$resolved = false;
        self::$owner = null;
    }

    /**
     * `sudo securenow agent --user www-data`: root (needed for iptables) reads and writes the
     * cache folder of the user PHP-FPM runs as, and hands every file it writes to that user.
     */
    public static function actAs(int $uid, int $gid): void
    {
        self::$owner = [$uid, $gid];
        self::$dir = null;
        self::$resolved = false;
    }

    /** The default folder for a given user (the web server's and the CLI's differ). */
    public static function defaultDir(?string $userTag = null): string
    {
        if ($userTag === null) {
            if (self::$owner !== null) {
                $userTag = (string) self::$owner[0];
            } else {
                $userTag = function_exists('posix_geteuid') ? (string) posix_geteuid() : preg_replace('/[^A-Za-z0-9_-]/', '', (string) @get_current_user());
            }
        }
        // Keyed by where the credentials come from: the web server and the CLI read the same file,
        // so they agree on the folder whatever their working directory or autoloader.
        $hash = substr(sha1((Config::appKey() ?? '') . '|' . Config::environment() . '|' . Config::source()), 0, 16);
        return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'securenow-' . $hash . '-u' . $userTag;
    }

    public static function dir(): ?string
    {
        if (self::$resolved) {
            return self::$dir;
        }
        self::$resolved = true;
        $configured = Config::get('runtime.cacheDir') ?? Config::env('SECURENOW_CACHE_DIR');
        $candidates = [];
        if (is_string($configured) && $configured !== '') {
            $candidates[] = rtrim($configured, '/\\');
        }
        $candidates[] = self::defaultDir();

        foreach ($candidates as $candidate) {
            if (self::usable($candidate)) {
                self::$dir = $candidate;
                return self::$dir;
            }
        }
        return null;
    }

    private static function usable(string $dir): bool
    {
        if (!@is_dir($dir)) {
            if (!@mkdir($dir, 0700, true) && !@is_dir($dir)) {
                return false;
            }
            self::own($dir);
        }
        if (@is_link($dir) || !@is_writable($dir)) {
            return false;
        }
        // A folder someone else created in a shared temp directory is not ours to trust.
        if (function_exists('posix_geteuid') && DIRECTORY_SEPARATOR === '/') {
            $expected = self::$owner !== null ? self::$owner[0] : posix_geteuid();
            $owner = @fileowner($dir);
            if ($owner !== false && $owner !== $expected) {
                return false;
            }
            $perms = @fileperms($dir);
            if ($perms !== false && ($perms & 0022) !== 0) {
                @chmod($dir, 0700);
            }
        }
        return true;
    }

    private static function own(string $path): void
    {
        if (self::$owner !== null) {
            @chown($path, self::$owner[0]);
            @chgrp($path, self::$owner[1]);
        }
    }

    public static function path(string $name): ?string
    {
        $dir = self::dir();
        return $dir === null ? null : $dir . DIRECTORY_SEPARATOR . $name;
    }

    public static function read(string $name): ?string
    {
        $path = self::path($name);
        if ($path === null || !@is_file($path)) {
            return null;
        }
        $data = @file_get_contents($path);
        return $data === false ? null : $data;
    }

    public static function write(string $name, string $data): bool
    {
        $path = self::path($name);
        if ($path === null) {
            return false;
        }
        $tmp = $path . '.' . bin2hex(pack('N', mt_rand())) . '.tmp';
        if (@file_put_contents($tmp, $data, LOCK_EX) === false) {
            return false;
        }
        @chmod($tmp, 0600);
        self::own($tmp);
        if (!@rename($tmp, $path)) {
            // Windows cannot rename over a file another process holds open.
            $ok = @copy($tmp, $path);
            @unlink($tmp);
            return $ok;
        }
        return true;
    }

    /** @return array<mixed>|null */
    public static function readArray(string $name): ?array
    {
        $data = self::read($name);
        if ($data === null || $data === '') {
            return null;
        }
        $value = @unserialize($data, ['allowed_classes' => false]);
        return is_array($value) ? $value : null;
    }

    /** @param array<mixed> $value */
    public static function writeArray(string $name, array $value): bool
    {
        return self::write($name, serialize($value));
    }

    public static function delete(string $name): void
    {
        $path = self::path($name);
        if ($path !== null) {
            @unlink($path);
        }
    }

    public static function append(string $name, string $data): bool
    {
        $path = self::path($name);
        if ($path === null) {
            return false;
        }
        $new = !@is_file($path);
        $ok = @file_put_contents($path, $data, FILE_APPEND | LOCK_EX) !== false;
        if ($ok && $new) {
            @chmod($path, 0600);
            self::own($path);
        }
        return $ok;
    }

    public static function size(string $name): int
    {
        $path = self::path($name);
        if ($path === null) {
            return 0;
        }
        clearstatcache(true, $path);
        $size = @filesize($path);
        return $size === false ? 0 : $size;
    }

    public static function mtime(string $name): int
    {
        $path = self::path($name);
        if ($path === null) {
            return 0;
        }
        clearstatcache(true, $path);
        $time = @filemtime($path);
        return $time === false ? 0 : $time;
    }

    /**
     * An exclusive lock other PHP processes on this machine respect. Returns the handle to pass to
     * unlock(), or null when the lock is held elsewhere (non-blocking) or cannot be taken.
     *
     * @return resource|null
     */
    public static function lock(string $name, bool $wait = false)
    {
        $path = self::path($name . '.lock');
        if ($path === null) {
            return null;
        }
        $new = !@is_file($path);
        $handle = @fopen($path, 'c');
        if ($handle === false) {
            return null;
        }
        if ($new) {
            self::own($path);
        }
        if (!@flock($handle, $wait ? LOCK_EX : LOCK_EX | LOCK_NB)) {
            fclose($handle);
            return null;
        }
        return $handle;
    }

    /** @param resource|null $handle */
    public static function unlock($handle): void
    {
        if (is_resource($handle)) {
            @flock($handle, LOCK_UN);
            @fclose($handle);
        }
    }

    public static function apcu(): bool
    {
        static $enabled = null;
        if ($enabled === null) {
            $enabled = function_exists('apcu_enabled') && @apcu_enabled()
                && (PHP_SAPI !== 'cli' || filter_var(ini_get('apc.enable_cli'), FILTER_VALIDATE_BOOLEAN));
        }
        return $enabled;
    }

    /** Files under a prefix, for cleanup. @return string[] */
    public static function glob(string $pattern): array
    {
        $path = self::path($pattern);
        if ($path === null) {
            return [];
        }
        $found = @glob($path);
        return is_array($found) ? $found : [];
    }
}
