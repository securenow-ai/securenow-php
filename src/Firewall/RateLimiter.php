<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\Store\Store;

/**
 * Counters for rate-limit rules. PHP workers share nothing, so the count lives outside the
 * request, in the first store that works:
 *  1. Redis, when config.firewall.rateLimitStore is a redis:// or rediss:// URL: one count for
 *     every server (the same keys and fixed, clock-aligned windows as the Node SDK).
 *  2. APCu: one count for every worker of this PHP-FPM pool.
 *  3. Files in the cache folder: one count for this machine.
 * A store that fails is skipped (the next one counts), so an outage never blocks traffic.
 */
final class RateLimiter
{
    /** @var resource|null|false */
    private static $redis = null;
    private static bool $redisFailed = false;

    public static function reset(): void
    {
        if (is_resource(self::$redis)) {
            @fclose(self::$redis);
        }
        self::$redis = null;
        self::$redisFailed = false;
    }

    /** Counts one request in a fixed window and returns the window's total, or null when nothing can count. */
    public static function hit(string $key, int $windowIndex, int $windowSeconds): ?int
    {
        $full = 'securenow:rl:' . $key . ':' . $windowIndex;
        $ttl = $windowSeconds + 1;

        $count = self::redisHit($full, $ttl);
        if ($count !== null) {
            return $count;
        }
        if (Store::apcu()) {
            $ok = false;
            $count = @apcu_inc($full, 1, $ok, $ttl);
            if ($ok && is_int($count)) {
                return $count;
            }
        }
        return self::fileHit($full, $windowIndex);
    }

    private static function fileHit(string $key, int $windowIndex): ?int
    {
        $dir = Store::path('rl');
        if ($dir === null) {
            return null;
        }
        if (!@is_dir($dir) && !@mkdir($dir, 0700, true) && !@is_dir($dir)) {
            return null;
        }
        $handle = @fopen($dir . DIRECTORY_SEPARATOR . sha1($key), 'c+');
        if ($handle === false) {
            return null;
        }
        try {
            if (!@flock($handle, LOCK_EX)) {
                return null;
            }
            $count = (int) stream_get_contents($handle) + 1;
            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, (string) $count);
            fflush($handle);
            @flock($handle, LOCK_UN);
            return $count;
        } finally {
            fclose($handle);
        }
    }

    /** Old counter files are removed now and then (called from the sync, off the request path). */
    public static function collectGarbage(int $olderThanSeconds = 7200): void
    {
        $dir = Store::path('rl');
        if ($dir === null || !@is_dir($dir)) {
            return;
        }
        $cutoff = time() - $olderThanSeconds;
        $n = 0;
        foreach ((array) @scandir($dir) as $name) {
            if ($name === '.' || $name === '..' || !is_string($name)) {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            $mtime = @filemtime($path);
            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($path);
            }
            if (++$n > 20000) {
                break;
            }
        }
    }

    // ---- Redis: a minimal RESP client (AUTH, SELECT, INCR, PEXPIRE), no dependency ----

    private static function redisHit(string $key, int $ttlSeconds): ?int
    {
        if (self::$redisFailed) {
            return null;
        }
        $socket = self::redisConnect();
        if ($socket === null) {
            return null;
        }
        try {
            $payload = self::encode(['INCR', $key]) . self::encode(['PEXPIRE', $key, (string) max(1000, $ttlSeconds * 1000)]);
            if (@fwrite($socket, $payload) === false) {
                throw new \RuntimeException('write failed');
            }
            $count = self::readReply($socket);
            self::readReply($socket);
            return is_int($count) ? $count : null;
        } catch (\Throwable $e) {
            self::$redisFailed = true;
            @fclose($socket);
            self::$redis = null;
            Diag::warn('rate-limit store unreachable (' . $e->getMessage() . '); counting locally');
            return null;
        }
    }

    /** @return resource|null */
    private static function redisConnect()
    {
        if (is_resource(self::$redis)) {
            return self::$redis;
        }
        $spec = Config::get('firewall.rateLimitStore');
        if (is_array($spec)) {
            $spec = $spec['url'] ?? null;
        }
        if (!is_string($spec) || $spec === '') {
            self::$redisFailed = true;
            return null;
        }
        $parts = parse_url($spec);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if (!is_array($parts) || !in_array($scheme, ['redis', 'rediss'], true)) {
            self::$redisFailed = true;
            Diag::warn('firewall.rateLimitStore must be a redis:// or rediss:// URL; counting locally');
            return null;
        }
        $host = (string) ($parts['host'] ?? '127.0.0.1');
        $port = (int) ($parts['port'] ?? 6379);
        $target = ($scheme === 'rediss' ? 'tls://' : 'tcp://') . $host . ':' . $port;
        $errno = 0;
        $errstr = '';
        // persistent: the connection is reused by later requests of this worker.
        $socket = @stream_socket_client($target, $errno, $errstr, 0.25, STREAM_CLIENT_CONNECT | STREAM_CLIENT_PERSISTENT);
        if ($socket === false) {
            self::$redisFailed = true;
            Diag::warn("rate-limit store unreachable ($errstr); counting locally");
            return null;
        }
        stream_set_timeout($socket, 0, 250000);
        try {
            // A reused persistent connection is already authenticated and on the right database.
            if (ftell($socket) === 0) {
                $password = isset($parts['pass']) ? rawurldecode((string) $parts['pass']) : '';
                $username = isset($parts['user']) ? rawurldecode((string) $parts['user']) : '';
                if ($password !== '') {
                    fwrite($socket, self::encode($username !== '' ? ['AUTH', $username, $password] : ['AUTH', $password]));
                    self::readReply($socket);
                }
                $db = (int) ltrim((string) ($parts['path'] ?? ''), '/');
                if ($db > 0) {
                    fwrite($socket, self::encode(['SELECT', (string) $db]));
                    self::readReply($socket);
                }
            }
        } catch (\Throwable $e) {
            self::$redisFailed = true;
            @fclose($socket);
            Diag::warn('rate-limit store setup failed (' . $e->getMessage() . '); counting locally');
            return null;
        }
        return self::$redis = $socket;
    }

    /** @param string[] $args */
    private static function encode(array $args): string
    {
        $out = '*' . count($args) . "\r\n";
        foreach ($args as $arg) {
            $out .= '$' . strlen($arg) . "\r\n" . $arg . "\r\n";
        }
        return $out;
    }

    /**
     * @param resource $socket
     * @return int|string|null
     */
    private static function readReply($socket)
    {
        $line = fgets($socket, 4096);
        if ($line === false || $line === '') {
            throw new \RuntimeException('no reply');
        }
        $type = $line[0];
        $value = rtrim(substr($line, 1), "\r\n");
        if ($type === '+') {
            return $value;
        }
        if ($type === ':') {
            return (int) $value;
        }
        if ($type === '-') {
            throw new \RuntimeException($value);
        }
        if ($type === '$') {
            $length = (int) $value;
            if ($length < 0) {
                return null;
            }
            $data = '';
            while (strlen($data) < $length + 2) {
                $chunk = fread($socket, $length + 2 - strlen($data));
                if ($chunk === false || $chunk === '') {
                    throw new \RuntimeException('short reply');
                }
                $data .= $chunk;
            }
            return substr($data, 0, $length);
        }
        throw new \RuntimeException('unexpected reply');
    }
}
