<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\Http\Transport;
use SecureNow\Store\Store;
use SecureNow\Util;
use SecureNow\Version;

/**
 * Ships spans, logs, security events and firewall hits.
 *
 * A PHP request has no background thread, so the work happens after the response is on its way
 * (fastcgi_finish_request under PHP-FPM): the visitor never waits for SecureNow. Each request
 * appends what it produced to a small spool in the cache folder; one request at a time holds the
 * flush lock and sends everything waiting, at most once per flush interval. A quiet site sends
 * per request; a busy site (or a flood of blocked requests) sends one batch a second from a
 * single worker. When `vendor/bin/securenow agent` runs, it does the sending instead.
 */
final class Exporter
{
    private const SPOOL = ['traces' => 'spool-traces.jsonl', 'logs' => 'spool-logs.jsonl', 'events' => 'spool-events.jsonl', 'fw' => 'spool-fw.jsonl'];
    private const SPOOL_MAX_BYTES = 4194304;
    private const POST_MAX_BYTES = 2097152;
    private const META = 'export.meta';
    private const WORKER_META = 'worker.meta';
    private const AGENT_HEARTBEAT = 'agent.heartbeat';
    private const MAX_ITEMS_PER_REQUEST = 2000;

    /** @var array<string,string[]> signal => spool lines */
    private static array $pending = ['traces' => [], 'logs' => [], 'events' => [], 'fw' => []];
    /** @var callable[] run after the flush, still off the response path */
    private static array $tasks = [];
    private static bool $detached = false;

    public static function reset(): void
    {
        self::$pending = ['traces' => [], 'logs' => [], 'events' => [], 'fw' => []];
        self::$tasks = [];
        self::$detached = false;
    }

    /** @param array<string,mixed> $span OTLP span */
    public static function addSpan(array $span, string $scope = 'securenow'): void
    {
        if (count(self::$pending['traces']) < self::MAX_ITEMS_PER_REQUEST) {
            self::$pending['traces'][] = str_replace(["\t", "\n"], ' ', $scope) . "\t" . Util::json($span);
        }
    }

    /** @param array<string,mixed> $record OTLP log record */
    public static function addLog(array $record, string $scope = 'php'): void
    {
        if (count(self::$pending['logs']) < self::MAX_ITEMS_PER_REQUEST) {
            self::$pending['logs'][] = str_replace(["\t", "\n"], ' ', $scope) . "\t" . Util::json($record);
        }
    }

    /** @param array<string,mixed> $event /v1/events item */
    public static function addEvent(array $event): void
    {
        if (count(self::$pending['events']) < self::MAX_ITEMS_PER_REQUEST) {
            self::$pending['events'][] = Util::json($event);
        }
    }

    /** @param array<string,mixed> $event /firewall/events item */
    public static function addFirewallEvent(array $event): void
    {
        if (count(self::$pending['fw']) < 100) {
            self::$pending['fw'][] = Util::json($event);
        }
    }

    public static function addTask(callable $task): void
    {
        self::$tasks[] = $task;
    }

    public static function hasPending(): bool
    {
        foreach (self::$pending as $lines) {
            if ($lines) {
                return true;
            }
        }
        return false;
    }

    /** Hand the response to the web server so the rest of this request costs the visitor nothing. */
    public static function detachResponse(): bool
    {
        if (self::$detached) {
            return true;
        }
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            return self::$detached = true;
        }
        try {
            // A second call returns false: Laravel and Symfony have already finished the request
            // themselves (Response::send()). Either way the response is on its way.
            if (function_exists('fastcgi_finish_request')) {
                @fastcgi_finish_request();
                self::$detached = true;
            } elseif (function_exists('litespeed_finish_request')) {
                @litespeed_finish_request();
                self::$detached = true;
            }
        } catch (\Throwable $e) {
            self::$detached = false;
        }
        return self::$detached;
    }

    public static function agentAlive(): bool
    {
        return (time() - Store::mtime(self::AGENT_HEARTBEAT)) < 20;
    }

    /** End of request: spool what this request produced, then send if it is this request's turn. */
    public static function finish(): void
    {
        try {
            $detached = self::detachResponse();
            $hadData = self::hasPending();
            $spooled = self::spool();
            if (!$spooled && $hadData) {
                // No writable cache folder: send this request's data directly.
                self::sendDirect();
            } elseif (self::agentAlive()) {
                // The agent ships the spool and keeps the policy fresh.
                return;
            } elseif (!$detached && PHP_SAPI !== 'cli-server' && self::handOffToWorker()) {
                // The response cannot be released early here (Apache mod_php): a background
                // process does the network work, the visitor does not wait for it.
                return;
            } else {
                self::flush($detached, false);
            }
            foreach (self::$tasks as $task) {
                try {
                    $task($detached);
                } catch (\Throwable $e) {
                    Diag::debug('post-response task failed: ' . $e->getMessage());
                }
            }
        } catch (\Throwable $e) {
            Diag::debug('export failed: ' . $e->getMessage());
        } finally {
            self::$pending = ['traces' => [], 'logs' => [], 'events' => [], 'fw' => []];
            self::$tasks = [];
        }
    }

    /**
     * Servers that cannot finish the response early (Apache mod_php): start `securenow work` in the
     * background, at most once per flush interval. It syncs the policy when due and sends the spool.
     * Returns false when PHP cannot start a process (exec functions disabled, no PHP CLI) or when
     * earlier starts did not result in a flush; the caller then sends inline, as a fallback.
     */
    private static function handOffToWorker(): bool
    {
        if (!function_exists('proc_open') || Store::dir() === null) {
            return false;
        }
        $php = self::cliBinary();
        if ($php === null) {
            return false;
        }
        $meta = Store::readArray(self::WORKER_META) ?? [];
        $now = Util::nowMs();
        // Started several times and never reported back: starting processes does not work here.
        if ((int) ($meta['tries'] ?? 0) >= 5) {
            // Try again now and then, in case it was a passing problem.
            if ($now - (int) ($meta['at'] ?? 0) < 300000) {
                return false;
            }
            $meta['tries'] = 3;
        }
        if ($now - (int) ($meta['at'] ?? 0) < max(1000, Config::int('export.flushIntervalMs', 1000, 0))) {
            return true;
        }
        $meta['at'] = $now;
        $meta['tries'] = (int) ($meta['tries'] ?? 0) + 1;
        Store::writeArray(self::WORKER_META, $meta);

        $script = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'securenow';
        $env = ['SECURENOW_CACHE_DIR' => (string) Store::dir(), 'SECURENOW_AUTOSTART' => '0', 'PATH' => (string) getenv('PATH')];
        $source = Config::source();
        if (strncmp($source, 'env:', 4) === 0) {
            $env[Config::ENV_CREDENTIALS] = (string) Config::env(Config::ENV_CREDENTIALS);
        } elseif ($source !== 'none' && $source !== 'code') {
            $env[Config::ENV_CREDENTIALS_FILE] = $source;
        } else {
            return false;
        }
        try {
            if (DIRECTORY_SEPARATOR === '\\') {
                $command = 'start /B "" ' . escapeshellarg($php) . ' ' . escapeshellarg($script) . ' work > NUL 2>&1';
            } else {
                $command = escapeshellarg($php) . ' ' . escapeshellarg($script) . ' work > /dev/null 2>&1 &';
            }
            $process = @proc_open($command, [0 => ['file', DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null', 'r']], $pipes, null, $env + self::baseEnv());
            if (!is_resource($process)) {
                return false;
            }
            proc_close($process);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Variables a child PHP needs to start (temp folder, home). @return array<string,string> */
    private static function baseEnv(): array
    {
        $out = [];
        foreach (['TMPDIR', 'TMP', 'TEMP', 'HOME', 'SystemRoot', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'] as $name) {
            $value = getenv($name);
            if (is_string($value) && $value !== '') {
                $out[$name] = $value;
            }
        }
        return $out;
    }

    /** The PHP command-line binary next to the running PHP, or null. */
    private static function cliBinary(): ?string
    {
        static $found = false;
        if ($found !== false) {
            return $found;
        }
        $candidates = [];
        if (PHP_BINARY !== '' && preg_match('/^php(\d|\.|$)/i', basename(PHP_BINARY)) && stripos(basename(PHP_BINARY), 'fpm') === false && stripos(basename(PHP_BINARY), 'cgi') === false) {
            $candidates[] = PHP_BINARY;
        }
        $candidates[] = PHP_BINDIR . DIRECTORY_SEPARATOR . 'php' . (DIRECTORY_SEPARATOR === '\\' ? '.exe' : '');
        $candidates[] = PHP_BINDIR . DIRECTORY_SEPARATOR . 'php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        foreach (['/usr/local/bin/php', '/usr/bin/php'] as $path) {
            $candidates[] = $path;
        }
        foreach ($candidates as $candidate) {
            if (@is_file($candidate) && @is_executable($candidate)) {
                return $found = $candidate;
            }
        }
        return $found = null;
    }

    /**
     * One pass of the background worker (`securenow work`): policy check when due, revocations
     * when in use, then the spool. Each step has its own lock, so a worker that finds another one
     * busy sending still checks the policy, and leaves.
     */
    public static function work(): void
    {
        // Reporting back first: it proves that starting a worker works, whatever this one finds to do.
        $meta = Store::readArray(self::WORKER_META) ?? [];
        Store::writeArray(self::WORKER_META, ['at' => (int) ($meta['at'] ?? Util::nowMs()), 'tries' => 0]);
        if (Config::apiKey() !== null) {
            \SecureNow\Firewall\Sync::maybe(true);
            if (\SecureNow\Sessions\Sessions::stats()['synced']) {
                \SecureNow\Sessions\Sessions::syncMaybe(true);
            }
        }
        self::flush(true, false);
    }

    private static function spool(): bool
    {
        if (Store::dir() === null) {
            return false;
        }
        $ok = true;
        foreach (self::$pending as $signal => $lines) {
            if (!$lines) {
                continue;
            }
            $file = self::SPOOL[$signal];
            // An unreachable ingest must not fill the disk: past the cap, new data is dropped.
            if (Store::size($file) > self::SPOOL_MAX_BYTES) {
                continue;
            }
            if (!Store::append($file, implode("\n", $lines) . "\n")) {
                $ok = false;
            }
        }
        if ($ok) {
            self::$pending = ['traces' => [], 'logs' => [], 'events' => [], 'fw' => []];
        }
        return $ok;
    }

    /**
     * Send everything in the spool. $force skips the interval and the outage pause (CLI, agent).
     *
     * @return array<string,int> signal => HTTP status of the last request sent (0 = network failure)
     */
    public static function flush(bool $mayWait = false, bool $force = true): array
    {
        $lock = Store::lock('flush');
        if ($lock === null) {
            return [];
        }
        try {
            $meta = Store::readArray(self::META) ?? [];
            $nowMs = Util::nowMs();
            if (!$force) {
                if ($nowMs < (int) ($meta['pauseUntil'] ?? 0)) {
                    return [];
                }
                $interval = Config::int('export.flushIntervalMs', 1000, 0);
                $elapsed = $nowMs - (int) ($meta['lastFlush'] ?? 0);
                if ($elapsed >= 0 && $elapsed < $interval) {
                    if (!$mayWait && PHP_SAPI !== 'cli-server') {
                        // The response is still attached: leave this batch to the next request.
                        return [];
                    }
                    if ($mayWait) {
                        // Hold the lock for the rest of the interval: requests finishing meanwhile add
                        // to the spool and this one sends them all.
                        usleep(($interval - $elapsed) * 1000);
                    }
                }
            }

            // Requests that finish while this one is sending find the lock taken and leave their
            // data in the spool: go round again for it, a few times at most, so nothing waits for
            // the next visitor.
            $statuses = [];
            for ($round = 0; $round < 5; $round++) {
                $batches = [];
                foreach (self::SPOOL as $signal => $file) {
                    $lines = self::takeSpool($file);
                    if ($lines) {
                        $batches[$signal] = $lines;
                    }
                }
                $meta['lastFlush'] = Util::nowMs();
                if (!$batches) {
                    break;
                }

                $sent = self::send($batches);
                $statuses = $sent + $statuses;
                $failed = false;
                foreach ($sent as $status) {
                    if ($status === 0 || $status === 429 || $status >= 500) {
                        $failed = true;
                    }
                }
                if ($failed) {
                    $failures = (int) ($meta['failures'] ?? 0) + 1;
                    $meta['failures'] = $failures;
                    // Stop trying for a while: a down ingest must not tie up PHP workers.
                    if ($failures >= 3) {
                        $meta['pauseUntil'] = Util::nowMs() + min(120000, 5000 * (2 ** min($failures - 3, 5)));
                    }
                    $meta['lastStatus'] = $statuses;
                    break;
                }
                $meta['failures'] = 0;
                $meta['pauseUntil'] = 0;
                $meta['lastStatus'] = $statuses;
                if (!self::spoolHasData()) {
                    break;
                }
                if (!$force && $mayWait) {
                    usleep(Config::int('export.flushIntervalMs', 1000, 0) * 1000);
                }
            }
            Store::writeArray(self::META, $meta);
            return $statuses;
        } finally {
            Store::unlock($lock);
        }
    }

    private static function spoolHasData(): bool
    {
        foreach (self::SPOOL as $file) {
            if (Store::size($file) > 0) {
                return true;
            }
        }
        return false;
    }

    /** @return string[] */
    private static function takeSpool(string $file): array
    {
        $path = Store::path($file);
        if ($path === null || !@is_file($path)) {
            return [];
        }
        $taken = $path . '.' . Util::randomHex(4) . '.sending';
        if (!@rename($path, $taken)) {
            return [];
        }
        $data = @file_get_contents($taken);
        @unlink($taken);
        if ($data === false || $data === '') {
            return [];
        }
        return array_values(array_filter(explode("\n", $data), static function (string $line): bool {
            return $line !== '';
        }));
    }

    private static function sendDirect(): void
    {
        $batches = array_filter(self::$pending);
        if ($batches) {
            self::send($batches);
        }
    }

    /**
     * @param array<string,string[]> $batches signal => spool lines
     * @return array<string,int>
     */
    private static function send(array $batches): array
    {
        $timeout = Config::int('export.timeoutMs', 3000, 250);
        $otlpHeaders = Config::otlpHeaders() + ['content-type' => 'application/json'];
        $requests = [];
        $n = 0;

        foreach (['traces', 'logs'] as $signal) {
            if (empty($batches[$signal])) {
                continue;
            }
            $url = $signal === 'traces' ? Config::tracesUrl() : Config::logsUrl();
            foreach (self::chunk($batches[$signal]) as $chunk) {
                $byScope = [];
                foreach ($chunk as $line) {
                    $tab = strpos($line, "\t");
                    if ($tab === false) {
                        continue;
                    }
                    $byScope[substr($line, 0, $tab)][] = substr($line, $tab + 1);
                }
                $requests[$signal . ':' . $n++] = self::post($url, $otlpHeaders, Otlp::envelope($signal, $byScope), $timeout, true);
            }
        }

        if (!empty($batches['events'])) {
            foreach (array_chunk($batches['events'], 500) as $chunk) {
                $requests['events:' . $n++] = self::post(Config::eventsUrl(), $otlpHeaders, '{"events":[' . implode(',', $chunk) . ']}', $timeout, false);
            }
        }

        if (!empty($batches['fw']) && Config::apiKey() !== null) {
            $query = http_build_query(array_filter(['app' => Config::appKey(), 'env' => Config::environment()]));
            $url = rtrim(Config::firewallApiUrl(), '/') . '/api/v1/firewall/events' . ($query !== '' ? '?' . $query : '');
            foreach (array_chunk(self::coalesceFirewallEvents($batches['fw']), 50) as $chunk) {
                $requests['fw:' . $n++] = self::post($url, self::controlHeaders() + ['content-type' => 'application/json'], '{"events":[' . implode(',', $chunk) . ']}', $timeout, false);
            }
        }

        $statuses = [];
        foreach (Transport::multi($requests) as $key => $result) {
            $signal = substr((string) $key, 0, (int) strpos((string) $key, ':'));
            $statuses[$signal] = $result['status'];
            if ($result['status'] < 200 || $result['status'] >= 300) {
                Diag::warn(sprintf(
                    '%s export failed: %s',
                    $signal,
                    $result['status'] === 0 ? (string) $result['error'] : 'HTTP ' . $result['status'] . ' ' . substr($result['body'], 0, 200)
                ));
            } else {
                Diag::debug($signal . ' exported (HTTP ' . $result['status'] . ')');
            }
        }
        return $statuses;
    }

    /** Headers for firewall control-plane calls (sync, hits, challenge verification, revocations). */
    public static function controlHeaders(): array
    {
        return [
            'authorization' => 'Bearer ' . (Config::apiKey() ?? ''),
            'user-agent' => 'securenow-firewall-sdk php/' . Version::SDK,
            'x-securenow-sdk-version' => Version::FIREWALL_PROTOCOL,
            'x-securenow-sdk' => Version::NAME . '/' . Version::SDK,
            'x-securenow-sdk-language' => 'php',
            'x-securenow-instance-id' => Config::instanceId(),
            'x-securenow-environment' => Config::environment(),
        ];
    }

    /**
     * @param array<string,string> $headers
     * @return array{method:string,url:string,headers:array<string,string>,body:string,timeoutMs:int}
     */
    private static function post(string $url, array $headers, string $body, int $timeout, bool $compress): array
    {
        if ($compress && strlen($body) > 8192 && function_exists('gzencode')) {
            $gz = @gzencode($body, 5);
            if (is_string($gz)) {
                $body = $gz;
                $headers['content-encoding'] = 'gzip';
            }
        }
        return ['method' => 'POST', 'url' => $url, 'headers' => $headers, 'body' => $body, 'timeoutMs' => $timeout];
    }

    /**
     * @param string[] $lines
     * @return array<int,string[]>
     */
    private static function chunk(array $lines): array
    {
        $chunks = [];
        $current = [];
        $size = 0;
        foreach ($lines as $line) {
            $length = strlen($line);
            if ($current && $size + $length > self::POST_MAX_BYTES) {
                $chunks[] = $current;
                $current = [];
                $size = 0;
            }
            $current[] = $line;
            $size += $length;
        }
        if ($current) {
            $chunks[] = $current;
        }
        return $chunks;
    }

    /**
     * A flood of blocked requests from one address becomes one ledger row with a count.
     *
     * @param string[] $lines
     * @return string[]
     */
    private static function coalesceFirewallEvents(array $lines): array
    {
        $merged = [];
        foreach ($lines as $line) {
            $event = json_decode($line, true);
            if (!is_array($event)) {
                continue;
            }
            $key = implode('|', [
                $event['ip'] ?? '', $event['action'] ?? '', $event['source'] ?? '', $event['ruleId'] ?? '',
                $event['method'] ?? '', $event['path'] ?? '', $event['matchedEntry'] ?? '',
            ]);
            if (isset($merged[$key])) {
                $merged[$key]['count'] = min(1000, (int) ($merged[$key]['count'] ?? 1) + (int) ($event['count'] ?? 1));
                $merged[$key]['occurredAt'] = $event['occurredAt'] ?? $merged[$key]['occurredAt'];
            } else {
                $merged[$key] = $event;
            }
        }
        return array_map([Util::class, 'json'], array_values($merged));
    }

    /** For `securenow status`: what the last flush did. @return array<string,mixed> */
    public static function meta(): array
    {
        $meta = Store::readArray(self::META) ?? [];
        $meta['spoolBytes'] = 0;
        foreach (self::SPOOL as $file) {
            $meta['spoolBytes'] += Store::size($file);
        }
        return $meta;
    }

    public static function touchAgentHeartbeat(): void
    {
        Store::write(self::AGENT_HEARTBEAT, (string) time());
    }

    public static function clearAgentHeartbeat(): void
    {
        Store::delete(self::AGENT_HEARTBEAT);
    }
}
