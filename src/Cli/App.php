<?php

declare(strict_types=1);

namespace SecureNow\Cli;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\Firewall\Firewall;
use SecureNow\Firewall\Layers\Cloud;
use SecureNow\Firewall\Layers\Iptables;
use SecureNow\Firewall\State;
use SecureNow\Firewall\Sync;
use SecureNow\Http\RequestInfo;
use SecureNow\Http\Transport;
use SecureNow\Net\ClientIp;
use SecureNow\Sessions\Sessions;
use SecureNow\Store\Store;
use SecureNow\Telemetry\Exporter;
use SecureNow\Telemetry\OtelBridge;
use SecureNow\Util;
use SecureNow\Version;

/**
 * vendor/bin/securenow: the runtime commands a PHP app needs (connect, check, test, agent).
 * Dashboard work (apps, alerts, forensics, blocklist...) stays in the language-neutral tools:
 * `npx securenow`, the MCP server and the dashboard.
 */
final class App
{
    /** @var array<string,string|bool> */
    private array $flags = [];
    /** @var string[] */
    private array $args = [];

    /** @param string[] $argv */
    public static function main(array $argv): int
    {
        $app = new self();
        try {
            return $app->run(array_slice($argv, 1));
        } catch (\Throwable $e) {
            fwrite(STDERR, 'securenow: ' . $e->getMessage() . "\n");
            return 1;
        }
    }

    /** @param string[] $argv */
    private function run(array $argv): int
    {
        $command = 'help';
        foreach ($argv as $i => $arg) {
            if (strncmp($arg, '--', 2) === 0) {
                $eq = strpos($arg, '=');
                if ($eq !== false) {
                    $this->flags[substr($arg, 2, $eq - 2)] = substr($arg, $eq + 1);
                } elseif (isset($argv[$i + 1]) && strncmp($argv[$i + 1], '--', 2) !== 0 && in_array(substr($arg, 2), self::VALUE_FLAGS, true)) {
                    $this->flags[substr($arg, 2)] = $argv[$i + 1];
                    $argv[$i + 1] = '--';
                } else {
                    $this->flags[substr($arg, 2)] = true;
                }
            } elseif ($arg !== '--') {
                $this->args[] = $arg;
            }
        }
        if ($this->args) {
            $command = array_shift($this->args);
        }
        if (!empty($this->flags['verbose']) || !empty($this->flags['debug'])) {
            Diag::setLevel('debug');
        } else {
            Diag::setLevel('info');
        }
        Diag::setSink(static function (string $line): void {
            fwrite(STDERR, $line . "\n");
        });

        switch ($command) {
            case 'help':
            case '--help':
            case '-h':
                return $this->help();
            case 'version':
            case '--version':
                $this->out('securenow-php ' . Version::SDK . ' (PHP ' . PHP_VERSION . ')');
                return 0;
            case 'login':
            case 'connect':
                return $this->login();
            case 'init':
                return $this->init();
            case 'status':
                return $this->status();
            case 'doctor':
                return $this->doctor();
            case 'test':
                return $this->test();
            case 'sync':
                return $this->sync();
            case 'flush':
                return $this->flush();
            case 'firewall:check':
            case 'check':
                return $this->firewallCheck();
            case 'agent':
                return $this->agent();
            default:
                fwrite(STDERR, "Unknown command: $command\n\n");
                $this->help();
                return 2;
        }
    }

    private const VALUE_FLAGS = [
        'api-key', 'app', 'name', 'env', 'dir', 'format', 'app-url', 'user', 'interval', 'path', 'method', 'ua', 'port', 'bind', 'timeout',
    ];

    private function out(string $line = ''): void
    {
        fwrite(STDOUT, $line . "\n");
    }

    private function flag(string $name, ?string $default = null): ?string
    {
        $value = $this->flags[$name] ?? null;
        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function help(): int
    {
        $this->out('SecureNow for PHP ' . Version::SDK);
        $this->out();
        $this->out('Usage: vendor/bin/securenow <command> [options]');
        $this->out();
        $this->out('  login                 Sign in in the browser, pick an app, write .securenow/runtime credentials');
        $this->out('                        [--no-browser] [--port 8765 --bind 0.0.0.0] inside a container');
        $this->out('  init                  Write credentials from --api-key and --app (CI, servers, no browser)');
        $this->out('                        [--name <label>] [--env production] [--format php|json] [--dir <project>]');
        $this->out('  status                What the SDK sees: credentials, cache folder, firewall policy, last export');
        $this->out('  doctor                Check PHP, extensions, credentials and connectivity to SecureNow');
        $this->out('  test                  Send a test trace and log, and print what SecureNow answered');
        $this->out('  sync                  Fetch the firewall policy now (full sync)');
        $this->out('  firewall:check <ip>   What the firewall would do for this address');
        $this->out('                        [--path /login] [--method POST] [--ua "curl/8"]');
        $this->out('  flush                 Send telemetry waiting in the spool');
        $this->out('  agent                 Long-running helper: syncs the policy on a timer, ships telemetry,');
        $this->out('                        and drives the OS firewall (iptables/nftables) and cloud WAF layers');
        $this->out('                        [--user www-data] when started as root for iptables');
        $this->out();
        $this->out('Options: --verbose   --json (status, doctor, firewall:check)');
        $this->out();
        $this->out('Apps, alert rules, forensics, blocklist and the rest of the dashboard: npx securenow,');
        $this->out('the SecureNow MCP server, or https://app.securenow.ai');
        return 0;
    }

    // ---- credentials ----

    private function projectDir(): string
    {
        $dir = $this->flag('dir') ?? (string) getcwd();
        return rtrim($dir, '/\\');
    }

    /** A project whose folder is served by the web server keeps secrets in a .php file. */
    private function looksWebExposed(string $dir): bool
    {
        if (is_file($dir . '/wp-config.php') || is_file($dir . '/wp-load.php')) {
            return true;
        }
        foreach (['public', 'web', 'public_html', 'htdocs', 'www'] as $docroot) {
            if (is_dir($dir . '/' . $docroot)) {
                return false;
            }
        }
        return is_file($dir . '/index.php');
    }

    /**
     * @param array<string,mixed> $runtime
     */
    private function writeRuntime(array $runtime): string
    {
        $dir = $this->projectDir();
        $folder = $dir . '/.securenow';
        if (!is_dir($folder) && !mkdir($folder, 0700, true) && !is_dir($folder)) {
            throw new \RuntimeException("cannot create $folder");
        }
        $format = $this->flag('format') ?? ($this->looksWebExposed($dir) ? 'php' : 'json');

        // Keep settings already made in an existing file.
        foreach (['runtime.php', 'runtime.json'] as $existing) {
            if (is_file($folder . '/' . $existing)) {
                $current = Config::readCredentialFile($folder . '/' . $existing);
                if (is_array($current) && isset($current['config']) && is_array($current['config'])) {
                    $runtime['config'] = array_replace_recursive($current['config'], $runtime['config'] ?? []);
                }
                if ($this->flag('format') === null) {
                    $format = $existing === 'runtime.php' ? 'php' : 'json';
                }
            }
        }
        if (empty($runtime['config'])) {
            unset($runtime['config']);
        }

        if ($format === 'php') {
            $file = $folder . '/runtime.php';
            $content = "<?php\n\n// SecureNow runtime credentials. Secret: do not commit.\n// A .php file prints nothing if a browser requests it.\n\nreturn " . var_export($runtime, true) . ";\n";
            @unlink($folder . '/runtime.json');
        } else {
            $file = $folder . '/runtime.json';
            $content = json_encode($runtime, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        }
        if (file_put_contents($file, $content, LOCK_EX) === false) {
            throw new \RuntimeException("cannot write $file");
        }

        // Belt and braces for a folder inside the web root.
        if (!is_file($folder . '/.htaccess')) {
            @file_put_contents($folder . '/.htaccess', "Require all denied\nDeny from all\n");
        }
        if (!is_file($folder . '/index.html')) {
            @file_put_contents($folder . '/index.html', '');
        }
        $this->ensureGitignore($dir);
        return $file;
    }

    private function ensureGitignore(string $dir): void
    {
        $file = $dir . '/.gitignore';
        $wanted = ['.securenow/runtime.json', '.securenow/runtime.php', '.securenow/admin.json', '.securenow/credentials*.json'];
        $current = is_file($file) ? (string) file_get_contents($file) : '';
        $missing = [];
        foreach ($wanted as $line) {
            if (strpos($current, $line) === false && strpos($current, "\n.securenow/\n") === false && strpos($current, "\n.securenow\n") === false) {
                $missing[] = $line;
            }
        }
        if ($missing && (is_file($file) || is_dir($dir . '/.git'))) {
            @file_put_contents($file, rtrim($current) . "\n\n# SecureNow credentials\n" . implode("\n", $missing) . "\n");
        }
    }

    private function afterCredentials(string $file, string $appKey, ?string $name): void
    {
        $this->out();
        $this->out('  Connected to ' . ($name ?? $appKey) . ' (' . $appKey . ')');
        $this->out('  Credentials: ' . $file);
        if ($this->looksWebExposed($this->projectDir()) && substr($file, -5) === '.json') {
            $this->out();
            $this->out('  Warning: this folder looks web-served. Use --format php, or keep the file outside the');
            $this->out('  web root and point SECURENOW_CREDENTIALS_FILE at it, so the key cannot be downloaded.');
        }
        $this->out('  The file holds a secret key: on a server, let only the user PHP runs as read it');
        $this->out('  (chown www-data ' . basename($file) . ' && chmod 600 ' . basename($file) . ').');
        $this->out();
        $this->out('  Next: load a page of your app, then run  vendor/bin/securenow status');
        $this->out('  Check the setup any time with            vendor/bin/securenow doctor');
        $this->out();
    }

    private function init(): int
    {
        // Credentials already in this project (written by `npx securenow login`, or an earlier run)
        // are kept: `init --format php` alone turns runtime.json into runtime.php.
        $existing = [];
        foreach (['runtime.php', 'runtime.json', 'credentials.json'] as $name) {
            $doc = Config::readCredentialFile($this->projectDir() . '/.securenow/' . $name);
            if (is_array($doc)) {
                $existing = isset($doc['runtime']) && is_array($doc['runtime']) ? $doc['runtime'] : $doc;
                break;
            }
        }
        $apiKey = $this->flag('api-key') ?? Config::env('SECURENOW_API_KEY') ?? (is_string($existing['apiKey'] ?? null) ? $existing['apiKey'] : null);
        $appKey = $this->flag('app') ?? Config::env('SECURENOW_APP_KEY') ?? (is_string($existing['app']['key'] ?? null) ? $existing['app']['key'] : null);
        if ($apiKey === null || $appKey === null) {
            fwrite(STDERR, "init needs --api-key snk_live_... and --app <app key> (or run: vendor/bin/securenow login)\n");
            return 2;
        }
        if (strncmp($apiKey, 'snk_live_', 9) !== 0) {
            fwrite(STDERR, "--api-key must be a runtime key (snk_live_...)\n");
            return 2;
        }
        $name = $this->flag('name') ?? (is_string($existing['app']['name'] ?? null) ? $existing['app']['name'] : null);
        $runtime = ['apiKey' => $apiKey, 'app' => $name !== null ? ['key' => $appKey, 'name' => $name] : ['key' => $appKey]];
        $env = $this->flag('env');
        if ($env !== null) {
            $runtime['config']['runtime']['deploymentEnvironment'] = $env;
        }
        $file = $this->writeRuntime($runtime);
        $this->afterCredentials($file, $appKey, $name);
        return 0;
    }

    /** The browser flow of `npx securenow app connect`: SecureNow calls back on 127.0.0.1 with the app and its key. */
    private function login(): int
    {
        $appUrl = rtrim($this->flag('app-url') ?? Config::env('SECURENOW_APP_URL') ?? Config::DEFAULT_APP_URL, '/');
        // Inside a container (Sail, DDEV, Docker): publish a port and listen on every interface,
        //   docker run -p 127.0.0.1:8765:8765 ... vendor/bin/securenow login --port 8765 --bind 0.0.0.0
        // The browser still calls back on 127.0.0.1.
        $bind = $this->flag('bind') ?? '127.0.0.1';
        $server = @stream_socket_server('tcp://' . $bind . ':' . (int) ($this->flag('port') ?? '0'), $errno, $errstr);
        if ($server === false) {
            throw new \RuntimeException("cannot open a local port for the sign-in callback: $errstr");
        }
        $port = (int) substr((string) stream_socket_get_name($server, false), (int) strrpos((string) stream_socket_get_name($server, false), ':') + 1);
        $nonce = Util::b64urlEncode(random_bytes(24));
        $url = $appUrl . '/cli/auth?' . http_build_query(['callback' => "http://127.0.0.1:$port/callback", 'state' => $nonce, 'mode' => 'runtime']);

        $this->out();
        $this->out('  Open this URL to sign in and pick the app:');
        $this->out();
        $this->out('  ' . $url);
        $this->out();
        if (empty($this->flags['no-browser'])) {
            $this->openBrowser($url);
        }
        $wait = max(30, (int) ($this->flag('timeout') ?? '300'));
        $this->out('  Waiting for the browser (' . (int) ceil($wait / 60) . ' minutes)...');

        $deadline = time() + $wait;
        $result = null;
        while (time() < $deadline && $result === null) {
            $conn = @stream_socket_accept($server, 2);
            if ($conn === false) {
                continue;
            }
            stream_set_timeout($conn, 5);
            $requestLine = (string) fgets($conn, 8192);
            while (($line = fgets($conn, 8192)) !== false && trim($line) !== '') {
                // headers are not needed
            }
            $target = explode(' ', $requestLine)[1] ?? '/';
            $query = [];
            parse_str((string) parse_url($target, PHP_URL_QUERY), $query);
            $path = (string) parse_url($target, PHP_URL_PATH);
            $page = static function (string $title, string $text): string {
                $body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SecureNow</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:60px">'
                    . '<h2>' . htmlspecialchars($title) . '</h2><p>' . htmlspecialchars($text) . '</p></body></html>';
                return "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body;
            };
            if ($path !== '/callback') {
                fwrite($conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            } elseif (!empty($query['error'])) {
                fwrite($conn, $page('Sign-in failed', 'You can close this window.'));
                $result = ['error' => (string) $query['error']];
            } elseif (!hash_equals($nonce, (string) ($query['state'] ?? ''))) {
                fwrite($conn, $page('Security error', 'This request did not come from your terminal. Please try again.'));
                $result = ['error' => 'state mismatch'];
            } else {
                fwrite($conn, $page('Connected', 'SecureNow is connected to this project. You can close this window.'));
                $result = $query;
            }
            fclose($conn);
        }
        fclose($server);

        if ($result === null) {
            throw new \RuntimeException('sign-in timed out. Without a browser: vendor/bin/securenow init --api-key snk_live_... --app <app key>');
        }
        if (isset($result['error'])) {
            throw new \RuntimeException('sign-in failed: ' . $result['error']);
        }
        $appKey = (string) ($result['app_key'] ?? '');
        $apiKey = (string) ($result['api_key'] ?? '');
        if ($appKey === '') {
            throw new \RuntimeException('no app was selected; nothing was written');
        }
        if (strncmp($apiKey, 'snk_live_', 9) !== 0) {
            throw new \RuntimeException('SecureNow returned no runtime key for this app. Create one in the dashboard (Settings, API keys), then: vendor/bin/securenow init --api-key ... --app ' . $appKey);
        }
        $name = (string) ($result['app_name'] ?? '');
        $file = $this->writeRuntime(['apiKey' => $apiKey, 'app' => $name !== '' ? ['key' => $appKey, 'name' => $name] : ['key' => $appKey]]);
        $this->afterCredentials($file, $appKey, $name !== '' ? $name : null);
        return 0;
    }

    private function openBrowser(string $url): void
    {
        if (!function_exists('proc_open')) {
            return;
        }
        if (PHP_OS_FAMILY === 'Windows') {
            $command = ['rundll32', 'url.dll,FileProtocolHandler', $url];
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            $command = ['open', $url];
        } else {
            $command = ['xdg-open', $url];
        }
        $process = @proc_open($command, [1 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w'], 2 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w']], $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }
    }

    // ---- inspection ----

    private function requireCredentials(): bool
    {
        if (Config::appKey() === null) {
            fwrite(STDERR, "No SecureNow credentials found (.securenow/runtime.json, .securenow/runtime.php or SECURENOW_CREDENTIALS).\nRun: vendor/bin/securenow login\n");
            return false;
        }
        $this->actAsUser();
        return true;
    }

    /** --user www-data: look at (and write) the cache folder of the user PHP runs as. */
    private function actAsUser(): void
    {
        $user = $this->flag('user');
        if ($user === null || !function_exists('posix_getpwnam')) {
            return;
        }
        $info = ctype_digit($user) ? posix_getpwuid((int) $user) : posix_getpwnam($user);
        if (!is_array($info)) {
            throw new \RuntimeException("unknown user: $user");
        }
        if (function_exists('posix_geteuid') && posix_geteuid() !== 0 && posix_geteuid() !== (int) $info['uid']) {
            throw new \RuntimeException('--user needs root (or run the command as that user: sudo -u ' . $user . ' vendor/bin/securenow ...)');
        }
        Store::actAs((int) $info['uid'], (int) $info['gid']);
    }

    private static function ago(?int $time): string
    {
        if (!$time) {
            return 'never';
        }
        $seconds = max(0, time() - $time);
        if ($seconds < 90) {
            return $seconds . ' s ago';
        }
        if ($seconds < 5400) {
            return round($seconds / 60) . ' min ago';
        }
        return round($seconds / 3600, 1) . ' h ago';
    }

    /** @return array<string,mixed> */
    private function snapshot(): array
    {
        $export = Exporter::meta();
        return [
            'sdk' => Version::SDK,
            'php' => PHP_VERSION,
            'app' => ['key' => Config::appKey(), 'name' => Config::appName()],
            'environment' => Config::environment(),
            'credentials' => Config::source(),
            'apiKey' => Config::apiKey() !== null ? 'set' : 'missing',
            'ingest' => Config::ingestBase(),
            'cacheDir' => Store::dir(),
            'agent' => Exporter::agentAlive() ? 'running' : 'not running',
            'firewall' => Config::apiKey() !== null ? Firewall::stats() : null,
            'sessions' => Sessions::stats(),
            'export' => [
                'lastFlush' => isset($export['lastFlush']) ? intdiv((int) $export['lastFlush'], 1000) : null,
                'lastStatus' => $export['lastStatus'] ?? null,
                'failures' => (int) ($export['failures'] ?? 0),
                'spoolBytes' => (int) ($export['spoolBytes'] ?? 0),
            ],
            'otelBridge' => OtelBridge::available() ? (extension_loaded('opentelemetry') ? 'available (extension loaded)' : 'available (no opentelemetry extension: manual spans only)') : 'not installed',
        ];
    }

    private function status(): int
    {
        if (!$this->requireCredentials()) {
            return 1;
        }
        $s = $this->snapshot();
        if (!empty($this->flags['json'])) {
            $this->out((string) json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            return 0;
        }
        $this->out();
        $this->out('  SecureNow for PHP ' . $s['sdk'] . '  (PHP ' . $s['php'] . ')');
        $this->out('  App           ' . ($s['app']['name'] ?? '-') . '  ' . $s['app']['key']);
        $this->out('  Environment   ' . $s['environment']);
        $this->out('  Credentials   ' . $s['credentials'] . '  (runtime key ' . $s['apiKey'] . ')');
        $this->out('  Ingest        ' . $s['ingest']);
        $this->out('  Cache folder  ' . ($s['cacheDir'] ?? 'NOT WRITABLE: the firewall cannot keep its policy'));
        $this->out('  Agent         ' . $s['agent']);
        $this->out('  OpenTelemetry ' . $s['otelBridge']);
        $fw = $s['firewall'];
        $this->out();
        if ($fw === null) {
            $this->out('  Firewall      off: no runtime key (snk_live_...)');
        } elseif (!$fw['synced']) {
            $this->out('  Firewall      no policy yet in this cache folder.');
            $this->out('                The web server usually runs as another user with its own folder:');
            $this->out('                add --user www-data (as root), or run  vendor/bin/securenow sync');
            if ($fw['lastError']) {
                $this->out('                last error: ' . $fw['lastError']);
            }
        } else {
            $this->out('  Firewall      ' . ($fw['remoteEnabled'] === false ? 'DISABLED from the dashboard' : 'enforcing'));
            $this->out('    blocked addresses   ' . $fw['blocklist'] . '  (+ ' . $fw['blocklistRules'] . ' route-scoped rules)');
            $this->out('    allowlist           ' . $fw['allowlist']);
            $this->out('    rate-limit rules    ' . $fw['rateLimitRules']);
            $this->out('    challenge rules     ' . $fw['challengeRules']);
            $this->out('    user-agent rules    ' . $fw['userAgentRules'] . '  (' . $fw['userAgentAllowRules'] . ' allow patterns)');
            $this->out('    policy checked      ' . self::ago($fw['checkedAt']) . ', changed ' . self::ago($fw['syncedAt']) . ', via ' . $fw['apiUrl']);
            if ($fw['consecutiveErrors'] > 0) {
                $this->out('    sync errors         ' . $fw['consecutiveErrors'] . ' in a row: ' . $fw['lastError']);
            }
        }
        $this->out();
        $this->out('  Telemetry     last sent ' . self::ago($s['export']['lastFlush'])
            . ($s['export']['lastStatus'] ? '  ' . json_encode($s['export']['lastStatus']) : '')
            . ($s['export']['spoolBytes'] > 0 ? ', ' . $s['export']['spoolBytes'] . ' bytes waiting' : ''));
        if ($s['export']['failures'] > 0) {
            $this->out('                ' . $s['export']['failures'] . ' failed sends in a row');
        }
        $this->out('  Sessions      ' . ($s['sessions']['synced'] ? $s['sessions']['revocations'] . ' active revocations' : 'not in use'));
        $this->out();
        return 0;
    }

    private function doctor(): int
    {
        $checks = [];
        $add = static function (string $name, bool $ok, string $detail, bool $required = true) use (&$checks): void {
            $checks[] = ['name' => $name, 'ok' => $ok, 'detail' => $detail, 'required' => $required];
        };
        $add('PHP version', PHP_VERSION_ID >= 80000, PHP_VERSION . (PHP_INT_SIZE < 8 ? ' (32-bit builds are not supported)' : ''));
        $add('json extension', function_exists('json_encode'), '');
        $add('curl extension', function_exists('curl_multi_init'), function_exists('curl_multi_init') ? '' : 'not loaded: telemetry is sent with PHP streams, one request at a time', false);
        $add('APCu', function_exists('apcu_enabled'), function_exists('apcu_enabled') ? 'rate-limit counters shared across PHP-FPM workers' : 'not loaded: counters use files in the cache folder (fine for most sites)', false);
        $otelExt = extension_loaded('opentelemetry');
        $add('OpenTelemetry', $otelExt && OtelBridge::available(), $otelExt
            ? (OtelBridge::available() ? 'extension and SDK present: framework, database and HTTP-client spans are exported' : 'extension loaded but open-telemetry/sdk is not installed: composer require open-telemetry/sdk')
            : 'optional: without the opentelemetry extension you get the request span, logs and the firewall; with it, database and framework spans too', false);

        $hasCreds = Config::appKey() !== null;
        $add('Credentials', $hasCreds, $hasCreds ? Config::source() : 'none found: vendor/bin/securenow login');
        if ($hasCreds) {
            $this->actAsUser();
            $add('Runtime key', Config::apiKey() !== null, Config::apiKey() !== null ? 'snk_live_... present' : 'missing: telemetry is refused and the firewall stays off');
            $source = Config::source();
            if (substr($source, -5) === '.json' && $this->looksWebExposed(dirname($source, 2))) {
                $add('Credentials are not web-readable', false, $source . ' sits in a web-served folder: use runtime.php (vendor/bin/securenow init --format php) or SECURENOW_CREDENTIALS_FILE', false);
            }
            $dir = Store::dir();
            $add('Cache folder', $dir !== null, $dir ?? 'not writable: set config.runtime.cacheDir or SECURENOW_CACHE_DIR');

            $probe = $this->sendProbe('securenow-cli-doctor');
            foreach (['traces' => 'Traces accepted', 'logs' => 'Logs accepted'] as $signal => $label) {
                $add($label, $probe[$signal]['status'] >= 200 && $probe[$signal]['status'] < 300, self::describeAnswer($probe[$signal]));
            }
            if (Config::apiKey() !== null) {
                $result = Sync::run(true, 8000);
                $add('Firewall sync', $result['ok'], $result['ok'] ? 'policy fetched (HTTP ' . $result['status'] . ')' : (string) $result['error']);
            }
        }

        if (!empty($this->flags['json'])) {
            $this->out((string) json_encode($checks, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $this->out();
            foreach ($checks as $check) {
                $mark = $check['ok'] ? ' ok ' : ($check['required'] ? 'FAIL' : 'note');
                $this->out(sprintf('  [%s] %-34s %s', $mark, $check['name'], $check['detail']));
            }
            $this->out();
            $this->out('  In web requests the SDK also needs: vendor/autoload.php loaded at the top of the entry file');
            $this->out('  (every framework does), or auto_prepend_file pointing at vendor/securenow/securenow/prepend.php.');
            $this->out();
        }
        foreach ($checks as $check) {
            if (!$check['ok'] && $check['required']) {
                return 1;
            }
        }
        return 0;
    }

    /**
     * A probe the ingest gateway recognises (resource telemetry.sdk.name "securenow-cli", records
     * marked test.source): it proves the path works without making the app look connected. The
     * dashboard shows the app as live when a real request arrives. Same markers as `npx securenow test-span`.
     *
     * @return array{traces:array<string,mixed>,logs:array<string,mixed>,traceId:string}
     */
    private function sendProbe(string $source): array
    {
        $now = Util::nowNs();
        $traceId = Util::randomHex(16);
        $spanId = Util::randomHex(8);
        $resource = \SecureNow\Telemetry\Otlp::attributes([
            'service.name' => Config::appKey(),
            'deployment.environment' => Config::environment(),
            'telemetry.sdk.name' => 'securenow-cli',
            'telemetry.sdk.language' => 'php',
            'telemetry.sdk.version' => Version::SDK,
        ]);
        $marks = \SecureNow\Telemetry\Otlp::attributes(['test.source' => $source, 'securenow.sdk' => 'php']);
        $traces = Util::json(['resourceSpans' => [[
            'resource' => ['attributes' => $resource],
            'scopeSpans' => [[
                'scope' => ['name' => 'securenow-cli', 'version' => Version::SDK],
                'spans' => [[
                    'traceId' => $traceId, 'spanId' => $spanId, 'name' => 'securenow.cli.test-span', 'kind' => 1,
                    'startTimeUnixNano' => (string) ($now - 5000000), 'endTimeUnixNano' => (string) $now,
                    'attributes' => $marks, 'status' => ['code' => 1],
                ]],
            ]],
        ]]]);
        $logs = Util::json(['resourceLogs' => [[
            'resource' => ['attributes' => $resource],
            'scopeLogs' => [[
                'scope' => ['name' => 'securenow-cli', 'version' => Version::SDK],
                'logRecords' => [[
                    'timeUnixNano' => (string) $now, 'observedTimeUnixNano' => (string) $now,
                    'severityNumber' => 9, 'severityText' => 'INFO',
                    'body' => ['stringValue' => 'SecureNow PHP SDK test log'],
                    'attributes' => $marks, 'traceId' => $traceId, 'spanId' => $spanId,
                ]],
            ]],
        ]]]);
        $headers = Config::otlpHeaders() + ['content-type' => 'application/json'];
        $results = Transport::multi([
            'traces' => ['method' => 'POST', 'url' => Config::tracesUrl(), 'headers' => $headers, 'body' => $traces, 'timeoutMs' => 8000],
            'logs' => ['method' => 'POST', 'url' => Config::logsUrl(), 'headers' => $headers, 'body' => $logs, 'timeoutMs' => 8000],
        ]);
        return ['traces' => $results['traces'], 'logs' => $results['logs'], 'traceId' => $traceId];
    }

    /** @param array<string,mixed> $result */
    private static function describeAnswer(array $result): string
    {
        if ($result['status'] === 0) {
            return 'no answer: ' . $result['error'];
        }
        $good = $result['status'] >= 200 && $result['status'] < 300;
        $hint = '';
        if ($result['status'] === 401 || $result['status'] === 403) {
            $hint = '  (the runtime key was revoked or belongs to another app: vendor/bin/securenow login)';
        } elseif ($result['status'] === 402) {
            $hint = '  (trial ended or subscription inactive)';
        }
        return 'HTTP ' . $result['status'] . ($good ? '  accepted' : '  REFUSED ' . substr((string) $result['body'], 0, 160) . $hint);
    }

    private function test(): int
    {
        if (!$this->requireCredentials()) {
            return 1;
        }
        $probe = $this->sendProbe('securenow-cli');
        $this->out();
        $this->out('  Sent a test trace (' . $probe['traceId'] . ') and a test log for app ' . Config::appKey());
        $ok = true;
        foreach (['traces', 'logs'] as $signal) {
            $ok = $ok && $probe[$signal]['status'] >= 200 && $probe[$signal]['status'] < 300;
            $this->out(sprintf('    %-7s %s', $signal, self::describeAnswer($probe[$signal])));
        }
        $this->out();
        if ($ok) {
            $this->out('  SecureNow accepted both: credentials and the network path are good.');
            $this->out('  A test does not count as the app running. Load a page of the app: that request shows in the');
            $this->out('  dashboard within a minute, and  npx securenow status  lists it.');
        } else {
            $this->out('  Something was refused: run  vendor/bin/securenow doctor --verbose');
        }
        $this->out();
        return $ok ? 0 : 1;
    }

    private function sync(): int
    {
        if (!$this->requireCredentials()) {
            return 1;
        }
        if (Config::apiKey() === null) {
            fwrite(STDERR, "No runtime key: the firewall is off.\n");
            return 1;
        }
        $result = Sync::run(true);
        if (!$result['ok']) {
            fwrite(STDERR, 'Sync failed: ' . $result['error'] . "\n");
            return 1;
        }
        Sessions::sync(true);
        $this->flags['json'] = $this->flags['json'] ?? false;
        return $this->status();
    }

    private function flush(): int
    {
        if (!$this->requireCredentials()) {
            return 1;
        }
        $statuses = Exporter::flush(false, true);
        $this->out($statuses ? 'Sent: ' . json_encode($statuses) : 'Nothing waiting.');
        return 0;
    }

    private function firewallCheck(): int
    {
        if (!$this->requireCredentials()) {
            return 1;
        }
        $ip = $this->args[0] ?? '';
        if ($ip === '') {
            fwrite(STDERR, "Usage: vendor/bin/securenow firewall:check <ip> [--path /x] [--method GET] [--ua \"...\"]\n");
            return 2;
        }
        if (State::load() === null) {
            Sync::run(true);
        }
        $request = new RequestInfo();
        $request->method = strtoupper($this->flag('method') ?? 'GET');
        $request->setTarget($this->flag('path') ?? '/');
        $request->headers = ['user-agent' => $this->flag('ua') ?? 'Mozilla/5.0 (securenow firewall:check)', 'accept' => 'application/json'];
        $request->remoteAddr = $ip;
        // Dry run: nothing is reported and no rate-limit bucket is spent.
        $state = State::load();
        $details = ['ip' => $ip];
        $verdict = null;
        if ($state !== null) {
            // In memory only: the policy on disk, which live requests read, is not touched.
            $dry = $state;
            $dry['rlRules'] = [];
            State::useInMemory($dry);
            try {
                $verdict = Firewall::check($request, $details);
            } finally {
                State::reset();
                Exporter::reset();
            }
        }
        $result = [
            'ip' => $ip,
            'method' => $request->method,
            'path' => $request->path,
            'decision' => $verdict === null ? 'allowed' : $verdict->action,
            'status' => $verdict === null ? null : $verdict->status,
            'details' => $verdict === null ? [] : $verdict->attributes,
            'policy' => $state === null ? 'none' : 'synced ' . self::ago($state['syncedAt'] ?? null),
        ];
        if (!empty($this->flags['json'])) {
            $this->out((string) json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $this->out();
            $this->out("  $ip  {$request->method} {$request->path}  ->  " . strtoupper($result['decision']) . ($verdict ? ' (HTTP ' . $verdict->status . ')' : ''));
            foreach ($result['details'] as $key => $value) {
                $this->out('    ' . $key . ' = ' . (is_bool($value) ? var_export($value, true) : $value));
            }
            $this->out('    policy: ' . $result['policy'] . ' (rate limits are not counted by this check)');
            $this->out();
        }
        return 0;
    }

    // ---- agent ----

    private function agent(): int
    {
        if (!$this->requireCredentials()) {
            return 1;
        }
        if (Store::dir() === null) {
            fwrite(STDERR, "The cache folder is not writable. Set config.runtime.cacheDir, or run as the web server's user (or as root with --user www-data).\n");
            return 1;
        }
        $interval = max(1, (int) ($this->flag('interval') ?? (string) Config::int('firewall.versionCheckInterval', 10, 1)));
        $layers = [];
        if (Config::bool('firewall.iptables', false)) {
            $iptables = new Iptables();
            if ($iptables->init()) {
                $layers[] = $iptables;
            }
        }
        $cloudProvider = Config::get('firewall.cloud');
        if (is_string($cloudProvider) && $cloudProvider !== '') {
            $cloud = new Cloud($cloudProvider);
            if ($cloud->init()) {
                $layers[] = $cloud;
            }
        }

        $running = true;
        if (function_exists('pcntl_signal')) {
            if (function_exists('pcntl_async_signals')) {
                pcntl_async_signals(true);
            }
            $stop = static function () use (&$running): void {
                $running = false;
            };
            // SIGQUIT too: the official PHP-FPM images stop their containers with it.
            foreach ([SIGTERM, SIGINT, SIGQUIT, SIGHUP] as $signal) {
                pcntl_signal($signal, $stop);
            }
        }

        $this->out('[securenow] agent started: app ' . Config::appKey() . ', cache ' . Store::dir() . ', policy check every ' . $interval . ' s'
            . ($layers ? ', layers: ' . implode(', ', array_map(static function ($l) { return $l instanceof Iptables ? 'os-firewall' : 'cloud-waf'; }, $layers)) : ''));

        $nextSync = 0;
        $nextRevocations = 0;
        $pushedGeneration = null;
        $firewallOn = Config::apiKey() !== null;
        try {
            while ($running) {
                Exporter::touchAgentHeartbeat();
                $now = time();
                if ($firewallOn && $now >= $nextSync) {
                    // With an API that long-polls, each check is held up to 5 seconds (telemetry is
                    // shipped between checks) and the next one follows at once.
                    $wait = min(5, (int) (State::meta()['longPoll'] ?? 0));
                    $result = Sync::run(false, 8000, (bool) $layers, $wait);
                    $syncMeta = State::meta();
                    $errors = (int) ($syncMeta['errors'] ?? 0);
                    $nextSync = ($errors === 0 && (int) ($syncMeta['longPoll'] ?? 0) > 0)
                        ? time()
                        : $now + (int) min($interval * (2 ** min($errors, 4)), 120);
                    if ($layers) {
                        $state = State::load(true);
                        $enabled = ($state['remoteEnabled'] ?? true) !== false;
                        $generation = ($state['gen'] ?? '') . ($enabled ? '' : ':off');
                        if (isset($result['ips']) || ($pushedGeneration !== null && $generation !== $pushedGeneration) || $pushedGeneration === null) {
                            $ips = $result['ips'] ?? null;
                            if ($ips === null) {
                                // The policy did not change in this run: fetch the list once for the layers.
                                $full = Sync::run(true, 8000, true);
                                $ips = $full['ips'] ?? [];
                            }
                            foreach ($layers as $layer) {
                                $layer->sync($enabled ? $ips : []);
                            }
                            $pushedGeneration = $generation;
                        }
                    }
                }
                if ($firewallOn && $now >= $nextRevocations && Sessions::stats()['synced']) {
                    Sessions::sync();
                    $nextRevocations = $now + 30;
                }
                Exporter::flush(false, true);
                usleep(1000000);
            }
        } finally {
            foreach ($layers as $layer) {
                if ($layer instanceof Iptables) {
                    $layer->shutdown();
                }
            }
            Exporter::clearAgentHeartbeat();
            $this->out('[securenow] agent stopped');
        }
        return 0;
    }
}
