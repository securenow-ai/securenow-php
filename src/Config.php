<?php

declare(strict_types=1);

namespace SecureNow;

/**
 * SecureNow configuration resolver. Mirrors the Node SDK (securenow/app-config): the same
 * .securenow/runtime.json the CLI writes, the same keys and defaults, and SECURENOW_CREDENTIALS
 * for hosts that cannot mount a file.
 *
 * PHP additions:
 *  - .securenow/runtime.php (a file that returns the same array). A .php file prints nothing when a
 *    browser requests it, so it is the safe choice when the project folder is also the web root.
 *  - SECURENOW_CREDENTIALS_FILE: an explicit path, for credentials kept outside the project.
 */
final class Config
{
    public const CLOUD_INGEST = 'https://ingest.securenow.ai';
    public const DEFAULT_API_URL = 'https://api.securenow.ai';
    public const DEFAULT_APP_URL = 'https://app.securenow.ai';
    public const LEGACY_GATEWAY = 'https://api.securenow.ai/api/otlp';
    public const ENV_CREDENTIALS = 'SECURENOW_CREDENTIALS';
    public const ENV_CREDENTIALS_FILE = 'SECURENOW_CREDENTIALS_FILE';

    private const FILE_ENVIRONMENTS = ['staging', 'production', 'preview', 'local', 'test', 'development', 'dev', 'prod'];

    public const DEFAULTS = [
        'logging' => ['enabled' => true, 'redact' => true, 'phpErrors' => true],
        'capture' => ['body' => true, 'multipart' => true, 'maxBodySize' => 10240, 'sensitiveFields' => []],
        'otel' => [
            'endpoint' => null,
            'tracesEndpoint' => null,
            'logsEndpoint' => null,
            'headers' => [],
            'logLevel' => 'error',
            'bridge' => true,
        ],
        'runtime' => [
            'deploymentEnvironment' => 'production',
            'cacheDir' => null,
            'cli' => false,
        ],
        'export' => ['mode' => 'auto', 'timeoutMs' => 3000, 'flushIntervalMs' => 1000],
        'firewall' => [
            'enabled' => true,
            'apiUrl' => self::DEFAULT_API_URL,
            'versionCheckInterval' => 10,
            'syncInterval' => 3600,
            'failMode' => 'open',
            'statusCode' => 403,
            'log' => false,
            'iptables' => false,
            'cloud' => null,
            'cloudDryRun' => false,
            'rateLimitStore' => null,
            'cloudflare' => ['apiToken' => null, 'accountId' => null],
            'aws' => [
                'wafIpSetId' => null,
                'wafIpSetName' => 'securenow-blocklist',
                'wafScope' => 'REGIONAL',
                'region' => null,
                'accessKeyId' => null,
                'secretAccessKey' => null,
                'sessionToken' => null,
            ],
            'gcp' => ['projectId' => null, 'securityPolicy' => null, 'accessToken' => null],
        ],
        'networking' => ['trustedProxies' => []],
        'sessions' => ['guard' => false, 'capture' => false, 'cookieNames' => []],
        'events' => ['auth' => true],
    ];

    /** @var array<string,mixed>|null */
    private static ?array $credentials = null;
    private static bool $loaded = false;
    private static string $source = 'none';
    /** @var array<string,mixed>|null */
    private static ?array $override = null;

    /** Test hook and programmatic configuration: SecureNow::start(['credentials' => [...]]). */
    public static function setCredentials(?array $credentials, string $source = 'code'): void
    {
        self::$override = $credentials;
        self::$loaded = false;
        self::$credentials = null;
        self::$source = $credentials === null ? 'none' : $source;
    }

    public static function reset(): void
    {
        self::$loaded = false;
        self::$credentials = null;
        self::$override = null;
        self::$source = 'none';
    }

    public static function env(string $name): ?string
    {
        $value = getenv($name);
        if ($value === false || $value === '') {
            $value = $_SERVER[$name] ?? $_ENV[$name] ?? null;
        }
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);
        return $value === '' ? null : $value;
    }

    public static function disabled(): bool
    {
        $value = self::env('SECURENOW_DISABLED');
        return $value !== null && in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
    }

    /** @return array<string,mixed>|null */
    public static function credentials(): ?array
    {
        if (self::$loaded) {
            return self::$credentials;
        }
        self::$loaded = true;
        self::$credentials = null;

        if (self::$override !== null) {
            self::$credentials = self::normalizeDocument(self::$override);
            return self::$credentials;
        }

        $fromEnv = self::loadEnvCredentials();
        if ($fromEnv !== null) {
            self::$credentials = $fromEnv;
            self::$source = 'env:' . self::ENV_CREDENTIALS;
            return self::$credentials;
        }

        $file = self::resolveCredentialsFile();
        if ($file !== null) {
            $doc = self::readCredentialFile($file);
            if ($doc !== null) {
                self::$credentials = self::normalizeDocument($doc);
                self::$source = realpath($file) ?: $file;
            }
        }
        return self::$credentials;
    }

    /** Where the runtime credentials came from, for diagnostics: never their content. */
    public static function source(): string
    {
        self::credentials();
        return self::$source;
    }

    /** @return array<string,mixed>|null */
    private static function loadEnvCredentials(): ?array
    {
        $raw = self::env(self::ENV_CREDENTIALS);
        if ($raw === null) {
            return null;
        }
        $json = $raw[0] === '{' ? $raw : (string) base64_decode($raw, true);
        $json = preg_replace('/^\xEF\xBB\xBF/', '', $json) ?? $json;
        $doc = json_decode($json, true);
        if (!is_array($doc)) {
            Diag::warn(self::ENV_CREDENTIALS . ' is set but is not runtime credentials JSON (raw or base64); ignoring it.');
            return null;
        }
        return self::normalizeDocument($doc);
    }

    /** @return array<string,mixed>|null */
    public static function readCredentialFile(string $file): ?array
    {
        if (!@is_file($file)) {
            return null;
        }
        if (substr($file, -4) === '.php') {
            try {
                $doc = (static function (string $__file) {
                    return include $__file;
                })($file);
            } catch (\Throwable $e) {
                return null;
            }
            return is_array($doc) ? $doc : null;
        }
        $content = @file_get_contents($file);
        if ($content === false) {
            return null;
        }
        if (strncmp($content, "\xEF\xBB\xBF", 3) === 0) {
            $content = substr($content, 3);
        }
        $doc = json_decode($content, true);
        return is_array($doc) ? $doc : null;
    }

    /** @return string[] */
    public static function credentialRelativePaths(): array
    {
        $paths = ['.securenow/runtime.php', '.securenow/runtime.json', '.securenow/credentials.json'];
        foreach (self::FILE_ENVIRONMENTS as $env) {
            $paths[] = ".securenow/credentials.$env.json";
        }
        return $paths;
    }

    /** The project folder: where composer.json and vendor/ live. */
    public static function projectRoot(): ?string
    {
        // Installed as vendor/securenow/securenow/src/Config.php.
        $candidate = dirname(__DIR__, 4);
        if (basename(dirname(__DIR__, 3)) === 'vendor' && @is_dir($candidate)) {
            return $candidate;
        }
        // A symlinked install (Composer path repository) resolves outside vendor/: ask Composer.
        if (class_exists(\Composer\InstalledVersions::class)) {
            try {
                $root = \Composer\InstalledVersions::getRootPackage();
                if (!empty($root['install_path'])) {
                    $path = realpath($root['install_path']);
                    if ($path !== false) {
                        return $path;
                    }
                }
            } catch (\Throwable $e) {
            }
        }
        return null;
    }

    /** @return string[] */
    public static function searchStartDirs(): array
    {
        $starts = [];
        $root = self::projectRoot();
        if ($root !== null) {
            $starts[] = $root;
        }
        $cwd = @getcwd();
        if (is_string($cwd) && $cwd !== '') {
            $starts[] = $cwd;
        }
        if (!empty($_SERVER['SCRIPT_FILENAME']) && is_string($_SERVER['SCRIPT_FILENAME'])) {
            $starts[] = dirname($_SERVER['SCRIPT_FILENAME']);
        }
        if (!empty($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT'])) {
            $starts[] = $_SERVER['DOCUMENT_ROOT'];
        }
        return array_values(array_unique($starts));
    }

    public static function resolveCredentialsFile(): ?string
    {
        $explicit = self::env(self::ENV_CREDENTIALS_FILE);
        if ($explicit !== null) {
            return @is_file($explicit) ? $explicit : null;
        }
        $relative = self::credentialRelativePaths();
        foreach (self::searchStartDirs() as $start) {
            $dir = $start;
            for ($depth = 0; $depth < 8; $depth++) {
                foreach ($relative as $path) {
                    $candidate = $dir . DIRECTORY_SEPARATOR . $path;
                    if (@is_file($candidate)) {
                        return $candidate;
                    }
                }
                $parent = dirname($dir);
                if ($parent === $dir || $parent === '' || $parent === '.') {
                    break;
                }
                $dir = $parent;
            }
        }
        $home = self::env('HOME') ?? self::env('USERPROFILE');
        if ($home !== null) {
            foreach ($relative as $path) {
                $candidate = $home . DIRECTORY_SEPARATOR . $path;
                if (@is_file($candidate)) {
                    return $candidate;
                }
            }
        }
        return null;
    }

    /**
     * A combined credentials document keeps runtime settings under "runtime"; a runtime file is the
     * runtime document itself.
     *
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    private static function normalizeDocument(array $doc): array
    {
        if (isset($doc['runtime']) && is_array($doc['runtime']) && !Util::isList($doc['runtime'])) {
            $runtime = $doc['runtime'];
            if (!empty($runtime['environment'])) {
                $runtime['config']['runtime']['deploymentEnvironment'] = $runtime['environment'];
                unset($runtime['environment']);
            }
            if (!empty($runtime['instanceUrl'])) {
                if (empty($runtime['config']['otel']['endpoint'])) {
                    $runtime['config']['otel']['endpoint'] = $runtime['instanceUrl'];
                }
                unset($runtime['instanceUrl']);
            }
            $doc = $runtime;
        }
        if (!isset($doc['config']) || !is_array($doc['config'])) {
            $doc['config'] = [];
        }
        return $doc;
    }

    /** @return mixed */
    private static function getPath(?array $tree, string $dotted)
    {
        $cur = $tree;
        foreach (explode('.', $dotted) as $part) {
            if (!is_array($cur) || !array_key_exists($part, $cur)) {
                return null;
            }
            $cur = $cur[$part];
        }
        return $cur;
    }

    /** @return mixed */
    private static function pick($value)
    {
        if ($value === null) {
            return null;
        }
        if (is_string($value)) {
            $value = trim($value);
            return $value === '' ? null : $value;
        }
        return $value;
    }

    /**
     * @param mixed $fallback
     * @return mixed
     */
    public static function get(string $path, $fallback = null)
    {
        $creds = self::credentials();
        $value = self::pick(self::getPath($creds['config'] ?? null, $path));
        if ($value !== null) {
            return $value;
        }
        $value = self::pick(self::getPath(self::DEFAULTS, $path));
        return $value !== null ? $value : $fallback;
    }

    public static function bool(string $path, bool $fallback = false): bool
    {
        return self::parseBool(self::get($path), $fallback);
    }

    /** @param mixed $value */
    public static function parseBool($value, bool $fallback = false): bool
    {
        if ($value === null || $value === '') {
            return $fallback;
        }
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return $value != 0;
        }
        $text = strtolower(trim((string) $value));
        if (in_array($text, ['0', 'false', 'no', 'off', 'disabled'], true)) {
            return false;
        }
        if (in_array($text, ['1', 'true', 'yes', 'on', 'enabled'], true)) {
            return true;
        }
        return $fallback;
    }

    public static function int(string $path, int $fallback, ?int $min = null): int
    {
        $value = self::get($path);
        $n = is_numeric($value) ? (int) $value : $fallback;
        return $min !== null ? max($min, $n) : $n;
    }

    /** @return string[] */
    public static function list(string $path): array
    {
        $value = self::get($path);
        if (is_array($value)) {
            $items = $value;
        } elseif ($value === null || $value === '') {
            return [];
        } else {
            $items = explode(',', (string) $value);
        }
        $out = [];
        foreach ($items as $item) {
            if (is_scalar($item)) {
                $item = trim((string) $item);
                if ($item !== '') {
                    $out[] = $item;
                }
            }
        }
        return $out;
    }

    public static function appKey(): ?string
    {
        $key = self::pick(self::getPath(self::credentials(), 'app.key'));
        return $key === null ? null : (string) $key;
    }

    public static function appName(): ?string
    {
        $name = self::pick(self::getPath(self::credentials(), 'app.name'));
        return $name === null ? null : (string) $name;
    }

    /** The runtime key (snk_live_...): authenticates telemetry and firewall sync. */
    public static function apiKey(): ?string
    {
        $key = self::pick(self::getPath(self::credentials(), 'apiKey'));
        return is_string($key) && strncmp($key, 'snk_live_', 9) === 0 ? $key : null;
    }

    public static function environment(): string
    {
        $raw = self::pick(self::get('runtime.deploymentEnvironment'));
        if ($raw === null) {
            return 'production';
        }
        $text = strtolower(trim((string) $raw));
        if ($text === 'dev' || $text === 'development') {
            return 'local';
        }
        if ($text === 'prod') {
            return 'production';
        }
        return preg_match('/^[a-z0-9_.-]{1,64}$/', $text) ? $text : 'production';
    }

    public static function normalizeInstanceEndpoint(string $value): string
    {
        $endpoint = rtrim(trim($value), '/');
        if ($endpoint === '') {
            return $endpoint;
        }
        if ($endpoint === self::LEGACY_GATEWAY) {
            return self::CLOUD_INGEST;
        }
        $parseable = preg_match('~^[a-z][a-z0-9+.-]*://~i', $endpoint) ? $endpoint : 'https://' . $endpoint;
        $parts = @parse_url($parseable);
        if (is_array($parts) && ($parts['port'] ?? null) === 4318) {
            $host = strtolower((string) ($parts['host'] ?? ''));
            if (substr($host, -13) === '.securenow.ai') {
                return self::CLOUD_INGEST;
            }
        }
        return $endpoint;
    }

    public static function ingestBase(): string
    {
        $endpoint = self::pick(self::get('otel.endpoint'));
        return $endpoint !== null ? self::normalizeInstanceEndpoint((string) $endpoint) : self::CLOUD_INGEST;
    }

    private static function signalEndpoint(string $path, string $signal): ?string
    {
        $value = self::pick(self::get($path));
        if ($value === null) {
            return null;
        }
        $endpoint = rtrim(trim((string) $value), '/');
        $suffix = '/v1/' . $signal;
        if (substr($endpoint, -strlen($suffix)) === $suffix) {
            return self::normalizeInstanceEndpoint(substr($endpoint, 0, -strlen($suffix))) . $suffix;
        }
        return $endpoint;
    }

    public static function tracesUrl(): string
    {
        return self::signalEndpoint('otel.tracesEndpoint', 'traces') ?? self::ingestBase() . '/v1/traces';
    }

    public static function logsUrl(): string
    {
        return self::signalEndpoint('otel.logsEndpoint', 'logs') ?? self::ingestBase() . '/v1/logs';
    }

    public static function eventsUrl(): string
    {
        return self::ingestBase() . '/v1/events';
    }

    /**
     * Headers for telemetry: app routing, runtime auth and environment, unless set explicitly.
     *
     * @return array<string,string>
     */
    public static function otlpHeaders(): array
    {
        $headers = [];
        $configured = self::get('otel.headers', []);
        if (is_array($configured)) {
            foreach ($configured as $key => $value) {
                $key = strtolower(trim((string) $key));
                if ($key !== '' && is_scalar($value) && trim((string) $value) !== '') {
                    $headers[$key] = (string) $value;
                }
            }
        } elseif (is_string($configured)) {
            foreach (explode(',', $configured) as $pair) {
                $i = strpos($pair, '=');
                if ($i === false) {
                    continue;
                }
                $key = strtolower(trim(substr($pair, 0, $i)));
                $value = trim(substr($pair, $i + 1));
                if ($key !== '' && $value !== '') {
                    $headers[$key] = $value;
                }
            }
        }
        $appKey = self::appKey();
        $apiKey = self::apiKey();
        if ($appKey !== null && !isset($headers['x-securenow-app-key'])) {
            $headers['x-securenow-app-key'] = $appKey;
        }
        if ($apiKey !== null && !isset($headers['authorization'])) {
            $headers['authorization'] = 'Bearer ' . $apiKey;
        }
        if (!isset($headers['x-securenow-environment'])) {
            $headers['x-securenow-environment'] = self::environment();
        }
        return $headers;
    }

    public static function normalizeFirewallApiUrl(?string $value): string
    {
        $raw = self::pick($value);
        if ($raw === null) {
            return self::CLOUD_INGEST;
        }
        $endpoint = self::normalizeInstanceEndpoint((string) $raw);
        if ($endpoint === '') {
            return self::CLOUD_INGEST;
        }
        $trimmed = preg_replace('~/api(?:/v1)?$~i', '', rtrim($endpoint, '/')) ?? $endpoint;
        // api.securenow.ai was the historical default. Hosted runtime sync shares the ingest gateway,
        // so an app needs one public SecureNow egress host.
        if ($trimmed === self::DEFAULT_API_URL || $trimmed === self::LEGACY_GATEWAY) {
            return self::CLOUD_INGEST;
        }
        return $trimmed;
    }

    public static function firewallApiUrl(): string
    {
        $value = self::get('firewall.apiUrl', self::DEFAULT_API_URL);
        return self::normalizeFirewallApiUrl(is_string($value) ? $value : null);
    }

    /** @return string[] */
    public static function firewallApiFallbacks(): array
    {
        $primary = self::firewallApiUrl();
        if ($primary === self::CLOUD_INGEST) {
            return [self::DEFAULT_API_URL];
        }
        if ($primary === self::DEFAULT_API_URL) {
            return [self::CLOUD_INGEST];
        }
        return [];
    }

    /** One stable id per host and app: PHP-FPM workers come and go, so a per-process id would never settle. */
    public static function instanceId(): string
    {
        $prefix = self::appKey() ?? 'securenow';
        $host = function_exists('gethostname') ? (string) gethostname() : 'host';
        return $prefix . '-' . substr(sha1($host . '|' . (self::projectRoot() ?? __DIR__)), 0, 16);
    }
}
