<?php

declare(strict_types=1);

/*
 * Dependency-free test runner:  php tests/run.php [filter]
 * Each file in tests/cases returns [name => closure]. A closure fails by throwing.
 */

putenv('SECURENOW_AUTOSTART=0');
require dirname(__DIR__) . '/prepend.php';

final class T
{
    public static int $assertions = 0;

    /** @param mixed $expected @param mixed $actual */
    public static function eq($expected, $actual, string $label = ''): void
    {
        self::$assertions++;
        if ($expected !== $actual) {
            throw new RuntimeException(($label !== '' ? $label . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
        }
    }

    /** @param mixed $value */
    public static function ok($value, string $label = ''): void
    {
        self::$assertions++;
        if (!$value) {
            throw new RuntimeException($label !== '' ? $label : 'expected a truthy value');
        }
    }

    public static function contains(string $needle, string $haystack, string $label = ''): void
    {
        self::$assertions++;
        if (strpos($haystack, $needle) === false) {
            throw new RuntimeException(($label !== '' ? $label . ': ' : '') . var_export($needle, true) . ' not found in ' . var_export(substr($haystack, 0, 400), true));
        }
    }

    public static function notContains(string $needle, string $haystack, string $label = ''): void
    {
        self::$assertions++;
        if (strpos($haystack, $needle) !== false) {
            throw new RuntimeException(($label !== '' ? $label . ': ' : '') . var_export($needle, true) . ' found in ' . var_export(substr($haystack, 0, 400), true));
        }
    }

    /** @return array<string,mixed> */
    public static function fixtures(): array
    {
        static $data = null;
        if ($data === null) {
            $data = json_decode((string) file_get_contents(__DIR__ . '/fixtures/node-parity.json'), true);
        }
        return $data;
    }

    /** A fresh SDK with test credentials and its own cache folder. @param array<string,mixed> $config */
    public static function boot(array $config = [], bool $withApiKey = true): string
    {
        \SecureNow\SecureNow::resetForTests();
        \SecureNow\Http\Transport::fake(null);
        $dir = sys_get_temp_dir() . '/securenow-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);
        $config['runtime']['cacheDir'] = $dir;
        $credentials = ['app' => ['key' => '11111111-2222-3333-4444-555555555555', 'name' => 'php-test'], 'config' => $config];
        if ($withApiKey) {
            $credentials['apiKey'] = 'snk_live_testkey0123456789';
        }
        \SecureNow\Config::setCredentials($credentials);
        return $dir;
    }

    /** @param array<string,string> $headers */
    public static function request(string $method, string $target, array $headers = [], string $remote = '198.51.100.10', ?string $body = null): \SecureNow\Http\RequestInfo
    {
        $r = new \SecureNow\Http\RequestInfo();
        $r->method = $method;
        $r->setTarget($target);
        foreach ($headers as $name => $value) {
            $r->headers[strtolower($name)] = $value;
        }
        $r->host = $r->headers['host'] ?? 'app.test';
        $r->headers['host'] = $r->host;
        $r->remoteAddr = $remote;
        $r->startTime = microtime(true);
        if ($body !== null) {
            $r->headers['content-length'] = (string) strlen($body);
            $reader = static function (int $max) use ($body): ?string {
                return substr($body, 0, $max);
            };
            $set = \Closure::bind(static function (\SecureNow\Http\RequestInfo $r, callable $reader): void {
                $r->bodyReader = $reader;
            }, null, \SecureNow\Http\RequestInfo::class);
            $set($r, $reader);
        }
        return $r;
    }
}

$filter = $argv[1] ?? '';
$passed = 0;
$failed = [];
foreach (glob(__DIR__ . '/cases/*.php') ?: [] as $file) {
    $cases = require $file;
    foreach ($cases as $name => $case) {
        $full = basename($file, '.php') . ' › ' . $name;
        if ($filter !== '' && stripos($full, $filter) === false) {
            continue;
        }
        try {
            $case();
            $passed++;
        } catch (Throwable $e) {
            $failed[] = $full . "\n    " . get_class($e) . ': ' . $e->getMessage() . "\n    at " . basename($e->getFile()) . ':' . $e->getLine();
        }
    }
}

echo "PHP " . PHP_VERSION . ": $passed passed, " . count($failed) . " failed, " . T::$assertions . " assertions\n";
foreach ($failed as $failure) {
    echo "  FAIL $failure\n";
}
exit($failed ? 1 : 0);
