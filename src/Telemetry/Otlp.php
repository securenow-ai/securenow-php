<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Config;
use SecureNow\Util;
use SecureNow\Version;

/**
 * OTLP/JSON encoding. The SecureNow ingest gateway reads JSON (it checks the app's capture
 * controls and forces service.name to the app key), so the SDK sends JSON, like the Node SDK.
 */
final class Otlp
{
    /** @var array<string,mixed>|null */
    private static ?array $resource = null;
    /** @var array<string,mixed> */
    private static array $extraResource = [];

    public static function reset(): void
    {
        self::$resource = null;
        self::$extraResource = [];
    }

    private const RESOURCE_FILE = 'resource.extra';

    /** @param mixed $value */
    public static function setResourceAttribute(string $key, $value): void
    {
        self::$extraResource[$key] = $value;
        self::$resource = null;
    }

    /** Remember the app's own resource attributes (framework, version) for whoever sends the spool. */
    public static function persistResource(): void
    {
        if (!self::$extraResource) {
            return;
        }
        $stored = \SecureNow\Store\Store::readArray(self::RESOURCE_FILE);
        if ($stored !== self::$extraResource) {
            \SecureNow\Store\Store::writeArray(self::RESOURCE_FILE, self::$extraResource);
        }
    }

    /**
     * @param mixed $value
     * @return array<string,mixed>
     */
    public static function anyValue($value): array
    {
        if (is_bool($value)) {
            return ['boolValue' => $value];
        }
        if (is_int($value)) {
            return ['intValue' => (string) $value];
        }
        if (is_float($value)) {
            return is_finite($value) ? ['doubleValue' => $value] : ['stringValue' => (string) $value];
        }
        if (is_string($value)) {
            return ['stringValue' => $value];
        }
        if (is_array($value) && Util::isList($value)) {
            $values = [];
            foreach ($value as $item) {
                if (is_scalar($item)) {
                    $values[] = self::anyValue($item);
                }
            }
            return ['arrayValue' => ['values' => $values]];
        }
        if ($value instanceof \Stringable) {
            return ['stringValue' => (string) $value];
        }
        return ['stringValue' => Util::json($value)];
    }

    /**
     * @param array<string,mixed> $attributes
     * @return array<int,array<string,mixed>>
     */
    public static function attributes(array $attributes): array
    {
        $out = [];
        foreach ($attributes as $key => $value) {
            if ($value === null) {
                continue;
            }
            $out[] = ['key' => (string) $key, 'value' => self::anyValue($value)];
        }
        return $out;
    }

    /** @return array<string,mixed> */
    public static function resourceAttributes(): array
    {
        $attrs = [
            // The dashboard matches service.name exactly against the app key: never suffix it.
            'service.name' => Config::appKey() ?? Config::appName() ?? 'securenow-php',
            'service.instance.id' => Config::instanceId(),
            'deployment.environment' => Config::environment(),
            'telemetry.sdk.name' => 'securenow',
            'telemetry.sdk.language' => 'php',
            'telemetry.sdk.version' => Version::SDK,
            'process.runtime.name' => 'php',
            'process.runtime.version' => PHP_VERSION,
            'process.runtime.description' => PHP_SAPI,
        ];
        $version = self::serviceVersion();
        if ($version !== null) {
            $attrs['service.version'] = $version;
        }
        // Telemetry is often sent by another process than the one that produced it (a request
        // answered before the framework booted, the background worker, the agent): what the app
        // said about itself is kept next to the spool.
        $extra = self::$extraResource;
        if (!$extra) {
            $stored = \SecureNow\Store\Store::readArray(self::RESOURCE_FILE);
            if (is_array($stored)) {
                $extra = $stored;
            }
        }
        return $extra + $attrs;
    }

    private static function serviceVersion(): ?string
    {
        if (class_exists(\Composer\InstalledVersions::class, false)) {
            try {
                $root = \Composer\InstalledVersions::getRootPackage();
                $version = (string) ($root['pretty_version'] ?? '');
                if ($version !== '' && strncmp($version, 'dev-', 4) !== 0 && $version !== '1.0.0+no-version-set') {
                    return $version;
                }
            } catch (\Throwable $e) {
            }
        }
        return null;
    }

    /** The resource as a JSON fragment, encoded once per request. */
    public static function resourceJson(): string
    {
        if (self::$resource === null) {
            self::$resource = ['json' => Util::json(['attributes' => self::attributes(self::resourceAttributes())])];
        }
        return self::$resource['json'];
    }

    /**
     * {"resourceSpans":[{"resource":...,"scopeSpans":[{"scope":...,"spans":[...]}]}]} built from
     * already-encoded span objects grouped by scope.
     *
     * @param array<string,string[]> $byScope scope name => encoded items
     */
    public static function envelope(string $signal, array $byScope): string
    {
        $resourceKey = $signal === 'traces' ? 'resourceSpans' : 'resourceLogs';
        $scopeKey = $signal === 'traces' ? 'scopeSpans' : 'scopeLogs';
        $itemKey = $signal === 'traces' ? 'spans' : 'logRecords';
        $scopes = [];
        foreach ($byScope as $scope => $items) {
            if (!$items) {
                continue;
            }
            $at = strrpos((string) $scope, '@');
            $name = $at === false ? (string) $scope : substr((string) $scope, 0, $at);
            $version = $at === false ? '' : substr((string) $scope, $at + 1);
            $scopes[] = '{"scope":' . Util::json($version === '' ? ['name' => $name] : ['name' => $name, 'version' => $version])
                . ',"' . $itemKey . '":[' . implode(',', $items) . ']}';
        }
        return '{"' . $resourceKey . '":[{"resource":' . self::resourceJson() . ',"' . $scopeKey . '":[' . implode(',', $scopes) . ']}]}';
    }
}
