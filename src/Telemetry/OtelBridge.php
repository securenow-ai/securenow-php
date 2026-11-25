<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Config;
use SecureNow\Diag;

/**
 * Optional OpenTelemetry bridge. When open-telemetry/sdk is installed (and, for zero-code
 * instrumentation, the `opentelemetry` extension plus the open-telemetry/opentelemetry-auto-*
 * packages), SecureNow registers a tracer provider whose spans are exported through SecureNow:
 * framework, database and HTTP-client spans nest under SecureNow's request span.
 *
 * Nothing here loads unless the OpenTelemetry classes exist. config.otel.bridge=false turns it off.
 */
final class OtelBridge
{
    private static bool $installed = false;
    /** @var object|null OpenTelemetry\Context\ScopeInterface */
    private static $scope = null;
    /** @var object|null OpenTelemetry\SDK\Trace\TracerProviderInterface */
    private static $provider = null;

    public static function available(): bool
    {
        return interface_exists(\OpenTelemetry\SDK\Trace\SpanExporterInterface::class)
            && class_exists(\OpenTelemetry\SDK\Trace\TracerProvider::class)
            && class_exists(\OpenTelemetry\API\Globals::class);
    }

    public static function installed(): bool
    {
        return self::$installed;
    }

    public static function install(): void
    {
        if (self::$installed || !Config::bool('otel.bridge', true)) {
            return;
        }
        try {
            if (!self::available()) {
                return;
            }
            $autoload = Config::env('OTEL_PHP_AUTOLOAD_ENABLED');
            if ($autoload !== null && in_array(strtolower($autoload), ['1', 'true', 'on'], true)) {
                Diag::warn('OTEL_PHP_AUTOLOAD_ENABLED is set: OpenTelemetry exports on its own and its spans do not reach SecureNow. Unset it to let SecureNow configure OpenTelemetry.');
                return;
            }
            self::$installed = true;
            self::registerSdkInstrumentations();

            $provider = new \OpenTelemetry\SDK\Trace\TracerProvider(
                new \OpenTelemetry\SDK\Trace\SpanProcessor\SimpleSpanProcessor(new OtelBridgeExporter())
            );
            self::$provider = $provider;
            \OpenTelemetry\API\Globals::registerInitializer(
                static function (\OpenTelemetry\API\Instrumentation\Configurator $configurator) use ($provider) {
                    return $configurator
                        ->withTracerProvider($provider)
                        ->withPropagator(\OpenTelemetry\API\Trace\Propagation\TraceContextPropagator::getInstance());
                }
            );
            self::activateRoot();
        } catch (\Throwable $e) {
            Diag::warn('OpenTelemetry bridge not started: ' . $e->getMessage());
        }
    }

    /**
     * Newer instrumentation packages (Laravel 1.10+, ...) do not hook anything on their own: the
     * SDK's autoloader registers them, and only when OTEL_PHP_AUTOLOAD_ENABLED is on. SecureNow
     * runs that registration here, with every OpenTelemetry exporter switched off: the spans go
     * through the tracer provider registered right after, so no OTEL_* variable is needed in the
     * web server's configuration (where PHP-FPM would not pass them anyway).
     */
    private static function registerSdkInstrumentations(): void
    {
        if (!class_exists(\OpenTelemetry\SDK\SdkAutoloader::class) || !method_exists(\OpenTelemetry\SDK\SdkAutoloader::class, 'autoload')) {
            return;
        }
        $set = static function (string $name, string $value): void {
            putenv($name . '=' . $value);
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        };
        $set('OTEL_TRACES_EXPORTER', 'none');
        $set('OTEL_METRICS_EXPORTER', 'none');
        $set('OTEL_LOGS_EXPORTER', 'none');
        $set('OTEL_PHP_AUTOLOAD_ENABLED', 'true');
        try {
            \OpenTelemetry\SDK\SdkAutoloader::autoload();
        } catch (\Throwable $e) {
            Diag::debug('OpenTelemetry instrumentations not registered: ' . $e->getMessage());
        } finally {
            // The SDK's own autoload file may still be ahead in Composer's list: it must not
            // register everything a second time.
            $set('OTEL_PHP_AUTOLOAD_ENABLED', 'false');
        }
    }

    /** Make SecureNow's request span the parent of every OpenTelemetry span of this request. */
    public static function activateRoot(): void
    {
        $root = Tracer::root();
        if (!self::$installed || $root === null) {
            return;
        }
        try {
            self::detach();
            $context = \OpenTelemetry\API\Trace\SpanContext::create(
                $root->traceId,
                $root->spanId,
                \OpenTelemetry\API\Trace\TraceFlags::SAMPLED
            );
            self::$scope = \OpenTelemetry\API\Trace\Span::wrap($context)->activate();
            // Framework instrumentations read the parent from the request headers.
            $_SERVER['HTTP_TRACEPARENT'] = $root->traceparent();
        } catch (\Throwable $e) {
            Diag::debug('OpenTelemetry context not activated: ' . $e->getMessage());
        }
    }

    public static function detach(): void
    {
        if (self::$scope !== null) {
            try {
                self::$scope->detach();
            } catch (\Throwable $e) {
            }
            self::$scope = null;
        }
    }

    public static function shutdown(): void
    {
        self::detach();
        if (self::$provider !== null) {
            try {
                self::$provider->forceFlush();
            } catch (\Throwable $e) {
            }
        }
    }
}
