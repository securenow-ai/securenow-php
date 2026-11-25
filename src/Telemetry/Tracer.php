<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Http\RequestInfo;
use SecureNow\Util;

/**
 * SecureNow's own request span and manual child spans. It needs no extension: the request span
 * exists on shared hosting too. With OpenTelemetry installed, its spans nest under this one
 * (OtelBridge).
 */
final class Tracer
{
    private static ?Span $root = null;
    /** @var Span[] */
    private static array $stack = [];
    private static ?string $route = null;
    private static bool $rootExported = false;

    public static function reset(): void
    {
        self::$root = null;
        self::$stack = [];
        self::$route = null;
        self::$rootExported = false;
    }

    /** @param array<string,mixed> $attributes */
    public static function startRoot(RequestInfo $request, array $attributes): Span
    {
        $traceId = null;
        $parent = null;
        // W3C trace context from an upstream service.
        if (preg_match('/^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/', strtolower(trim($request->header('traceparent'))), $m)
            && $m[1] !== str_repeat('0', 32) && $m[2] !== str_repeat('0', 16)) {
            $traceId = $m[1];
            $parent = $m[2];
        }
        $span = new Span($request->method, Span::KIND_SERVER, $traceId ?? Util::randomHex(16), $parent, Util::floatSecondsToNs($request->startTime));
        $span->setAttributes($attributes);
        self::$root = $span;
        self::$stack = [$span];
        self::$route = null;
        self::$rootExported = false;
        return $span;
    }

    public static function root(): ?Span
    {
        return self::$root;
    }

    public static function current(): ?Span
    {
        $n = count(self::$stack);
        return $n ? self::$stack[$n - 1] : null;
    }

    /** @param array<string,mixed> $attributes */
    public static function start(string $name, int $kind = Span::KIND_INTERNAL, array $attributes = []): Span
    {
        $parent = self::current();
        $span = new Span($name, $kind, $parent ? $parent->traceId : Util::randomHex(16), $parent ? $parent->spanId : null);
        $span->setAttributes($attributes);
        self::$stack[] = $span;
        return $span;
    }

    public static function end(Span $span): void
    {
        if ($span === self::$root) {
            return;
        }
        $span->end();
        $index = array_search($span, self::$stack, true);
        if ($index !== false) {
            array_splice(self::$stack, (int) $index);
        }
        Exporter::addSpan($span->toOtlp(), $span->scope);
    }

    /**
     * No span for this request: the firewall answered it. Like the Node SDK, a blocked,
     * rate-limited or challenged request is reported as a firewall hit (with a count), not as
     * a trace, so a flood of refused requests costs no telemetry.
     */
    public static function discardRoot(): void
    {
        self::$rootExported = true;
        self::$stack = self::$root !== null ? [self::$root] : [];
    }

    public static function setRoute(?string $route): void
    {
        $route = $route === null ? null : trim($route);
        if ($route === null || $route === '') {
            return;
        }
        if ($route[0] !== '/') {
            $route = '/' . $route;
        }
        self::$route = $route;
    }

    public static function route(): ?string
    {
        return self::$route;
    }

    /** Ends the request span with the response status and queues it (and any span left open). */
    public static function finishRoot(int $status): void
    {
        $root = self::$root;
        if ($root === null || self::$rootExported) {
            return;
        }
        self::$rootExported = true;
        for ($i = count(self::$stack) - 1; $i > 0; $i--) {
            $open = self::$stack[$i];
            $open->end();
            Exporter::addSpan($open->toOtlp(), $open->scope);
        }
        self::$stack = [$root];

        if (self::$route !== null) {
            $root->setAttribute('http.route', self::$route);
            $root->updateName(($root->attributes['http.method'] ?? $root->name) . ' ' . self::$route);
        }
        if ($status > 0) {
            $root->setAttribute('http.status_code', $status);
            $root->setAttribute('http.response.status_code', $status);
            if ($status >= 500 && $root->statusCode !== Span::STATUS_ERROR) {
                $root->setStatus(Span::STATUS_ERROR);
            }
        }
        $root->end();
        Exporter::addSpan($root->toOtlp(), $root->scope);
    }
}
