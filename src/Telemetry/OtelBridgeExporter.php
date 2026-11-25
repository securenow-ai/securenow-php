<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use OpenTelemetry\SDK\Common\Future\CancellationInterface;
use OpenTelemetry\SDK\Common\Future\CompletedFuture;
use OpenTelemetry\SDK\Common\Future\FutureInterface;
use OpenTelemetry\SDK\Trace\SpanExporterInterface;
use SecureNow\Redaction\Redactor;

/**
 * Receives finished OpenTelemetry spans and queues them on SecureNow's exporter. Loaded only
 * when open-telemetry/sdk is installed (see OtelBridge).
 *
 * - A framework's own SERVER span sits under SecureNow's request span, so it is exported as
 *   INTERNAL: one request stays one server span, the one that carries the client address and the
 *   captured request. Its http.route moves up to the request span.
 * - Stable database and HTTP-client names get the legacy aliases SecureNow's queries read
 *   (db.statement, http.url, ...), as the Node SDK does.
 */
final class OtelBridgeExporter implements SpanExporterInterface
{
    private const KINDS = [
        0 => Span::KIND_INTERNAL,
        1 => Span::KIND_CLIENT,
        2 => Span::KIND_SERVER,
        3 => Span::KIND_PRODUCER,
        4 => Span::KIND_CONSUMER,
    ];

    private const ALIASES = [
        'db.query.text' => 'db.statement',
        'db.system.name' => 'db.system',
        'db.namespace' => 'db.name',
        'db.operation.name' => 'db.operation',
        'db.collection.name' => 'db.sql.table',
        'server.address' => 'net.peer.name',
        'server.port' => 'net.peer.port',
        'url.full' => 'http.url',
        'http.request.method' => 'http.method',
        'http.response.status_code' => 'http.status_code',
    ];

    /** @param iterable<\OpenTelemetry\SDK\Trace\SpanDataInterface> $batch */
    public function export(iterable $batch, ?CancellationInterface $cancellation = null): FutureInterface
    {
        foreach ($batch as $span) {
            try {
                $this->queue($span);
            } catch (\Throwable $e) {
                // One odd span must not lose the rest.
            }
        }
        return new CompletedFuture(true);
    }

    public function shutdown(?CancellationInterface $cancellation = null): bool
    {
        return true;
    }

    public function forceFlush(?CancellationInterface $cancellation = null): bool
    {
        return true;
    }

    /** @param \OpenTelemetry\SDK\Trace\SpanDataInterface $data */
    private function queue($data): void
    {
        $context = $data->getContext();
        $root = Tracer::root();
        // OpenTelemetry's API orders kinds internal, client, server, producer, consumer (0..4);
        // OTLP orders them internal, server, client, producer, consumer (1..5).
        $kind = self::KINDS[(int) $data->getKind()] ?? Span::KIND_INTERNAL;
        $attributes = $data->getAttributes()->toArray();
        $underRoot = $root !== null && $context->getTraceId() === $root->traceId;

        if ($kind === Span::KIND_SERVER && $underRoot) {
            $kind = Span::KIND_INTERNAL;
            $route = $attributes['http.route'] ?? null;
            if (is_string($route) && $route !== '' && Tracer::route() === null) {
                Tracer::setRoute($route);
            }
        } else {
            foreach (self::ALIASES as $stable => $legacy) {
                if (isset($attributes[$stable]) && !isset($attributes[$legacy])) {
                    $attributes[$legacy] = $attributes[$stable];
                }
            }
        }
        foreach ($attributes as $key => $value) {
            if (is_string($value) && strpos($value, '?') !== false) {
                $attributes[$key] = Redactor::redactOtpQuery($value);
            }
        }

        $status = $data->getStatus();
        $code = Span::STATUS_UNSET;
        $statusCode = strtolower((string) $status->getCode());
        if ($statusCode === 'ok') {
            $code = Span::STATUS_OK;
        } elseif ($statusCode === 'error') {
            $code = Span::STATUS_ERROR;
        }

        $span = [
            'traceId' => $context->getTraceId(),
            'spanId' => $context->getSpanId(),
            'name' => Redactor::redactOtpQuery((string) $data->getName()),
            'kind' => $kind,
            'startTimeUnixNano' => (string) $data->getStartEpochNanos(),
            'endTimeUnixNano' => (string) $data->getEndEpochNanos(),
            'attributes' => Otlp::attributes($attributes),
            'status' => $status->getDescription() !== ''
                ? ['code' => $code, 'message' => (string) $status->getDescription()]
                : ['code' => $code],
        ];
        $parent = (string) $data->getParentSpanId();
        if ($parent !== '' && $parent !== '0000000000000000') {
            $span['parentSpanId'] = $parent;
        }
        $events = [];
        foreach ($data->getEvents() as $event) {
            $eventAttributes = $event->getAttributes()->toArray();
            $events[] = [
                'timeUnixNano' => (string) $event->getEpochNanos(),
                'name' => (string) $event->getName(),
                'attributes' => Otlp::attributes($eventAttributes),
            ];
            // An exception the framework caught still marks the request.
            if ($event->getName() === 'exception' && $underRoot && $root !== null && $code === Span::STATUS_ERROR && count($root->events) < 8) {
                $root->addEvent('exception', $eventAttributes);
            }
        }
        if ($events) {
            $span['events'] = $events;
        }

        $scope = $data->getInstrumentationScope();
        $scopeName = (string) $scope->getName();
        $version = (string) ($scope->getVersion() ?? '');
        Exporter::addSpan($span, $version !== '' ? $scopeName . '@' . $version : $scopeName);
    }
}
