<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Util;

/** One span, in OTLP terms. Times are wall-clock nanoseconds; durations come from the monotonic clock. */
final class Span
{
    public const KIND_INTERNAL = 1;
    public const KIND_SERVER = 2;
    public const KIND_CLIENT = 3;
    public const KIND_PRODUCER = 4;
    public const KIND_CONSUMER = 5;

    public const STATUS_UNSET = 0;
    public const STATUS_OK = 1;
    public const STATUS_ERROR = 2;

    public string $traceId;
    public string $spanId;
    public ?string $parentSpanId;
    public string $name;
    public int $kind;
    public int $startNs;
    public ?int $endNs = null;
    /** @var array<string,mixed> */
    public array $attributes = [];
    /** @var array<int,array{name:string,timeNs:int,attributes:array<string,mixed>}> */
    public array $events = [];
    public int $statusCode = self::STATUS_UNSET;
    public string $statusMessage = '';
    public string $scope = 'securenow@' . \SecureNow\Version::SDK;

    private int $startHr;

    public function __construct(string $name, int $kind, string $traceId, ?string $parentSpanId = null, ?int $startNs = null)
    {
        $this->name = $name;
        $this->kind = $kind;
        $this->traceId = $traceId;
        $this->parentSpanId = $parentSpanId;
        $this->spanId = Util::randomHex(8);
        $now = Util::nowNs();
        $this->startNs = $startNs ?? $now;
        // Anchor the monotonic clock to the wall-clock start, also when the start is in the past.
        $this->startHr = hrtime(true) - ($now - $this->startNs);
    }

    /** @param mixed $value */
    public function setAttribute(string $key, $value): self
    {
        if ($value === null) {
            unset($this->attributes[$key]);
        } elseif (count($this->attributes) < 256 || isset($this->attributes[$key])) {
            $this->attributes[$key] = $value;
        }
        return $this;
    }

    /** @param array<string,mixed> $attributes */
    public function setAttributes(array $attributes): self
    {
        foreach ($attributes as $key => $value) {
            $this->setAttribute((string) $key, $value);
        }
        return $this;
    }

    /** @param array<string,mixed> $attributes */
    public function addEvent(string $name, array $attributes = []): self
    {
        if (count($this->events) < 64) {
            $this->events[] = ['name' => $name, 'timeNs' => $this->nowNs(), 'attributes' => $attributes];
        }
        return $this;
    }

    public function recordException(\Throwable $e, bool $escaped = false): self
    {
        $this->addEvent('exception', [
            'exception.type' => get_class($e),
            'exception.message' => Util::truncate($e->getMessage(), 4000),
            'exception.stacktrace' => Util::truncate(self::formatThrowable($e), 16000),
            'exception.escaped' => $escaped,
        ]);
        return $this;
    }

    public function setStatus(int $code, string $message = ''): self
    {
        $this->statusCode = $code;
        $this->statusMessage = $message;
        return $this;
    }

    public function updateName(string $name): self
    {
        $this->name = $name;
        return $this;
    }

    private function nowNs(): int
    {
        return $this->startNs + (hrtime(true) - $this->startHr);
    }

    public function end(): self
    {
        if ($this->endNs === null) {
            $this->endNs = max($this->startNs, $this->nowNs());
        }
        return $this;
    }

    public function isEnded(): bool
    {
        return $this->endNs !== null;
    }

    public function traceparent(): string
    {
        return '00-' . $this->traceId . '-' . $this->spanId . '-01';
    }

    /** @return array<string,mixed> */
    public function toOtlp(): array
    {
        $span = [
            'traceId' => $this->traceId,
            'spanId' => $this->spanId,
            'name' => Util::truncate($this->name, 512),
            'kind' => $this->kind,
            'startTimeUnixNano' => (string) $this->startNs,
            'endTimeUnixNano' => (string) ($this->endNs ?? $this->nowNs()),
            'attributes' => Otlp::attributes($this->attributes),
            'status' => $this->statusMessage !== ''
                ? ['code' => $this->statusCode, 'message' => Util::truncate($this->statusMessage, 1024)]
                : ['code' => $this->statusCode],
        ];
        if ($this->parentSpanId !== null && $this->parentSpanId !== '') {
            $span['parentSpanId'] = $this->parentSpanId;
        }
        if ($this->events) {
            $events = [];
            foreach ($this->events as $event) {
                $events[] = [
                    'timeUnixNano' => (string) $event['timeNs'],
                    'name' => $event['name'],
                    'attributes' => Otlp::attributes($event['attributes']),
                ];
            }
            $span['events'] = $events;
        }
        return $span;
    }

    public static function formatThrowable(\Throwable $e): string
    {
        $out = '';
        $depth = 0;
        for ($current = $e; $current !== null && $depth < 5; $current = $current->getPrevious(), $depth++) {
            if ($depth > 0) {
                $out .= "\nCaused by: ";
            }
            $out .= get_class($current) . ': ' . $current->getMessage()
                . ' in ' . $current->getFile() . ':' . $current->getLine()
                . "\n" . $current->getTraceAsString();
        }
        return $out;
    }
}
