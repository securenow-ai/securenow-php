<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Config;
use SecureNow\Redaction\Redactor;
use SecureNow\Util;

/**
 * Log records sent to SecureNow (OTLP logs). The PHP counterpart of the Node SDK's console
 * capture: PHP errors, uncaught exceptions and fatal errors are recorded automatically; app
 * logs come through Monolog (Laravel, Symfony), the PSR-3 logger, or SecureNow::log().
 * Lines are redacted before they leave the process unless config.logging.redact is false.
 */
final class Logger
{
    public const TRACE = 1;
    public const DEBUG = 5;
    public const INFO = 9;
    public const WARN = 13;
    public const ERROR = 17;
    public const FATAL = 21;

    private const TEXT = [1 => 'TRACE', 5 => 'DEBUG', 9 => 'INFO', 13 => 'WARN', 17 => 'ERROR', 21 => 'FATAL'];
    private const MAX_PER_REQUEST = 500;
    private const MAX_BODY = 32768;

    private static int $count = 0;
    private static ?bool $enabled = null;
    private static ?bool $redact = null;

    public static function reset(): void
    {
        self::$count = 0;
        self::$enabled = null;
        self::$redact = null;
    }

    public static function enabled(): bool
    {
        if (self::$enabled === null) {
            self::$enabled = Config::appKey() !== null && Config::bool('logging.enabled', true);
        }
        return self::$enabled;
    }

    /** PSR-3 / Monolog level name -> OTLP severity number. */
    public static function severityFor(string $level): int
    {
        switch (strtolower($level)) {
            case 'trace':
                return self::TRACE;
            case 'debug':
                return self::DEBUG;
            case 'info':
            case 'notice':
                return self::INFO;
            case 'warn':
            case 'warning':
                return self::WARN;
            case 'error':
                return self::ERROR;
            case 'critical':
            case 'alert':
            case 'emergency':
            case 'fatal':
                return self::FATAL;
            default:
                return self::INFO;
        }
    }

    /**
     * @param array<string,mixed> $attributes exported as set
     */
    public static function emit(int $severity, string $body, array $attributes = [], string $scope = 'php'): void
    {
        if (!self::enabled() || self::$count >= self::MAX_PER_REQUEST) {
            return;
        }
        self::$count++;
        if (self::$redact === null) {
            self::$redact = Config::bool('logging.redact', true);
        }
        if (self::$redact) {
            $body = Redactor::redactLogText($body);
        }
        $now = (string) Util::nowNs();
        $record = [
            'timeUnixNano' => $now,
            'observedTimeUnixNano' => $now,
            'severityNumber' => $severity,
            'severityText' => self::TEXT[$severity] ?? 'INFO',
            'body' => ['stringValue' => Util::truncate($body, self::MAX_BODY)],
            'attributes' => Otlp::attributes($attributes),
        ];
        $span = Tracer::current();
        if ($span !== null) {
            $record['traceId'] = $span->traceId;
            $record['spanId'] = $span->spanId;
            $record['flags'] = 1;
        }
        Exporter::addLog($record, $scope);
    }

    /**
     * PSR-3 style: {placeholders} filled from the context, the rest of the context as attributes.
     *
     * @param mixed $message
     * @param array<mixed> $context
     */
    public static function log(string $level, $message, array $context = [], string $source = 'app', string $scope = 'php'): void
    {
        if (!self::enabled()) {
            return;
        }
        $text = is_string($message) ? $message : (is_scalar($message) || $message instanceof \Stringable ? (string) $message : Util::json($message));
        $attributes = ['log.source' => $source, 'log.level' => strtolower($level)];
        $exception = $context['exception'] ?? null;
        if ($exception instanceof \Throwable) {
            $attributes['exception.type'] = get_class($exception);
            $attributes['exception.message'] = Util::truncate($exception->getMessage(), 4000);
            $attributes['exception.stacktrace'] = Util::truncate(Span::formatThrowable($exception), 16000);
            unset($context['exception']);
        }
        if ($context) {
            if (self::$redact ?? (self::$redact = Config::bool('logging.redact', true))) {
                $context = Redactor::redactLogContext($context);
            }
            $replacements = [];
            $n = 0;
            foreach ($context as $key => $value) {
                if (!is_string($key) && !is_int($key)) {
                    continue;
                }
                $string = self::stringify($value);
                if (is_string($key) && strpos($text, '{' . $key . '}') !== false) {
                    $replacements['{' . $key . '}'] = $string;
                }
                if ($n++ < 32) {
                    $attributes['context.' . $key] = Util::truncate($string, 2048);
                }
            }
            if ($replacements) {
                $text = strtr($text, $replacements);
            }
        }
        self::emit(self::severityFor($level), $text, $attributes, $scope);
    }

    /** @param mixed $value */
    private static function stringify($value): string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_scalar($value) || $value === null) {
            return var_export($value, true);
        }
        if ($value instanceof \Throwable) {
            return get_class($value) . ': ' . $value->getMessage();
        }
        if ($value instanceof \DateTimeInterface) {
            return $value->format(DATE_ATOM);
        }
        if ($value instanceof \Stringable) {
            return (string) $value;
        }
        if (is_object($value) && !($value instanceof \JsonSerializable)) {
            return '[object ' . get_class($value) . ']';
        }
        return Util::json($value);
    }
}
