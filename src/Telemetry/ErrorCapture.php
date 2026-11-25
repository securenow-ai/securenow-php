<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Config;
use SecureNow\Util;

/**
 * Crash and error capture, the PHP counterpart of the Node SDK's crash-capture.js:
 *  - a fatal error (E_ERROR, E_PARSE, out of memory, timeout) or an uncaught exception becomes a
 *    FATAL log record with exception.type/message/stacktrace, and marks the request span;
 *  - warnings, notices and deprecations become log records (config.logging.phpErrors), deduplicated;
 *  - the app's own handlers keep working: SecureNow records, then hands over to them, and when
 *    there is none PHP reports the error exactly as it would without SecureNow.
 */
final class ErrorCapture
{
    private const FATAL_TYPES = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR;
    private const MAX_PHP_ERRORS = 25;

    private static bool $installed = false;
    /** @var callable|null */
    private static $previousErrorHandler = null;
    /** @var callable|null */
    private static $previousExceptionHandler = null;
    private static bool $uncaughtRecorded = false;
    /** @var array<string,true> */
    private static array $seen = [];
    private static bool $inHandler = false;

    public static function reset(): void
    {
        self::$uncaughtRecorded = false;
        self::$seen = [];
    }

    public static function install(): void
    {
        if (self::$installed) {
            return;
        }
        self::$installed = true;
        if (Config::bool('logging.phpErrors', true)) {
            self::$previousErrorHandler = set_error_handler([self::class, 'handleError']);
        }
        self::$previousExceptionHandler = set_exception_handler([self::class, 'handleException']);
    }

    /** @return bool false lets PHP's own handling (display, error_log) continue */
    public static function handleError(int $errno, string $errstr, string $errfile = '', int $errline = 0): bool
    {
        // Respect error_reporting and the @ operator.
        if ((error_reporting() & $errno) && !self::$inHandler) {
            self::$inHandler = true;
            try {
                self::recordPhpError($errno, $errstr, $errfile, $errline);
            } catch (\Throwable $e) {
            } finally {
                self::$inHandler = false;
            }
        }
        if (self::$previousErrorHandler !== null) {
            return (bool) (self::$previousErrorHandler)($errno, $errstr, $errfile, $errline);
        }
        return false;
    }

    private static function recordPhpError(int $errno, string $message, string $file, int $line): void
    {
        $key = $errno . '|' . $file . '|' . $line;
        if (isset(self::$seen[$key]) || count(self::$seen) >= self::MAX_PHP_ERRORS) {
            return;
        }
        self::$seen[$key] = true;
        [$name, $severity] = self::describe($errno);
        Logger::emit($severity, "PHP $name: $message in $file:$line", [
            'log.source' => 'php_error',
            'php.error.type' => $name,
            'code.filepath' => $file,
            'code.lineno' => $line,
        ]);
    }

    /** @return array{0:string,1:int} */
    private static function describe(int $errno): array
    {
        switch ($errno) {
            case E_WARNING:
            case E_USER_WARNING:
            case E_CORE_WARNING:
            case E_COMPILE_WARNING:
                return ['Warning', Logger::WARN];
            case E_NOTICE:
            case E_USER_NOTICE:
                return ['Notice', Logger::INFO];
            case E_DEPRECATED:
            case E_USER_DEPRECATED:
                return ['Deprecated', Logger::DEBUG];
            case E_PARSE:
                return ['Parse error', Logger::FATAL];
            case E_USER_ERROR:
            case E_RECOVERABLE_ERROR:
                return ['Error', Logger::ERROR];
            default:
                return ['Fatal error', Logger::FATAL];
        }
    }

    public static function handleException(\Throwable $e): void
    {
        $handledByApp = self::$previousExceptionHandler !== null;
        if (!self::$uncaughtRecorded) {
            self::$uncaughtRecorded = true;
            self::recordException($e, !$handledByApp, 'uncaughtException');
        }
        if ($handledByApp) {
            (self::$previousExceptionHandler)($e);
            return;
        }
        // No app handler: let PHP report it as it would without SecureNow (fatal "Uncaught ...",
        // HTTP 500). With no handler set, the rethrow goes to PHP itself, not back here.
        set_exception_handler(null);
        throw $e;
    }

    /**
     * Records an exception as a log record and on the current span. Framework integrations call
     * this for exceptions the framework catches and renders itself.
     */
    public static function recordException(\Throwable $e, bool $fatal = false, string $origin = 'handled'): void
    {
        $stack = Span::formatThrowable($e);
        Logger::emit(
            $fatal ? Logger::FATAL : Logger::ERROR,
            ($fatal ? 'Uncaught exception, request crashed: ' : 'Exception: ') . $stack,
            [
                'log.source' => $fatal ? 'crash' : 'exception',
                'exception.type' => get_class($e),
                'exception.message' => Util::truncate($e->getMessage(), 4000),
                'exception.stacktrace' => Util::truncate($stack, 16000),
                'exception.origin' => $origin,
                'exception.escaped' => $fatal,
                'process.pid' => (int) getmypid(),
            ]
        );
        self::markSpan($e, $fatal);
    }

    /** The exception on the current span only, for integrations whose logger already reported it. */
    public static function markSpan(\Throwable $e, bool $fatal = false): void
    {
        $span = Tracer::current() ?? Tracer::root();
        if ($span !== null) {
            $span->recordException($e, $fatal);
            $span->setStatus(Span::STATUS_ERROR, Util::truncate($e->getMessage(), 512));
        }
    }

    /** Called at shutdown: a fatal error that ended the script. */
    public static function captureFatal(): void
    {
        $error = error_get_last();
        if (!is_array($error) || !($error['type'] & self::FATAL_TYPES)) {
            return;
        }
        $message = (string) $error['message'];
        // The rethrown uncaught exception was recorded already, with its real stack.
        if (self::$uncaughtRecorded && strncmp($message, 'Uncaught ', 9) === 0) {
            return;
        }
        [$name] = self::describe((int) $error['type']);
        $type = 'PHP ' . $name;
        if (preg_match('/^Uncaught ([\w\\\\]+)/', $message, $m)) {
            $type = $m[1];
        }
        $where = (string) $error['file'] . ':' . (int) $error['line'];
        Logger::emit(Logger::FATAL, "PHP $name, request crashed: $message in $where", [
            'log.source' => 'crash',
            'exception.type' => $type,
            'exception.message' => Util::truncate($message, 4000),
            'exception.stacktrace' => Util::truncate($message . "\n  at " . $where, 16000),
            'exception.origin' => 'fatalError',
            'exception.escaped' => true,
            'code.filepath' => (string) $error['file'],
            'code.lineno' => (int) $error['line'],
            'process.pid' => (int) getmypid(),
        ]);
        $root = Tracer::root();
        if ($root !== null) {
            $root->addEvent('exception', [
                'exception.type' => $type,
                'exception.message' => Util::truncate($message, 4000),
                'exception.stacktrace' => $message . "\n  at " . $where,
                'exception.escaped' => true,
            ]);
            $root->setStatus(Span::STATUS_ERROR, Util::truncate($message, 512));
        }
    }
}
