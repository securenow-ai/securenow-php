<?php

declare(strict_types=1);

namespace SecureNow;

/**
 * SDK diagnostics. Written with error_log(), never to the response. config.otel.logLevel sets the
 * level (none, error, warn, info, debug); SECURENOW_DEBUG=1 forces debug.
 */
final class Diag
{
    private const LEVELS = ['none' => 0, 'error' => 1, 'warn' => 2, 'info' => 3, 'debug' => 4];

    private static ?int $level = null;
    /** @var callable|null */
    private static $sink = null;
    private static bool $busy = false;

    /** Route diagnostics somewhere else (the CLI prints them). */
    public static function setSink(?callable $sink): void
    {
        self::$sink = $sink;
    }

    public static function setLevel(string $level): void
    {
        self::$level = self::LEVELS[strtolower($level)] ?? 1;
    }

    private static function level(): int
    {
        if (self::$level !== null) {
            return self::$level;
        }
        if (self::$busy) {
            return 1;
        }
        self::$busy = true;
        try {
            $debug = Config::env('SECURENOW_DEBUG');
            if ($debug !== null && $debug !== '0') {
                self::$level = 4;
            } else {
                $name = strtolower((string) Config::get('otel.logLevel', 'error'));
                self::$level = self::LEVELS[$name] ?? 1;
            }
        } finally {
            self::$busy = false;
        }
        return self::$level ?? 1;
    }

    private static function write(int $level, string $message): void
    {
        if (self::level() < $level) {
            return;
        }
        $line = '[securenow] ' . $message;
        if (self::$sink !== null) {
            (self::$sink)($line);
            return;
        }
        @error_log($line);
    }

    public static function error(string $message): void
    {
        self::write(1, $message);
    }

    public static function warn(string $message): void
    {
        self::write(2, $message);
    }

    public static function info(string $message): void
    {
        self::write(3, $message);
    }

    public static function debug(string $message): void
    {
        self::write(4, $message);
    }
}
