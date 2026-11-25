<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Monolog;

use Monolog\Handler\HandlerInterface;
use SecureNow\SecureNow;
use SecureNow\Telemetry\Logger;

/**
 * Monolog handler (Monolog 2 and 3): every record also goes to SecureNow.
 *
 *   $logger->pushHandler(new \SecureNow\Integrations\Monolog\SecureNowHandler());
 *
 * Symfony (config/packages/monolog.yaml):
 *   handlers:
 *     securenow: { type: service, id: SecureNow\Integrations\Monolog\SecureNowHandler }
 *
 * Laravel needs nothing: the service provider already listens to every log line.
 */
final class SecureNowHandler implements HandlerInterface
{
    private int $minimumLevel;

    /** @param int $minimumLevel a Monolog level value (100 = debug, 200 = info, 400 = error) */
    public function __construct(int $minimumLevel = 100)
    {
        $this->minimumLevel = $minimumLevel;
    }

    /** @param mixed $record */
    private static function level($record): int
    {
        if (is_array($record)) {
            return (int) ($record['level'] ?? 200);
        }
        $level = $record->level ?? 200;
        return is_object($level) ? (int) $level->value : (int) $level;
    }

    /** @param mixed $record array (Monolog 2) or Monolog\LogRecord (Monolog 3) */
    public function isHandling($record): bool
    {
        return self::level($record) >= $this->minimumLevel;
    }

    /** @param mixed $record */
    public function handle($record): bool
    {
        try {
            if (!$this->isHandling($record)) {
                return false;
            }
            if (!SecureNow::isStarted() && !SecureNow::start()) {
                return false;
            }
            if (is_array($record)) {
                $levelName = (string) ($record['level_name'] ?? 'INFO');
                $message = (string) ($record['message'] ?? '');
                $context = (array) ($record['context'] ?? []);
                $channel = (string) ($record['channel'] ?? 'app');
            } else {
                $level = $record->level;
                $levelName = is_object($level) && method_exists($level, 'getName') ? $level->getName() : 'INFO';
                $message = (string) $record->message;
                $context = (array) $record->context;
                $channel = (string) $record->channel;
            }
            Logger::log(strtolower($levelName), $message, $context, 'monolog', $channel !== '' ? $channel : 'app');
        } catch (\Throwable $e) {
            // Logging must never break the app.
        }
        // false: the record continues to the other handlers.
        return false;
    }

    /** @param array<mixed> $records */
    public function handleBatch(array $records): void
    {
        foreach ($records as $record) {
            $this->handle($record);
        }
    }

    public function close(): void
    {
    }
}
