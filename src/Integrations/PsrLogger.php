<?php

declare(strict_types=1);

namespace SecureNow\Integrations;

use SecureNow\Telemetry\Logger;

/**
 * A logger that sends to SecureNow, with the PSR-3 method set. It works without psr/log; when
 * psr/log is installed, SecureNow::logger() returns the subclass that implements
 * Psr\Log\LoggerInterface (see PsrLogger3.php), so it can be injected anywhere.
 */
class PsrLogger
{
    protected string $channel;

    public function __construct(string $channel = 'app')
    {
        $this->channel = $channel;
    }

    /**
     * @param mixed $level
     * @param mixed $message
     * @param array<mixed> $context
     */
    public function log($level, $message, array $context = []): void
    {
        Logger::log(is_scalar($level) ? (string) $level : 'info', $message, $context, 'app', $this->channel);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function emergency($message, array $context = []): void
    {
        $this->log('emergency', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function alert($message, array $context = []): void
    {
        $this->log('alert', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function critical($message, array $context = []): void
    {
        $this->log('critical', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function error($message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function warning($message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function notice($message, array $context = []): void
    {
        $this->log('notice', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function info($message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    /** @param mixed $message @param array<mixed> $context */
    public function debug($message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }
}
