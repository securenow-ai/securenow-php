<?php

declare(strict_types=1);

namespace SecureNow\Integrations;

/**
 * PsrLogger as a Psr\Log\LoggerInterface (psr/log 1, 2 and 3). Loaded only when psr/log is installed.
 */
final class Psr3Logger extends PsrLogger implements \Psr\Log\LoggerInterface
{
}
