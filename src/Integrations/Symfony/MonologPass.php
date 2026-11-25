<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Symfony;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Adds SecureNow's Monolog handler to every Monolog channel, so the app's log lines reach
 * SecureNow with no monolog.yaml change. Registered by SecureNowBundle::build().
 */
final class MonologPass implements CompilerPassInterface
{
    public const HANDLER_ID = 'securenow.monolog_handler';

    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(self::HANDLER_ID)) {
            return;
        }
        foreach ($container->getDefinitions() as $id => $definition) {
            if ($id !== 'monolog.logger' && strncmp($id, 'monolog.logger.', 15) !== 0) {
                continue;
            }
            if ($definition->isAbstract()) {
                continue;
            }
            $definition->addMethodCall('pushHandler', [new Reference(self::HANDLER_ID)]);
        }
    }
}
