<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Symfony;

use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\SecureNow;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Symfony integration. Add it to config/bundles.php:
 *
 *   SecureNow\Integrations\Symfony\SecureNowBundle::class => ['all' => true],
 *
 * The SDK itself already started when vendor/autoload.php loaded; the bundle adds the route
 * template, exceptions the kernel renders, sign-in events, and Monolog lines.
 */
final class SecureNowBundle extends Bundle
{
    public function build(\Symfony\Component\DependencyInjection\ContainerBuilder $container): void
    {
        parent::build($container);
        // Monolog (when installed): every channel also logs to SecureNow.
        if (interface_exists(\Monolog\Handler\HandlerInterface::class)) {
            $container->setParameter('securenow.monolog', true);
            $container->register(MonologPass::HANDLER_ID, \SecureNow\Integrations\Monolog\SecureNowHandler::class)->setPublic(false);
            $container->addCompilerPass(new MonologPass(), \Symfony\Component\DependencyInjection\Compiler\PassConfig::TYPE_BEFORE_OPTIMIZATION, -64);
        }
    }

    public function boot(): void
    {
        try {
            if (Config::disabled() || Config::appKey() === null || $this->container === null) {
                return;
            }
            $version = defined('Symfony\Component\HttpKernel\Kernel::VERSION') ? \Symfony\Component\HttpKernel\Kernel::VERSION : null;
            SecureNow::setFramework('symfony', $version);

            if ($this->container->has('event_dispatcher')) {
                $dispatcher = $this->container->get('event_dispatcher');
                $subscriber = new SecureNowSubscriber($this->container->hasParameter('securenow.monolog'));
                foreach (SecureNowSubscriber::listeners() as $event => [$method, $priority]) {
                    $dispatcher->addListener($event, [$subscriber, $method], $priority);
                }
            }
        } catch (\Throwable $e) {
            Diag::debug('Symfony integration not wired: ' . $e->getMessage());
        }
    }
}
