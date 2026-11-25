<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Laravel;

use Illuminate\Support\ServiceProvider;
use SecureNow\Config;
use SecureNow\Diag;
use SecureNow\SecureNow;
use SecureNow\Telemetry\Logger;
use SecureNow\Telemetry\ErrorCapture;

/**
 * Laravel integration, discovered automatically (composer.json "extra.laravel.providers").
 * The SDK itself already started when vendor/autoload.php loaded; this adds what only Laravel knows:
 *  - http.route from the matched route (/users/{id});
 *  - every Laravel log line and reported exception, as SecureNow logs;
 *  - sign-in events (auth.login.success / failure, lockout, logout, password reset, signup);
 *  - the session guard with Laravel's own session id (its cookie is re-encrypted on every response);
 *  - Octane: one request span and one firewall check per request in the long-running worker.
 */
final class SecureNowServiceProvider extends ServiceProvider
{
    public function register(): void
    {
    }

    public function boot(): void
    {
        try {
            if (Config::disabled() || Config::appKey() === null) {
                return;
            }
            $this->wire();
        } catch (\Throwable $e) {
            Diag::debug('Laravel integration not wired: ' . $e->getMessage());
        }
    }

    private function wire(): void
    {
        $app = $this->app;
        SecureNow::setFramework('laravel', method_exists($app, 'version') ? (string) $app->version() : null);
        $events = $app['events'];

        $events->listen('Illuminate\Routing\Events\RouteMatched', static function ($event): void {
            try {
                SecureNow::setRoute((string) $event->route->uri());
            } catch (\Throwable $e) {
            }
        });

        $events->listen('Illuminate\Log\Events\MessageLogged', static function ($event): void {
            try {
                if (!SecureNow::isStarted() && !SecureNow::start()) {
                    return;
                }
                $context = is_array($event->context) ? $event->context : [];
                $exception = $context['exception'] ?? null;
                Logger::log((string) $event->level, $event->message, $context, 'laravel', 'laravel');
                if ($exception instanceof \Throwable) {
                    ErrorCapture::markSpan($exception);
                }
            } catch (\Throwable $e) {
            }
        });

        if (Config::bool('events.auth', true)) {
            $this->wireAuthEvents($events);
        }

        // Queue workers run for hours: send what each job produced when it ends.
        foreach (['Illuminate\Queue\Events\JobProcessed', 'Illuminate\Queue\Events\JobFailed'] as $jobEvent) {
            $events->listen($jobEvent, static function (): void {
                try {
                    SecureNow::flush();
                } catch (\Throwable $e) {
                }
            });
        }

        if (isset($_SERVER['LARAVEL_OCTANE']) || isset($_ENV['LARAVEL_OCTANE'])) {
            $kernel = $app->make('Illuminate\Contracts\Http\Kernel');
            if (method_exists($kernel, 'prependMiddleware')) {
                $kernel->prependMiddleware(OctaneMiddleware::class);
            }
        }

        if (Config::bool('sessions.guard', false) || Config::bool('sessions.capture', false)) {
            $app['router']->pushMiddlewareToGroup('web', SessionGuard::class);
        }
    }

    /** @param mixed $events */
    private function wireAuthEvents($events): void
    {
        $identity = static function ($user): array {
            $props = [];
            try {
                if (is_object($user) && method_exists($user, 'getAuthIdentifier')) {
                    $id = $user->getAuthIdentifier();
                    if (is_scalar($id) && (string) $id !== '') {
                        $props['userId'] = (string) $id;
                    }
                }
                $request = function_exists('request') ? request() : null;
                if ($request !== null && method_exists($request, 'hasSession') && $request->hasSession()) {
                    $sessionId = (string) $request->session()->getId();
                    if ($sessionId !== '') {
                        $props['sessionId'] = SecureNow::sessionHash($sessionId);
                    }
                }
            } catch (\Throwable $e) {
            }
            return $props;
        };

        $map = [
            'Illuminate\Auth\Events\Login' => 'auth.login.success',
            'Illuminate\Auth\Events\Failed' => 'auth.login.failure',
            'Illuminate\Auth\Events\Logout' => 'auth.logout',
            'Illuminate\Auth\Events\Lockout' => 'auth.lockout',
            'Illuminate\Auth\Events\PasswordReset' => 'auth.password_reset.completed',
            'Illuminate\Auth\Events\Registered' => 'auth.signup',
        ];
        foreach ($map as $class => $type) {
            $events->listen($class, static function ($event) use ($type, $identity): void {
                try {
                    $props = $identity($event->user ?? null);
                    $attributes = [];
                    if (isset($event->guard) && is_string($event->guard)) {
                        $attributes['guard'] = $event->guard;
                    }
                    if ($attributes) {
                        $props['attributes'] = $attributes;
                    }
                    if ($type === 'auth.login.failure' || $type === 'auth.lockout') {
                        $props['severity'] = 'warn';
                    }
                    SecureNow::track($type, $props);
                } catch (\Throwable $e) {
                }
            });
        }

        $events->listen('Illuminate\Auth\Events\Authenticated', static function ($event) use ($identity): void {
            try {
                $props = $identity($event->user ?? null);
                SecureNow::setUser($props['userId'] ?? null, $props['sessionId'] ?? null);
            } catch (\Throwable $e) {
            }
        });
    }
}
