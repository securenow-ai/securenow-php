<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Symfony;

use SecureNow\Config;
use SecureNow\SecureNow;
use SecureNow\Telemetry\ErrorCapture;

/**
 * Kernel and security listeners for Symfony. No Symfony type appears in a signature, so the
 * class loads on every Symfony version from 5.4 on.
 */
final class SecureNowSubscriber
{
    private bool $monolog;

    /** @param bool $monolog Monolog already reports exceptions as log lines: only mark the span */
    public function __construct(bool $monolog = false)
    {
        $this->monolog = $monolog;
    }

    /** @return array<string,array{0:string,1:int}> event => [method, priority] */
    public static function listeners(): array
    {
        $listeners = [
            // After the router (priority 32) has set _route and _route_params.
            'kernel.request' => ['onRequest', 0],
            'kernel.exception' => ['onException', 0],
        ];
        if (Config::bool('events.auth', true)) {
            $listeners['Symfony\Component\Security\Http\Event\LoginSuccessEvent'] = ['onLoginSuccess', 0];
            $listeners['Symfony\Component\Security\Http\Event\LoginFailureEvent'] = ['onLoginFailure', 0];
            $listeners['Symfony\Component\Security\Http\Event\LogoutEvent'] = ['onLogout', 0];
        }
        return $listeners;
    }

    /** @param object $event RequestEvent */
    public function onRequest($event): void
    {
        try {
            if (method_exists($event, 'isMainRequest') ? !$event->isMainRequest() : (method_exists($event, 'isMasterRequest') && !$event->isMasterRequest())) {
                return;
            }
            $request = $event->getRequest();
            $name = $request->attributes->get('_route');
            if (!is_string($name) || $name === '') {
                return;
            }
            // The route template, rebuilt from the path and the matched parameters: /users/42 -> /users/{id}.
            $path = (string) $request->getPathInfo();
            $params = $request->attributes->get('_route_params');
            if (is_array($params)) {
                foreach ($params as $key => $value) {
                    if (!is_string($key) || $key === '' || $key[0] === '_' || !is_scalar($value) || (string) $value === '') {
                        continue;
                    }
                    $segment = '/' . rawurlencode((string) $value);
                    $at = strpos($path . '/', $segment . '/');
                    if ($at === false) {
                        $segment = '/' . $value;
                        $at = strpos($path . '/', $segment . '/');
                    }
                    if ($at !== false) {
                        $path = substr($path, 0, $at) . '/{' . $key . '}' . substr($path, $at + strlen($segment));
                    }
                }
            }
            SecureNow::setRoute($path);
            SecureNow::setAttribute('symfony.route', $name);
        } catch (\Throwable $e) {
        }
    }

    /** @param object $event ExceptionEvent */
    public function onException($event): void
    {
        try {
            $exception = $event->getThrowable();
            // 4xx responses raised as exceptions (404, 403) are ordinary answers, not errors.
            if (method_exists($exception, 'getStatusCode') && (int) $exception->getStatusCode() < 500) {
                return;
            }
            if ($this->monolog) {
                ErrorCapture::markSpan($exception);
            } else {
                ErrorCapture::recordException($exception, false, 'symfony');
            }
        } catch (\Throwable $e) {
        }
    }

    /** @param object $event */
    public function onLoginSuccess($event): void
    {
        try {
            $user = $event->getUser();
            $id = is_object($user) && method_exists($user, 'getUserIdentifier') ? (string) $user->getUserIdentifier() : '';
            SecureNow::track('auth.login.success', $id !== '' ? ['userId' => $id] : []);
            if ($id !== '') {
                SecureNow::setUser($id);
            }
        } catch (\Throwable $e) {
        }
    }

    /** @param object $event */
    public function onLoginFailure($event): void
    {
        try {
            SecureNow::track('auth.login.failure', ['severity' => 'warn']);
        } catch (\Throwable $e) {
        }
    }

    /** @param object $event */
    public function onLogout($event): void
    {
        try {
            $token = method_exists($event, 'getToken') ? $event->getToken() : null;
            $id = is_object($token) && method_exists($token, 'getUserIdentifier') ? (string) $token->getUserIdentifier() : '';
            SecureNow::track('auth.logout', $id !== '' ? ['userId' => $id] : []);
        } catch (\Throwable $e) {
        }
    }
}
