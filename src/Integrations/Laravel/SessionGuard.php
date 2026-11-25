<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Laravel;

use SecureNow\Config;
use SecureNow\SecureNow;

/**
 * Session revocation for Laravel's "web" group, added by the service provider when
 * config.sessions.guard or config.sessions.capture is on. It runs after StartSession, so it uses
 * Laravel's session id and signed-in user: a revoked session or user is signed out and answered 401.
 */
final class SessionGuard
{
    /**
     * @param mixed $request Illuminate\Http\Request
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        try {
            $sessionId = null;
            // Only a session the visitor came back with: Laravel opens a new one for every request
            // without a cookie (bots, health checks), and those are not sessions to watch.
            if (method_exists($request, 'hasSession') && $request->hasSession()
                && (!method_exists($request, 'hasPreviousSession') || $request->hasPreviousSession())) {
                $raw = (string) $request->session()->getId();
                $sessionId = $raw !== '' ? SecureNow::sessionHash($raw) : null;
            }
            $userId = null;
            $user = $request->user();
            if (is_object($user) && method_exists($user, 'getAuthIdentifier')) {
                $id = $user->getAuthIdentifier();
                $userId = is_scalar($id) && (string) $id !== '' ? (string) $id : null;
            }
            if ($sessionId !== null || $userId !== null) {
                SecureNow::setUser($userId, $sessionId);
                $result = SecureNow::checkSession([
                    'sessionId' => $sessionId,
                    'userId' => $userId,
                    'capture' => Config::bool('sessions.capture', false),
                ]);
                if ($result['revoked'] && Config::bool('sessions.guard', false)) {
                    try {
                        if (function_exists('auth')) {
                            auth()->logout();
                        }
                        $request->session()->invalidate();
                    } catch (\Throwable $e) {
                    }
                    SecureNow::setAttribute('securenow.session.revoked', true);
                    return response()->json(['error' => 'Session revoked. Please sign in again.', 'code' => 'session_revoked'], 401);
                }
            }
        } catch (\Throwable $e) {
            // fail-open
        }
        return $next($request);
    }
}
