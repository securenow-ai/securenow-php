<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Laravel;

use SecureNow\Http\RequestInfo;
use SecureNow\SecureNow;

/**
 * Laravel Octane (Swoole, RoadRunner, FrankenPHP): the worker stays alive between requests, so
 * the request span and the firewall check are driven per request here instead of at autoload.
 * The service provider prepends it to the global middleware when Octane runs.
 */
final class OctaneMiddleware
{
    /**
     * @param mixed $request Illuminate\Http\Request
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        $verdict = null;
        try {
            $verdict = SecureNow::beginRequest(RequestInfo::fromSymfony($request));
        } catch (\Throwable $e) {
        }
        if ($verdict !== null) {
            $response = response($verdict->body, $verdict->status, $verdict->headers);
            foreach ($verdict->cookies as $cookie) {
                $response->headers->set('Set-Cookie', $cookie, false);
            }
            return $response;
        }
        return $next($request);
    }

    /**
     * @param mixed $request
     * @param mixed $response
     */
    public function terminate($request, $response): void
    {
        try {
            $status = is_object($response) && method_exists($response, 'getStatusCode') ? (int) $response->getStatusCode() : 200;
            SecureNow::endRequest($status);
        } catch (\Throwable $e) {
        }
    }
}
