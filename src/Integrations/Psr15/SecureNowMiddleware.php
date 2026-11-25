<?php

declare(strict_types=1);

namespace SecureNow\Integrations\Psr15;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SecureNow\Http\RequestInfo;
use SecureNow\SecureNow;
use SecureNow\Telemetry\ErrorCapture;

/**
 * PSR-15 middleware for Slim, Mezzio and any PSR-15 stack.
 *
 * Under PHP-FPM / mod_php the SDK already guarded the request when vendor/autoload.php loaded;
 * here the middleware only adds the route template and exceptions:
 *
 *   $app->add(new SecureNowMiddleware());      // Slim 4: add it BEFORE $app->addRoutingMiddleware()
 *
 * In a long-running worker (RoadRunner, FrankenPHP worker mode, Swoole, ReactPHP) there is no
 * per-request autoload, so the middleware drives the whole request: the firewall check, the
 * request span and the export. Give it a response factory so it can answer blocked requests:
 *
 *   new SecureNowMiddleware($psr17Factory)     // outermost middleware
 */
final class SecureNowMiddleware implements MiddlewareInterface
{
    private ?ResponseFactoryInterface $responses;

    public function __construct(?ResponseFactoryInterface $responses = null)
    {
        $this->responses = $responses;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $worker = PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg';
        if ($worker) {
            try {
                $verdict = SecureNow::beginRequest(RequestInfo::fromPsr7($request));
            } catch (\Throwable $e) {
                $verdict = null;
            }
            if ($verdict !== null && $this->responses !== null) {
                $response = $this->responses->createResponse($verdict->status);
                foreach ($verdict->headers as $name => $value) {
                    $response = $response->withHeader($name, $value);
                }
                foreach ($verdict->cookies as $cookie) {
                    $response = $response->withAddedHeader('Set-Cookie', $cookie);
                }
                $response->getBody()->write($verdict->body);
                SecureNow::endRequest($verdict->status);
                return $response;
            }
        }

        try {
            $response = $handler->handle($request);
        } catch (\Throwable $e) {
            $this->noteRoute($request);
            ErrorCapture::recordException($e, false, 'psr15');
            if ($worker) {
                SecureNow::endRequest(500);
            }
            throw $e;
        }
        $this->noteRoute($request);
        if ($worker) {
            SecureNow::endRequest($response->getStatusCode());
        }
        return $response;
    }

    private function noteRoute(ServerRequestInterface $request): void
    {
        try {
            // Slim 4 (RouteContext::ROUTE).
            $route = $request->getAttribute('__route__');
            if (is_object($route) && method_exists($route, 'getPattern')) {
                SecureNow::setRoute((string) $route->getPattern());
                return;
            }
            // Mezzio.
            $result = $request->getAttribute('Mezzio\Router\RouteResult');
            if (is_object($result) && method_exists($result, 'getMatchedRoute')) {
                $matched = $result->getMatchedRoute();
                if (is_object($matched) && method_exists($matched, 'getPath')) {
                    SecureNow::setRoute((string) $matched->getPath());
                }
            }
        } catch (\Throwable $e) {
        }
    }
}
