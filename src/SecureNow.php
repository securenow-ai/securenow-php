<?php

declare(strict_types=1);

namespace SecureNow;

use SecureNow\Events\Events;
use SecureNow\Firewall\Firewall;
use SecureNow\Firewall\State;
use SecureNow\Firewall\Sync;
use SecureNow\Firewall\Verdict;
use SecureNow\Http\RequestInfo;
use SecureNow\Net\ClientIp;
use SecureNow\Sessions\Sessions;
use SecureNow\Telemetry\ErrorCapture;
use SecureNow\Telemetry\Exporter;
use SecureNow\Telemetry\Logger;
use SecureNow\Telemetry\OtelBridge;
use SecureNow\Telemetry\Otlp;
use SecureNow\Telemetry\RequestCapture;
use SecureNow\Telemetry\Span;
use SecureNow\Telemetry\Tracer;

/**
 * SecureNow for PHP: the public API.
 *
 * Most apps never call it: `composer require securenow/securenow` plus .securenow/runtime.json
 * is enough, because the SDK starts when vendor/autoload.php loads (see bootstrap.php).
 *
 *   SecureNow::track('auth.login.failure', ['userId' => $id]);   // security events
 *   SecureNow::log('warning', 'payment declined', ['order' => $id]);
 *   SecureNow::setUser($user->id);
 *   SecureNow::span('render-invoice', fn () => $pdf->render());
 *   if (SecureNow::checkSession()['revoked']) { ... }
 */
final class SecureNow
{
    private static bool $started = false;
    private static string $mode = 'off';
    private static ?RequestInfo $request = null;
    /** @var array<string,mixed>|null */
    private static ?array $ip = null;
    private static bool $finished = false;
    private static bool $autostartTried = false;

    /**
     * Start SecureNow for this process. Safe to call more than once.
     *
     * @param array{credentials?:array<string,mixed>} $options credentials: the runtime document, instead of a file
     */
    public static function start(array $options = []): bool
    {
        if (self::$started) {
            return true;
        }
        if (Config::disabled()) {
            return false;
        }
        if (isset($options['credentials']) && is_array($options['credentials'])) {
            Config::setCredentials($options['credentials']);
        }
        if (Config::appKey() === null) {
            Diag::debug('no app key found (.securenow/runtime.json or SECURENOW_CREDENTIALS): SecureNow sends nothing and blocks nothing.');
            return false;
        }
        self::$started = true;

        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
            // Commands, queue workers, long-running servers: no request to guard here. Events and
            // logs are sent when the process ends; a worker runtime calls beginRequest/endRequest.
            self::$mode = 'cli';
            if (Config::bool('runtime.cli', false)) {
                ErrorCapture::install();
            }
            register_shutdown_function([self::class, 'onCliShutdown']);
            return true;
        }

        self::$mode = 'web';
        ErrorCapture::install();
        register_shutdown_function([self::class, 'onShutdown']);
        $verdict = self::beginRequest(RequestInfo::fromGlobals());
        if ($verdict !== null) {
            $verdict->send();
            exit;
        }
        return true;
    }

    /** Called by bootstrap.php when Composer's autoloader loads. Never throws. */
    public static function autostart(): void
    {
        if (self::$started) {
            // Started earlier from auto_prepend_file, before Composer's autoloader existed: the
            // OpenTelemetry classes are loadable only now.
            if (self::$mode === 'web' && self::$request !== null && !OtelBridge::installed()) {
                OtelBridge::install();
            }
            return;
        }
        if (self::$autostartTried) {
            return;
        }
        self::$autostartTried = true;
        $flag = Config::env('SECURENOW_AUTOSTART');
        if ($flag !== null && in_array(strtolower($flag), ['0', 'false', 'off', 'no'], true)) {
            return;
        }
        if ((PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') && !Config::bool('runtime.cli', false)) {
            // Plain commands (composer, artisan, tests) start lazily, on the first track() or log().
            return;
        }
        self::start();
    }

    public static function isStarted(): bool
    {
        return self::$started;
    }

    private static function ensureStarted(): bool
    {
        return self::$started || self::start();
    }

    // ---- request lifecycle ----

    /**
     * Begin a request: opens the request span and runs the firewall. Returns the response to send
     * instead of running the app (403, 429, a challenge, 401), or null to continue.
     *
     * PHP-FPM, mod_php and the built-in server go through start(); worker runtimes (RoadRunner,
     * FrankenPHP worker mode, Swoole, Octane) call this once per request, then endRequest().
     */
    public static function beginRequest(RequestInfo $request): ?Verdict
    {
        if (!self::ensureStarted()) {
            return null;
        }
        Tracer::reset();
        Logger::reset();
        ErrorCapture::reset();
        State::reset();
        Sessions::reset();
        self::$finished = false;
        self::$request = $request;
        self::$ip = ClientIp::resolve($request);

        try {
            $root = Tracer::startRoot($request, RequestCapture::requestAttributes($request, self::$ip));
        } catch (\Throwable $e) {
            Diag::debug('request capture failed: ' . $e->getMessage());
            $root = Tracer::startRoot($request, ['http.method' => $request->method, 'http.target' => $request->path]);
        }
        self::guessRoute($request);
        OtelBridge::install();
        OtelBridge::activateRoot();

        $verdict = null;
        try {
            $verdict = Firewall::check($request, self::$ip) ?? Sessions::guard($request, (string) self::$ip['ip']);
        } catch (\Throwable $e) {
            // The firewall fails open: a bug or a full disk must not take the app down.
            Diag::error('firewall check failed: ' . $e->getMessage());
        }
        if ($verdict !== null) {
            Tracer::discardRoot();
        }
        return $verdict;
    }

    /** End a request begun with beginRequest(): closes the span and ships telemetry. */
    public static function endRequest(int $status = 200): void
    {
        if (self::$finished) {
            return;
        }
        self::$finished = true;
        try {
            OtelBridge::shutdown();
            Tracer::finishRoot($status);
            if (Firewall::active()) {
                Exporter::addTask([Sync::class, 'maybe']);
            }
        } catch (\Throwable $e) {
            Diag::debug('finishing the request failed: ' . $e->getMessage());
        }
        Exporter::finish();
        if (self::$mode !== 'web') {
            self::$request = null;
            self::$ip = null;
        }
    }

    /** @internal */
    public static function onShutdown(): void
    {
        // Queue the real work behind every shutdown function the app registered: the status code
        // and the framework's own cleanup are final by then.
        register_shutdown_function([self::class, 'finishWebRequest']);
    }

    /** @internal */
    public static function finishWebRequest(): void
    {
        try {
            ErrorCapture::captureFatal();
        } catch (\Throwable $e) {
        }
        $status = http_response_code();
        self::endRequest(is_int($status) ? $status : 200);
    }

    /** @internal */
    public static function onCliShutdown(): void
    {
        try {
            if (self::$request !== null && !self::$finished) {
                self::endRequest(0);
                return;
            }
            if (Config::bool('runtime.cli', false)) {
                ErrorCapture::captureFatal();
            }
            if (Exporter::hasPending()) {
                Exporter::finish();
            }
        } catch (\Throwable $e) {
        }
    }

    /** A plain PHP page is its own route: /contact.php. Front controllers set theirs through the framework. */
    private static function guessRoute(RequestInfo $request): void
    {
        $script = $request->scriptName;
        if ($script === '' || $script[0] !== '/') {
            return;
        }
        $path = $request->path;
        if ($path === $script) {
            Tracer::setRoute($script);
        } elseif (substr($path, -1) === '/' && $script === $path . 'index.php' && $path !== '/') {
            Tracer::setRoute($path);
        }
    }

    // ---- public API ----

    /** The visitor's address for the current request ('' outside a request), trusted-proxy rules applied. */
    public static function clientIp(): string
    {
        return (string) (self::$ip['ip'] ?? '');
    }

    public static function userAgent(): string
    {
        return self::$request !== null ? self::$request->header('user-agent') : '';
    }

    public static function request(): ?RequestInfo
    {
        return self::$request;
    }

    /**
     * Send a security event (auth.login.failure, auth.otp.verify.failure, ...). Never throws.
     *
     * @param array<string,mixed> $props userId, sessionId, ip, userAgent, severity, ts, attributes
     */
    public static function track(string $type, array $props = []): void
    {
        if (self::ensureStarted()) {
            Events::track($type, $props);
        }
    }

    /**
     * Send a log line. $level is a PSR-3 level; {placeholders} are filled from the context.
     *
     * @param mixed $message
     * @param array<mixed> $context
     */
    public static function log(string $level, $message, array $context = []): void
    {
        if (self::ensureStarted()) {
            Logger::log($level, $message, $context);
        }
    }

    /** A logger that sends to SecureNow: a Psr\Log\LoggerInterface when psr/log is installed. */
    public static function logger(string $channel = 'app'): object
    {
        self::ensureStarted();
        return interface_exists(\Psr\Log\LoggerInterface::class)
            ? new Integrations\Psr3Logger($channel)
            : new Integrations\PsrLogger($channel);
    }

    /** The route template of the current request (/users/{id}). Framework integrations set it for you. */
    public static function setRoute(string $route): void
    {
        Tracer::setRoute($route);
    }

    /**
     * Attach the signed-in user (and session) to the request span.
     *
     * @param int|string|null $userId
     */
    public static function setUser($userId, ?string $sessionId = null): void
    {
        $root = Tracer::root();
        if ($root === null) {
            return;
        }
        if ($userId !== null && $userId !== '') {
            $root->setAttribute('enduser.id', (string) $userId);
        }
        if ($sessionId !== null && $sessionId !== '') {
            $root->setAttribute('session.id', $sessionId);
        }
    }

    /** Add an attribute to the request span. @param mixed $value */
    public static function setAttribute(string $key, $value): void
    {
        $span = Tracer::current() ?? Tracer::root();
        if ($span !== null) {
            $span->setAttribute($key, $value);
        }
    }

    /** Record an exception your code caught: a log record, and an error on the current span. */
    public static function recordException(\Throwable $e): void
    {
        if (self::ensureStarted()) {
            ErrorCapture::recordException($e, false, 'handled');
        }
    }

    /**
     * Run $fn inside a child span.
     *
     * @param array<string,mixed> $attributes
     * @return mixed what $fn returns
     */
    public static function span(string $name, callable $fn, array $attributes = [])
    {
        if (!self::$started || Tracer::root() === null) {
            return $fn();
        }
        $span = Tracer::start($name, Span::KIND_INTERNAL, $attributes);
        try {
            return $fn($span);
        } catch (\Throwable $e) {
            $span->recordException($e, true);
            $span->setStatus(Span::STATUS_ERROR, $e->getMessage());
            throw $e;
        } finally {
            Tracer::end($span);
        }
    }

    /** @param array<string,mixed> $attributes */
    public static function startSpan(string $name, array $attributes = [], int $kind = Span::KIND_INTERNAL): ?Span
    {
        if (!self::$started || Tracer::root() === null) {
            return null;
        }
        return Tracer::start($name, $kind, $attributes);
    }

    public static function endSpan(?Span $span): void
    {
        if ($span !== null) {
            Tracer::end($span);
        }
    }

    /** W3C traceparent of the current span, to pass to a downstream service. */
    public static function traceparent(): ?string
    {
        $span = Tracer::current();
        return $span === null ? null : $span->traceparent();
    }

    /**
     * Is the current request's session or user revoked? Pass ids when your framework has its own
     * (Laravel's session id, your user id); otherwise they are read from the Bearer token or
     * session cookie. Also feeds session-theft detection unless capture is false.
     *
     * @param array{sessionId?:?string,userId?:int|string|null,ip?:string,capture?:bool} $options
     * @return array{revoked:bool,sessionId:?string,userId:?string}
     */
    public static function checkSession(array $options = []): array
    {
        $none = ['revoked' => false, 'sessionId' => null, 'userId' => null];
        if (!self::ensureStarted()) {
            return $none;
        }
        try {
            $identity = self::$request !== null ? Sessions::identify(self::$request) : ['sessionId' => null, 'userId' => null];
            $sessionId = isset($options['sessionId']) && $options['sessionId'] !== '' ? (string) $options['sessionId'] : $identity['sessionId'];
            $userId = isset($options['userId']) && $options['userId'] !== '' ? (string) $options['userId'] : $identity['userId'];
            $ip = isset($options['ip']) && $options['ip'] !== '' ? (string) $options['ip'] : self::clientIp();
            return Sessions::check($sessionId, $userId, $ip, ($options['capture'] ?? true) !== false);
        } catch (\Throwable $e) {
            return $none;
        }
    }

    /** SHA-256, the way SecureNow derives a session id from a raw token or cookie. */
    public static function sessionHash(string $rawSessionValue): string
    {
        return Sessions::sha256($rawSessionValue);
    }

    /** Framework integrations name themselves: shown on the app in the dashboard. */
    public static function setFramework(string $name, ?string $version = null): void
    {
        Otlp::setResourceAttribute('securenow.framework', $name);
        if ($version !== null && $version !== '') {
            Otlp::setResourceAttribute('securenow.framework.version', $version);
        }
        try {
            Otlp::persistResource();
        } catch (\Throwable $e) {
        }
    }

    /** Send everything queued now (long-running commands; requests do this on their own). */
    public static function flush(): void
    {
        if (!self::$started) {
            return;
        }
        Exporter::finish();
        Exporter::flush(false, true);
    }

    /** @internal test hook */
    public static function resetForTests(): void
    {
        self::$started = false;
        self::$mode = 'off';
        self::$request = null;
        self::$ip = null;
        self::$finished = false;
        self::$autostartTried = false;
        Config::reset();
        Tracer::reset();
        Exporter::reset();
        Logger::reset();
        ErrorCapture::reset();
        State::reset();
        Sessions::reset();
        Otlp::reset();
        RequestCapture::reset();
        ClientIp::reset();
        \SecureNow\Store\Store::reset();
        \SecureNow\Firewall\RateLimiter::reset();
    }
}
