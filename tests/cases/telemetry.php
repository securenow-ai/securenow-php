<?php

declare(strict_types=1);

use SecureNow\Config;
use SecureNow\Http\Transport;
use SecureNow\Net\ClientIp;
use SecureNow\SecureNow;
use SecureNow\Telemetry\ErrorCapture;
use SecureNow\Telemetry\Exporter;
use SecureNow\Telemetry\Logger;
use SecureNow\Telemetry\RequestCapture;
use SecureNow\Telemetry\Tracer;

/** @return array<int,array<string,mixed>> */
function tel_capture_calls(): array
{
    $calls = [];
    Transport::fake(static function (array $request) use (&$calls): array {
        $calls[] = $request;
        return ['status' => 200, 'headers' => [], 'body' => '{}'];
    });
    return $calls;
}

/** @param array<int,array<string,mixed>> $attributes @return array<string,mixed> */
function tel_attrs(array $attributes): array
{
    $out = [];
    foreach ($attributes as $attribute) {
        $out[$attribute['key']] = current($attribute['value']);
    }
    return $out;
}

return [
    'request attributes follow the telemetry contract' => static function (): void {
        T::boot();
        $request = T::request('POST', '/api/login?next=/home&code=123456', [
            'user-agent' => 'Mozilla/5.0',
            'content-type' => 'application/json',
            'authorization' => 'Bearer abc.def.ghi',
            'cookie' => 'sid=1',
            'x-forwarded-for' => '198.51.100.7',
            'x-request-id' => 'req-1',
        ], '10.0.0.5', '{"email":"a@b.co","password":"hunter2","q":"<script>alert(1)</script>"}');
        $attrs = RequestCapture::requestAttributes($request, ClientIp::resolve($request));

        T::eq('POST', $attrs['http.method']);
        T::eq('/api/login?next=/home&code=REDACTED', $attrs['http.target']);
        T::eq('http://app.test/api/login?next=/home&code=REDACTED', $attrs['http.url']);
        T::eq('app.test', $attrs['http.host']);
        T::eq('Mozilla/5.0', $attrs['http.user_agent']);
        T::eq('198.51.100.7', $attrs['http.client_ip']);
        T::eq('x-forwarded-for', $attrs['http.client_ip.source']);
        T::eq('10.0.0.5', $attrs['http.socket_ip']);
        T::eq('true', $attrs['http.proxy.trusted']);
        T::eq('198.51.100.7', $attrs['http.forwarded_for']);
        T::eq('true', $attrs['http.security.auth_present']);
        T::eq('true', $attrs['http.security.cookies_present']);

        $headers = json_decode($attrs['http.request.headers'], true);
        T::eq('[REDACTED]', $headers['authorization']);
        T::eq('[REDACTED]', $headers['cookie']);
        T::eq('req-1', $headers['x-request-id']);

        T::eq('json', $attrs['http.request.body.type']);
        $body = json_decode($attrs['http.request.body'], true);
        T::eq('[REDACTED]', $body['password']);
        T::eq('[REDACTED]', $body['email']);
        T::eq('<script>alert(1)</script>', $body['q']);
        T::contains('<script>alert(1)</script>', $attrs['http.request.body'], 'payload kept as sent');
    },

    'bodies: too large, unparseable, form, multipart, disabled' => static function (): void {
        T::boot();
        $big = T::request('POST', '/u', ['content-type' => 'application/json'], '198.51.100.1', '{"a":"' . str_repeat('x', 20000) . '"}');
        $attrs = RequestCapture::bodyAttributes($big);
        T::contains('[TOO LARGE:', $attrs['http.request.body']);

        $bad = RequestCapture::bodyAttributes(T::request('POST', '/u', ['content-type' => 'application/json'], '198.51.100.1', '{not json'));
        T::eq('[UNPARSEABLE - REDACTED FOR SAFETY]', $bad['http.request.body']);
        T::eq(true, $bad['http.request.body.parse_error']);

        $form = RequestCapture::bodyAttributes(T::request('POST', '/u', ['content-type' => 'application/x-www-form-urlencoded'], '198.51.100.1', 'user=bob&password=x&note=hi+there'));
        T::eq('{"user":"bob","password":"[REDACTED]","note":"hi there"}', $form['http.request.body']);
        T::eq('form', $form['http.request.body.type']);

        $multipart = T::request('POST', '/upload', ['content-type' => 'multipart/form-data; boundary=----X'], '198.51.100.1');
        $multipart->postFields = ['title' => 'Report', 'api_key' => 'secret'];
        $multipart->files = [['field' => 'doc', 'filename' => 'a.pdf', 'contentType' => 'application/pdf', 'size' => 1234]];
        $m = RequestCapture::bodyAttributes($multipart);
        T::eq('multipart', $m['http.request.body.type']);
        T::eq('{"fields":{"title":"Report","api_key":"[REDACTED]"},"files":[{"field":"doc","filename":"a.pdf","contentType":"application/pdf","size":1234}]}', $m['http.request.body']);
        T::eq(1, $m['http.request.body.files_count']);

        T::eq([], RequestCapture::bodyAttributes(T::request('GET', '/u', ['content-type' => 'application/json'], '198.51.100.1', '{}')), 'GET bodies are not captured');

        T::boot(['capture' => ['body' => false, 'multipart' => false]]);
        T::eq([], RequestCapture::bodyAttributes(T::request('POST', '/u', ['content-type' => 'application/json'], '198.51.100.1', '{"a":1}')));
    },

    'a request exports one trace, its logs and events, with the right envelope' => static function (): void {
        T::boot(['runtime' => ['deploymentEnvironment' => 'staging']]);
        $calls = [];
        Transport::fake(static function (array $request) use (&$calls): array {
            $calls[] = $request;
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        T::ok(SecureNow::start());
        SecureNow::beginRequest(T::request('GET', '/users/42', ['traceparent' => '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'], '198.51.100.90'));
        SecureNow::setRoute('users/{id}');
        SecureNow::setUser(42, 'sess-hash');
        $value = SecureNow::span('load-user', static function () {
            SecureNow::log('warning', 'slow query for {user}', ['user' => 42, 'password' => 'hunter2']);
            return 'done';
        }, ['db.system' => 'mysql']);
        T::eq('done', $value);
        SecureNow::track('auth.login.failure', ['userId' => 42, 'attributes' => ['method' => 'password']]);
        SecureNow::endRequest(200);
        Exporter::flush(false, true);

        $byUrl = [];
        foreach ($calls as $call) {
            $byUrl[(string) $call['url']] = $call;
        }
        T::ok(isset($byUrl['https://ingest.securenow.ai/v1/traces'], $byUrl['https://ingest.securenow.ai/v1/logs'], $byUrl['https://ingest.securenow.ai/v1/events']), 'three posts: ' . implode(', ', array_keys($byUrl)));
        $headers = $byUrl['https://ingest.securenow.ai/v1/traces']['headers'];
        T::eq('Bearer snk_live_testkey0123456789', $headers['authorization']);
        T::eq('staging', $headers['x-securenow-environment']);
        T::eq('application/json', $headers['content-type']);

        $traces = json_decode((string) $byUrl['https://ingest.securenow.ai/v1/traces']['body'], true);
        $resource = tel_attrs($traces['resourceSpans'][0]['resource']['attributes']);
        T::eq('11111111-2222-3333-4444-555555555555', $resource['service.name'], 'service.name is the app key, no suffix');
        T::eq('php', $resource['telemetry.sdk.language']);
        T::eq('staging', $resource['deployment.environment']);
        $spans = $traces['resourceSpans'][0]['scopeSpans'][0]['spans'];
        T::eq(2, count($spans));
        [$child, $root] = $spans;
        T::eq('load-user', $child['name']);
        T::eq($root['spanId'], $child['parentSpanId']);
        T::eq('GET /users/{id}', $root['name']);
        T::eq('0af7651916cd43dd8448eb211c80319c', $root['traceId'], 'continues the upstream trace');
        T::eq('b7ad6b7169203331', $root['parentSpanId']);
        T::ok((int) $root['endTimeUnixNano'] >= (int) $root['startTimeUnixNano']);
        $rootAttrs = tel_attrs($root['attributes']);
        T::eq('/users/{id}', $rootAttrs['http.route']);
        T::eq('200', $rootAttrs['http.status_code']);
        T::eq('42', $rootAttrs['enduser.id']);
        T::eq('198.51.100.90', $rootAttrs['http.client_ip']);

        $logs = json_decode((string) $byUrl['https://ingest.securenow.ai/v1/logs']['body'], true);
        $record = $logs['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0];
        T::eq('slow query for 42', $record['body']['stringValue']);
        T::eq('WARN', $record['severityText']);
        T::eq($root['traceId'], $record['traceId']);
        T::eq($child['spanId'], $record['spanId']);
        T::eq('[REDACTED]', tel_attrs($record['attributes'])['context.password']);

        $events = json_decode((string) $byUrl['https://ingest.securenow.ai/v1/events']['body'], true)['events'];
        T::eq('auth.login.failure', $events[0]['type']);
        T::eq('42', $events[0]['user_id']);
        T::eq('198.51.100.90', $events[0]['ip'], 'the event takes the request address');
        T::eq(['method' => 'password'], $events[0]['attributes']);
    },

    'a 500 marks the span as an error; exceptions are recorded' => static function (): void {
        T::boot();
        $calls = [];
        Transport::fake(static function (array $request) use (&$calls): array {
            $calls[] = $request;
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        SecureNow::start();
        SecureNow::beginRequest(T::request('GET', '/boom', [], '198.51.100.91'));
        ErrorCapture::recordException(new RuntimeException('database is down, password=hunter2'), false, 'test');
        SecureNow::endRequest(500);
        Exporter::flush(false, true);
        $traces = null;
        $logs = null;
        foreach ($calls as $call) {
            if (substr((string) $call['url'], -10) === '/v1/traces') {
                $traces = json_decode((string) $call['body'], true);
            } elseif (substr((string) $call['url'], -8) === '/v1/logs') {
                $logs = json_decode((string) $call['body'], true);
            }
        }
        $root = $traces['resourceSpans'][0]['scopeSpans'][0]['spans'][0];
        T::eq(2, $root['status']['code']);
        T::eq('exception', $root['events'][0]['name']);
        T::eq('RuntimeException', tel_attrs($root['events'][0]['attributes'])['exception.type']);
        $record = $logs['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0];
        T::eq('ERROR', $record['severityText']);
        T::notContains('hunter2', $record['body']['stringValue'], 'log lines are redacted');
    },

    'PHP warnings become log records and the app handler still runs' => static function (): void {
        T::boot();
        Transport::fake(static function (): array {
            return ['status' => 200, 'headers' => [], 'body' => '{}'];
        });
        SecureNow::start();
        SecureNow::beginRequest(T::request('GET', '/', [], '198.51.100.92'));
        $seenByApp = 0;
        $previous = set_error_handler(static function () use (&$seenByApp): bool {
            $seenByApp++;
            return true;
        });
        T::eq(false, ErrorCapture::handleError(E_USER_WARNING, 'careful', __FILE__, 10));
        T::eq(false, ErrorCapture::handleError(E_USER_WARNING, 'careful', __FILE__, 10), 'deduplicated, still passed on');
        restore_error_handler();
        T::ok(Exporter::hasPending());
        SecureNow::endRequest(200);
        Exporter::flush(false, true);
        unset($previous);
    },

    'logging off, and nothing without credentials' => static function (): void {
        T::boot(['logging' => ['enabled' => false]]);
        Logger::emit(Logger::INFO, 'hidden');
        T::eq(false, Exporter::hasPending());

        SecureNow::resetForTests();
        Config::setCredentials(['config' => []]);
        T::eq(false, SecureNow::start(), 'no app key, no start');
        SecureNow::track('x');
        SecureNow::log('info', 'y');
        T::eq(false, Exporter::hasPending());
        T::eq(null, SecureNow::beginRequest(T::request('GET', '/')));
    },

    'an ingest outage pauses exports instead of piling up' => static function (): void {
        $dir = T::boot();
        $calls = 0;
        Transport::fake(static function () use (&$calls): array {
            $calls++;
            return ['status' => 0, 'headers' => [], 'body' => '', 'error' => 'timeout'];
        });
        SecureNow::start();
        for ($i = 0; $i < 6; $i++) {
            Logger::emit(Logger::INFO, "line $i");
            Exporter::finish();
            usleep(1100000 > 0 ? 0 : 0);
            // Pretend the flush interval passed.
            $meta = unserialize((string) file_get_contents($dir . '/export.meta'), ['allowed_classes' => false]);
            $meta['lastFlush'] = 0;
            file_put_contents($dir . '/export.meta', serialize($meta));
        }
        T::eq(3, $calls, 'after three failures the SDK stops trying for a while');
        $meta = unserialize((string) file_get_contents($dir . '/export.meta'), ['allowed_classes' => false]);
        T::ok($meta['pauseUntil'] > \SecureNow\Util::nowMs());
    },

    'the background worker sends the spool and reports back' => static function (): void {
        $dir = T::boot();
        $calls = [];
        Transport::fake(static function (array $request) use (&$calls): array {
            $calls[] = (string) $request['url'];
            return ['status' => 200, 'headers' => ['etag' => '"e"'], 'body' => '{}'];
        });
        SecureNow::start();
        Logger::emit(Logger::INFO, 'spooled by a request');
        // What a request does on a server that cannot finish the response early: spool only.
        $spool = new ReflectionMethod(Exporter::class, 'spool');
        if (PHP_VERSION_ID < 80100) {
            $spool->setAccessible(true);
        }
        T::eq(true, $spool->invoke(null));
        T::ok(filesize($dir . '/spool-logs.jsonl') > 0);
        file_put_contents($dir . '/worker.meta', serialize(['at' => 1, 'tries' => 4]));

        Exporter::work();
        T::ok(in_array('https://ingest.securenow.ai/v1/logs', $calls, true), 'logs sent: ' . implode(', ', $calls));
        T::ok((bool) preg_grep('~/api/v1/firewall/sync~', $calls), 'the policy was checked');
        $meta = unserialize((string) file_get_contents($dir . '/worker.meta'), ['allowed_classes' => false]);
        T::eq(0, $meta['tries'], 'the worker reports back');
        T::ok(!is_file($dir . '/spool-logs.jsonl') || filesize($dir . '/spool-logs.jsonl') === 0, 'the spool is empty');
    },

    'configuration: files, env and defaults' => static function (): void {
        SecureNow::resetForTests();
        $dir = sys_get_temp_dir() . '/securenow-cfg-' . bin2hex(random_bytes(4));
        mkdir($dir . '/.securenow', 0700, true);
        file_put_contents($dir . '/.securenow/runtime.php', "<?php return ['apiKey' => 'snk_live_fromphp', 'app' => ['key' => 'app-php'], 'config' => ['capture' => ['maxBodySize' => 2048]]];");
        putenv('SECURENOW_CREDENTIALS_FILE=' . $dir . '/.securenow/runtime.php');
        T::eq('app-php', Config::appKey());
        T::eq('snk_live_fromphp', Config::apiKey());
        T::eq(2048, Config::int('capture.maxBodySize', 10240, 1024));
        T::eq(true, Config::bool('capture.body'), 'default');
        T::eq('production', Config::environment());
        T::eq('https://ingest.securenow.ai/v1/traces', Config::tracesUrl());
        T::eq('https://ingest.securenow.ai', Config::firewallApiUrl(), 'api.securenow.ai default is served by the gateway');

        Config::reset();
        putenv('SECURENOW_CREDENTIALS=' . base64_encode(json_encode(['apiKey' => 'not-a-runtime-key', 'app' => ['key' => 'app-env'], 'config' => ['runtime' => ['deploymentEnvironment' => 'dev'], 'otel' => ['endpoint' => 'https://collector.example.com/']]])));
        T::eq('app-env', Config::appKey(), 'SECURENOW_CREDENTIALS wins over files');
        T::eq(null, Config::apiKey(), 'only snk_live_ keys count');
        T::eq('local', Config::environment());
        T::eq('https://collector.example.com/v1/logs', Config::logsUrl());
        T::eq('env:SECURENOW_CREDENTIALS', Config::source());
        putenv('SECURENOW_CREDENTIALS');
        putenv('SECURENOW_CREDENTIALS_FILE');

        Config::reset();
        putenv('SECURENOW_DISABLED=1');
        T::eq(true, Config::disabled());
        putenv('SECURENOW_DISABLED');
        Config::reset();
    },
];
