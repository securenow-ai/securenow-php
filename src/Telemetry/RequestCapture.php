<?php

declare(strict_types=1);

namespace SecureNow\Telemetry;

use SecureNow\Config;
use SecureNow\Http\RequestInfo;
use SecureNow\Net\ClientIp;
use SecureNow\Redaction\Redactor;
use SecureNow\Util;

/**
 * The attributes SecureNow's detections read on a request span, with the names of the telemetry
 * contract (telemetry-schema.json): client address and proxy details, the legacy and stable HTTP
 * names, redacted headers and the redacted, size-capped request body.
 */
final class RequestCapture
{
    private static ?Redactor $redactor = null;

    public static function reset(): void
    {
        self::$redactor = null;
    }

    public static function redactor(): Redactor
    {
        if (self::$redactor === null) {
            self::$redactor = new Redactor(Config::list('capture.sensitiveFields'));
        }
        return self::$redactor;
    }

    /**
     * @param array<string,mixed> $ip ClientIp::resolve()
     * @return array<string,mixed>
     */
    public static function requestAttributes(RequestInfo $request, array $ip): array
    {
        $scheme = $request->https ? 'https' : 'http';
        $proto = strtolower(trim(explode(',', $request->header('x-forwarded-proto'))[0]));
        if (!empty($ip['trustedProxy']) && ($proto === 'https' || $proto === 'http')) {
            $scheme = $proto;
        }
        $search = $request->query === '' ? '' : Redactor::redactSearch('?' . $request->query);
        $target = $request->path . $search;
        $host = $request->host;
        $hostname = preg_replace('/:\d{1,5}$/', '', $host) ?: 'localhost';
        $userAgent = $request->header('user-agent');

        $attrs = [
            'http.method' => $request->method,
            'http.target' => $target,
            'http.url' => $host !== '' ? $scheme . '://' . $host . $target : $target,
            'http.scheme' => $scheme,
            'http.flavor' => $request->protocol,
            'net.transport' => 'ip_tcp',
            'net.host.name' => $hostname,
            // Stable HTTP semantic conventions, next to the names the SecureNow pipeline filters on.
            'http.request.method' => $request->method,
            'url.path' => $request->path,
            'url.scheme' => $scheme,
            'server.address' => $hostname,
            'network.protocol.version' => $request->protocol,
        ];
        if ($host !== '') {
            $attrs['http.host'] = $host;
        }
        if ($search !== '') {
            $attrs['url.query'] = substr($search, 1);
        }
        if ($userAgent !== '') {
            $attrs['http.user_agent'] = $userAgent;
            $attrs['user_agent.original'] = $userAgent;
        }
        $length = $request->contentLength();
        if ($length !== null) {
            $attrs['http.request_content_length_uncompressed'] = $length;
        }

        if (($ip['ip'] ?? '') !== '') {
            $attrs['http.client_ip'] = $ip['ip'];
            $attrs['http.client_ip.source'] = $ip['source'];
            $attrs['http.socket_ip'] = $ip['socketIp'];
            $attrs['http.proxy.trusted'] = $ip['trustedProxy'] ? 'true' : 'false';
            $attrs['client.address'] = $ip['ip'];
            if ($ip['socketIp'] !== '') {
                $attrs['net.peer.ip'] = $ip['socketIp'];
                $attrs['network.peer.address'] = $ip['socketIp'];
            }
            if ($ip['forwardedFor'] !== '') {
                $attrs['http.forwarded_for'] = $ip['forwardedFor'];
                $attrs['http.request.header.x_forwarded_for'] = $ip['forwardedFor'];
            }
            if ($ip['realIp'] !== '') {
                $attrs['http.real_ip'] = $ip['realIp'];
                $attrs['http.request.header.x_real_ip'] = $ip['realIp'];
            }
            if ($ip['cfConnectingIp'] !== '') {
                $attrs['http.cf.connecting_ip'] = $ip['cfConnectingIp'];
                $attrs['http.request.header.cf_connecting_ip'] = $ip['cfConnectingIp'];
            }
            if ($ip['trueClientIp'] !== '') {
                $attrs['http.request.header.true_client_ip'] = $ip['trueClientIp'];
            }
            if ($ip['clientIp'] !== '') {
                $attrs['http.request.header.x_client_ip'] = $ip['clientIp'];
            }
        }

        // Presence only: never the values.
        if ($request->header('authorization') !== '') {
            $attrs['http.security.auth_present'] = 'true';
        }
        if ($request->header('cookie') !== '') {
            $attrs['http.security.cookies_present'] = 'true';
        }
        if ($request->header('x-csrf-token') !== '' || $request->header('x-xsrf-token') !== '') {
            $attrs['http.security.csrf_token_present'] = 'true';
        }

        $headers = self::headersAttribute($request);
        if ($headers !== null) {
            $attrs['http.request.headers'] = $headers;
        }
        return $attrs + self::bodyAttributes($request);
    }

    /** Request headers as JSON: credential-bearing ones by name, secret shapes in the rest. */
    public static function headersAttribute(RequestInfo $request): ?string
    {
        $redactor = self::redactor();
        $safe = new \stdClass();
        foreach ($request->headers as $name => $value) {
            $name = (string) $name;
            if ($redactor->isSensitiveHeader($name)) {
                $safe->{$name} = Redactor::MARK;
                continue;
            }
            $safe->{$name} = Util::truncate(Redactor::redactValue(Redactor::redactOtpQuery((string) $value)), 500);
        }
        $serialized = Util::json($safe);
        return strlen($serialized) <= 8192 ? $serialized : null;
    }

    /** @return array<string,mixed> */
    public static function bodyAttributes(RequestInfo $request): array
    {
        $captureBody = Config::bool('capture.body', true);
        $captureMultipart = Config::bool('capture.multipart', true);
        if (!$captureBody && !$captureMultipart) {
            return [];
        }
        if (!in_array($request->method, ['POST', 'PUT', 'PATCH'], true)) {
            return [];
        }
        $contentType = $request->header('content-type');
        $ct = strtolower($contentType);
        $maxBodySize = Config::int('capture.maxBodySize', 10240, 1024);

        if (strpos($ct, 'multipart/form-data') !== false) {
            if (!$captureMultipart) {
                return [
                    'http.request.body' => '[MULTIPART - NOT CAPTURED]',
                    'http.request.body.type' => 'multipart',
                    'http.request.body.note' => 'Multipart capture disabled by config.capture.multipart=false',
                ];
            }
            return self::multipartAttributes($request, $maxBodySize);
        }

        $structured = $captureBody && (
            strpos($ct, 'application/json') !== false
            || strpos($ct, 'application/graphql') !== false
            || strpos($ct, 'application/x-www-form-urlencoded') !== false
        );
        if (!$structured) {
            return [];
        }

        $declared = $request->contentLength();
        if ($declared !== null && $declared > $maxBodySize) {
            return ['http.request.body' => "[TOO LARGE: $declared bytes]", 'http.request.body.size' => $declared];
        }
        $body = $request->body($maxBodySize + 1);
        if ($body === null || $body === '') {
            return [];
        }
        $size = strlen($body);
        if ($size > $maxBodySize) {
            $size = $declared ?? $size;
            return ['http.request.body' => "[TOO LARGE: $size bytes]", 'http.request.body.size' => $size];
        }
        try {
            $redacted = self::redactor()->redactBodyText($body, $contentType);
            if ($redacted === null) {
                return [];
            }
            return [
                'http.request.body' => Util::truncate($redacted['body'], $maxBodySize),
                'http.request.body.type' => $redacted['type'],
                'http.request.body.size' => $size,
            ];
        } catch (\Throwable $e) {
            return [
                'http.request.body' => '[UNPARSEABLE - REDACTED FOR SAFETY]',
                'http.request.body.parse_error' => true,
                'http.request.body.size' => $size,
            ];
        }
    }

    /**
     * Multipart: text fields (redacted) and file metadata. PHP has already parsed the upload, so
     * file content is never read here.
     *
     * @return array<string,mixed>
     */
    private static function multipartAttributes(RequestInfo $request, int $maxBodySize): array
    {
        $redactor = self::redactor();
        $fields = new \stdClass();
        $count = 0;
        foreach ($request->postFields as $name => $value) {
            $name = (string) $name;
            $fields->{$name} = $redactor->isSensitiveField($name)
                ? Redactor::MARK
                : Redactor::redactValue(Util::truncate((string) $value, 1000));
            $count++;
        }
        $parsed = ['fields' => $fields, 'files' => $request->files];
        $attrs = [
            'http.request.body' => Util::truncate(Util::json($parsed), $maxBodySize),
            'http.request.body.type' => 'multipart',
            'http.request.body.fields_count' => $count,
            'http.request.body.files_count' => count($request->files),
        ];
        $size = $request->contentLength();
        if ($size !== null) {
            $attrs['http.request.body.size'] = $size;
        }
        return $attrs;
    }
}
