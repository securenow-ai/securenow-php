<?php

declare(strict_types=1);

namespace SecureNow\Http;

/**
 * Outbound HTTP for the SDK: cURL when the extension is loaded (parallel requests, millisecond
 * timeouts), PHP streams otherwise. Never throws: a failed request comes back with status 0.
 */
final class Transport
{
    /** @var callable|null test hook: fn(array $request): array */
    private static $fake = null;
    /** @var mixed */
    private static $share = null;

    public static function fake(?callable $handler): void
    {
        self::$fake = $handler;
    }

    /**
     * @param array<string,string> $headers
     * @return array{status:int,headers:array<string,string>,body:string,error:?string}
     */
    public static function request(string $method, string $url, array $headers = [], ?string $body = null, int $timeoutMs = 5000): array
    {
        $results = self::multi([['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body, 'timeoutMs' => $timeoutMs]]);
        return $results[0];
    }

    /**
     * Sends the requests at the same time (cURL) and returns the results in the same order.
     *
     * @param array<int|string,array{method:string,url:string,headers?:array<string,string>,body?:?string,timeoutMs?:int}> $requests
     * @return array<int|string,array{status:int,headers:array<string,string>,body:string,error:?string}>
     */
    public static function multi(array $requests): array
    {
        if (!$requests) {
            return [];
        }
        if (self::$fake !== null) {
            $out = [];
            foreach ($requests as $key => $request) {
                $out[$key] = (self::$fake)($request) + ['status' => 0, 'headers' => [], 'body' => '', 'error' => null];
            }
            return $out;
        }
        if (function_exists('curl_multi_init')) {
            return self::curlMulti($requests);
        }
        $out = [];
        foreach ($requests as $key => $request) {
            $out[$key] = self::stream($request);
        }
        return $out;
    }

    /**
     * @param array<string,string> $headers
     * @return string[]
     */
    private static function headerLines(array $headers, bool $hasBody): array
    {
        $lines = [];
        $seen = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . str_replace(["\r", "\n"], '', (string) $value);
            $seen[strtolower((string) $name)] = true;
        }
        if (!isset($seen['user-agent'])) {
            $lines[] = 'User-Agent: securenow-php/' . \SecureNow\Version::SDK;
        }
        if ($hasBody) {
            $lines[] = 'Expect:';
        }
        return $lines;
    }

    /** @return mixed */
    private static function shareHandle()
    {
        if (self::$share !== null) {
            return self::$share ?: null;
        }
        self::$share = false;
        // PHP 8.5: connections, DNS answers and TLS sessions survive across requests in a worker.
        if (function_exists('curl_share_init_persistent')) {
            try {
                self::$share = \curl_share_init_persistent([CURL_LOCK_DATA_DNS, CURL_LOCK_DATA_CONNECT, CURL_LOCK_DATA_SSL_SESSION]);
            } catch (\Throwable $e) {
                self::$share = false;
            }
        }
        return self::$share ?: null;
    }

    /**
     * @param array<int|string,array<string,mixed>> $requests
     * @return array<int|string,array{status:int,headers:array<string,string>,body:string,error:?string}>
     */
    private static function curlMulti(array $requests): array
    {
        $multi = curl_multi_init();
        $handles = [];
        $responseHeaders = [];
        $share = self::shareHandle();
        foreach ($requests as $key => $request) {
            $ch = curl_init();
            $timeout = max(100, (int) ($request['timeoutMs'] ?? 5000));
            $body = $request['body'] ?? null;
            $responseHeaders[$key] = [];
            $options = [
                CURLOPT_URL => $request['url'],
                CURLOPT_CUSTOMREQUEST => strtoupper((string) $request['method']),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_NOSIGNAL => true,
                CURLOPT_TIMEOUT_MS => $timeout,
                CURLOPT_CONNECTTIMEOUT_MS => min($timeout, 3000),
                CURLOPT_HTTPHEADER => self::headerLines($request['headers'] ?? [], $body !== null),
                CURLOPT_ENCODING => '',
                CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders, $key): int {
                    $i = strpos($line, ':');
                    if ($i !== false) {
                        $responseHeaders[$key][strtolower(trim(substr($line, 0, $i)))] = trim(substr($line, $i + 1));
                    }
                    return strlen($line);
                },
            ];
            if ($body !== null) {
                $options[CURLOPT_POSTFIELDS] = $body;
            }
            if ($share !== null) {
                $options[CURLOPT_SHARE] = $share;
            }
            curl_setopt_array($ch, $options);
            curl_multi_add_handle($multi, $ch);
            $handles[$key] = $ch;
        }

        $running = 0;
        do {
            $status = curl_multi_exec($multi, $running);
            if ($running > 0) {
                if (curl_multi_select($multi, 0.5) === -1) {
                    usleep(1000);
                }
            }
        } while ($running > 0 && $status === CURLM_OK);

        $out = [];
        foreach ($handles as $key => $ch) {
            $body = curl_multi_getcontent($ch);
            $errno = curl_errno($ch);
            $out[$key] = [
                'status' => $errno ? 0 : (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
                'headers' => $responseHeaders[$key],
                'body' => is_string($body) ? $body : '',
                'error' => $errno ? curl_error($ch) . ' (curl ' . $errno . ')' : null,
            ];
            curl_multi_remove_handle($multi, $ch);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
        }
        curl_multi_close($multi);
        return $out;
    }

    /**
     * @param array<string,mixed> $request
     * @return array{status:int,headers:array<string,string>,body:string,error:?string}
     */
    private static function stream(array $request): array
    {
        $body = $request['body'] ?? null;
        $timeout = max(100, (int) ($request['timeoutMs'] ?? 5000));
        $headers = self::headerLines($request['headers'] ?? [], false);
        $headers[] = 'Connection: close';
        $context = stream_context_create([
            'http' => [
                'method' => strtoupper((string) $request['method']),
                'header' => implode("\r\n", $headers),
                'content' => $body ?? '',
                'timeout' => $timeout / 1000,
                'ignore_errors' => true,
                'follow_location' => 0,
                'protocol_version' => 1.1,
            ],
        ]);
        $http_response_header = [];
        $data = @file_get_contents((string) $request['url'], false, $context);
        if ($data === false) {
            $last = error_get_last();
            return ['status' => 0, 'headers' => [], 'body' => '', 'error' => (string) ($last['message'] ?? 'request failed')];
        }
        $status = 0;
        $responseHeaders = [];
        foreach ($http_response_header as $line) {
            if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m)) {
                $status = (int) $m[1];
                $responseHeaders = [];
                continue;
            }
            $i = strpos($line, ':');
            if ($i !== false) {
                $responseHeaders[strtolower(trim(substr($line, 0, $i)))] = trim(substr($line, $i + 1));
            }
        }
        return ['status' => $status, 'headers' => $responseHeaders, 'body' => $data, 'error' => null];
    }
}
