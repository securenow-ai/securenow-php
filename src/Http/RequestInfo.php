<?php

declare(strict_types=1);

namespace SecureNow\Http;

/**
 * The incoming request as SecureNow reads it, built from PHP's globals (PHP-FPM, mod_php, the
 * built-in server) or from a PSR-7 request (RoadRunner, FrankenPHP workers, Swoole, Octane).
 */
final class RequestInfo
{
    public string $method = 'GET';
    /** Path and query exactly as received. */
    public string $target = '/';
    public string $path = '/';
    /** Query string without the leading "?". */
    public string $query = '';
    /** @var array<string,string> lower-case header name => value */
    public array $headers = [];
    public string $remoteAddr = '';
    public bool $https = false;
    public string $host = '';
    public string $protocol = '1.1';
    /** @var array<string,string> POST fields (multipart capture) */
    public array $postFields = [];
    /** @var array<int,array{field:string,filename:string,contentType:string,size:int}> */
    public array $files = [];
    public float $startTime = 0.0;
    public string $scriptName = '';

    /** @var callable|null fn(int $maxBytes): ?string */
    private $bodyReader = null;
    /** @var array<string,string>|null */
    private ?array $cookies = null;

    public static function fromGlobals(): self
    {
        $r = new self();
        $server = $_SERVER;
        $r->method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
        $uri = (string) ($server['REQUEST_URI'] ?? '/');
        if (preg_match('~^https?://[^/]+~i', $uri, $m)) {
            $uri = substr($uri, strlen($m[0]));
        }
        $r->setTarget($uri === '' ? '/' : $uri);

        $headers = [];
        if (function_exists('getallheaders')) {
            $all = @getallheaders();
            if (is_array($all)) {
                foreach ($all as $name => $value) {
                    $headers[strtolower((string) $name)] = (string) $value;
                }
            }
        }
        if (!$headers) {
            foreach ($server as $key => $value) {
                if (!is_string($value)) {
                    continue;
                }
                if (strncmp($key, 'HTTP_', 5) === 0) {
                    $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
                } elseif ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                    if ($value !== '') {
                        $headers[strtolower(str_replace('_', '-', $key))] = $value;
                    }
                }
            }
        }
        $r->headers = $headers;
        $r->remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        $r->https = ($https !== '' && $https !== 'off') || (string) ($server['SERVER_PORT'] ?? '') === '443';
        $r->host = (string) ($headers['host'] ?? ($server['SERVER_NAME'] ?? ''));
        $protocol = (string) ($server['SERVER_PROTOCOL'] ?? 'HTTP/1.1');
        $r->protocol = strncasecmp($protocol, 'HTTP/', 5) === 0 ? substr($protocol, 5) : $protocol;
        $r->startTime = isset($server['REQUEST_TIME_FLOAT']) ? (float) $server['REQUEST_TIME_FLOAT'] : microtime(true);
        $r->scriptName = (string) ($server['SCRIPT_NAME'] ?? '');

        $r->postFields = self::flattenFields($_POST ?? []);
        $r->files = self::flattenFiles($_FILES ?? []);
        $r->bodyReader = static function (int $max): ?string {
            $body = @file_get_contents('php://input', false, null, 0, $max);
            return $body === false ? null : $body;
        };
        return $r;
    }

    /**
     * @param object $request Psr\Http\Message\ServerRequestInterface
     */
    public static function fromPsr7(object $request): self
    {
        $r = new self();
        $r->method = strtoupper((string) $request->getMethod());
        $uri = $request->getUri();
        $path = (string) $uri->getPath();
        $query = (string) $uri->getQuery();
        $r->setTarget(($path === '' ? '/' : $path) . ($query !== '' ? '?' . $query : ''));
        foreach ($request->getHeaders() as $name => $values) {
            $r->headers[strtolower((string) $name)] = implode(', ', (array) $values);
        }
        $server = $request->getServerParams();
        $r->remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
        $r->https = strtolower((string) $uri->getScheme()) === 'https';
        $r->host = (string) ($r->headers['host'] ?? $uri->getHost());
        $r->protocol = (string) $request->getProtocolVersion();
        $r->startTime = isset($server['REQUEST_TIME_FLOAT']) ? (float) $server['REQUEST_TIME_FLOAT'] : microtime(true);
        $r->scriptName = (string) ($server['SCRIPT_NAME'] ?? '');
        $parsed = $request->getParsedBody();
        $r->postFields = is_array($parsed) ? self::flattenFields($parsed) : [];
        foreach (self::walkUploadedFiles($request->getUploadedFiles()) as $field => $file) {
            $r->files[] = [
                'field' => $field,
                'filename' => (string) $file->getClientFilename(),
                'contentType' => (string) ($file->getClientMediaType() ?: 'unknown'),
                'size' => (int) $file->getSize(),
            ];
        }
        $r->bodyReader = static function (int $max) use ($request): ?string {
            try {
                $body = $request->getBody();
                if (!$body->isSeekable()) {
                    return null;
                }
                $pos = $body->tell();
                $body->rewind();
                $data = $body->read($max);
                $body->seek($pos);
                return $data;
            } catch (\Throwable $e) {
                return null;
            }
        };
        return $r;
    }

    /**
     * @param object $request Symfony\Component\HttpFoundation\Request (Laravel's request extends it)
     */
    public static function fromSymfony(object $request): self
    {
        $r = new self();
        $r->method = strtoupper((string) (method_exists($request, 'getRealMethod') ? $request->getRealMethod() : $request->getMethod()));
        $uri = (string) $request->getRequestUri();
        $r->setTarget($uri === '' ? '/' : $uri);
        foreach ($request->headers->all() as $name => $values) {
            $r->headers[strtolower((string) $name)] = implode(', ', array_map('strval', (array) $values));
        }
        $r->remoteAddr = (string) $request->server->get('REMOTE_ADDR', '');
        $https = strtolower((string) $request->server->get('HTTPS', ''));
        $r->https = ($https !== '' && $https !== 'off') || (string) $request->server->get('SERVER_PORT', '') === '443';
        $r->host = (string) ($r->headers['host'] ?? $request->server->get('SERVER_NAME', ''));
        $protocol = (string) $request->server->get('SERVER_PROTOCOL', 'HTTP/1.1');
        $r->protocol = strncasecmp($protocol, 'HTTP/', 5) === 0 ? substr($protocol, 5) : $protocol;
        $start = $request->server->get('REQUEST_TIME_FLOAT');
        $r->startTime = is_numeric($start) ? (float) $start : microtime(true);
        $r->scriptName = (string) $request->server->get('SCRIPT_NAME', '');
        $r->postFields = self::flattenFields($request->request->all());
        foreach (self::walkSymfonyFiles($request->files->all()) as $field => $file) {
            $r->files[] = [
                'field' => $field,
                'filename' => (string) $file->getClientOriginalName(),
                'contentType' => (string) ($file->getClientMimeType() ?: 'unknown'),
                'size' => (int) $file->getSize(),
            ];
        }
        $r->bodyReader = static function (int $max) use ($request): ?string {
            $content = $request->getContent();
            return is_string($content) ? substr($content, 0, $max) : null;
        };
        return $r;
    }

    /**
     * @param array<mixed> $files
     * @return array<string,object>
     */
    private static function walkSymfonyFiles(array $files, string $prefix = ''): array
    {
        $out = [];
        foreach ($files as $key => $file) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($file)) {
                $out += self::walkSymfonyFiles($file, $name);
            } elseif (is_object($file) && method_exists($file, 'getClientOriginalName')) {
                $out[$name] = $file;
            }
        }
        return $out;
    }

    public function setTarget(string $target): void
    {
        $this->target = $target;
        $q = strpos($target, '?');
        if ($q === false) {
            $this->path = $target;
            $this->query = '';
        } else {
            $this->path = substr($target, 0, $q);
            $this->query = substr($target, $q + 1);
        }
        $hash = strpos($this->path, '#');
        if ($hash !== false) {
            $this->path = substr($this->path, 0, $hash);
        }
        if ($this->path === '') {
            $this->path = '/';
        }
    }

    public function header(string $name): string
    {
        return $this->headers[strtolower($name)] ?? '';
    }

    /** Cookies as sent (not URL-decoded), so a session cookie hashes the same way on every SDK. */
    public function cookies(): array
    {
        if ($this->cookies !== null) {
            return $this->cookies;
        }
        $out = [];
        $header = $this->header('cookie');
        if ($header !== '') {
            foreach (explode(';', $header) as $part) {
                $i = strpos($part, '=');
                if ($i === false || $i === 0) {
                    continue;
                }
                $name = trim(substr($part, 0, $i));
                if ($name !== '' && !isset($out[$name])) {
                    $out[$name] = trim(substr($part, $i + 1));
                }
            }
        }
        return $this->cookies = $out;
    }

    public function cookie(string $name): string
    {
        return $this->cookies()[$name] ?? '';
    }

    /** The request body, at most $max bytes, without consuming it: the app still reads it as usual. */
    public function body(int $max): ?string
    {
        if ($this->bodyReader === null) {
            return null;
        }
        try {
            return ($this->bodyReader)($max);
        } catch (\Throwable $e) {
            return null;
        }
    }

    public function contentLength(): ?int
    {
        $raw = $this->header('content-length');
        return ctype_digit($raw) ? (int) $raw : null;
    }

    /**
     * user[name]=x arrives in PHP as a nested array; capture reports the field names as sent.
     *
     * @param array<mixed> $fields
     * @return array<string,string>
     */
    private static function flattenFields(array $fields, string $prefix = '', int $depth = 0): array
    {
        $out = [];
        foreach ($fields as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($value)) {
                if ($depth < 5) {
                    $out += self::flattenFields($value, $name, $depth + 1);
                }
            } elseif (is_scalar($value)) {
                $out[$name] = (string) $value;
            }
            if (count($out) >= 100) {
                break;
            }
        }
        return $out;
    }

    /**
     * @param array<mixed> $files
     * @return array<int,array{field:string,filename:string,contentType:string,size:int}>
     */
    private static function flattenFiles(array $files): array
    {
        $out = [];
        foreach ($files as $field => $file) {
            if (!is_array($file) || !array_key_exists('name', $file)) {
                continue;
            }
            self::collectFile($out, (string) $field, $file['name'], $file['type'] ?? '', $file['size'] ?? 0);
        }
        return $out;
    }

    /**
     * @param array<int,array{field:string,filename:string,contentType:string,size:int}> $out
     * @param mixed $name
     * @param mixed $type
     * @param mixed $size
     */
    private static function collectFile(array &$out, string $field, $name, $type, $size): void
    {
        if (count($out) >= 100) {
            return;
        }
        if (is_array($name)) {
            foreach ($name as $key => $sub) {
                self::collectFile(
                    $out,
                    $field . '[' . $key . ']',
                    $sub,
                    is_array($type) ? ($type[$key] ?? '') : '',
                    is_array($size) ? ($size[$key] ?? 0) : 0
                );
            }
            return;
        }
        if ((string) $name === '') {
            return;
        }
        $out[] = [
            'field' => $field,
            'filename' => (string) $name,
            'contentType' => is_string($type) && $type !== '' ? $type : 'unknown',
            'size' => (int) (is_scalar($size) ? $size : 0),
        ];
    }

    /**
     * @param array<mixed> $files
     * @return array<string,object>
     */
    private static function walkUploadedFiles(array $files, string $prefix = ''): array
    {
        $out = [];
        foreach ($files as $key => $file) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($file)) {
                $out += self::walkUploadedFiles($file, $name);
            } elseif (is_object($file) && method_exists($file, 'getClientFilename')) {
                $out[$name] = $file;
            }
        }
        return $out;
    }
}
