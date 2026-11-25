<?php

declare(strict_types=1);

namespace SecureNow\Firewall;

/** A response the firewall (or the session guard) decided to send instead of running the app. */
final class Verdict
{
    public int $status;
    /** @var array<string,string> */
    public array $headers;
    public string $body;
    /** blocked | rate_limited | challenged | challenge_passed | challenge_failed | session_revoked */
    public string $action;
    /** @var string[] full Set-Cookie header values */
    public array $cookies = [];
    /** @var array<string,mixed> attributes for the request span */
    public array $attributes = [];

    /** @param array<string,string> $headers */
    public function __construct(string $action, int $status, array $headers, string $body)
    {
        $this->action = $action;
        $this->status = $status;
        $this->headers = $headers;
        $this->body = $body;
    }

    /** Send through PHP's SAPI (PHP-FPM, mod_php, built-in server). */
    public function send(): void
    {
        if (!headers_sent()) {
            http_response_code($this->status);
            foreach ($this->headers as $name => $value) {
                header($name . ': ' . $value, true);
            }
            foreach ($this->cookies as $cookie) {
                header('Set-Cookie: ' . $cookie, false);
            }
        }
        echo $this->body;
    }
}
