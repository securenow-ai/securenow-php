# SecureNow PHP SDK — Agent Skill

The integration playbook for the `securenow/securenow` Composer package. A coding agent that reads only
this file can plug SecureNow into a PHP web app, turn on every feature, deploy it and prove it works.
It describes 1.0.0. The Node.js playbook is `SKILL-API.md` in the npm package; the CLI reference is
`SKILL-CLI.md`.

## Rules for the agent

1. Never print, paste or commit `.securenow/runtime.json`, `.securenow/runtime.php`,
   `.securenow/admin.json` or `.securenow/credentials*.json`: they hold the runtime API key
   (`snk_live_...`) and the admin token. Mask keys in summaries.
2. Sign-in is `vendor/bin/securenow login` (PHP only) or `npx securenow login` (also sets up the admin
   CLI and MCP) from the project root. Wait for the person to finish the browser step. Never open an
   auth URL yourself.
3. If the project folder is served by the web server (WordPress, a site with `index.php` at the top),
   the credentials must be `.securenow/runtime.php`, never `runtime.json`: run
   `vendor/bin/securenow init --format php`. A `.json` file there can be downloaded by anyone.
4. Configuration lives in the credentials file. The SDK reads these environment variables and no
   others: `SECURENOW_CREDENTIALS`, `SECURENOW_CREDENTIALS_FILE`, `SECURENOW_CACHE_DIR`,
   `SECURENOW_DISABLED`, `SECURENOW_AUTOSTART`, `SECURENOW_DEBUG`. Do not create `.env` entries for
   anything else, and remember PHP-FPM passes no environment to PHP unless the pool says so.
5. Ask the person before anything that changes enforcement in production: blocks, allowlist entries,
   rate limits, challenges, session revocations, rule promotion, `firewall.failMode: closed`,
   `firewall.iptables`, `firewall.cloud`.
6. Do not set `OTEL_PHP_AUTOLOAD_ENABLED` or `OTEL_EXPORTER_*` next to SecureNow: SecureNow registers
   OpenTelemetry itself. Keep the project's own middleware, handlers and loggers.

## 1. Your stack → what to do

| Your stack | Wire it with |
|---|---|
| Laravel (tested on 13, should work from 9; PHP-FPM, `artisan serve`) | Nothing: the package is auto-discovered |
| Laravel Octane | Nothing: the provider adds its middleware when Octane runs (not tested end to end) |
| Symfony (tested on the current release, needs 5.4 or later) | One line in `config/bundles.php` (section 2) |
| Slim 4, Mezzio, another PSR-15 app under PHP-FPM | `$app->add(new \SecureNow\Integrations\Psr15\SecureNowMiddleware());` before the routing middleware |
| WordPress | `require` of `prepend.php` as the first line of `wp-config.php`, plus the mu-plugin |
| Plain PHP, a legacy app, anything without `vendor/autoload.php` at the top | `auto_prepend_file = /path/to/vendor/securenow/securenow/prepend.php` |
| RoadRunner, FrankenPHP worker mode, Swoole (one request at a time per worker) | `new SecureNowMiddleware($psr17ResponseFactory)` as the outermost PSR-15 middleware (not tested end to end) |
| Coroutine servers that interleave requests in one worker | not supported |
| PHP 7.x, 32-bit PHP | not supported: PHP 8.0 or later, 64-bit |

## 2. Setup checklist

1. **Install.** `composer require securenow/securenow`. No required dependencies; `ext-curl` is
   recommended.
2. **Log in.** `vendor/bin/securenow login` from the project root. The person picks or creates the app
   in the browser. It writes `.securenow/runtime.json` (or `runtime.php` in a web-served folder) and
   adds it to `.gitignore`. Without a browser:
   `vendor/bin/securenow init --api-key snk_live_... --app <app key> [--env production]`.
   If `npx securenow login` was used instead, the PHP SDK reads the same file; run
   `npx securenow init` to print the PHP steps for the detected framework.
3. **Wire.** Most apps need nothing: the SDK starts when `vendor/autoload.php` loads.

   ```php
   // Symfony: config/bundles.php
   SecureNow\Integrations\Symfony\SecureNowBundle::class => ['all' => true],
   ```

   ```php
   // Slim 4: the middleware is added BEFORE addRoutingMiddleware(), so it runs after routing
   $app->add(new \SecureNow\Integrations\Psr15\SecureNowMiddleware());
   $app->addRoutingMiddleware();
   ```

   ```php
   // WordPress: first line of wp-config.php
   require __DIR__ . '/vendor/securenow/securenow/prepend.php';
   // and copy vendor/securenow/securenow/src/Integrations/WordPress/securenow.php to wp-content/mu-plugins/
   ```

   ```ini
   ; Plain PHP: php.ini, .user.ini in the web root, or the PHP-FPM pool (php_admin_value[auto_prepend_file] = ...)
   auto_prepend_file = /var/www/app/vendor/securenow/securenow/prepend.php
   ```

4. **Deploy credentials.** Ship the credentials file as `<project>/.securenow/runtime.json` (or
   `runtime.php`), readable by the user PHP runs as and nobody else (`chown www-data`, `chmod 600`).
   Or point `SECURENOW_CREDENTIALS_FILE` at a file outside the project. Or store the JSON (raw or
   base64) in `SECURENOW_CREDENTIALS`; under PHP-FPM that needs `env[SECURENOW_CREDENTIALS] = ...`
   or `clear_env = no` in the pool. For a per-environment file: `npx securenow credentials runtime
   --env production`.
5. **Verify.** `vendor/bin/securenow doctor`, then one real request to the app, then
   `sudo -u www-data vendor/bin/securenow status` (the user PHP runs as) and `npx securenow status`.

## 3. What is automatic

No application code is involved in any of these:

- A span per request: method, target, route template (Laravel, Symfony, Slim, WordPress REST; a
  plain page is its own route), status, client address and how it was resolved, redacted headers,
  redacted body (JSON, form, GraphQL; multipart as field values and file names, types and sizes).
- PHP warnings, notices and deprecations as log records; uncaught exceptions and fatal errors as
  FATAL log records with `exception.type`, `exception.message`, `exception.stacktrace`, and an error
  status on the request span. The app's own error handlers keep running.
- Laravel: every log line (`Log::...`) and reported exception. Symfony: every Monolog channel.
- Sign-in events from Laravel (`auth.login.success`, `auth.login.failure`, `auth.lockout`,
  `auth.logout`, `auth.password_reset.completed`, `auth.signup`), Symfony Security
  (`auth.login.success`, `auth.login.failure`, `auth.logout`) and WordPress (`wp_login`,
  `wp_login_failed`, ...). Turn off with `"events": { "auth": false }`.
- The firewall: blocked IPs and ranges (IPv4, IPv6), the allowlist, route-scoped blocks, rate
  limits, proof-of-work challenges, Scraper Shield user-agent rules. It starts when the credentials
  hold a `snk_live_` runtime key, and answers before the framework boots.
- With the `opentelemetry` extension and OpenTelemetry packages installed: database, HTTP-client
  and framework spans under the request span (section 6).

## 4. Configuration: the credentials file

The same file and keys as the Node.js SDK. The ones worth knowing:

```json
{
  "app": { "key": "<app uuid>", "name": "my-app" },
  "apiKey": "snk_live_...",
  "config": {
    "runtime": { "deploymentEnvironment": "production", "cacheDir": "/var/lib/securenow", "cli": false },
    "capture": { "body": true, "multipart": true, "maxBodySize": 10240, "sensitiveFields": ["internalRef"] },
    "logging": { "enabled": true, "redact": true, "phpErrors": true },
    "networking": { "trustedProxies": ["cloudflare", "203.0.113.10", "198.51.100.0/24"] },
    "firewall": { "failMode": "open", "statusCode": 403, "rateLimitStore": "redis://redis:6379" },
    "sessions": { "guard": true, "capture": true, "cookieNames": ["my_session"] },
    "events": { "auth": true },
    "otel": { "bridge": true, "logLevel": "error" }
  }
}
```

`runtime.php` is the same document as a PHP array: `<?php return ['apiKey' => '...', 'app' => [...], 'config' => [...]];`

- `networking.trustedProxies`: private, loopback and Unix-socket connections are trusted already
  (nginx in front of PHP-FPM passes the visitor's address). Add public proxies or `"cloudflare"`.
  Without it, behind a public proxy every visitor has the proxy's address.
- `runtime.cacheDir`: where the SDK keeps the synced firewall policy and telemetry waiting to be
  sent. Default: a private folder (0700) per app and per user in the system temp directory. Set it
  when the temp directory is not writable or is wiped often.
- `firewall.rateLimitStore`: counters are shared through Redis when set, else APCu (one PHP-FPM
  pool), else files (one machine). Windows are fixed and aligned to the clock.
- `sessions.cookieNames`: `PHPSESSID`, `wordpress_logged_in_*` and common names are known. Laravel
  needs nothing: its integration uses Laravel's own session id.
- `runtime.cli`, `logging.phpErrors`, `events.auth`, `otel.bridge` and `runtime.cacheDir` exist in the
  PHP SDK only.
- `SECURENOW_DISABLED=1` turns the SDK off for one process: use it for test runs (`phpunit.xml`:
  `<env name="SECURENOW_DISABLED" value="1"/>`).

## 5. Features in code

```php
use SecureNow\SecureNow;

// Security events (never throws; ip and user agent are filled in inside a request)
SecureNow::track('auth.login.failure', ['userId' => $email, 'attributes' => ['method' => 'password']]);
SecureNow::track('auth.login.success', ['userId' => (string) $user->id, 'sessionId' => SecureNow::sessionHash($token)]);

// Session revocation, when the app decides the answer itself
$result = SecureNow::checkSession();                         // the current request
if ($result['revoked']) { /* answer 401 and clear the session */ }
SecureNow::checkSession(['sessionId' => $sid, 'userId' => (string) $user->id]);   // the app's own identifiers

// Logs
SecureNow::log('warning', 'Payment declined for order {order}', ['order' => $id]);
$logger = SecureNow::logger('billing');                      // Psr\Log\LoggerInterface when psr/log is installed
$monolog->pushHandler(new \SecureNow\Integrations\Monolog\SecureNowHandler());

// The request span
SecureNow::setUser($user->id);
SecureNow::setRoute('/orders/{id}');                         // front controllers without a framework integration
$pdf = SecureNow::span('render-invoice', fn () => $renderer->render($invoice));
SecureNow::recordException($e);                              // an exception the app caught

// The visitor's address, resolved with the trusted-proxy rules
$ip = SecureNow::clientIp();

// Long-running commands: send what is buffered now
SecureNow::flush();
```

Recommended authentication events: `auth.login.failure`, `auth.login.success`,
`auth.otp.send.requested`, `auth.otp.verify.failure`, `auth.password_reset.requested`,
`auth.password_reset.completed`, `auth.mfa.challenge.failure`, `auth.session.revoked`.

Zero-code session guard: `"sessions": { "guard": true, "capture": true }` answers 401 (and clears the
session cookie) for a revoked session or user. A session id is the SHA-256 of the Bearer token or
session cookie; a user id is the JWT `sub`. Revoke with `npx securenow revoke session <id>` or
`revoke user <id>`.

## 6. OpenTelemetry (optional: spans inside the request)

```bash
pecl install opentelemetry                 # or install-php-extensions opentelemetry; php.ini: extension=opentelemetry.so
composer config allow-plugins.php-http/discovery false
composer config allow-plugins.tbachert/spi true
composer require open-telemetry/sdk nyholm/psr7 open-telemetry/opentelemetry-auto-pdo
composer require open-telemetry/opentelemetry-auto-laravel     # or -auto-symfony, -auto-slim, -auto-wordpress, -auto-psr18, -auto-guzzle
```

Nothing else: no `OTEL_*` variable. Each request keeps one server span (SecureNow's); the framework's
own server span is exported as an internal span under it, database and HTTP-client spans as client
spans, with `db.statement` and the other names SecureNow's queries read.

## 7. Deployment

```nginx
# nginx + PHP-FPM: nothing SecureNow-specific. The SDK reads REMOTE_ADDR, which nginx passes.
location ~ \.php$ { include fastcgi_params; fastcgi_pass unix:/run/php/php-fpm.sock; }
```

```dockerfile
COPY .securenow/credentials.production.json /var/www/app/.securenow/runtime.json
RUN chown www-data /var/www/app/.securenow/runtime.json && chmod 600 /var/www/app/.securenow/runtime.json
```

```ini
; systemd unit for the optional agent (policy sync on a timer, telemetry shipping, OS firewall and cloud WAF layers)
[Service]
WorkingDirectory=/var/www/app
ExecStart=/usr/bin/php vendor/bin/securenow agent
User=www-data
Restart=always
; for "firewall": { "iptables": true } run it as root instead:  ExecStart=/usr/bin/php vendor/bin/securenow agent --user www-data
; in a container based on an official php image, the stop signal is SIGQUIT: the agent handles it
```

- PHP-FPM: telemetry is sent after the response (`fastcgi_finish_request`); the visitor does not wait.
- Apache `mod_php` has no such call: sending happens at the end of the request with a 3-second cap.
  Run the agent there, so requests only write to the spool.
- Several servers: each keeps its own cache folder and syncs on its own. Use Redis for shared
  rate-limit counters.
- The policy reaches a server within about 10 seconds of traffic. With the agent it arrives in under a
  second (the agent keeps a long-poll open to SecureNow).
- Scraper Shield never blocks the account's own addresses, the app server's address or reserved ranges
  (the API sends them as exempt): test a user-agent rule with `vendor/bin/securenow firewall:check
  <a public ip> --ua "<user agent>"`, not from your own machine.
- A request the firewall answers (403, 429, challenge) is reported as a firewall hit, not as a trace.

## 8. Verification checklist

1. `vendor/bin/securenow doctor` prints `ok` for credentials, runtime key, cache folder, traces
   accepted, logs accepted and firewall sync.
2. One real request to the app, then `sudo -u www-data vendor/bin/securenow status`: "Firewall
   enforcing", "Telemetry last sent ... {"traces":200}".
3. `npx securenow traces list` (or the dashboard) shows the request with its route and client IP.
4. `vendor/bin/securenow firewall:check <ip> --path /login --method POST` shows what the firewall
   would answer for an address.

`vendor/bin/securenow test` and `doctor` prove the connection, not that the app runs: the dashboard
shows the app as being set up until a real request arrives.

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No SecureNow credentials found` | The file is not in the project root (or a parent of the web root). Move it, or set `SECURENOW_CREDENTIALS_FILE`. |
| `test` passes, nothing arrives from the app | The entry file does not load `vendor/autoload.php` (legacy app): set `auto_prepend_file`. Or the web user cannot read the credentials file. |
| `REFUSED ... HTTP 401/403` | The runtime key was revoked or belongs to another app: `vendor/bin/securenow login` again. |
| `REFUSED ... HTTP 402` | Trial ended or subscription inactive. |
| Every request has the proxy's IP | The proxy is on a public address: add it to `networking.trustedProxies`. `http.client_ip.source` and `http.socket_ip` on the span show what the SDK saw. |
| `status` says "no policy yet" but the app blocks | `status` ran as another user than PHP: `sudo -u www-data vendor/bin/securenow status`. |
| Cache folder not writable | Set `runtime.cacheDir` to a folder the web user owns. |
| No database or framework spans | The `opentelemetry` extension or `open-telemetry/sdk` is missing (section 6), or `OTEL_PHP_AUTOLOAD_ENABLED` is set (unset it). |
| Firewall never syncs | Outbound HTTPS to `ingest.securenow.ai` is blocked. |
| Need more detail | `"otel": { "logLevel": "debug" }` or `SECURENOW_DEBUG=1`: the SDK writes to the PHP error log. |

## 10. Tested on, and honest limits

- Tested with PHP 8.3 on nginx + PHP-FPM: plain PHP (`auto_prepend_file`), Slim 4, Laravel 13,
  Symfony; with and without the `opentelemetry` extension and APCu. Plain PHP on the built-in server
  with PHP 8.0, 8.1 and 8.5. Unit and parity tests (same inputs through the Node SDK) on PHP 8.0 to 8.5.
- Tested live against SecureNow from an AWS EC2 host (Ubuntu 24.04): telemetry, blocks, rate limits,
  challenges, session revocation, Scraper Shield rules, hit reports, the agent's long-poll (a block is
  enforced in under a second) and the OS firewall layer (iptables with the nftables backend: rules
  loaded and removed; packet drops from a listed address not exercised).
- Not tested end to end yet: WordPress, Apache `mod_php`, LiteSpeed, FrankenPHP, RoadRunner, Swoole,
  Laravel Octane, the cloud WAF pushes against real provider accounts.
- Not in PHP: the Node SDK's TCP-drop layer (PHP does not own the socket); the admin CLI and the MCP
  server (use `npx securenow` or the hosted MCP server).
- Not supported: coroutine servers that interleave requests in one worker, serverless PHP runtimes
  (not tested), WebSocket messages.
- SecureNow does not need the source code; sensitive fields are redacted in the process before
  telemetry is exported.

## 11. Package entry points

| Entry point | What it is |
|---|---|
| `vendor/autoload.php` (Composer) | Starts the SDK for web requests |
| `vendor/securenow/securenow/prepend.php` | Starts it from `auto_prepend_file` or a `require`, without Composer |
| `SecureNow\SecureNow::start()` | Start by hand (`SECURENOW_AUTOSTART=0`); idempotent |
| `SecureNow\SecureNow::track()`, `log()`, `logger()`, `setUser()`, `setRoute()`, `span()`, `recordException()`, `checkSession()`, `clientIp()`, `flush()` | The public API |
| `SecureNow\SecureNow::beginRequest()` / `endRequest()` | One request in a worker runtime |
| `SecureNow\Integrations\Laravel\SecureNowServiceProvider` | Auto-discovered |
| `SecureNow\Integrations\Symfony\SecureNowBundle` | `config/bundles.php` |
| `SecureNow\Integrations\Psr15\SecureNowMiddleware` | Slim, Mezzio, worker runtimes |
| `SecureNow\Integrations\Monolog\SecureNowHandler` | Monolog 2 and 3 |
| `vendor/bin/securenow` | `login`, `init`, `status`, `doctor`, `test`, `sync`, `firewall:check`, `flush`, `agent` |
