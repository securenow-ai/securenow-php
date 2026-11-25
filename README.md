# SecureNow for PHP

Monitor and protect a PHP app with one Composer package: request traces, logs, crash capture, redacted
request capture, and an in-app firewall (IP blocking, allowlist, rate limits, proof-of-work challenges,
scraper blocking, session revocation). Laravel, Symfony, Slim, WordPress and plain PHP.

It is the PHP counterpart of the `securenow` npm package: the same credentials file, the same
telemetry fields, the same dashboard, alert rules, CLI and MCP tools on the SecureNow side.

```bash
composer require securenow/securenow
vendor/bin/securenow login     # sign in, pick the app; writes .securenow/runtime.json
vendor/bin/securenow test      # sends a test trace and log
```

That is the whole setup for most apps. The SDK starts when `vendor/autoload.php` loads, which every
framework does at the top of its entry file, so there is no code to add.

- **PHP** 8.0 to 8.5, 64-bit. **Required extensions:** `json`. **Recommended:** `curl`.
- **Servers:** built for PHP-FPM (nginx, Apache, Caddy), Apache `mod_php`, LiteSpeed, FrankenPHP and the
  built-in server; worker runtimes (Octane, RoadRunner, FrankenPHP worker mode) through a middleware.
  [What has been tested end to end](#tested-on) is narrower.
- No required Composer dependencies.

## What you get

| | |
|---|---|
| **Traces** | One server span per request with method, route, status, duration, the real client address (trusted-proxy aware), redacted headers and request body. Child spans with `SecureNow::span()`, or automatically with OpenTelemetry (below). |
| **Logs** | PHP warnings and notices, uncaught exceptions and fatal errors, plus your app's log lines (Laravel and Monolog automatically, or `SecureNow::log()`). Secrets are redacted before they leave the server. |
| **Firewall** | Blocked addresses and ranges (IPv4 and IPv6) get a 403 before your framework boots. Also: allowlist mode, route-scoped blocks, rate limits (429 with `Retry-After`), proof-of-work challenges, and scraper blocking by user agent. Managed from the dashboard, the CLI or your coding agent. |
| **Sessions** | A revoked session or user gets a 401 on its next request; `session.seen` events feed session-theft detection. |
| **Security events** | `SecureNow::track('auth.login.failure', ...)`. Laravel, Symfony and WordPress sign-in events are sent for you. |

## Install

### 1. Add the package

```bash
composer require securenow/securenow
```

### 2. Connect the app

```bash
vendor/bin/securenow login
```

It opens the browser, you pick (or create) the app, and it writes the runtime credentials to
`.securenow/runtime.json` and adds them to `.gitignore`. On a server or in CI, without a browser:

```bash
vendor/bin/securenow init --api-key snk_live_... --app <app key> [--env production]
```

Already using the Node CLI? `npx securenow login` writes the same file; the PHP SDK reads it.

Inside a container (Sail, DDEV, plain Docker) the browser cannot reach the CLI's callback port unless you
publish one: `vendor/bin/securenow login --port 8765 --bind 0.0.0.0 --no-browser` with `-p 127.0.0.1:8765:8765`,
then open the printed URL.

**Is your project folder also the web root** (WordPress, a plain PHP site with `index.php` at the top)?
Then the SDK writes `.securenow/runtime.php` instead: a PHP file prints nothing when a browser asks
for it, where a `.json` file would be downloadable. `login` and `init` detect this; force it with
`--format php`. You can also keep the file anywhere and set `SECURENOW_CREDENTIALS_FILE=/path/to/runtime.json`.

Hosts without a writable disk (containers built in CI, PaaS): put the same JSON, raw or base64, in one
variable, `SECURENOW_CREDENTIALS`.

### 3. Check

```bash
vendor/bin/securenow test      # SecureNow must answer "accepted" for the trace and the log
vendor/bin/securenow doctor    # PHP, extensions, credentials, connectivity
```

A test proves the connection, not that the app runs. Load a page of your app: that request appears in
the dashboard within a minute.

## Frameworks

**Laravel** (tested on 13; the integration uses events present since Laravel 9): nothing to add. The service provider is auto-discovered and sets the route
(`/users/{id}`), forwards every log line and reported exception, and sends sign-in events
(`auth.login.success`, `auth.login.failure`, `auth.lockout`, `auth.logout`, `auth.password_reset.completed`,
`auth.signup`). With Octane, the provider adds a middleware that drives each request in the worker.

**Symfony** (tested on the current release; needs 5.4 or later): add the bundle to `config/bundles.php`:

```php
SecureNow\Integrations\Symfony\SecureNowBundle::class => ['all' => true],
```

It sets the route, records exceptions the kernel renders, sends sign-in events from the Security
component, and adds a Monolog handler when Monolog is installed.

**Slim, Mezzio, any PSR-15 stack**: add the middleware so spans carry the route template:

```php
$app->add(new \SecureNow\Integrations\Psr15\SecureNowMiddleware());   // before $app->addRoutingMiddleware()
$app->addRoutingMiddleware();
```

**WordPress**: `composer require securenow/securenow` next to `wp-config.php` (or copy the package to
`wp-content/securenow`), then copy `vendor/securenow/securenow/src/Integrations/WordPress/securenow.php`
to `wp-content/mu-plugins/`. For the firewall to answer before WordPress loads, add as the first line of
`wp-config.php`:

```php
require __DIR__ . '/vendor/securenow/securenow/prepend.php';
```

**Plain PHP, or no Composer autoloader**: point `auto_prepend_file` at the SDK, no code change:

```ini
; php.ini, .user.ini, or the PHP-FPM pool: php_admin_value[auto_prepend_file] = ...
auto_prepend_file = /var/www/app/vendor/securenow/securenow/prepend.php
```

A page that is its own script (`/contact.php`) is its own route. In a front controller, name the route
yourself: `SecureNow::setRoute('/users/{id}')`.

**Worker runtimes** (RoadRunner, FrankenPHP worker mode, Swoole, ReactPHP): the process outlives the
request, so nothing runs "at autoload" per request. Make the PSR-15 middleware the outermost one and give
it a PSR-17 response factory; it runs the firewall, the request span and the export for each request:

```php
new \SecureNow\Integrations\Psr15\SecureNowMiddleware($psr17Factory)
```

One request at a time per worker is assumed (as in RoadRunner, FrankenPHP and Octane). Coroutine servers
that interleave requests in one worker are not supported.

**Commands, queue workers, cron** (`php artisan ...`, `bin/console ...`): the SDK starts on the first
`SecureNow::track()` or `SecureNow::log()` and sends when the process ends; Laravel queue workers send
after each job. Set `"runtime": { "cli": true }` to also capture PHP errors and crashes there.

## Using the API

```php
use SecureNow\SecureNow;

// Security events: feed detections such as brute force or OTP abuse.
SecureNow::track('auth.login.failure', [
    'userId' => $user->id,                       // optional
    'attributes' => ['method' => 'password'],    // optional, your own fields
]);

// Logs (PSR-3 levels; {placeholders} are filled from the context).
SecureNow::log('warning', 'Payment declined for order {order}', ['order' => $id]);
$logger = SecureNow::logger('billing');          // a Psr\Log\LoggerInterface

// Who is signed in, on the request span.
SecureNow::setUser($user->id);

// A child span around something slow.
$pdf = SecureNow::span('render-invoice', fn () => $renderer->render($invoice));

// An exception you caught yourself.
SecureNow::recordException($e);

// Session revocation in your own auth check (or turn on the zero-code guard, below).
if (SecureNow::checkSession()['revoked']) {
    http_response_code(401);
    exit;
}

// The visitor's address, with trusted proxies applied.
$ip = SecureNow::clientIp();
```

Inside a request, `track()` fills in the visitor's address and user agent. The address is resolved the
way the firewall resolves it, so a client cannot choose it with `X-Forwarded-For`.

Recommended event names: `auth.login.success`, `auth.login.failure`, `auth.otp.send.requested`,
`auth.otp.verify.failure`, `auth.otp.verify.success`, `auth.password_reset.requested`,
`auth.password_reset.completed`, `auth.mfa.challenge.failure`, `auth.session.revoked`.

## Configuration

Everything lives in the credentials file, under `config`. The keys and defaults are the Node SDK's.

```json
{
  "apiKey": "snk_live_...",
  "app": { "key": "your-app-key", "name": "my-app" },
  "config": {
    "runtime": { "deploymentEnvironment": "production" },
    "networking": { "trustedProxies": ["cloudflare"] },
    "capture": { "body": true, "maxBodySize": 10240, "sensitiveFields": ["internalNote"] },
    "sessions": { "guard": true, "capture": true }
  }
}
```

| Key | Default | What it does |
|---|---|---|
| `runtime.deploymentEnvironment` | `production` | The environment the telemetry and the firewall policy belong to. |
| `runtime.cacheDir` | system temp | Where the SDK keeps the synced firewall policy and telemetry waiting to be sent. |
| `runtime.cli` | `false` | Also capture PHP errors and crashes in CLI processes. |
| `networking.trustedProxies` | `[]` | Proxies whose `X-Forwarded-For` counts: addresses, CIDR ranges, or `"cloudflare"`. Private and loopback connections are trusted already. |
| `capture.body` | `true` | Capture JSON, GraphQL and form bodies of POST/PUT/PATCH, redacted. |
| `capture.multipart` | `true` | Capture multipart text fields and file names, types and sizes. File content is never read. |
| `capture.maxBodySize` | `10240` | Bodies larger than this many bytes are recorded as `[TOO LARGE]`. |
| `capture.sensitiveFields` | `[]` | Extra field names to redact, besides the built-in list. |
| `logging.enabled` | `true` | Send logs. |
| `logging.redact` | `true` | Redact credentials and secret shapes in log lines. |
| `logging.phpErrors` | `true` | Record PHP warnings, notices and deprecations as logs. |
| `firewall.failMode` | `open` | `open`: traffic passes if no policy could ever be fetched. `closed`: it is blocked. |
| `firewall.statusCode` | `403` | Status of a blocked request. |
| `firewall.versionCheckInterval` | `10` | Seconds between policy checks. |
| `firewall.rateLimitStore` | none | `redis://host:6379` to count rate limits across servers. |
| `firewall.iptables`, `firewall.cloud` | off | OS firewall and cloud WAF layers, run by the agent (below). |
| `sessions.guard` | `false` | Answer 401 to a revoked session or user, with no code. |
| `sessions.capture` | `false` | Send `session.seen` (once per session and address every 5 minutes). |
| `sessions.cookieNames` | `[]` | Your session cookie names, besides `PHPSESSID`, `wordpress_logged_in_*` and the common ones. |
| `events.auth` | `true` | Send framework sign-in events automatically. |
| `otel.bridge` | `true` | Export OpenTelemetry spans through SecureNow when OpenTelemetry is installed. |
| `otel.logLevel` | `error` | SDK diagnostics in the PHP error log: `none`, `error`, `warn`, `info`, `debug`. |

Environment variables: `SECURENOW_CREDENTIALS` (the credentials JSON), `SECURENOW_CREDENTIALS_FILE`
(a path), `SECURENOW_CACHE_DIR`, `SECURENOW_DISABLED=1` (off for this process, for test runs),
`SECURENOW_AUTOSTART=0` (do not start at autoload; call `SecureNow::start()` yourself),
`SECURENOW_DEBUG=1`.

Under PHP-FPM, environment variables reach PHP only with `clear_env = no` or `env[NAME] = value` in the
pool configuration. The credentials file needs neither.

## How it works in PHP

A Node process holds the firewall policy in memory and syncs it on a timer. A PHP-FPM worker keeps
nothing between requests and has no timer, so the SDK works like this:

- **At autoload** it reads the credentials, opens the request span, and checks the request against the
  policy stored in a private cache folder (`0700`, in the system temp directory unless you set
  `runtime.cacheDir`). A blocklist of any size is stored as sorted binary ranges and searched without
  being loaded: the check costs well under a millisecond.
- **After the response is sent** (`fastcgi_finish_request()` under PHP-FPM, so the visitor never waits)
  it sends the request's telemetry, and, when the policy is older than 10 seconds, asks SecureNow whether
  it changed (one small request, usually answered `304`). A block made in the dashboard reaches every
  worker within about 10 seconds of traffic.
- **Batching:** each request appends to a small spool; one request at a time sends everything waiting,
  at most once per second. A quiet site sends per request; a busy site, or a flood of blocked requests,
  sends one batch per second from a single worker.
- **Refused requests:** a request the firewall answers (403, 429, a challenge) is reported as a firewall
  hit with a count, not as a trace, so a flood of blocked requests costs no telemetry.
- **Outages:** if SecureNow cannot be reached, the last policy keeps being enforced, exports pause after
  three failures and resume on their own, and the spool is capped at 4 MB per signal. Nothing blocks the app.

Rate-limit counters are shared through Redis (`firewall.rateLimitStore`), else APCu (one PHP-FPM pool),
else files in the cache folder (one machine).

Without `fastcgi_finish_request()` (Apache `mod_php`), sending happens at the end of the request with a
3-second cap; run the agent there, so requests only write to the spool.

### The agent (optional)

```bash
vendor/bin/securenow agent            # as the user PHP runs as
sudo vendor/bin/securenow agent --user www-data    # as root, needed for the OS firewall layer
```

A small long-running process (systemd, Supervisor, a container sidecar). While it runs, web requests
stop syncing and sending and only write to the spool; the agent ships telemetry and keeps a long-poll open
to SecureNow, so a block made in the dashboard is enforced within about a second. It also runs the two layers that need a long-lived, privileged process:

- **OS firewall** (`"firewall": { "iptables": true }`): blocked addresses are dropped by iptables,
  ip6tables or nftables in a chain of its own (`SECURENOW_BLOCK`), before they reach the web server.
- **Cloud WAF** (`"firewall": { "cloud": "cloudflare" | "aws" | "gcp" }`): the blocklist is pushed to a
  Cloudflare list, an AWS WAF IP set or Cloud Armor rules. `"firewall": { "cloudDryRun": true }` logs
  what would be pushed without pushing.

  | Provider | Settings under `config.firewall` | Credentials |
  |---|---|---|
  | `cloudflare` | `cloudflare.accountId` | `cloudflare.apiToken`, or `CLOUDFLARE_API_TOKEN` (and `CLOUDFLARE_ACCOUNT_ID`) |
  | `aws` | `aws.wafIpSetId`, `aws.wafIpSetName` (default `securenow-blocklist`), `aws.wafScope` (`REGIONAL` or `CLOUDFRONT`), `aws.region` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and `AWS_SESSION_TOKEN`), or the EC2 instance role |
  | `gcp` | `gcp.projectId`, `gcp.securityPolicy` | `GOOGLE_OAUTH_ACCESS_TOKEN`, or the service account of the VM (metadata server) |

  The agent reads these variables from its own environment (systemd `Environment=`), so the keys stay
  out of the credentials file the web server reads.

The OS firewall layer filters the host's `INPUT` chain: it protects what listens on the host itself
(nginx, PHP-FPM, SSH). Traffic that Docker forwards to a published container port goes through
`FORWARD`, not `INPUT`; the app still answers those requests with 403. The agent removes its chain when
it stops (SIGTERM, SIGINT, SIGQUIT or SIGHUP); after a hard kill, remove it with
`iptables -D INPUT -j SECURENOW_BLOCK; iptables -F SECURENOW_BLOCK; iptables -X SECURENOW_BLOCK`.
The first 10,000 blocklist entries are loaded; the app enforces the rest.

The Node SDK's "TCP drop" layer has no PHP equivalent (PHP does not own the socket): use the OS firewall layer.

## OpenTelemetry

SecureNow's request span, logs and firewall need no extension. For spans inside the request (database
queries, outgoing HTTP calls, framework internals) the SDK bridges OpenTelemetry's zero-code
instrumentation, the same setup the OpenTelemetry and SigNoz PHP guides describe:

```bash
pecl install opentelemetry          # or: install-php-extensions opentelemetry
# php.ini: extension=opentelemetry.so

composer config allow-plugins.php-http/discovery false
composer config allow-plugins.tbachert/spi true
composer require open-telemetry/sdk nyholm/psr7 \
    open-telemetry/opentelemetry-auto-laravel open-telemetry/opentelemetry-auto-pdo
```

Other packages: `open-telemetry/opentelemetry-auto-symfony`, `-auto-slim`, `-auto-wordpress`,
`-auto-psr18`, `-auto-guzzle`, `-auto-curl`. Do **not** set `OTEL_PHP_AUTOLOAD_ENABLED` or the
`OTEL_EXPORTER_*` variables: SecureNow registers the tracer provider and sends the spans itself, under
its own request span. The framework's server span is exported as an internal span, so each request stays
one server span, the one detections read.

## CLI

```
vendor/bin/securenow login                 sign in, pick an app, write credentials
vendor/bin/securenow init                  write credentials from --api-key and --app
vendor/bin/securenow status                credentials, cache folder, firewall policy, last export
vendor/bin/securenow doctor                PHP, extensions, credentials, connectivity
vendor/bin/securenow test                  send a test trace and log
vendor/bin/securenow sync                  fetch the firewall policy now
vendor/bin/securenow firewall:check <ip>   what the firewall would do for this address
vendor/bin/securenow flush                 send telemetry waiting in the spool
vendor/bin/securenow agent                 the long-running helper
```

The web server usually runs PHP as another user (`www-data`), with its own cache folder: run `status` as
that user (`sudo -u www-data vendor/bin/securenow status`) to see what the web requests see.

Apps, alert rules, the blocklist, forensics and the rest of the dashboard are language-neutral: use
`npx securenow`, the SecureNow MCP server from your coding agent, or https://app.securenow.ai.

## What is redacted

- **Headers:** `Cookie`, `Authorization`, and any header whose name holds `token`, `secret`, `password`,
  `csrf`, `xsrf`, `session`, `api-key`, `credential`, `signature` are recorded as `[REDACTED]`.
- **Bodies and query strings:** fields named like credentials or personal data (`password`, `token`,
  `card`, `email`, `phone`, `ssn`, OTP codes...) become `[REDACTED]`; so do values shaped like JWTs,
  Bearer credentials, API keys, emails and card numbers. Attack payloads in other fields are kept as sent,
  so detections still match them.
- **Logs:** the same value shapes, plus `password=...` and `"token":"..."` assignments.

## Differences from the Node SDK

| | Node | PHP |
|---|---|---|
| Start | `node -r securenow/register` | Composer autoload (or `auto_prepend_file`) |
| Policy sync | timer in the process | after responses, or the agent |
| Log capture | `console.*` | PHP errors, Monolog / Laravel log, `SecureNow::log()` |
| Child spans | OpenTelemetry auto-instrumentation, bundled | OpenTelemetry extension, optional |
| Firewall layer 2 (TCP drop) | yes | no (use the OS firewall layer) |
| Admin CLI and MCP server | `npx securenow` | use `npx securenow` or the hosted MCP server |

## Troubleshooting

- **Nothing in the dashboard:** `vendor/bin/securenow test`. If it is accepted, the app is not loading
  the SDK: check that the entry file requires `vendor/autoload.php`, or set `auto_prepend_file`.
  `SECURENOW_DEBUG=1` (or `"otel": { "logLevel": "debug" }`) writes what the SDK does to the PHP error log.
- **The wrong client address:** behind a load balancer or CDN with public addresses, list it in
  `networking.trustedProxies`. The span attributes `http.client_ip.source` and `http.socket_ip` show what
  the SDK saw.
- **`status` says "no policy yet" but the app blocks:** you are looking at your own user's cache folder.
  Run it as the web server's user.
- **Tests:** set `SECURENOW_DISABLED=1` in your test environment.

## Tested on

- PHP 8.3 on nginx + PHP-FPM: plain PHP (`auto_prepend_file`), Slim 4, Laravel 13 and Symfony, each
  across traces, body capture, errors, logs, events, blocking, scraper rules, rate limits, challenges
  and session revocation; with and without the `opentelemetry` extension and APCu.
- Plain PHP on the built-in server with PHP 8.0, 8.1 and 8.5.
- Unit tests, and parity tests that run the same inputs through the Node SDK, on PHP 8.0 to 8.5.
- Live, against SecureNow itself, from an AWS EC2 host (Ubuntu 24.04): the same four apps sending traces,
  logs and events; a block and an unblock made with `npx securenow blocklist` enforced by every app within
  about 3 seconds of traffic, and in under a second with the agent; a rate limit (429 with `Retry-After`),
  a proof-of-work challenge solved from a real client, a revoked session (401), the account's Scraper
  Shield rules, and the hits listed by `npx securenow firewall hits`. `vendor/bin/securenow login` was
  used to create and connect the app.
- The OS firewall layer on that host (iptables with the nftables backend): 10,000 DROP rules loaded in
  3 seconds and removed when the agent stopped. Dropping packets from a listed address was not exercised.
- Measured there, with a 78,000-address policy: about 0.7 ms added to a plain PHP request, about 3 ms to a
  Laravel or Symfony request with the OpenTelemetry instrumentation on. Telemetry is sent after the response.
- Not tested end to end yet: WordPress, Apache `mod_php`, LiteSpeed, FrankenPHP, RoadRunner, Swoole,
  Laravel Octane, the cloud WAF pushes against real provider accounts.

## Development

```bash
php tests/run.php                        # unit and behaviour tests, no dependencies
node tests/tools/gen-fixtures.js         # regenerate parity fixtures from the Node SDK
# end to end (nginx + PHP-FPM with Laravel, Symfony, Slim and plain PHP): see tests/e2e/README.md
```

License: ISC.
