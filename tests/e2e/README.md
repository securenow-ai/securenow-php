# End-to-end matrix

Real servers, real frameworks, a fake SecureNow backend. One container runs nginx + PHP-FPM with four
apps (plain PHP started by `auto_prepend_file`, Slim, Laravel, Symfony); `fake-backend.js` stands in for
the ingest gateway and the firewall API and records what the SDK sends; `run.js` drives the apps and
asserts on what arrived.

```bash
# from securenow-php/
docker build -f tests/e2e/Dockerfile --build-arg PHP_VERSION=8.3 -t securenow-php-e2e:8.3 .
docker build -f tests/e2e/Dockerfile --build-arg PHP_VERSION=8.3 --build-arg WITH_OTEL=1 --build-arg WITH_APCU=1 \
  -t securenow-php-e2e:8.3-otel .

docker run -d --name sn-fake-backend -p 4000:4000 -v "$PWD/tests/e2e:/e2e:ro" node:22-alpine node /e2e/fake-backend.js 4000
docker run -d --name sn-php-e2e -p 8081-8084:8081-8084 \
  -e SECURENOW_E2E_BACKEND=http://host.docker.internal:4000 securenow-php-e2e:8.3

node tests/e2e/run.js            # add --otel with the -otel image, --apps=plain,slim to narrow
```

To iterate on the SDK without rebuilding, add `-v "$PWD:/sdk"` to the app container (the SDK is installed
as a symlinked Composer path repository). On Docker Desktop for Windows that bind mount makes every PHP
file check slow: fine for correctness, useless for timing.

| Column | What is checked |
|---|---|
| trace | server span with client address (from `X-Forwarded-For` through a trusted proxy), route template, status, headers, resource |
| body | JSON body captured redacted, attack payload kept, and the app still reads its own body |
| error | 500: span status, exception event, exactly one log record with `exception.type` |
| log | app log line arrives redacted, placeholders filled, linked to the trace |
| event | `SecureNow::track()` with the request's address and user agent |
| block403 | blocklist (exact, CIDR, IPv6): HTML and JSON answers, hit report, span attributes, unblock |
| userAgent | Scraper Shield rule blocks by user agent, a browser passes |
| rateLimit | 429 after the limit with `Retry-After`, per address, hit report |
| challenge | proof-of-work: JSON challenge, interstitial, solve, clearance cookie bound to the address |
| session | revoked session answered 401 with the cookie cleared, `session.seen` for the others |
| plainPhp | page-as-route, fatal error and warning logs, child span, `$_POST` untouched |
| laravelAuth | Laravel's failed sign-in becomes `auth.login.failure`; Laravel log lines; framework on the resource |
| otel | OpenTelemetry spans (PDO, framework) nest under the request span; one server span per request |

Live mode (the same image against SecureNow itself): set `SECURENOW_E2E_LIVE=1`,
`SECURENOW_E2E_API_KEY` and the four `SECURENOW_E2E_APP_*` keys; the apps then use the default
endpoints.
