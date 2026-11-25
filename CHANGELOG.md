# Changelog

## 1.0.0 (2026-11-24)

First release: the PHP counterpart of the `securenow` npm package. Same credentials file, same
telemetry attributes, same firewall API.

- **Start:** at Composer autoload (no code), from `auto_prepend_file` (`prepend.php`, no Composer
  needed), or `SecureNow::start()`. PHP 8.0 to 8.5, no required dependencies.
- **Traces:** one server span per request with the legacy and stable HTTP attribute names, the client
  address resolved with trusted proxies (IPv4 and IPv6, `"cloudflare"` preset), redacted headers and
  bodies (JSON, form, GraphQL, multipart metadata), W3C `traceparent` in and out, `SecureNow::span()`.
- **Logs:** PHP errors, uncaught exceptions and fatal errors; Laravel log lines; Monolog 2 and 3;
  a PSR-3 logger; redaction of credentials and secret shapes.
- **Firewall (layer 1):** blocklist and allowlist of any size (binary range files, searched without
  loading), route-scoped blocks, rate limits (Redis, APCu or files), proof-of-work challenges
  wire-compatible with the Node SDK and the API, Scraper Shield user-agent rules, fail-open by
  default, hit reporting with counts.
- **Sessions and events:** zero-code session guard, `SecureNow::checkSession()`, `session.seen`,
  `SecureNow::track()`; sign-in events sent automatically for Laravel, Symfony and WordPress.
- **Export:** after the response (`fastcgi_finish_request`), batched through a local spool by one
  worker at a time, paused during ingest outages.
- **Integrations:** Laravel (auto-discovered provider, Octane middleware), Symfony bundle, PSR-15
  middleware (Slim, Mezzio, worker runtimes), WordPress mu-plugin.
- **OpenTelemetry bridge:** with the `opentelemetry` extension and `open-telemetry/sdk`, framework,
  database and HTTP-client spans are exported under SecureNow's request span, with no `OTEL_*`
  configuration.
- **CLI:** `vendor/bin/securenow login | init | status | doctor | test | sync | firewall:check | flush | agent`.
- **Agent:** long-poll policy sync (a block is enforced in under a second) and telemetry shipping; OS firewall layer (iptables, ip6tables,
  nftables) and cloud WAF layer (Cloudflare, AWS WAF, Cloud Armor).

Tested end to end on nginx + PHP-FPM (PHP 8.3) with plain PHP, Slim 4, Laravel 13 and Symfony, with
and without the OpenTelemetry extension and APCu, and on the built-in server with PHP 8.0, 8.1 and 8.5.
Tested live against SecureNow from an AWS EC2 host (Ubuntu 24.04): telemetry, blocks, rate limits,
challenges, session revocation, Scraper Shield rules, hit reports, the agent's long-poll and the OS
firewall layer (rules loaded and removed).
Not tested end to end yet: WordPress, Apache `mod_php`, LiteSpeed, worker runtimes, the cloud WAF
pushes against real provider accounts.
