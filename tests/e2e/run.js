'use strict';

// End-to-end matrix: drives the apps in the e2e container (nginx + PHP-FPM) and checks what the
// SDK sent to the fake backend. See tests/e2e/README.md.
//   node tests/e2e/run.js [--otel] [--apps plain,slim,laravel,symfony]

const crypto = require('crypto');

const BACKEND = process.env.E2E_BACKEND || 'http://127.0.0.1:4000';
const HOST = process.env.E2E_HOST || 'http://127.0.0.1';
const OTEL = process.argv.includes('--otel');
const only = (process.argv.find((a) => a.startsWith('--apps=')) || '').slice(7).split(',').filter(Boolean);

const APPS = {
  plain: { port: 8081, key: '00000000-0000-4000-8000-000000000001' },
  slim: { port: 8082, key: '00000000-0000-4000-8000-000000000002' },
  laravel: { port: 8083, key: '00000000-0000-4000-8000-000000000003' },
  symfony: { port: 8084, key: '00000000-0000-4000-8000-000000000004' },
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const RUN = crypto.randomBytes(4).toString('hex');
let ipCounter = 10;
const nextIp = () => `198.51.100.${ipCounter++}`;

async function control(path, body) {
  const res = await fetch(BACKEND + path, { method: body === undefined ? 'GET' : 'POST', body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  return res.json();
}

function client(app) {
  const base = `${HOST}:${app.port}`;
  return async function request(method, path, { ip, headers = {}, body } = {}) {
    const res = await fetch(base + path, {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(30000),
      headers: { ...(ip ? { 'x-forwarded-for': ip } : {}), ...(body !== undefined && !headers['content-type'] ? { 'content-type': 'application/json' } : {}), ...headers },
      body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, text, json: () => { try { return JSON.parse(text); } catch (_) { return null; } } };
  };
}

async function waitFor(app, pick, what, timeoutMs = 10000) {
  const started = Date.now();
  for (;;) {
    const calls = await control(`/__control/calls?app=${app.key}`);
    const found = pick(calls);
    if (found) return found;
    if (Date.now() - started > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(150);
  }
}

// The policy reaches the app on its next version check (1 s in the e2e config), which a request triggers.
async function untilStatus(request, method, path, options, expected, timeoutMs = 10000) {
  const started = Date.now();
  let last;
  for (;;) {
    last = await request(method, path, options);
    if (last.status === expected) return last;
    if (Date.now() - started > timeoutMs) throw new Error(`expected HTTP ${expected} for ${method} ${path}, still ${last.status}`);
    await sleep(300);
  }
}

function leadingZeroBits(buf) {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) { bits += 8; continue; }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

const serverSpans = (calls) => calls.spans.filter((s) => s.kind === 2);

function checks(name, app) {
  const request = client(app);
  const setPolicy = (policy) => control(`/__control/policy?app=${app.key}`, policy);
  const list = [];
  const add = (label, fn, when = true) => { if (when) list.push([label, fn]); };

  add('trace', async () => {
    const ip = nextIp();
    const res = await request('GET', '/users/42?ref=e2e', { ip, headers: { 'user-agent': 'e2e-agent/1.0' } });
    expect(res.status === 200 && res.json().id === 42, `app answered ${res.status} ${res.text.slice(0, 80)}`);
    const span = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip), 'the request span');
    const a = span.attributes;
    expect(a['http.method'] === 'GET', `http.method ${a['http.method']}`);
    expect(a['http.target'] === '/users/42?ref=e2e', `http.target ${a['http.target']}`);
    expect(a['http.status_code'] === 200, `http.status_code ${a['http.status_code']}`);
    expect(a['http.client_ip.source'] === 'x-forwarded-for', `source ${a['http.client_ip.source']}`);
    expect(a['http.user_agent'] === 'e2e-agent/1.0', `user agent ${a['http.user_agent']}`);
    expect(a['http.route'] === '/users/{id}', `http.route ${a['http.route']}`);
    expect(span.name === 'GET /users/{id}', `span name ${span.name}`);
    expect(span.resource['service.name'] === app.key, `service.name ${span.resource['service.name']}`);
    expect(span.resource['telemetry.sdk.language'] === 'php', 'telemetry.sdk.language');
    expect(JSON.parse(a['http.request.headers'])['user-agent'] === 'e2e-agent/1.0', 'captured headers');
    expect(span.durationMs >= 0 && span.durationMs < 5000, `duration ${span.durationMs}`);
  });

  add('body', async () => {
    const ip = nextIp();
    const payload = { email: 'a@b.co', password: 'hunter2', note: '<script>alert(1)</script>', path: '../../etc/passwd' };
    const res = await request('POST', '/echo', { ip, body: payload });
    expect(res.status === 200, `echo answered ${res.status} ${res.text.slice(0, 120)}`);
    expect(res.json().received.password === 'hunter2', 'the app still read its own body');
    const span = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip), 'the POST span');
    const body = span.attributes['http.request.body'];
    expect(body && !body.includes('hunter2') && !body.includes('a@b.co'), `secrets in captured body: ${body}`);
    expect(body.includes('<script>alert(1)</script>') && body.includes('../../etc/passwd'), `payload not kept as sent: ${body}`);
    expect(span.attributes['http.request.body.type'] === 'json', 'body type');
  });

  add('error', async () => {
    const ip = nextIp();
    const res = await request('GET', '/boom', { ip });
    expect(res.status === 500, `boom answered ${res.status}`);
    const span = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip), 'the failing span');
    expect(span.attributes['http.status_code'] === 500, 'status 500 on the span');
    expect(span.status === 2, `span status ${span.status}`);
    expect(span.events.some((e) => e.name === 'exception' && /RuntimeException/.test(e.attributes['exception.type'] || '')), 'exception event on the span');
    const log = await waitFor(app, (c) => c.logs.find((l) => l.traceId === span.traceId && l.attributes['exception.type'] && /boom/.test(l.body || '')), 'the exception log');
    const all = (await control(`/__control/calls?app=${app.key}`)).logs.filter((l) => l.traceId === span.traceId && l.attributes['exception.type']);
    expect(all.length === 1, `one log per exception, got ${all.length}`);
    expect(['ERROR', 'FATAL'].includes(log.severity), `log severity ${log.severity}`);
    expect(/RuntimeException/.test(log.attributes['exception.type'] || ''), 'exception.type on the log');
  });

  add('log', async () => {
    const ip = nextIp();
    const res = await request('GET', '/log', { ip });
    expect(res.status === 200, `log answered ${res.status}`);
    const log = await waitFor(app, (c) => c.logs.find((l) => /log line/.test(l.body || '')), 'the app log');
    expect(!log.body.includes('hunter2') && log.body.includes('[REDACTED]'), `log not redacted: ${log.body}`);
    expect(log.body.includes('bob'), `placeholder not filled: ${log.body}`);
    expect(log.severity === 'WARN', `severity ${log.severity}`);
    expect(log.traceId.length === 32, 'log carries the trace id');
  });

  add('event', async () => {
    const ip = nextIp();
    await request('GET', '/event', { ip, headers: { 'user-agent': 'e2e-agent/1.0' } });
    const event = await waitFor(app, (c) => c.events.find((e) => e.type === 'auth.login.failure' && e.ip === ip), 'the security event');
    expect(event.user_id === 'u1', 'user id');
    expect(event.user_agent === 'e2e-agent/1.0', 'user agent');
    expect(event.attributes.method === 'password', 'attributes');
  });

  add('block403', async () => {
    const blocked = nextIp();
    const other = nextIp();
    await setPolicy({ blocklistIps: [blocked, '203.0.113.0/24', '2001:db8:bad::/48'] });
    const res = await untilStatus(request, 'GET', '/', { ip: blocked, headers: { accept: 'text/html' } }, 403);
    expect(res.text.includes('Access Blocked') && res.text.includes(blocked), 'block page');
    expect((await request('GET', '/', { ip: '203.0.113.77' })).status === 403, 'CIDR range');
    expect((await request('GET', '/', { ip: '2001:db8:bad::5' })).status === 403, 'IPv6 range');
    const json = await request('GET', '/', { ip: blocked, headers: { accept: 'application/json' } });
    expect(json.json().error === 'Forbidden', 'JSON block answer');
    expect((await request('GET', '/', { ip: other })).status === 200, 'another address passes');
    await waitFor(app, (c) => c.firewallEvents.find((e) => e.ip === blocked && e.source === 'blocklist'), 'the firewall hit report');
    // A refused request is a firewall hit, not a trace.
    await sleep(1500);
    const after = await control(`/__control/calls?app=${app.key}`);
    expect(!after.spans.some((s) => s.attributes['http.status_code'] === 403), 'no trace for a request the firewall answered');
    await setPolicy({});
    await untilStatus(request, 'GET', '/', { ip: blocked }, 200);
  });

  add('userAgent', async () => {
    const ip = nextIp();
    await setPolicy({ userAgentRules: { version: 'x', rules: [{ id: 'evilbot', pattern: 'EvilBot/\\d', category: 'scraper' }], allow: [], exemptIps: [] } });
    await untilStatus(request, 'GET', '/', { ip, headers: { 'user-agent': 'Mozilla/5.0 (compatible; EvilBot/2.1)' } }, 403);
    expect((await request('GET', '/', { ip, headers: { 'user-agent': 'Mozilla/5.0 Chrome/120' } })).status === 200, 'a browser passes');
    await waitFor(app, (c) => c.firewallEvents.find((e) => e.matchedEntry === 'ua:evilbot'), 'the user-agent hit report');
    await setPolicy({});
    await untilStatus(request, 'GET', '/', { ip, headers: { 'user-agent': 'EvilBot/2.1' } }, 200);
  });

  add('rateLimit', async () => {
    const ip = nextIp();
    await setPolicy({ rateLimitRules: [{ id: `rl-users-${RUN}`, ip: '', method: 'GET', pathPattern: '/users', pathMatchMode: 'prefix', limit: 3, windowSeconds: 86400, keyBy: 'ip' }] });
    // A probe address shows when the rule has arrived (its fourth request is refused).
    const probe = nextIp();
    await untilStatus(request, 'GET', '/users/1', { ip: probe }, 429);
    const statuses = [];
    let limited = null;
    for (let i = 0; i < 6; i++) {
      const res = await request('GET', '/users/1', { ip });
      statuses.push(res.status);
      if (res.status === 429) limited = limited || res;
    }
    expect(statuses.slice(0, 3).every((s) => s === 200), `first three should pass: ${statuses}`);
    expect(statuses.slice(3).every((s) => s === 429), `the rest should be limited: ${statuses}`);
    expect(Number(limited.headers.get('retry-after')) >= 1, 'Retry-After');
    expect(limited.headers.get('x-ratelimit-limit') === '3', 'X-RateLimit-Limit');
    expect((await request('GET', '/', { ip })).status === 200, 'other routes are not limited');
    await waitFor(app, (c) => c.firewallEvents.find((e) => e.ip === ip && e.action === 'rate_limited'), 'the rate-limit report');
    await setPolicy({});
    await untilStatus(request, 'GET', '/users/1', { ip }, 200);
  });

  add('challenge', async () => {
    const ip = nextIp();
    const ua = 'e2e-browser/1.0';
    await setPolicy({ challengeRules: [{ id: 'ch-users', ip: '', method: 'ALL', pathPattern: '/users', pathMatchMode: 'prefix' }] });
    const first = await untilStatus(request, 'GET', '/users/7', { ip, headers: { accept: 'application/json', 'user-agent': ua } }, 403);
    const { challenge } = first.json();
    expect(challenge && challenge.alg === 'pow-sha256', `challenge answer: ${first.text.slice(0, 100)}`);
    expect(first.headers.get('x-securenow-challenge') === 'required', 'challenge header');
    const page = await request('GET', '/users/7', { ip, headers: { accept: 'text/html', 'user-agent': ua } });
    expect(page.text.includes('Verifying your browser'), 'interstitial page');
    let nonce = 0;
    while (leadingZeroBits(crypto.createHash('sha256').update(`${challenge.token}.${nonce}`).digest()) < challenge.difficulty) nonce++;
    const solved = await request('POST', challenge.submit, { ip, headers: { 'user-agent': ua }, body: { token: challenge.token, nonce: String(nonce) } });
    expect(solved.status === 204, `solve answered ${solved.status} ${solved.text}`);
    const cookie = (solved.headers.get('set-cookie') || '').split(';')[0];
    expect(cookie.startsWith('__sn_clearance=k1.'), `clearance cookie: ${solved.headers.get('set-cookie')}`);
    const cleared = await request('GET', '/users/7', { ip, headers: { 'user-agent': ua, cookie } });
    expect(cleared.status === 200 && cleared.json().id === 7, `cleared request answered ${cleared.status}`);
    expect((await request('GET', '/users/7', { ip: nextIp(), headers: { 'user-agent': ua, cookie } })).status === 403, 'clearance is bound to the address');
    await setPolicy({});
    await untilStatus(request, 'GET', '/users/7', { ip: nextIp() }, 200);
  });

  add('session', async () => {
    const ip = nextIp();
    const res = await request('GET', '/', { ip, headers: { cookie: 'PHPSESSID=stolen-session-value' } });
    expect(res.status === 401 && /session_revoked/.test(res.text), `revoked session answered ${res.status} ${res.text.slice(0, 80)}`);
    expect(/PHPSESSID=;/.test(res.headers.get('set-cookie') || ''), 'the session cookie is cleared');
    expect((await request('GET', '/', { ip, headers: { cookie: `PHPSESSID=session-${RUN}` } })).status === 200, 'another session passes');
    await waitFor(app, (c) => c.events.find((e) => e.type === 'session.seen' && e.session_id === sha256(`session-${RUN}`) && e.ip === ip), 'session.seen');
  });

  // ---- app-specific ----

  add('plainPhp', async () => {
    const ip = nextIp();
    expect((await request('GET', '/contact.php', { ip })).status === 200, 'contact page');
    const page = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip), 'the page span');
    expect(page.attributes['http.route'] === '/contact.php', `a plain page is its own route: ${page.attributes['http.route']}`);

    const ip2 = nextIp();
    const fatal = await request('GET', '/fatal', { ip: ip2 });
    expect(fatal.status === 500, `fatal answered ${fatal.status}`);
    const crash = await waitFor(app, (c) => c.logs.find((l) => l.severity === 'FATAL' && /this_function_does_not_exist/.test(l.body || '')), 'the crash log');
    expect(crash.attributes['log.source'] === 'crash', 'crash log source');
    const crashed = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip2), 'the crashed span');
    expect(crashed.status === 2 && crashed.attributes['http.status_code'] === 500, 'crashed span is an error');

    await request('GET', '/warn', { ip: nextIp() });
    await waitFor(app, (c) => c.logs.find((l) => l.attributes['log.source'] === 'php_error' && /nonexistent/.test(l.body || '')), 'the PHP warning log');

    const ip3 = nextIp();
    await request('GET', '/span', { ip: ip3 });
    const root = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip3), 'the span request');
    const child = await waitFor(app, (c) => c.spans.find((s) => s.name === 'compute' && s.traceId === root.traceId), 'the child span');
    expect(child.parentSpanId === root.spanId && child.durationMs >= 10, 'child span nests and lasts');

    const form = await request('POST', '/echo', { ip: nextIp(), headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'user=bob&password=secret' });
    expect(form.json().post.password === 'secret', 'the app still gets $_POST');
  }, name === 'plain');

  add('laravelAuth', async () => {
    const ip = nextIp();
    const res = await request('POST', '/login', { ip, body: { email: 'nobody@example.com', password: 'wrong' } });
    expect(res.status === 401, `login answered ${res.status} ${res.text.slice(0, 120)}`);
    const event = await waitFor(app, (c) => c.events.find((e) => e.type === 'auth.login.failure' && e.ip === ip && e.attributes && e.attributes.guard), 'the automatic sign-in failure event');
    expect(event.severity === 'warn', 'severity');
    const log = await waitFor(app, (c) => c.logs.find((l) => l.scope === 'laravel'), 'a Laravel log line');
    expect(log.attributes['log.source'] === 'laravel', 'log source');
    const span = await waitFor(app, (c) => serverSpans(c).find((s) => s.resource['securenow.framework'] === 'laravel'), 'framework on the resource');
    expect(Boolean(span), 'framework resource attribute');
  }, name === 'laravel');

  add('otel', async () => {
    const ip = nextIp();
    const res = await request('GET', '/db', { ip });
    expect(res.status === 200, `db answered ${res.status} ${res.text.slice(0, 120)}`);
    const root = await waitFor(app, (c) => serverSpans(c).find((s) => s.attributes['http.client_ip'] === ip), 'the db request span');
    const calls = await control(`/__control/calls?app=${app.key}`);
    const trace = calls.spans.filter((s) => s.traceId === root.traceId);
    expect(trace.filter((s) => s.kind === 2).length === 1, `exactly one server span per request, got ${trace.filter((s) => s.kind === 2).length}`);
    const db = trace.find((s) => /pdo/i.test(s.scope || '') || s.attributes['db.system'] || s.attributes['db.system.name']);
    expect(Boolean(db), `no database span in the trace: ${trace.map((s) => `${s.scope}:${s.name}`).join(', ')}`);
    const ids = new Set(trace.map((s) => s.spanId));
    const orphans = trace.filter((s) => s.spanId !== root.spanId && !ids.has(s.parentSpanId));
    expect(orphans.length === 0, `spans outside the request tree: ${orphans.map((s) => `${s.scope}:${s.name}`).join(', ')}`);
    expect(db.kind === 3, `a database span is a client span, got kind ${db.kind}`);
  }, OTEL && name !== 'plain');

  return list;
}

(async () => {
  await control('/__control/reset', {});
  const results = {};
  let failed = 0;
  for (const [name, app] of Object.entries(APPS)) {
    if (only.length && !only.includes(name)) continue;
    await control(`/__control/revocations?app=${app.key}`, [{ type: 'session', value: sha256('stolen-session-value') }]);
    results[name] = {};
    for (const [label, fn] of checks(name, app)) {
      try {
        await fn();
        results[name][label] = 'ok';
      } catch (e) {
        results[name][label] = 'FAIL';
        failed++;
        console.log(`  FAIL ${name} › ${label}: ${e.message}`);
      }
    }
  }
  const labels = [...new Set(Object.values(results).flatMap((r) => Object.keys(r)))];
  console.log('\n' + ['app'.padEnd(9), ...labels.map((l) => l.padEnd(11))].join(' '));
  for (const [name, r] of Object.entries(results)) {
    console.log([name.padEnd(9), ...labels.map((l) => (r[l] || '-').padEnd(11))].join(' '));
  }
  console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
