'use strict';

// A stand-in for SecureNow's ingest gateway and firewall API, for the end-to-end matrix.
// It records what the SDK sends and serves a firewall policy per app.
//   node fake-backend.js [port]
// Control endpoints (used by run.js):
//   POST /__control/reset
//   POST /__control/policy?app=<key>      body: partial policy (blocklistIps, rateLimitRules, ...)
//   POST /__control/revocations?app=<key> body: [{ type, value }]
//   GET  /__control/calls?app=<key>       -> { spans, logs, events, firewallEvents, syncs }

const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');

const port = Number(process.argv[2] || 4000);
const CHALLENGE_SECRET = 'e2e-challenge-secret';

let apps = new Map();

function app(key) {
  if (!apps.has(key)) {
    apps.set(key, {
      spans: [], logs: [], events: [], firewallEvents: [], syncs: 0, headers: [],
      // Versions never repeat across resets: an app that kept an old policy must not be answered 304.
      policy: {}, policyVersion: Date.now(), revocations: [],
    });
  }
  return apps.get(key);
}

function attrs(list) {
  const out = {};
  for (const a of list || []) {
    const v = a.value || {};
    out[a.key] = 'stringValue' in v ? v.stringValue
      : 'intValue' in v ? Number(v.intValue)
      : 'boolValue' in v ? v.boolValue
      : 'doubleValue' in v ? v.doubleValue
      : JSON.stringify(v);
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let buf = Buffer.concat(chunks);
      if (/gzip/i.test(req.headers['content-encoding'] || '')) {
        try { buf = zlib.gunzipSync(buf); } catch (_) { /* leave as is */ }
      }
      resolve(buf.toString('utf8'));
    });
  });
}

function send(res, status, body, headers = {}) {
  const text = body === undefined ? '' : (typeof body === 'string' ? body : JSON.stringify(body));
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(text);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://backend');
  const path = url.pathname;
  const body = req.method === 'GET' ? '' : await readBody(req);

  if (path === '/__control/reset') { apps = new Map(); return send(res, 200, { ok: true }); }
  if (path === '/__control/policy') {
    const a = app(url.searchParams.get('app'));
    a.policy = body ? JSON.parse(body) : {};
    a.policyVersion++;
    return send(res, 200, { ok: true, version: a.policyVersion });
  }
  if (path === '/__control/revocations') {
    app(url.searchParams.get('app')).revocations = body ? JSON.parse(body) : [];
    return send(res, 200, { ok: true });
  }
  if (path === '/__control/calls') {
    const a = app(url.searchParams.get('app'));
    return send(res, 200, { spans: a.spans, logs: a.logs, events: a.events, firewallEvents: a.firewallEvents, syncs: a.syncs, headers: a.headers.slice(-5) });
  }

  // ---- ingest ----
  const appKey = req.headers['x-securenow-app-key'] || url.searchParams.get('app') || '';
  const authorized = /^Bearer snk_live_/.test(req.headers.authorization || '');
  if (path === '/v1/traces' || path === '/v1/logs' || path === '/v1/events') {
    if (!appKey || !authorized) return send(res, 401, { error: 'unauthorized' });
    const a = app(appKey);
    a.headers.push({ path, contentType: req.headers['content-type'], encoding: req.headers['content-encoding'] || '', env: req.headers['x-securenow-environment'] });
    let parsed;
    try { parsed = JSON.parse(body); } catch (_) { return send(res, 400, { error: 'invalid json' }); }
    if (path === '/v1/traces') {
      for (const rs of parsed.resourceSpans || []) {
        const resource = attrs(rs.resource && rs.resource.attributes);
        for (const ss of rs.scopeSpans || []) {
          for (const s of ss.spans || []) {
            a.spans.push({
              traceId: s.traceId, spanId: s.spanId, parentSpanId: s.parentSpanId || '', name: s.name, kind: s.kind,
              status: (s.status && s.status.code) || 0, durationMs: (Number(s.endTimeUnixNano) - Number(s.startTimeUnixNano)) / 1e6,
              scope: ss.scope && ss.scope.name, attributes: attrs(s.attributes), resource,
              events: (s.events || []).map((e) => ({ name: e.name, attributes: attrs(e.attributes) })),
            });
          }
        }
      }
    } else if (path === '/v1/logs') {
      for (const rl of parsed.resourceLogs || []) {
        for (const sl of rl.scopeLogs || []) {
          for (const r of sl.logRecords || []) {
            a.logs.push({ body: r.body && r.body.stringValue, severity: r.severityText, traceId: r.traceId || '', scope: sl.scope && sl.scope.name, attributes: attrs(r.attributes) });
          }
        }
      }
    } else {
      if (!Array.isArray(parsed.events)) return send(res, 400, { error: 'invalid events' });
      a.events.push(...parsed.events);
    }
    return send(res, 200, { partialSuccess: {} });
  }

  // ---- firewall control plane ----
  if (path.startsWith('/api/v1/')) {
    if (!authorized) return send(res, 401, { error: 'unauthorized' });
    const key = url.searchParams.get('app') || '';
    const a = app(key);
    if (path === '/api/v1/firewall/sync') {
      a.syncs++;
      const v = String(a.policyVersion);
      const etag = `"production|${v}|ua:${v}"`;
      if (req.headers['if-none-match'] === etag) return send(res, 304, undefined, { etag });
      const p = a.policy;
      return send(res, 200, {
        blocklist: { version: v, count: (p.blocklistIps || []).length },
        allowlist: { version: v, count: (p.allowlistIps || []).length },
        rateLimits: { version: v, count: (p.rateLimitRules || []).length },
        challenges: { version: v, count: (p.challengeRules || []).length },
        environment: 'production',
        userAgentRules: p.userAgentRules || { version: v, rules: [], exemptIps: [], allow: [] },
        app: { key, firewallEnabled: p.firewallEnabled !== false, challenge: { secret: CHALLENGE_SECRET, difficulty: 8, challengeTtl: 120, clearanceTtl: 1800, verify: 'auto' } },
        blocklistIps: p.blocklistIps || [],
        blocklistRules: p.blocklistRules || [],
        allowlistIps: p.allowlistIps || [],
        rateLimitRules: p.rateLimitRules || [],
        challengeRules: p.challengeRules || [],
      }, { etag });
    }
    if (path === '/api/v1/firewall/events') {
      const parsed = JSON.parse(body || '{}');
      a.firewallEvents.push(...(parsed.events || []));
      return send(res, 200, { success: true });
    }
    if (path === '/api/v1/revocations/sync') {
      const etag = `"${crypto.createHash('sha1').update(JSON.stringify(a.revocations)).digest('hex')}"`;
      if (req.headers['if-none-match'] === etag) return send(res, 304, undefined, { etag });
      return send(res, 200, { revocations: { entries: a.revocations } }, { etag });
    }
  }
  send(res, 404, { error: 'not found', path });
});

server.listen(port, '0.0.0.0', () => console.log('fake SecureNow backend on :' + port));
