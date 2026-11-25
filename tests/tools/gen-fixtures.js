'use strict';

// Generates tests/fixtures/node-parity.json from the Node SDK (../../securenow-npm), so the PHP
// tests can assert the two SDKs redact, match and sign the same way.
//   node tests/tools/gen-fixtures.js
// With --verify <file>, checks tokens minted by PHP (tests/out/php-tokens.json) with the Node SDK.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const verifyFile = process.argv[2] === '--verify' ? path.resolve(process.argv[3]) : null;
const npm = path.resolve(__dirname, '..', '..', '..', 'securenow-npm');
process.chdir(path.resolve(__dirname)); // no .securenow credentials here: default config
const capture = require(path.join(npm, 'request-capture'));
const otp = require(path.join(npm, 'otp-redaction'));
const headerRedaction = require(path.join(npm, 'header-redaction'));
const logRedaction = require(path.join(npm, 'log-redaction'));
const semconv = require(path.join(npm, 'legacy-semconv'));
const paths = require(path.join(npm, 'firewall-paths'));
const ua = require(path.join(npm, 'firewall-ua'));
const cidr = require(path.join(npm, 'cidr'));
const challenge = require(path.join(npm, 'challenge'));
const resolveIp = require(path.join(npm, 'resolve-ip'));

const SECRET = 'test-secret-0123456789abcdef';

if (process.argv[2] === '--verify') {
  const tokens = JSON.parse(fs.readFileSync(verifyFile, 'utf8'));
  const solved = challenge.verifyChallengeSolution(SECRET, { token: tokens.challenge.token, nonce: tokens.challenge.nonce, ip: tokens.ip });
  const cleared = challenge.verifyClearance(SECRET, { cookie: tokens.clearance, ip: tokens.ip, ua: tokens.ua });
  const wrongIp = challenge.verifyClearance(SECRET, { cookie: tokens.clearance, ip: '198.51.100.9', ua: tokens.ua });
  console.log(JSON.stringify({ solved, cleared: cleared.ok, wrongIp: wrongIp.ok }));
  process.exit(solved.ok && cleared.ok && !wrongIp.ok ? 0 : 1);
}

const values = [
  'hello world',
  'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c end',
  'Authorization: Bearer abcdefghijklmnop123456',
  'basic dXNlcjpwYXNzd29yZA==',
  'key sk_live_abcdefgh12345678 and pk_test_ZZZZZZZZ1111',
  'contact me at john.doe+tag@example.co.uk please',
  'card 4111 1111 1111 1111 expires',
  'not a card 1234 5678 9012 3456',
  'order 4111111111111111',
  '/reset?code=123456&next=/home',
  '/search?q=<script>alert(1)</script>&otp=9999',
  "' OR 1=1 -- ",
  '../../etc/passwd',
  'mutation { login(email: "a@b.co", password: "hunter2", code: "445566") }',
  'a@b',
  'x'.repeat(300) + '@example.com',
  'eyJ' + 'a'.repeat(50),
  'snk_live_0123456789abcdef',
  '{"nested":"Bearer zzzzzzzzzzzz"}',
  'ünïcödé text with émail user@exämple.com',
];

const bodies = [
  ['application/json', '{"email":"a@b.co","password":"hunter2","name":"Bob","note":"<script>alert(1)</script>"}'],
  ['application/json', '{"user":{"firstName":"A","creditCard":"4111111111111111","id":7},"items":[{"sku":"x","token":"abc"}],"path":"../../etc/passwd"}'],
  ['application/json; charset=utf-8', '{"code":"123456","status_code":200,"otpCode":"1","url":"https://x.test/a/b?c=d"}'],
  ['application/json', '{"q":"\' OR 1=1 --","list":[1,2,3],"empty":{},"arr":[],"unicode":"héllo ✓","slash":"a/b"}'],
  ['application/json', '[{"password":"x"},"plain",3]'],
  ['application/json', '"just a string with user@example.com"'],
  ['application/x-www-form-urlencoded', 'username=bob&password=secret&comment=hello+world&q=%3Cscript%3E'],
  ['application/x-www-form-urlencoded', 'a=1&a=2&empty=&novalue&user%5Bname%5D=x&code=123456'],
  ['application/graphql', 'mutation { login(username: "bob", password: "hunter2") { token } }'],
  ['application/graphql', 'query { user(id: 5, email: "a@b.co") { name } }'],
  ['text/plain', 'ignored'],
];

const headerNames = [
  'cookie', 'authorization', 'x-csrf-token', 'x-api-key', 'user-agent', 'accept', 'x-session-id', 'x-otp',
  'content-type', 'x-forwarded-for', 'x-code', 'x-verification-code', 'proxy-authorization', 'x-goog-api-key',
  'x-custom-secret-thing', 'referer', 'x-amz-signature', 'x-auth-request', 'if-none-match', 'x-my-private-key',
];

const logLines = [
  'user logged in password=hunter2 from 1.2.3.4',
  '{"level":"info","password":"x","user":"bob"}',
  'payload {"apiKey":"abc123","code":"1234","error_code":"E42"} done',
  'GET /cb?token=abcdef&state=1 200',
  'code=123456 verified',
  'code=E1234 failed',
  'plain message',
  'email sent to someone@example.com with Bearer abcdefghijkl',
  'authorization=Basic dXNlcjpwYXNz cookie=sid=1',
];

const searches = ['?a=1&sig=abc&b=2', '?code=123456', '?X-Amz-Signature=zzz&x=1', '?q=hello', '?otp=1&otpCode=2&normal=3', '?', '', '?a'];

const pathCases = [];
const pathRules = [
  { pathPattern: '/api/login', pathMatchMode: 'exact' },
  { pathPattern: '/api/*', pathMatchMode: 'prefix' },
  { pathPattern: '/admin' },
  { pathPattern: '^/users/\\d+$', pathMatchMode: 'regex' },
  { pathPattern: '(a+)+$', pathMatchMode: 'regex' },
  { pathPattern: '', pathMatchMode: 'prefix' },
  { pathPattern: '/Files/Report.PDF', pathMatchMode: 'exact' },
  { pathPattern: '^/wp-(admin|login)', pathMatchMode: 'regex' },
];
const pathInputs = ['/api/login', '/API/LOGIN/', '/api//login', '/api/%6Cogin', '/api/login/x', '/admin/users', '/Admin', '/users/42', '/users/abc',
  '/', '/files/report.pdf', '/wp-admin/x', '/wp-login.php', '/%zz/bad', '/api/login?x=1', '/aaaa'];
for (const rule of pathRules) for (const input of pathInputs) pathCases.push({ rule, path: input, match: paths.rulePathMatches(rule, input) });
const canonical = pathInputs.map((p) => ({ path: p, plain: paths.canonicalPath(p), stripped: paths.canonicalPath(p, { stripTrailingSlash: true }) }));

const uaPatterns = [
  'GPTBot', 'Bytespider', 'python-requests/\\d+', '(a+)+', 'a.*b.*c', '(?=x)y', '(a|ab)+', 'scrapy', '[a-z]+bot', '\\1x', '(',
  'curl/[0-9.]+', '(web )?crawler', '(ab?){2}', '(a{1,30}){1,30}', 'x{2,}y{3,}', 'x+?y', 'foo\\', '[abc', '', 'a'.repeat(600),
  '(?<name>bot)', '(?:Headless)?Chrome', 'a|b', 'x{3}', 'x{2,5}', '^Mozilla/5\\.0 \\(compatible; (\\w+)bot',
];
const uaProblems = uaPatterns.map((p) => ({ pattern: p, refused: ua.uaPatternProblem(p) !== '' }));

const uaRuleSet = {
  rules: [
    { id: 'gptbot', pattern: 'GPTBot', category: 'ai' },
    { id: 'bytespider', pattern: 'Bytespider', category: 'ai' },
    { id: 'pyreq', pattern: 'python-requests/\\d+', category: 'lib' },
    { id: 'bad', pattern: '(a+)+', category: 'x' },
    { id: 'phantom', pattern: 'PhantomJS', category: 'headless' },
    { id: 'curl', pattern: '^curl/', category: 'lib' },
  ],
  allow: [{ id: 'prerender', pattern: 'Prerender' }],
  exemptIps: ['203.0.113.0/24', '2001:db8::1'],
};
const uaMatcher = ua.createUserAgentMatcher(ua.compileUserAgentRules(uaRuleSet));
const uaInputs = [
  ['Mozilla/5.0 (Windows NT 10.0) Chrome/120', '198.51.100.1'],
  ['Mozilla/5.0 AppleWebKit (compatible; GPTBot/1.0)', '198.51.100.1'],
  ['gptbot lowercase', '198.51.100.1'],
  ['python-requests/2.31', '198.51.100.1'],
  ['python-requests/2.31', '203.0.113.9'],
  ['Mozilla/5.0 PhantomJS Prerender', '198.51.100.1'],
  ['Mozilla/5.0 PhantomJS', '198.51.100.1'],
  ['curl/8.0', '2001:db8::1'],
  ['curl/8.0', '2001:db8::2'],
  ['', '198.51.100.1'],
];
const uaMatches = uaInputs.map(([agent, ip]) => ({ ua: agent, ip, rule: (uaMatcher.match(agent, ip) || {}).id || null }));

const ipList = ['1.2.3.4', '10.0.0.0/8', '192.168.1.0/24', '2001:db8::/32', '2001:DB8:0::1', '::ffff:5.6.7.8', '203.0.113.7/32',
  '0.0.0.0/x', 'not-an-ip', '172.16.0.0/12', '::ffff:9.9.9.0/120', 'fe80::1', '100.64.0.0/10', '8.8.8.8/33', '1.1.1.1/y'];
const matcher = cidr.createMatcher(ipList);
const ipInputs = ['1.2.3.4', '1.2.3.5', '10.255.255.255', '11.0.0.0', '192.168.1.77', '192.168.2.1', '2001:db8::dead', '2001:db9::1',
  '2001:db8::1', '5.6.7.8', '::ffff:5.6.7.8', '::ffff:1.2.3.4', '203.0.113.7', '203.0.113.8', 'not-an-ip', '172.31.255.255', '172.32.0.0',
  '9.9.9.200', '9.9.10.1', 'fe80::1', 'fe80::2', '100.127.0.1', '', '[2001:db8::5]', '8.8.8.8'];
const ipMatches = ipInputs.map((ip) => ({ ip, blocked: matcher.isBlocked(ip) }));

// Challenge: a token minted and solved by Node, and a clearance issued by Node.
const ip = '198.51.100.23';
const agent = 'Mozilla/5.0 Test';
const token = challenge.signChallenge(SECRET, { ip, difficulty: 10, rid: 'rule-1', challengeTtl: 315360000 });
let nonce = 0;
while (!challenge.meetsDifficulty(crypto.createHash('sha256').update(`${token}.${nonce}`).digest(), 10)) nonce++;
const clearance = challenge.issueClearance(SECRET, { ip, ua: agent, rid: 'rule-1', clearanceTtl: 315360000 });

// Client IP resolution (default config: private and loopback sockets are trusted proxies).
const ipCases = [
  { remote: '203.0.113.5', headers: { 'x-forwarded-for': '1.1.1.1' } },
  { remote: '10.0.0.2', headers: { 'x-forwarded-for': '198.51.100.7, 10.0.0.9' } },
  { remote: '127.0.0.1', headers: { 'x-forwarded-for': '198.51.100.7, 203.0.113.9' } },
  { remote: '127.0.0.1', headers: {} },
  { remote: '::ffff:10.1.2.3', headers: { 'x-real-ip': '198.51.100.8' } },
  { remote: '10.0.0.2', headers: { 'cf-connecting-ip': '198.51.100.9', 'x-real-ip': '198.51.100.8' } },
  { remote: '10.0.0.2', headers: { 'x-forwarded-for': '10.0.0.5, 192.168.1.1' } },
  { remote: '192.168.1.1', headers: { 'x-forwarded-for': '[2001:db8::7]' } },
  { remote: '172.20.0.1', headers: { 'x-forwarded-for': '198.51.100.7:4567' } },
  { remote: '8.8.8.8', headers: {} },
].map((c) => {
  const d = resolveIp.resolveClientIpWithDetails({ socket: { remoteAddress: c.remote }, headers: c.headers });
  return { ...c, ip: d.ip, source: d.source, trustedProxy: d.trustedProxy };
});

const isSensitiveHeader = headerRedaction.createHeaderNameRedactor(['csrfToken', 'my-private']);
const customFields = ['internalNote'];
const allFields = [...capture.DEFAULT_SENSITIVE_FIELDS, ...customFields];

const out = {
  secret: SECRET,
  values: values.map((v) => ({ in: v, out: capture.redactSensitiveValue(v) })),
  bodies: bodies.map(([ct, body]) => {
    let result = null;
    try { result = capture.redactBodyText(body, ct, allFields); } catch (e) { result = { error: true }; }
    return { contentType: ct, body, result };
  }),
  customFields,
  headers: headerNames.map((name) => ({ name, sensitive: isSensitiveHeader(name) })),
  headerCustom: ['csrfToken', 'my-private'],
  logs: logLines.map((line) => ({ in: line, out: logRedaction.redactLogText(line) })),
  searches: searches.map((s) => ({ in: s, out: semconv.redactSearch(s) })),
  otpFields: ['code', 'status_code', 'otpCode', 'x-otp', 'user[code]', 'http.request.header.x_code', 'error_code', 'OTP', 'passcode', 'zipcode', 'mfa_code', '2fa-code']
    .map((k) => ({ key: k, otp: otp.isOtpCodeField(k) })),
  pathCases,
  canonical,
  uaProblems,
  uaRuleSet,
  uaMatches,
  ipList,
  ipMatches,
  challenge: { ip, ua: agent, token, nonce: String(nonce), clearance: clearance.value },
  ipCases,
};

const dir = path.resolve(__dirname, '..', 'fixtures');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'node-parity.json'), JSON.stringify(out, null, 1));
console.log('wrote', path.join(dir, 'node-parity.json'));
