'use strict';
// A small stand-in for Anubis implementing the handshake as documented publicly:
// challenge JSON in <script id="anubis_challenge">, cookie-test cookie, pass-challenge GET -> 302 + signed auth cookie.
const http = require('node:http');
const crypto = require('node:crypto');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const PASS = '/.within.website/x/cmd/anubis/api/pass-challenge';
const TEST_COOKIE = 'techaro.lol-anubis-cookie-verification';
const AUTH = 'techaro.lol-anubis-auth';

function startMock({ mode = 'pow', method = 'fast', difficulty = 3, protect = true, challengeStatus = 200 } = {}) {
  const challenges = new Map(); const tokens = new Set(); const stats = { challengePages: 0, passes: 0, rejected: 0, real: 0 };
  const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split(/=(.*)/s).slice(0, 2)).filter(a => a[0]));
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'); const ck = cookies(req);
    if (u.pathname === PASS) {
      const id = u.searchParams.get('id'); const rd = challenges.get(id);
      const resp = u.searchParams.get('response'), nonce = u.searchParams.get('nonce');
      let ok = !!rd && ck[TEST_COOKIE] !== undefined;
      if (ok && mode === 'pow') ok = resp === sha(rd + nonce) && resp.startsWith('0'.repeat(difficulty));
      if (ok && mode === 'preact') ok = u.searchParams.get('result') === sha(rd); // real preact answers via `result`
      if (ok && mode === 'meta') ok = resp === rd;
      if (!ok) { stats.rejected++; res.writeHead(403, { 'content-type': 'text/html' }); return res.end('invalid response'); }
      stats.passes++;
      const tok = crypto.randomBytes(8).toString('hex'); tokens.add(tok);
      const jwt = ['e30', Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 7 * 86400 })).toString('base64url'), tok].join('.');
      res.writeHead(302, { location: u.searchParams.get('redir') || '/', 'set-cookie': [`${AUTH}=${jwt}; Path=/; Expires=${new Date(Date.now() + 7 * 864e5).toUTCString()}; HttpOnly`] });
      return res.end();
    }
    const authed = ck[AUTH] && tokens.has(ck[AUTH].split('.')[2]);
    if (!protect || authed) { stats.real++; res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html><body>REAL CONTENT ' + 'x'.repeat(2000) + '</body></html>'); }
    if (mode === 'deny') { res.writeHead(403, { 'content-type': 'text/html' }); return res.end('<html>Access Denied: protected by Anubis</html>'); }
    stats.challengePages++;
    const id = crypto.randomUUID(); const rd = crypto.randomBytes(32).toString('hex'); challenges.set(id, rd);
    const headers = { 'content-type': 'text/html', 'set-cookie': [`${TEST_COOKIE}=${crypto.randomBytes(8).toString('hex')}; Path=/`] };
    res.writeHead(challengeStatus, headers);
    const json = JSON.stringify({ rules: { algorithm: mode === 'meta' ? 'metarefresh' : mode === 'preact' ? 'preact' : method, difficulty, report_as: difficulty }, challenge: { id, method: mode === 'meta' ? 'metarefresh' : mode === 'preact' ? 'preact' : method, randomData: rd, difficulty } });
    const meta = mode === 'meta' ? `<meta http-equiv="refresh" content="0; url=${PASS}?id=${id}&amp;response=${rd}&amp;nonce=0&amp;redir=%2F&amp;elapsedTime=0">` : '';
    res.end(`<!doctype html><html><head>${meta}<script id="anubis_base_prefix" type="application/json">""</script><script id="anubis_challenge" type="application/json">${json}</script></head><body>Making sure you're not a bot!</body></html>`);
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${server.address().port}/`, stats, close: () => new Promise(r => server.close(r)) })));
}
module.exports = { startMock };
