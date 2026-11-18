'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { startMock } = require('./helpers/mock-anubis');
const { solve, parseChallenge, looksLikeChallenge, closePool, UnsupportedChallengeError, DeniedError, toPuppeteerCookies } = require('../src');

test.after(() => closePool());

async function withMock(opts, fn) { const m = await startMock(opts); try { await fn(m); } finally { await m.close(); } }

test('solves fast PoW and the cookie unlocks the page', async () => {
  await withMock({ difficulty: 4 }, async m => {
    const r = await solve(m.url);
    assert.strictEqual(r.challenged, true);
    assert.strictEqual(r.method, 'fast');
    assert.ok(r.authCookie && /anubis-auth/.test(r.authCookie.name));
    assert.ok(r.expiresAt > new Date(Date.now() + 6 * 864e5));
    const page = await (await fetch(m.url, { headers: { cookie: r.cookieHeader, 'user-agent': r.userAgent } })).text();
    assert.match(page, /REAL CONTENT/);
    assert.strictEqual(m.stats.passes, 1);
    assert.ok(toPuppeteerCookies(r).every(c => c.name && c.value && c.domain));
  });
});

test('higher difficulty uses the worker pool', async () => {
  await withMock({ difficulty: 5 }, async m => {
    const r = await solve(m.url, { threads: 2 });
    assert.strictEqual(r.difficulty, 5);
    assert.ok(r.attempts > 0);
  });
});

test('"slow" algorithm name is treated like fast', async () => {
  await withMock({ difficulty: 3, method: 'slow' }, async m => { assert.strictEqual((await solve(m.url)).challenged, true); });
});

test('meta-refresh challenge', async () => {
  await withMock({ mode: 'meta', difficulty: 1 }, async m => { const r = await solve(m.url); assert.strictEqual(r.method, 'metarefresh'); });
});

test('preact challenge', async () => {
  await withMock({ mode: 'preact', difficulty: 1 }, async m => { const r = await solve(m.url); assert.strictEqual(r.method, 'preact'); });
});

test('challenge page served with HTTP 403 (as on scpfoundation.net) still solves', async () => {
  await withMock({ mode: 'preact', difficulty: 5, challengeStatus: 403 }, async m => { assert.strictEqual((await solve(m.url)).challenged, true); });
});

test('unprotected site returns challenged:false', async () => {
  await withMock({ protect: false }, async m => { assert.strictEqual((await solve(m.url)).challenged, false); });
});

test('unknown algorithm escalates with UnsupportedChallengeError', async () => {
  await withMock({ method: 'argon2id' }, async m => { await assert.rejects(() => solve(m.url), UnsupportedChallengeError); });
});

test('policy deny is reported, not retried', async () => {
  await withMock({ mode: 'deny' }, async m => { await assert.rejects(() => solve(m.url), DeniedError); });
});

test('parser + detector', () => {
  assert.strictEqual(parseChallenge('<html>plain</html>'), null);
  assert.strictEqual(looksLikeChallenge('<script src="/.within.website/x/cmd/anubis/static/js/main.mjs"></script>'), true);
  assert.strictEqual(looksLikeChallenge('<html>hello</html>'), false);
});
