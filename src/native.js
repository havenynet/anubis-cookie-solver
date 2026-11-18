'use strict';
const { solvePow, sha256hex } = require('./pow');
const { Jar } = require('./jar');
const { parseChallenge, UnsupportedChallengeError, ChallengeFailedError, DeniedError } = require('./challenge');

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const PASS = '/.within.website/x/cmd/anubis/api/pass-challenge';
const sleep = ms => new Promise(r => setTimeout(r, ms));

function jwtExp(token) {
  try { const p = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')); return p.exp ? new Date(p.exp * 1000) : null; } catch { return null; }
}

/**
 * Solve an Anubis challenge with plain HTTP + local hashing (no browser).
 * Throws UnsupportedChallengeError when the challenge type is unknown, so callers can escalate to a browser tier.
 */
async function solveNative(url, opts = {}) {
  const {
    fetch: doFetch = globalThis.fetch, userAgent = DEFAULT_UA, headers = {}, signal, timeoutMs = 30000,
    threads, verify = true, jar = new Jar(), maxRedirects = 5,
  } = opts;
  const sig = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)].filter(Boolean));
  const baseHeaders = {
    'user-agent': userAgent,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
    ...headers,
  };
  const T0 = Date.now();

  async function get(target, follow = true) {
    let cur = target;
    for (let i = 0; i <= maxRedirects; i++) {
      const h = { ...baseHeaders }; const c = jar.header(); if (c) h.cookie = c;
      const res = await doFetch(cur, { redirect: 'manual', headers: h, signal: sig });
      jar.setFromResponse(res, new URL(cur).hostname);
      const loc = res.headers.get('location');
      if (follow && res.status >= 300 && res.status < 400 && loc) { await res.arrayBuffer().catch(() => {}); cur = new URL(loc, cur).href; continue; }
      return { res, url: cur };
    }
    throw new ChallengeFailedError('too many redirects');
  }

  const first = await get(url);
  const body = await first.res.text();
  const ch = parseChallenge(body);
  const out = extra => ({ backend: 'native', userAgent, url, cookies: jar.list(), cookieHeader: jar.header(), totalMs: Date.now() - T0, ...extra });

  if (!ch) {
    if ([403, 418, 429].includes(first.res.status) && /anubis/i.test(body)) throw new DeniedError(first.res.status);
    return out({ challenged: false });
  }
  if (ch.kind === 'unsupported') throw new UnsupportedChallengeError(ch.algorithm, ch);

  const origin = new URL(first.url).origin;
  const here = new URL(first.url);
  const redir = here.pathname + here.search;
  const pass = q => `${origin}${ch.basePrefix || ''}${PASS}?${q}`;
  let passUrl, solveMs = 0, attempts = 0;

  if (ch.kind === 'pow') {
    const r = await solvePow({ randomData: ch.randomData, difficulty: ch.difficulty, threads, signal: sig });
    solveMs = r.ms; attempts = r.attempts;
    const q = new URLSearchParams();
    if (ch.id) q.set('id', ch.id);
    q.set('response', r.hash); q.set('nonce', String(r.nonce)); q.set('redir', redir); q.set('elapsedTime', String(Math.max(1, Math.round(r.ms))));
    passUrl = pass(q.toString());
  } else if (ch.kind === 'preact') { // experimental: wait, then answer with sha256(randomData)
    await sleep(ch.difficulty * 80);
    const q = new URLSearchParams();
    if (ch.id) q.set('id', ch.id);
    const h = sha256hex(ch.randomData);
    q.set('result', h); q.set('response', h); // preact uses `result`; `response` kept for older versions (extra params are ignored)
    q.set('redir', redir); q.set('elapsedTime', String(ch.difficulty * 80));
    passUrl = pass(q.toString());
  } else if (ch.kind === 'meta-refresh') {
    await sleep(ch.waitMs);
    passUrl = new URL(ch.url, first.url).href;
  }

  const passed = await get(passUrl, false);
  const passedText = await passed.res.text().catch(() => '');
  const auth = jar.list().find(c => /anubis-auth/i.test(c.name));
  if (!auth) throw new ChallengeFailedError(`pass-challenge returned HTTP ${passed.res.status} without an auth cookie`, {
    status: passed.res.status, method: ch.algorithm, difficulty: ch.difficulty,
    bodySnippet: passedText.replace(/\s+/g, ' ').slice(0, 200), cookieNames: jar.list().map(c => c.name),
  });

  if (verify) {
    const v = await get(url);
    const vb = await v.res.text();
    if (parseChallenge(vb) || v.res.status >= 400) throw new ChallengeFailedError(`cookie rejected on verification (HTTP ${v.res.status})`, { status: v.res.status });
  }
  return out({ challenged: true, method: ch.algorithm, difficulty: ch.difficulty, attempts, solveMs, authCookie: auth, expiresAt: auth.expires || jwtExp(auth.value) });
}

const toPuppeteerCookies = r => r.cookies.map(c => ({
  name: c.name, value: c.value, domain: c.domain, path: c.path, httpOnly: c.httpOnly, secure: c.secure,
  ...(c.expires ? { expires: Math.floor(c.expires.getTime() / 1000) } : {}), ...(c.sameSite ? { sameSite: c.sameSite } : {}),
}));

module.exports = { solveNative, toPuppeteerCookies, DEFAULT_UA };
