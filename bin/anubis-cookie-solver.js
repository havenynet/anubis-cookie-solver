#!/usr/bin/env node
'use strict';
const { solveNative } = require('../src/native');
const { parseChallenge } = require('../src/challenge');
const { closePool } = require('../src/pow');

const [cmd, url, ...flags] = process.argv.slice(2);
const usage = () => { console.error('usage: anubis-cookie-solver <probe|solve> <url> [--no-solve] [--threads N]'); process.exit(2); };
if (!['probe', 'solve'].includes(cmd) || !url) usage();
const ti = flags.indexOf('--threads');
const threads = ti >= 0 ? parseInt(flags[ti + 1], 10) : undefined;

(async () => {
  if (cmd === 'probe') {
    // Prints what the site serves, in a form that is safe to paste into an issue (no cookie values).
    
    const res = await fetch(url, { redirect: 'follow', headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' } });
    const body = await res.text();
    const ch = parseChallenge(body);
    const info = {
      url, status: res.status, server: res.headers.get('server'), challenged: !!ch,
      kind: ch && ch.kind, algorithm: ch && ch.algorithm, difficulty: ch && ch.difficulty,
      hasId: !!(ch && ch.id), randomDataLength: ch && ch.randomData ? ch.randomData.length : undefined,
      basePrefix: ch && ch.basePrefix, jsonKeys: ch && ch.keys, metaRefreshWaitMs: ch && ch.waitMs,
      setCookieNames: (res.headers.getSetCookie ? res.headers.getSetCookie() : []).map(c => c.split('=')[0]),
    };
    console.log(JSON.stringify(info, null, 2));
    if (!flags.includes('--no-solve') && ch && ch.kind !== 'unsupported') {
      try {
        const r = await solveNative(url, { threads });
        console.log(JSON.stringify({ solved: true, method: r.method, difficulty: r.difficulty, attempts: r.attempts, solveMs: Math.round(r.solveMs), totalMs: r.totalMs, cookieNames: r.cookies.map(c => c.name), expiresAt: r.expiresAt }, null, 2));
      } catch (e) { console.log(JSON.stringify({ solved: false, error: e.name, message: e.message, status: e.status, bodySnippet: e.bodySnippet, cookieNames: e.cookieNames }, null, 2)); }
    }
  } else {
    const r = await solveNative(url, { threads });
    console.log(JSON.stringify({ cookieHeader: r.cookieHeader, userAgent: r.userAgent, expiresAt: r.expiresAt, method: r.method, difficulty: r.difficulty }, null, 2));
  }
})().catch(e => { console.error(`${e.name}: ${e.message}`); process.exitCode = 1; }).finally(() => closePool());
