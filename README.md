# anubis-cookie-solver

Get the [Anubis](https://github.com/TecharoHQ/anubis) auth cookie **without a browser**: fetch the challenge page, solve the proof-of-work locally, submit it, return the cookie. Zero runtime dependencies, Node >= 20.3.

> Status: **0.1 — native tier.** Verified against live Anubis deployments (including `scpfoundation.net`). Supports `fast`/`slow` SHA-256 PoW and `preact` challenges. Skips the browser entirely, using ~10MB of RAM instead of Chromium's 200MB.

## Installation

Available on the npm registry:

```bash
npm install anubis-cookie-solver
```

Usage

```js
const { solve, toPuppeteerCookies } = require('anubis-cookie-solver');

const r = await solve('https://example.org/', { threads: 4 });

r.challenged     // true if an Anubis challenge was detected and solved
r.cookieHeader   // "techaro.lol-anubis-auth=...; ..." (ready to pass to fetch/undici)
r.userAgent      // reuse this exact UA: the challenge/cookie is bound to request attributes
r.expiresAt      // typically ~7 days, solve once and cache
```

solve() throws UnsupportedChallengeError for algorithms it doesn't know (so a caller can escalate to a browser tier) and DeniedError when policy blocks you outright (no challenge offered, e.g. HTTP 418).

If you need to pass the cookies to Puppeteer, use the included helper: const ppCookies = toPuppeteerCookies(r);

Probe a site

```bash
npx anubis-cookie-solver probe https://example.org/      # shows algorithm/difficulty, then tries to solve
```

Speed

Single-thread SHA-256 search with a precomputed prefix midstate and in-place decimal nonce increments, spread over worker_threads for difficulty >= 5. npm run bench on your machine:

strategy (1 core) rate
crypto.createHash per attempt 1.3 MH/s
crypto.hash one-shot 3.0 MH/s
this package's kernel 3.4 MH/s

Default difficulty 4 (~65k attempts) solves in ~5-25 ms; difficulty 5 in ~0.2-0.3 s on one core.

Note: For preact challenges, the total solve time is dictated by the server's required delay (usually 1.5–3 seconds), not by hashing speed.

Supported challenges

method status
fast / slow (SHA-256, leading hex zeros) implemented, live-tested
metarefresh implemented, live-tested
preact implemented, live-tested (uses the result parameter)
newer WASM-era variants (e.g. argon2id) not supported: throws UnsupportedChallengeError

Responsible use

Anubis exists to make bulk scraping expensive. This package performs the work the challenge asks for; it does not exploit anything. Use it only on sites you are permitted to crawl, keep request rates polite, and cache the cookie instead of re-solving.

Prior art

sleeyax/anubis-solver (Go; native and embedded-V8 modes), gan-anubis (Python).