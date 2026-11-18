# anubis-cookie-solver

Get the [Anubis](https://github.com/TecharoHQ/anubis) auth cookie **without a browser**: fetch the challenge page, solve the SHA-256 proof-of-work locally, submit it, return the cookie. Zero runtime dependencies, Node >= 20.3.

> Status: **0.1 — native tier only.** Verified against a mock server that implements the handshake as publicly documented, *not yet against live Anubis versions*. Run the probe below on your target and open an issue with the output.

```js
const { solve, toPuppeteerCookies } = require('anubis-cookie-solver');

const r = await solve('https://example.org/', { threads: 4 });
r.cookieHeader   // "techaro.lol-anubis-auth=...; ..."
r.userAgent      // reuse this exact UA: the challenge/cookie is bound to request attributes
r.expiresAt      // typically ~7 days, solve once and cache
r.challenged     // false if the site served no challenge
```

`solve()` throws `UnsupportedChallengeError` for algorithms it doesn't know (so a caller can escalate to a browser) and `DeniedError` when policy blocks you outright (no challenge to solve).

## Probe a site

```bash
npx anubis-cookie-solver probe https://example.org/      # shows algorithm/difficulty, then tries to solve
```

## Speed

Single-thread SHA-256 search with a precomputed prefix midstate and in-place decimal nonce increments, spread over `worker_threads` for difficulty >= 5. `npm run bench` on your machine:

| strategy (1 core) | rate |
|---|---|
| `crypto.createHash` per attempt | 1.3 MH/s |
| `crypto.hash` one-shot | 3.0 MH/s |
| this package's kernel | 3.4 MH/s |

Default difficulty 4 (~65k attempts) solves in ~5-25 ms; difficulty 5 in ~0.2-0.3 s on one core, less with more.

## Supported challenges

| method | status |
|---|---|
| `fast` / `slow` (SHA-256, leading hex zeros) | implemented, mock-tested |
| `metarefresh` | implemented, mock-tested |
| `preact` | experimental |
| newer WASM-era variants (e.g. argon2id) | not supported: throws `UnsupportedChallengeError` |

## Responsible use

Anubis exists to make bulk scraping expensive. This package performs the work the challenge asks for; it does not exploit anything. Use it only on sites you are permitted to crawl, keep request rates polite, and cache the cookie instead of re-solving.

## Prior art

[sleeyax/anubis-solver](https://github.com/sleeyax/anubis-solver) (Go; native and embedded-V8 modes), [gan-anubis](https://pypi.org/project/gan-anubis/) (Python).
