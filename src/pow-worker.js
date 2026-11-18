'use strict';
const { parentPort } = require('node:worker_threads');
const { makeSearcher } = require('./sha256');

// Workers claim nonce chunks from a shared counter, so every thread stays busy until one finds a hit.
parentPort.on('message', ({ id, randomData, difficulty, ctl, chunk }) => {
  let nonce = -1, attempts = 0;
  try {
    const s = makeSearcher(Buffer.from(randomData, 'utf8'), difficulty);
    for (;;) {
      if (Atomics.load(ctl, 1)) break;
      const c = Atomics.add(ctl, 0, 1);
      const start = c * chunk;
      const r = s.search(start, start + chunk);
      if (r >= 0) { nonce = r; attempts += r - start + 1; Atomics.store(ctl, 1, 1); break; }
      attempts += chunk;
    }
  } catch (e) {
    Atomics.store(ctl, 1, 1);
    parentPort.postMessage({ id, nonce: -1, attempts, error: String(e && e.message || e) });
    return;
  }
  parentPort.postMessage({ id, nonce, attempts });
});
