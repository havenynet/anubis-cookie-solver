'use strict';
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Worker } = require('node:worker_threads');
const { makeSearcher } = require('./sha256');

const CHUNK = 1 << 14;
const defaultThreads = () =>
  Math.max(1, Math.min(8, typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length));

class PowError extends Error { constructor(m) { super(m); this.name = 'PowError'; this.code = 'POW_FAILED'; } }

const sha256hex = s => crypto.createHash('sha256').update(s).digest('hex');
const verifyPow = (randomData, nonce, difficulty) => {
  const h = sha256hex(randomData + nonce);
  return h.startsWith('0'.repeat(difficulty)) ? h : null;
};

class Pool {
  constructor(size) { this.size = size; this.workers = []; this.chain = Promise.resolve(); this.seq = 0; }
  _ensure() {
    while (this.workers.length < this.size) {
      const w = new Worker(path.join(__dirname, 'pow-worker.js'));
      w.unref();
      w.on('error', () => { this.workers = this.workers.filter(x => x !== w); });
      this.workers.push(w);
    }
  }
  run(job) { const p = this.chain.then(() => this._run(job)); this.chain = p.catch(() => {}); return p; }
  _run({ randomData, difficulty, signal, deadline }) {
    this._ensure();
    const ctl = new Int32Array(new SharedArrayBuffer(8));
    const id = ++this.seq;
    const workers = this.workers.slice();
    return new Promise((resolve, reject) => {
      let pending = workers.length, found = -1, attempts = 0, err = null;
      const stop = () => Atomics.store(ctl, 1, 1);
      const timer = deadline ? setTimeout(() => { err = err || new PowError('timeout'); stop(); }, Math.max(0, deadline - Date.now())) : null;
      const onAbort = () => { err = err || signal.reason || new PowError('aborted'); stop(); };
      if (signal) { if (signal.aborted) onAbort(); else signal.addEventListener('abort', onAbort, { once: true }); }
      const done = () => {
        if (timer) clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);
        found >= 0 ? resolve({ nonce: found, attempts }) : reject(err || new PowError('search exhausted'));
      };
      for (const w of workers) {
        let settled = false;
        const fin = m => {
          if (settled) return; settled = true;
          w.off('message', onMsg); w.off('error', onErr);
          if (m) { attempts += m.attempts || 0; if (m.error) err = err || new PowError(m.error); if (m.nonce >= 0 && found < 0) found = m.nonce; }
          if (--pending === 0) done();
        };
        const onMsg = m => { if (m.id === id) fin(m); };
        const onErr = e => { err = err || e; stop(); fin(null); };
        w.on('message', onMsg); w.on('error', onErr);
        w.postMessage({ id, randomData, difficulty, ctl, chunk: CHUNK });
      }
    });
  }
  close() { const ws = this.workers; this.workers = []; return Promise.all(ws.map(w => w.terminate())); }
}

let pool = null;
const getPool = n => { if (!pool || pool.size !== n) { if (pool) pool.close(); pool = new Pool(n); } return pool; };
const closePool = async () => { if (pool) { const p = pool; pool = null; await p.close(); } };

async function solveInline(prefix, difficulty, signal, deadline) {
  const s = makeSearcher(prefix, difficulty);
  const step = CHUNK * 4;
  let start = 0;
  for (;;) {
    const n = s.search(start, start + step);
    if (n >= 0) return { nonce: n, attempts: n + 1 };
    start += step;
    if (signal && signal.aborted) throw signal.reason || new PowError('aborted');
    if (deadline && Date.now() > deadline) throw new PowError('timeout');
    await new Promise(r => setImmediate(r)); // keep the event loop alive between chunks
  }
}

/**
 * Find nonce with sha256(randomData + nonce) starting with `difficulty` zero hex nibbles.
 * Small difficulties run inline (a few ms); larger ones fan out over worker threads.
 */
async function solvePow({ randomData, difficulty, threads, signal, timeoutMs, inlineMaxDifficulty = 4 }) {
  if (typeof randomData !== 'string') throw new TypeError('randomData must be a string');
  const t0 = process.hrtime.bigint();
  const deadline = timeoutMs ? Date.now() + timeoutMs : 0;
  const n = threads || defaultThreads();
  const r = (n <= 1 || difficulty <= inlineMaxDifficulty)
    ? await solveInline(Buffer.from(randomData, 'utf8'), difficulty, signal, deadline)
    : await getPool(n).run({ randomData, difficulty, signal, deadline });
  const hash = verifyPow(randomData, r.nonce, difficulty);
  if (!hash) throw new PowError('internal error: solver produced an invalid nonce');
  return { nonce: r.nonce, hash, attempts: r.attempts, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
}

module.exports = { solvePow, verifyPow, closePool, sha256hex, PowError, defaultThreads };
