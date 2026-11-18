'use strict';
// node bench/bench.js  — compares hashing strategies and end-to-end time-to-solve.
const crypto = require('node:crypto');
const { makeSearcher } = require('../src/sha256');
const { solvePow, closePool, defaultThreads } = require('../src/pow');

const prefix = crypto.randomBytes(32).toString('hex');
const N = 1_000_000;
const time = f => { const t = process.hrtime.bigint(); f(); return Number(process.hrtime.bigint() - t) / 1e6; };
const rate = ms => (N / ms / 1000).toFixed(2) + ' MH/s';

const s = makeSearcher(Buffer.from(prefix), 8); s.search(0, 50_000);
console.log('single-thread hashing, 1M attempts');
console.log('  crypto.createHash (naive)  ', rate(time(() => { for (let n = 0; n < N; n++) crypto.createHash('sha256').update(prefix + n).digest('hex'); })));
if (crypto.hash) console.log('  crypto.hash one-shot       ', rate(time(() => { for (let n = 0; n < N; n++) crypto.hash('sha256', prefix + n, 'hex'); })));
console.log('  midstate kernel (this pkg) ', rate(time(() => s.search(100_000, 100_000 + N))));

(async () => {
  const median = a => a.sort((x, y) => x - y)[a.length >> 1];
  console.log(`\ntime-to-solve (median of 9 random challenges), cores=${defaultThreads()}`);
  for (const d of [4, 5, 6]) for (const th of [1, defaultThreads()]) {
    if (th === 1 && d === 6) continue;               // ~16M attempts single-threaded: slow, skip by default
    const xs = [];
    for (let i = 0; i < 9; i++) xs.push((await solvePow({ randomData: crypto.randomBytes(32).toString('hex'), difficulty: d, threads: th })).ms);
    console.log(`  difficulty ${d}  threads ${String(th).padEnd(2)} -> ${median(xs).toFixed(0).padStart(5)} ms`);
  }
  await closePool();
})();
