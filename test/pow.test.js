'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { makeSearcher } = require('../src/sha256');
const { solvePow, verifyPow, closePool } = require('../src/pow');

test.after(() => closePool());

test('kernel matches node:crypto across prefix lengths, block edges and digit rollovers', () => {
  const lens = [0, 1, 31, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128, 200];
  for (const len of lens) for (const diff of [0, 1, 2, 3]) {
    const prefix = crypto.randomBytes(len).toString('hex').slice(0, len);
    const s = makeSearcher(Buffer.from(prefix), diff);
    for (const start of [0, 7, 95, 990, 9990, 99990]) {
      const n = s.search(start, start + 200000);
      assert.ok(n >= start, `hit len=${len} diff=${diff} start=${start}`);
      const z = '0'.repeat(diff);
      assert.ok(crypto.createHash('sha256').update(prefix + n).digest('hex').startsWith(z));
      for (let m = start; m < n; m++) assert.ok(!crypto.createHash('sha256').update(prefix + m).digest('hex').startsWith(z), `missed earlier nonce ${m}`);
    }
  }
});

test('solvePow inline (low difficulty)', async () => {
  for (let i = 0; i < 20; i++) {
    const rd = crypto.randomBytes(32).toString('hex');
    const r = await solvePow({ randomData: rd, difficulty: 3 });
    assert.ok(verifyPow(rd, r.nonce, 3));
    assert.strictEqual(r.hash, crypto.createHash('sha256').update(rd + r.nonce).digest('hex'));
  }
});

test('solvePow via worker pool (difficulty 5)', async () => {
  const rd = crypto.randomBytes(32).toString('hex');
  const r = await solvePow({ randomData: rd, difficulty: 5, threads: 3 });
  assert.ok(r.hash.startsWith('00000'));
  assert.ok(verifyPow(rd, r.nonce, 5));
  // pool is reusable and jobs serialise correctly
  const rs = await Promise.all([1, 2, 3].map(() => solvePow({ randomData: crypto.randomBytes(32).toString('hex'), difficulty: 5, threads: 3 })));
  for (const x of rs) assert.ok(x.hash.startsWith('00000'));
});

test('abort and timeout are honoured', async () => {
  const rd = crypto.randomBytes(32).toString('hex');
  await assert.rejects(() => solvePow({ randomData: rd, difficulty: 9, threads: 2, timeoutMs: 150 }), /timeout/);
  await assert.rejects(() => solvePow({ randomData: rd, difficulty: 9, threads: 1, timeoutMs: 150 }), /timeout/);
  const ac = new AbortController(); setTimeout(() => ac.abort(), 100);
  await assert.rejects(() => solvePow({ randomData: rd, difficulty: 9, threads: 2, signal: ac.signal }));
});
