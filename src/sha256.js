'use strict';
// Specialised SHA-256 nonce search for Anubis-style PoW:
//   find n such that sha256(prefix + decimal(n)) starts with `difficulty` zero hex nibbles.
// Speedups vs. hashing strings with node:crypto per attempt:
//   - the constant prefix is compressed ONCE (midstate); only the 1-2 tail blocks are hashed per nonce
//   - the decimal nonce is incremented in place inside the message block (no string/Buffer allocation)
//   - only the first digest words are inspected (no hex conversion)

const K = Int32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const IV = Int32Array.from([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

// W: Int32Array(64) whose first 16 words hold the block. S: Int32Array(8), updated in place.
function compress(S, W) {
  for (let t = 16; t < 64; t++) {
    const x = W[t - 15], y = W[t - 2];
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
  }
  let a = S[0], b = S[1], c = S[2], d = S[3], e = S[4], f = S[5], g = S[6], h = S[7];
  for (let t = 0; t < 64; t++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  S[0] = (S[0] + a) | 0; S[1] = (S[1] + b) | 0; S[2] = (S[2] + c) | 0; S[3] = (S[3] + d) | 0;
  S[4] = (S[4] + e) | 0; S[5] = (S[5] + f) | 0; S[6] = (S[6] + g) | 0; S[7] = (S[7] + h) | 0;
}

function loadBlock(bytes, off, W) {
  for (let i = 0; i < 16; i++) {
    const o = off + i * 4;
    W[i] = (bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3];
  }
}

const POW10 = [1];
for (let i = 1; i <= 15; i++) POW10.push(POW10[i - 1] * 10);
const digitsOf = n => (n === 0 ? 1 : Math.floor(Math.log10(n)) + 1);

function makeSearcher(prefix /* Buffer|Uint8Array */, difficulty) {
  if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > 16) {
    throw new RangeError('difficulty must be an integer 0..16 (leading hex nibbles)');
  }
  const P = prefix.length;
  const full = P - (P % 64);
  const rem = P % 64;
  const mid = Int32Array.from(IV);
  const tmp = new Int32Array(64);
  for (let off = 0; off < full; off += 64) { loadBlock(prefix, off, tmp); compress(mid, tmp); }

  const trivial = difficulty === 0;
  const shift = 32 - 4 * Math.min(difficulty, 8);
  const needSecond = difficulty > 8;
  const shift2 = 32 - 4 * (difficulty - 8);

  function segment(nd, from, to) {
    const tailLen = rem + nd;
    const nblocks = tailLen + 9 <= 64 ? 1 : 2;
    const T = new Uint8Array(nblocks * 64);
    T.set(prefix.subarray(full, P), 0);
    T[tailLen] = 0x80;
    const bitLen = (P + nd) * 8;
    const L = T.length;
    const hi = Math.floor(bitLen / 4294967296), lo = bitLen >>> 0;
    T[L - 8] = hi >>> 24; T[L - 7] = hi >>> 16; T[L - 6] = hi >>> 8; T[L - 5] = hi;
    T[L - 4] = lo >>> 24; T[L - 3] = lo >>> 16; T[L - 2] = lo >>> 8; T[L - 1] = lo;

    const W1 = new Int32Array(64), W2 = new Int32Array(64);
    const wordOf = k => (T[4 * k] << 24) | (T[4 * k + 1] << 16) | (T[4 * k + 2] << 8) | T[4 * k + 3];
    const s = String(from);
    for (let j = 0; j < nd; j++) T[rem + j] = s.charCodeAt(j);
    for (let k = 0; k < nblocks * 16; k++) (k < 16 ? W1 : W2)[k & 15] = wordOf(k);

    const S = new Int32Array(8);
    for (let n = from; n < to; n++) {
      S.set(mid);
      compress(S, W1);
      if (nblocks === 2) compress(S, W2);
      if (trivial || ((S[0] >>> shift) === 0 && (!needSecond || (S[1] >>> shift2) === 0))) return n;

      // increment the decimal nonce in place, refresh only the touched words
      let i = nd - 1;
      while (i >= 0 && T[rem + i] === 57) { T[rem + i] = 48; i--; }
      if (i < 0) break; // overflow: callers never cross a digit-count boundary
      T[rem + i]++;
      const k0 = (rem + i) >> 2, k1 = (rem + nd - 1) >> 2;
      for (let k = k0; k <= k1; k++) (k < 16 ? W1 : W2)[k & 15] = wordOf(k);
    }
    return -1;
  }

  // Search nonces in [start, end). Returns the first hit or -1. Splits at decimal-length boundaries.
  function search(start, end) {
    let n = start;
    while (n < end) {
      const nd = digitsOf(n);
      const to = Math.min(end, POW10[nd]);
      const r = segment(nd, n, to);
      if (r >= 0) return r;
      n = to;
    }
    return -1;
  }
  return { search };
}

module.exports = { makeSearcher, compress, IV, K };
