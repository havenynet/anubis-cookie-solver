'use strict';
const { solveNative, toPuppeteerCookies, DEFAULT_UA } = require('./native');
const { solvePow, verifyPow, closePool } = require('./pow');
const { looksLikeChallenge, parseChallenge, ChallengeError, UnsupportedChallengeError, ChallengeFailedError, DeniedError } = require('./challenge');
const { Jar } = require('./jar');

/** solve(url, opts) -> { cookies, cookieHeader, userAgent, expiresAt, ... }. Only the native tier exists so far. */
const solve = (url, opts) => solveNative(url, opts);

module.exports = {
  solve, solveNative, solvePow, verifyPow, closePool, looksLikeChallenge, parseChallenge, toPuppeteerCookies, Jar, DEFAULT_UA,
  ChallengeError, UnsupportedChallengeError, ChallengeFailedError, DeniedError,
};
