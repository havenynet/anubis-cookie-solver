'use strict';

const MARK = /\.within\.website\/x\/cmd\/anubis\//;
const CHALLENGE_RE = /<script[^>]*\bid=["']anubis_challenge["'][^>]*>([\s\S]*?)<\/script>/i;
const PREFIX_RE = /<script[^>]*\bid=["']anubis_base_prefix["'][^>]*>([\s\S]*?)<\/script>/i;
const META_RE = /<meta\b[^>]*http-equiv=["']?refresh["']?[^>]*>/i;

/** Cheap check: does this body look like an Anubis interstitial? */
const looksLikeChallenge = body => typeof body === 'string' && (MARK.test(body) || CHALLENGE_RE.test(body));

const decodeEntities = s => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');

/**
 * Parse an Anubis challenge page. Returns null when the body is not a challenge.
 *   kind: 'pow' | 'preact' | 'meta-refresh' | 'unsupported'
 */
function parseChallenge(html) {
  if (typeof html !== 'string') return null;
  let basePrefix = '';
  const pm = PREFIX_RE.exec(html);
  if (pm) { try { const v = JSON.parse(pm[1].trim()); if (typeof v === 'string') basePrefix = v.replace(/\/$/, ''); } catch { /* ignore */ } }

  const cm = CHALLENGE_RE.exec(html);
  if (cm) {
    let j;
    try { j = JSON.parse(cm[1].trim()); } catch { return { kind: 'unsupported', algorithm: 'unparseable-json', basePrefix }; }
    const rules = j.rules || {}, ch = j.challenge || {};
    const algorithm = String(ch.method || rules.algorithm || '').toLowerCase();
    const difficulty = Number(ch.difficulty ?? rules.difficulty);
    const base = { algorithm, difficulty, id: ch.id, randomData: ch.randomData, basePrefix, keys: { rules: Object.keys(rules), challenge: Object.keys(ch) } };
    if ((algorithm === 'fast' || algorithm === 'slow') && typeof ch.randomData === 'string' && Number.isInteger(difficulty) && difficulty >= 0 && difficulty <= 16)
      return { kind: 'pow', ...base };
    if (algorithm === 'preact' && typeof ch.randomData === 'string') return { kind: 'preact', ...base };
    if (algorithm === 'metarefresh') { const m = parseMeta(html); if (m) return { kind: 'meta-refresh', ...base, ...m }; }
    return { kind: 'unsupported', ...base };
  }
  const m = parseMeta(html);
  if (m && MARK.test(m.url)) return { kind: 'meta-refresh', algorithm: 'metarefresh', basePrefix, ...m };
  return null;
}

function parseMeta(html) {
  const tag = META_RE.exec(html);
  if (!tag) return null;
  const c = /content=["']\s*([\d.]+)\s*;\s*url=([^"']+)["']/i.exec(tag[0]);
  if (!c) return null;
  return { waitMs: Math.round(parseFloat(c[1]) * 1000), url: decodeEntities(c[2].trim()) };
}

class ChallengeError extends Error { constructor(m, code, extra) { super(m); this.name = new.target.name; this.code = code; Object.assign(this, extra); } }
class UnsupportedChallengeError extends ChallengeError { constructor(algorithm, info) { super(`unsupported Anubis challenge: ${algorithm || 'unknown'}`, 'UNSUPPORTED', { algorithm, info }); } }
class ChallengeFailedError extends ChallengeError { constructor(m, extra) { super(m, 'FAILED', extra); } }
class DeniedError extends ChallengeError { constructor(status) { super(`blocked by Anubis policy (HTTP ${status}); no challenge offered`, 'DENIED', { status }); } }

module.exports = { looksLikeChallenge, parseChallenge, ChallengeError, UnsupportedChallengeError, ChallengeFailedError, DeniedError };
