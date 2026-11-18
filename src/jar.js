'use strict';

/** Minimal single-site cookie jar (enough for the Anubis handshake). */
class Jar {
  constructor() { this.map = new Map(); }
  setFromResponse(res, host) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    for (const sc of list) this.add(sc, host);
  }
  add(setCookie, host) {
    const parts = setCookie.split(';').map(s => s.trim());
    const eq = parts[0].indexOf('=');
    if (eq < 1) return;
    const c = { name: parts[0].slice(0, eq), value: parts[0].slice(eq + 1), path: '/', domain: host || '', expires: null, httpOnly: false, secure: false, sameSite: undefined };
    for (const p of parts.slice(1)) {
      const i = p.indexOf('='); const k = (i < 0 ? p : p.slice(0, i)).toLowerCase(); const v = i < 0 ? '' : p.slice(i + 1);
      if (k === 'path') c.path = v || '/';
      else if (k === 'domain') c.domain = v.replace(/^\./, '');
      else if (k === 'expires') { const d = new Date(v); if (!isNaN(d)) c.expires = d; }
      else if (k === 'max-age') { const n = parseInt(v, 10); if (!isNaN(n)) c.expires = new Date(Date.now() + n * 1000); }
      else if (k === 'httponly') c.httpOnly = true;
      else if (k === 'secure') c.secure = true;
      else if (k === 'samesite') c.sameSite = v;
    }
    const key = `${c.name}|${c.domain}|${c.path}`;
    if (c.expires && c.expires.getTime() <= Date.now()) this.map.delete(key); else this.map.set(key, c);
  }
  header() { return this.list().map(c => `${c.name}=${c.value}`).join('; '); }
  list() { const now = Date.now(); return [...this.map.values()].filter(c => !c.expires || c.expires.getTime() > now); }
}

module.exports = { Jar };
