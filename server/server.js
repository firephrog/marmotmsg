'use strict';
/**
 * Marmot server — accounts, prekey directory, encrypted mailbox and an
 * encrypted per-user blob store, plus a WebSocket that pushes new envelopes.
 *
 * It never holds a key that opens message content or a user's chat history:
 *   - envelopes are Double Ratchet ciphertext produced in the browser;
 *   - the account vault (identity private keys) is encrypted in the browser
 *     with a key derived from the password, and the server only ever sees a
 *     separate derived *auth* key, which it stores as an scrypt verifier;
 *   - blobs (ratchet state, message history, prekey privates) are encrypted
 *     in the browser with a data key that lives inside that vault.
 * On top of that, every sensitive column is sealed at rest (see seal.js).
 */
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const { WebSocketServer } = require('ws');
const store = require('./db');
const { Discord, Bridge } = require('./discord');
const admin = require('./admin');

const VERSION = '0.6.0';
const TOKEN_TTL = 30 * 24 * 3600 * 1000;
const ENVELOPE_TTL = 30 * 24 * 3600 * 1000;
const MIN_ITER = 300000;
const LIMITS = {
  body: '6mb', puts: 600, putBytes: 256 * 1024, sends: 32, payloadBytes: 128 * 1024,
  opksPerCommit: 200, opksTotal: 500, blobsTotal: 100000, inbox: 300,
  peers: 2000, globalPage: 50, groupMembers: 32, groups: 200, groupApps: 50, appReason: 200, groupTag: 4
};
const TAG_VIS = new Set(['off', 'friends', 'all']);
const TAG_MODES = new Set(['join', 'apply']);
const MAX_GMUTE = 365 * 24 * 3600 * 1000;
const PEER_ACTIONS = new Set(['request', 'accept', 'remove', 'block', 'unblock']);
const USERNAME = /^[a-zA-Z0-9._-]{3,24}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const BLOBKEY = /^[0-9a-f]{32}$/;
const GROUPID = /^[0-9a-f]{24}$/;
// A profile picture: already downscaled by the client to a small square image.
const AVATAR = /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const AVATAR_CHARS = 64 * 1024;
/** What others see of someone while they are signed in: online/idle by activity, do not disturb, or offline. */
const PRESENCE_MODES = new Set(['auto', 'dnd', 'invisible']);
const PROFILE_MAX = { display: 32, bio: 300, status: 80 };
const ACCENT = /^#[0-9a-fA-F]{6}$/;
// control characters (a bio keeps its line breaks), and the bidi overrides that can make a name read as someone else's
const UNSAFE = /[\u0000-\u0009\u000b-\u001f\u007f‪-‮⁦-⁩]/g;

/* ------------------------------------------------------------- helpers */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = msg => new HttpError(400, msg);
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const b64bytes = (s, n) => typeof s === 'string' && B64.test(s) && Buffer.from(s, 'base64').length === n;
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && B64.test(s);
const asArray = (v, max, what) => {
  if (v == null) return [];
  if (!Array.isArray(v)) throw bad(what + ' must be a list');
  if (v.length > max) throw bad('too many ' + what);
  return v;
};

function userIdFor(ik, sk) {
  return sha256(Buffer.concat([Buffer.from(ik, 'base64'), Buffer.from(sk, 'base64')])).slice(0, 32);
}
function verifyEd25519(pubB64, sigB64, data) {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pubB64, 'base64').toString('base64url') }, format: 'jwk' });
    return crypto.verify(null, data, key, Buffer.from(sigB64, 'base64'));
  } catch (e) { return false; }
}
function makeVerifier(authB64) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(Buffer.from(authB64, 'base64'), salt, 32, { N: 16384, r: 8, p: 1 });
  return 'scrypt$' + salt.toString('base64') + '$' + hash.toString('base64');
}
function checkVerifier(verifier, authB64) {
  const [, salt, hash] = String(verifier).split('$');
  const want = Buffer.from(hash, 'base64');
  const got = crypto.scryptSync(Buffer.from(String(authB64), 'base64'), Buffer.from(salt, 'base64'), 32, { N: 16384, r: 8, p: 1 });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
function checkVault(v) {
  if (!v || typeof v !== 'object' || !isB64(v.iv, 64) || !isB64(v.ct, 64 * 1024)) throw bad('malformed vault');
  return { iv: v.iv, ct: v.ct };
}
function checkOpks(list, max) {
  return asArray(list, max, 'prekeys').map(p => {
    if (!p || !Number.isInteger(p.id) || p.id < 1 || p.id > 2 ** 31 || !b64bytes(p.pub, 32)) throw bad('malformed prekey');
    return { id: p.id, pub: p.pub };
  });
}
/** One profile field as text: unsafe characters out, trimmed, at most `max` long. Only a bio keeps line breaks. */
function profileText(v, max, what, lines) {
  if (v == null) return '';
  if (typeof v !== 'string') throw bad(what + ' must be text');
  let s = v.normalize('NFC');
  s = lines ? s.replace(/\r\n?/g, '\n').replace(UNSAFE, '').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n')
    : s.replace(/\s+/g, ' ').replace(UNSAFE, '');
  s = s.trim();
  if (s.length > max) throw bad(what + ' can be at most ' + max + ' characters');
  return s;
}
/** One emoji (a single grapheme that is a pictograph or a flag), or '' for none. */
const EMOJI_PARTS = /^(?:\p{Extended_Pictographic}|\p{Regional_Indicator}|\p{Emoji_Modifier}|[\u200d\ufe0f\u20e3#*0-9])+$/u;
const EMOJI_CORE = /\p{Extended_Pictographic}|\p{Regional_Indicator}/u;
const graphemes = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
function checkEmoji(v) {
  if (v == null || v === '') return '';
  if (typeof v !== 'string' || v.length > 16) throw bad('the tag emoji must be one emoji');
  const e = v.normalize('NFC').trim();
  if (!e) return '';
  if (!EMOJI_PARTS.test(e) || !EMOJI_CORE.test(e) || [...graphemes.segment(e)].length !== 1) throw bad('the tag emoji must be one emoji');
  return e;
}
/** A profile update merged over the current one; fields left out stay as they were. */
function checkProfile(b, cur) {
  const out = { display: cur.display || '', bio: cur.bio || '', status: cur.status || '', accent: cur.accent || '' };
  if (cur.gtag) out.gtag = cur.gtag;
  if ('display' in b) out.display = profileText(b.display, PROFILE_MAX.display, 'a display name');
  if ('bio' in b) out.bio = profileText(b.bio, PROFILE_MAX.bio, 'a bio', true);
  if ('status' in b) out.status = profileText(b.status, PROFILE_MAX.status, 'a status');
  if ('accent' in b) {
    if (b.accent != null && b.accent !== '' && (typeof b.accent !== 'string' || !ACCENT.test(b.accent))) throw bad('the accent color must look like #f0a92a');
    out.accent = b.accent ? b.accent.toLowerCase() : '';
  }
  if ('gtag' in b) {
    if (b.gtag != null && b.gtag !== '' && (typeof b.gtag !== 'string' || !GROUPID.test(b.gtag))) throw bad('malformed group tag');
    if (b.gtag) out.gtag = b.gtag; else delete out.gtag;
  }
  return out;
}
function checkPuts(list) {
  return asArray(list, LIMITS.puts, 'puts').map(p => {
    if (!p || typeof p.k !== 'string' || !BLOBKEY.test(p.k)) throw bad('malformed blob name');
    if (typeof p.v !== 'string' || p.v.length > LIMITS.putBytes) throw bad('blob too large');
    return { k: p.k, v: p.v };
  });
}

/** Tiny fixed-window limiter for the unauthenticated endpoints. */
function limiter(perMinute) {
  const hits = new Map();
  setInterval(() => hits.clear(), 60000).unref();
  return (req, res, next) => {
    const k = req.ip + ' ' + req.path;
    const n = (hits.get(k) || 0) + 1;
    hits.set(k, n);
    if (n > perMinute) return res.status(429).json({ ok: false, error: 'too many attempts — wait a minute' });
    next();
  };
}

/** Reads the client file and the VERSION it declares, again only when the file changes. */
function clientReader(file) {
  let cached = null;
  return () => {
    let st;
    try { st = fs.statSync(file); } catch (e) { throw new HttpError(404, 'client not found'); }
    if (!cached || cached.mtime !== st.mtimeMs || cached.size !== st.size) {
      const html = fs.readFileSync(file, 'utf8');
      const m = /const VERSION='([\d.]+)'/.exec(html);
      if (!m) throw new HttpError(404, 'client has no version');
      cached = { mtime: st.mtimeMs, size: st.size, html, v: m[1] };
    }
    return cached;
  };
}

/* ---------------------------------------------------------------- app */
function createServer(opts) {
  opts = opts || {};
  const db = opts.db || store.open(opts);
  const dataDir = opts.dataDir || process.env.MARMOT_DATA || path.join(__dirname, 'data');
  const staff = opts.staff || new admin.Staff(opts.adminFile || process.env.MARMOT_ADMIN || path.join(dataDir, 'admin.json'));
  const app = express();
  // A number is a hop count (CloudFront → nginx → here is 2); anything else is Express's own syntax.
  const tp = process.env.TRUST_PROXY;
  if (tp) app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : tp === 'true' ? true : tp);
  app.disable('x-powered-by');

  // The client is a standalone HTML file that may be opened from file:// (Origin: null)
  // or any host. Auth is a bearer token, never a cookie, so open CORS cannot be ridden.
  app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.set('Access-Control-Max-Age', '600');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
  app.use(express.json({ limit: LIMITS.body }));

  // An IP-banned address gets nothing but this. `banned` tells a signed-in client to sign out.
  app.use('/api', (req, res, next) => {
    if (db.ipBanned(admin.normIp(req.ip))) return res.status(403).json({ ok: false, error: 'this network is banned from this server', banned: true });
    next();
  });

  const wrap = fn => (req, res) => {
    Promise.resolve().then(() => fn(req, res)).then(out => {
      if (!res.headersSent) res.json(Object.assign({ ok: true }, out));
    }).catch(err => {
      const status = err.status || (err.type === 'entity.too.large' ? 413 : 500);
      if (status === 500) console.error(err);
      res.status(status).json(Object.assign({ ok: false, error: status === 500 ? 'server error' : err.message }, status === 500 ? {} : err.extra));
    });
  };

  function auth(req) {
    const m = /^Bearer (\S+)$/.exec(req.get('authorization') || '');
    if (!m) throw new HttpError(401, 'not signed in');
    const hash = sha256(m[1]);
    const s = db.session(hash);
    const now = Date.now();
    if (!s || s.expires < now) throw new HttpError(401, 'session expired — sign in again');
    if (s.expires - now < TOKEN_TTL - 3600 * 1000) db.extendSession(hash, now + TOKEN_TTL);
    db.touch(s.user_id, now);
    const row = db.userRow(s.user_id);
    if (!row) throw new HttpError(401, 'account no longer exists');
    req.tokenHash = hash;
    seenAt(row, req);
    return row;
  }
  /** Remembers the address each account last used, which is what an IP ban bans. Written only when it changes. */
  const lastIp = new Map();
  function seenAt(row, req) {
    const ip = admin.normIp(req.ip);
    if (!ip || lastIp.get(row.id) === ip) return;
    if (lastIp.size > 50000) lastIp.clear();
    lastIp.set(row.id, ip);
    if (db.lastIp(row) !== ip) db.setLastIp(row.id, ip);
  }
  /** 'admin' or 'mod' for staff, so clients can tag them in chats; undefined for everyone else. */
  const roleOf = row => { const s = staff.of(row.username); return s ? s.role : undefined; };
  /** When a user's mute ends (0 = permanent), so clients can tag them; undefined if they are not muted. */
  const mutedOf = row => { const m = db.mute(row.id); return m ? m.until : undefined; };
  /** What the signed-in user should know about their standing: staff role and any mute. */
  function standing(row) {
    const m = db.mute(row.id);
    return { staff: staff.of(row.username), mute: m && { until: m.until, reason: m.reason } };
  }
  /** Muted users cannot send anything that says something; see 'say' in /api/commit. */
  function checkMute(row) {
    const m = db.mute(row.id);
    if (m) throw Object.assign(new HttpError(403, m.until ? 'you are muted until ' + new Date(m.until).toUTCString() : 'you are muted permanently'), { extra: { muted: m.until } });
  }
  /** This account's own profile and presence mode, for a login or /api/me. */
  const mine = row => ({ pv: row.profile_v, profile: db.profile(row), presence: row.presence || 'auto' });
  /**
   * What `viewer` may see of someone's profile in a list: its version, the display name, and
   * presence (`pr`). Presence is only for people who can reach each other (friends, or members of
   * a group in common, with no block either way); for anyone else `pr` is null.
   */
  function profView(row, viewer, reach) {
    const see = row.id === viewer || (reach != null ? reach : canReach(viewer, row.id));
    const pf = db.profile(row);
    return { pv: row.profile_v, dn: pf.display || '', ps: pf.status || '', pr: see ? presenceOf(row.id, row) : null };
  }
  /** Everyone who might be showing this user: their peers and the people they share a group with. */
  function audience(userId) {
    const out = new Set(db.peers(userId).map(p => p.peer));
    for (const g of db.groupIdsOf(userId)) for (const m of db.groupMembers(g)) out.add(m.userId);
    out.delete(userId);
    return out;
  }
  function pushProfile(row) {
    const pf = db.profile(row);
    const msg = { t: 'profile', userId: row.id, v: row.profile_v, username: row.username, dn: pf.display || '', ps: pf.status || '' };
    for (const o of audience(row.id).add(row.id)) hub.push(o, msg);
  }
  /** online | idle | dnd | offline: what others see right now. Idle is every open socket saying so. */
  function presenceOf(userId, row) {
    row = row || db.userRow(userId);
    const set = hub.sockets.get(userId);
    if (!row || !set || !set.size || row.presence === 'invisible') return 'offline';
    if (row.presence === 'dnd') return 'dnd';
    for (const ws of set) if (!ws.idle) return 'online';
    return 'idle';
  }
  /** Tells everyone who can see it when someone's presence moves. Going offline by losing the
      socket waits out a short grace, so a reload or a network blip does not flicker. */
  const shownPr = new Map(), prTimers = new Map();
  const offlineGrace = opts.offlineGrace != null ? opts.offlineGrace : 8000;
  let stopped = false;
  /** Runs from socket events and timers, where a throw would take the process down: errors are logged instead. */
  function presenceChanged(userId, now) {
    clearTimeout(prTimers.get(userId)); prTimers.delete(userId);
    if (stopped) return;
    try { updatePresence(userId, now); } catch (e) { console.error('[marmot] presence update failed:', e.message); }
  }
  function updatePresence(userId, now) {
    const row = db.userRow(userId), p = presenceOf(userId, row), was = shownPr.get(userId) || 'offline';
    if (p === was) return;
    if (p === 'offline' && !now && offlineGrace > 0) {
      const t = setTimeout(() => { prTimers.delete(userId); presenceChanged(userId, true); }, offlineGrace);
      if (t.unref) t.unref();
      prTimers.set(userId, t);
      return;
    }
    if (p === 'offline') shownPr.delete(userId); else shownPr.set(userId, p);
    if (!row) return;
    for (const o of audience(userId)) if (canReach(userId, o)) hub.push(o, { t: 'presence', userId, p });
  }
  function issueToken(userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    db.createSession(sha256(token), userId, TOKEN_TTL);
    return token;
  }

  const strict = limiter(opts.authPerMinute || 20);

  // Voice: STUN finds each browser's public address; TURN relays audio when
  // the two cannot reach each other directly. TURN credentials are minted per
  // request from a shared secret (coturn's use-auth-secret) and expire, so the
  // secret never reaches a browser.
  const list = v => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
  const ice = opts.ice || {
    stun: process.env.STUN_URLS != null ? list(process.env.STUN_URLS) : ['stun:stun.l.google.com:19302'],
    turn: list(process.env.TURN_URLS),
    secret: process.env.TURN_SECRET || ''
  };

  app.get('/api/health', wrap(() => ({ service: 'marmot', v: VERSION, ts: Date.now() })));

  app.get('/api/available', limiter(60), wrap(req => {
    const name = String(req.query.username || '');
    return { free: USERNAME.test(name) && !db.userRowByName(name) };
  }));

  /**
   * Signup claims a username and publishes the identity + prekeys. The client
   * proves the bundle hangs together: the user id must be the hash of the
   * identity keys, and the signed prekey must verify under the signing key.
   */
  app.post('/api/signup', strict, wrap(req => {
    const b = req.body || {};
    const username = String(b.username || '').trim();
    if (!USERNAME.test(username)) throw bad('usernames are 3-24 characters: letters, digits, dot, dash, underscore');
    if (!b64bytes(b.salt, 16) || !Number.isInteger(b.iter) || b.iter < MIN_ITER || b.iter > 5e6) throw bad('bad key-derivation parameters');
    if (!b64bytes(b.auth, 32)) throw bad('bad auth key');
    const id = b.identity || {}, spk = b.spk || {};
    if (!b64bytes(id.ik, 32) || !b64bytes(id.sk, 32)) throw bad('malformed identity keys');
    if (!Number.isInteger(spk.id) || !b64bytes(spk.pub, 32) || !b64bytes(spk.sig, 64)) throw bad('malformed signed prekey');
    if (!verifyEd25519(id.sk, spk.sig, Buffer.from(spk.pub, 'base64'))) throw bad('signed prekey does not verify');
    const userId = userIdFor(id.ik, id.sk);
    if (b.userId !== userId) throw bad('user id does not match identity keys');
    const opks = checkOpks(b.opks, LIMITS.opksPerCommit);
    const puts = checkPuts(b.puts);
    if (db.userRowByName(username)) throw new HttpError(409, 'that username is taken');
    if (db.userRow(userId)) throw new HttpError(409, 'this identity is already registered');
    try {
      db.signup({ id: userId, username, salt: b.salt, iter: b.iter, verifier: makeVerifier(b.auth),
        identity: { ik: id.ik, sk: id.sk }, spk: { id: spk.id, pub: spk.pub, sig: spk.sig }, vault: checkVault(b.vault) }, opks, puts);
    } catch (e) {
      if (/UNIQUE/.test(e.message)) throw new HttpError(409, 'that username is taken');
      throw e;
    }
    lastIp.delete(userId);
    seenAt(db.userRow(userId), req);
    return { token: issueToken(userId), userId, username };
  }));

  /** Salt and iteration count, so the client can derive its keys before logging in. */
  app.post('/api/prelogin', strict, wrap(req => {
    const row = db.userRowByName(String((req.body || {}).username || '').trim());
    if (!row) throw new HttpError(404, 'no such account');
    return { salt: row.salt, iter: row.iter };
  }));

  /**
   * One active device per account: the ratchet state is a single line of
   * history, and two devices advancing it at once would fork it. Logging in
   * revokes every other session and tells their sockets to sign out.
   */
  app.post('/api/login', strict, wrap(req => {
    const b = req.body || {};
    const row = db.userRowByName(String(b.username || '').trim());
    if (!row || !b64bytes(b.auth, 32) || !checkVerifier(row.verifier, b.auth)) throw new HttpError(401, 'wrong username or password');
    const token = issueToken(row.id);
    db.deleteOtherSessions(row.id, sha256(token));
    hub.revoke(row.id);
    seenAt(row, req);
    return Object.assign({ token, userId: row.id, username: row.username, vault: db.vault(row), discoverable: !!row.discoverable, av: row.avatar_v }, standing(row), mine(row));
  }));

  app.post('/api/logout', wrap(req => {
    auth(req);
    db.deleteSession(req.tokenHash);
    return {};
  }));

  app.get('/api/me', wrap(req => {
    const row = auth(req);
    const spk = db.spk(row);
    return Object.assign({ userId: row.id, username: row.username, created: row.created, spkId: spk.id,
      opkCount: db.prekeyCount(row.id), blobCount: db.blobCount(row.id), discoverable: !!row.discoverable, av: row.avatar_v }, standing(row), mine(row));
  }));

  /**
   * Profile pictures are public, like usernames: any signed-in user who can
   * look someone up can fetch theirs. Views carry only the version (`av`), so
   * clients fetch a picture once and again only when it changes.
   */
  app.post('/api/me/avatar', limiter(20), wrap(req => {
    const me = auth(req);
    const a = (req.body || {}).avatar;
    if (a !== null && (typeof a !== 'string' || a.length > AVATAR_CHARS || !AVATAR.test(a))) {
      throw bad('the picture must be a small JPEG, PNG or WebP image');
    }
    const v = db.setAvatar(me.id, a);
    for (const o of audience(me.id).add(me.id)) hub.push(o, { t: 'avatar', userId: me.id, v });
    return { av: v };
  }));

  /**
   * Profiles are public like pictures: a display name, a bio, a status line and an
   * accent color. Views carry the version (`pv`) and the display name (`dn`), so lists
   * can show the name straight away and fetch the rest once, when it is wanted.
   */
  app.get('/api/profile/:id', wrap(req => {
    const me = auth(req);
    const row = db.userRow(String(req.params.id));
    if (!row) throw new HttpError(404, 'no such user');
    return { user: Object.assign({ userId: row.id, username: row.username, created: row.created, av: row.avatar_v,
      profile: db.profile(row), role: roleOf(row), muted: mutedOf(row), gtag: tagOf(row) }, profView(row, me.id)) };
  }));

  app.post('/api/me/profile', limiter(30), wrap(req => {
    const me = auth(req);
    const p = checkProfile(req.body || {}, db.profile(me));
    if (p.gtag && p.gtag !== db.profile(me).gtag) {
      const g = db.inGroup(p.gtag, me.id) && db.group(p.gtag);
      if (!g) throw new HttpError(404, 'you are not in that group');
      if (gset(g).tag.vis === 'off' || !gset(g).tag.text) throw new HttpError(409, 'that group has no tag to show');
    }
    const v = db.setProfile(me.id, p);
    pushProfile(db.userRow(me.id));
    return { pv: v, profile: p, gtag: tagOf(db.userRow(me.id)) };
  }));

  /** auto: online or idle by activity · dnd: do not disturb · invisible: shown offline. */
  app.post('/api/me/presence', limiter(60), wrap(req => {
    const me = auth(req);
    const mode = (req.body || {}).mode;
    if (!PRESENCE_MODES.has(mode)) throw bad('presence must be auto, dnd or invisible');
    db.setPresence(me.id, mode);
    presenceChanged(me.id, true);
    return { presence: mode, pr: presenceOf(me.id) };
  }));

  /**
   * A new username. It is what people log in with and find each other by, so it takes
   * the password, like deleting the account. Identity is the keys, not the name: the
   * user id stays, so friends, groups and chats carry over. Admins are named in the
   * server's config and cannot rename here; a moderator's appointment moves with them.
   */
  app.post('/api/me/username', strict, wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const username = String(b.username || '').trim();
    if (!USERNAME.test(username)) throw bad('usernames are 3-24 characters: letters, digits, dot, dash, underscore');
    // 403, not 401: a wrong password here must not sign the client out
    if (!b64bytes(b.auth, 32) || !checkVerifier(me.verifier, b.auth)) throw new HttpError(403, 'wrong password');
    if (username === me.username) return { username, pv: me.profile_v };
    const same = username.toLowerCase() === me.username.toLowerCase();
    const other = db.userRowByName(username);
    if (other && other.id !== me.id) throw new HttpError(409, 'that username is taken');
    const was = staff.of(me.username);
    if (was && was.role === 'admin') throw new HttpError(403, 'admins are named in the server config — change it there');
    // staff go by username: a name the config already lists must not be taken by someone else
    if (!same && staff.of(username)) throw new HttpError(409, 'that username is reserved');
    const moving = !!was && !same;
    if (moving) staff.setMod(username, was.perms);   // throws, changing nothing, if the config cannot be written
    let v;
    try { v = db.rename(me.id, username); }
    catch (e) {
      if (moving) try { staff.setMod(username, []); } catch (x) {}
      if (/UNIQUE/.test(e.message)) throw new HttpError(409, 'that username is taken');
      throw e;
    }
    if (moving) try { staff.setMod(me.username, []); } catch (e) { console.error('[marmot] could not drop the old name of renamed moderator ' + username + ':', e.message); }
    db.log({ by: username, action: 'rename', target: me.username });
    pushProfile(db.userRow(me.id));
    if (was) for (const o of audience(me.id)) hub.push(o, { t: 'roles' });
    return { username, pv: v };
  }));

  app.get('/api/avatar/:id', wrap(req => {
    auth(req);
    const row = db.userRow(String(req.params.id));
    if (!row) throw new HttpError(404, 'no such user');
    return { userId: row.id, av: row.avatar_v, avatar: db.avatar(row) };
  }));

  /** Global discovery is opt-in: off until the user turns it on. */
  app.post('/api/me/discovery', wrap(req => {
    const me = auth(req);
    const on = (req.body || {}).on;
    if (typeof on !== 'boolean') throw bad('on must be true or false');
    db.setDiscoverable(me.id, on);
    return { discoverable: on };
  }));

  app.get('/api/vault', wrap(req => ({ vault: db.vault(auth(req)) })));

  /** Public identity only — fetching this does not consume a prekey. */
  app.get('/api/users/lookup', wrap(req => {
    const me = auth(req);
    const row = req.query.id ? db.userRow(String(req.query.id)) : db.userRowByName(String(req.query.username || '').trim());
    if (!row) throw new HttpError(404, 'no such user');
    const u = db.publicUser(row);
    return { user: Object.assign({ userId: u.userId, username: u.username, ik: u.ik, sk: u.sk, av: row.avatar_v, role: roleOf(row), muted: mutedOf(row) }, profView(row, me.id)) };
  }));

  /** Full prekey bundle for starting a session. Consumes one one-time prekey. */
  app.get('/api/bundle/:id', wrap(req => {
    const me = auth(req);
    const row = db.userRow(req.params.id);
    if (!row) throw new HttpError(404, 'no such user');
    if (row.id === me.id) throw bad('cannot open a session with yourself');
    // Only friends and fellow group members can start a session, so strangers cannot drain someone's prekeys.
    if (!canReach(me.id, row.id)) throw new HttpError(403, 'you can only message friends');
    const u = db.publicUser(row);
    const opk = db.takePrekey(row.id);
    const left = db.prekeyCount(row.id);
    if (left < 20) hub.push(row.id, { t: 'prekeys', count: left });
    return { bundle: { userId: u.userId, username: u.username, ik: u.ik, sk: u.sk, spk: db.spk(row), opk } };
  }));

  /**
   * ICE servers for a voice call. A relay sees only SRTP it cannot decrypt:
   * the DTLS keys are agreed between the two browsers, over the ratchet.
   */
  app.get('/api/ice', limiter(60), wrap(req => {
    auth(req);
    const iceServers = [];
    if (ice.stun.length) iceServers.push({ urls: ice.stun });
    const relay = ice.turn.length > 0 && !!ice.secret;
    if (relay) {
      const username = Math.floor(Date.now() / 1000 + 6 * 3600) + ':' + crypto.randomBytes(6).toString('hex');
      iceServers.push({ urls: ice.turn, username, credential: crypto.createHmac('sha1', ice.secret).update(username).digest('base64') });
    }
    return { iceServers, relay };
  }));

  app.get('/api/store', wrap(req => ({ blobs: db.blobs(auth(req).id) })));

  app.get('/api/inbox', wrap(req => ({ envelopes: db.inbox(auth(req).id, LIMITS.inbox) })));

  /* ------------------------------------------------------------ peers */
  const peerView = (me, p) => {
    const row = db.userRow(p.peer);
    return row && Object.assign({ userId: row.id, username: row.username, state: p.state, since: p.since, av: row.avatar_v, role: roleOf(row), muted: mutedOf(row) },
      profView(row, me, p.state === 'friend' ? true : undefined));
  };

  /** Everyone I have a relationship with: friends, requests both ways, and people I blocked. */
  app.get('/api/peers', wrap(req => {
    const me = auth(req);
    return { peers: db.peers(me.id).map(p => peerView(me.id, p)).filter(Boolean) };
  }));

  /** Users who turned on global discovery, minus anyone who blocked me. */
  app.get('/api/peers/global', limiter(120), wrap(req => {
    const me = auth(req);
    const search = String(req.query.q || '').trim().slice(0, 24);
    const offset = Math.max(0, Math.min(10000, parseInt(req.query.offset, 10) || 0));
    const users = db.discoverable(me.id, search, LIMITS.globalPage, offset);
    return {
      users: users.filter(u => { const t = db.peer(u.userId, me.id); return !t || t.state !== 'blocked'; }),
      more: users.length === LIMITS.globalPage
    };
  }));

  /**
   * The relationship state machine. Each side holds its own row:
   *   friend    both sides
   *   outgoing  I asked them   (their side: incoming)
   *   incoming  they asked me  (my side of their outgoing)
   *   blocked   I blocked them (their side is removed, and stays absent:
   *             their new requests sit as 'outgoing' and never reach me)
   * Nothing else lets two users talk: commits and prekey bundles check 'friend',
   * or a shared group chat (see canReach).
   */
  app.post('/api/peers', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    if (!PEER_ACTIONS.has(b.action)) throw bad('unknown action');
    const row = b.userId ? db.userRow(String(b.userId)) : db.userRowByName(String(b.username || '').trim());
    if (!row) throw new HttpError(404, 'no such user');
    if (row.id === me.id) throw bad('that is you');
    const them = row.id;

    const notify = db.tx(() => {
      const mine = db.peer(me.id, them), theirs = db.peer(them, me.id);
      const s = mine && mine.state, blockedByThem = !!theirs && theirs.state === 'blocked';
      const befriend = () => { db.setPeer(me.id, them, 'friend'); db.setPeer(them, me.id, 'friend'); return true; };
      const dropTheirs = () => { if (theirs && !blockedByThem) { db.delPeer(them, me.id); return true; } return false; };
      switch (b.action) {
        case 'request':
          if (s === 'blocked') throw new HttpError(409, 'unblock them first');
          if (s === 'friend' || s === 'outgoing') return false;
          if (s === 'incoming' || (theirs && theirs.state === 'outgoing')) return befriend();
          if (db.peerCount(me.id) >= LIMITS.peers) throw new HttpError(507, 'too many peers');
          db.setPeer(me.id, them, 'outgoing');
          // A user who blocked me, or whose list is full, never sees the request.
          if (blockedByThem || db.peerCount(them) >= LIMITS.peers) return false;
          db.setPeer(them, me.id, 'incoming');
          return true;
        case 'accept':
          if (s !== 'incoming') throw new HttpError(409, 'there is no request from them');
          return befriend();
        case 'remove':     // unfriend, decline, or cancel a request
          if (!s || s === 'blocked') return false;
          db.delPeer(me.id, them);
          return dropTheirs();
        case 'block':
          if (s !== 'blocked' && s !== 'friend' && db.peerCount(me.id) >= LIMITS.peers) throw new HttpError(507, 'too many peers');
          db.setPeer(me.id, them, 'blocked');
          return dropTheirs();
        case 'unblock':
          if (s !== 'blocked') return false;
          db.delPeer(me.id, them);
          // a request they sent while blocked now reaches me
          if (theirs && theirs.state === 'outgoing') db.setPeer(me.id, them, 'incoming');
          return false;
      }
    });

    hub.push(me.id, { t: 'peers' });
    if (notify) hub.push(them, { t: 'peers' });
    const now = db.peer(me.id, them);
    return { peer: { userId: them, username: row.username, state: now ? now.state : 'none', since: now ? now.since : null } };
  }));

  /* ------------------------------------------------------- group chats */
  /**
   * Friends can always reach each other. Two people who are not friends can
   * when they share a group, unless either one has blocked the other.
   */
  function canReach(a, b) {
    if (db.isFriend(a, b)) return true;
    if (!db.shareGroup(a, b)) return false;
    const ab = db.peer(a, b), ba = db.peer(b, a);
    return !(ab && ab.state === 'blocked') && !(ba && ba.state === 'blocked');
  }
  /*
   * Inside a group there are three ranks: the owner, the group's moderators, and
   * everyone else. These are separate from the server's own staff (admin.js).
   * The owner is whoever started the group; if they leave, the longest-serving
   * moderator takes over, or else the longest-serving member. Moderators kick
   * and mute members below them, change the settings and handle join requests;
   * only the owner appoints moderators.
   *
   * A group mute is enforced in two places: the server refuses envelopes the
   * client labels as something said in that group (see /api/commit), and the
   * other members' clients drop group texts from a muted member.
   */
  /** A group's settings with defaults filled in. */
  function gset(g) {
    const t = g.tag || {};
    return {
      owner: g.owner || g.createdBy || null,
      mods: Array.isArray(g.mods) ? g.mods : [],
      mutes: g.mutes && typeof g.mutes === 'object' ? g.mutes : {},
      invite: g.invite === 'mods' ? 'mods' : 'all',
      tag: { text: t.text || '', emoji: typeof t.emoji === 'string' ? t.emoji : '', vis: TAG_VIS.has(t.vis) ? t.vis : 'off', mode: TAG_MODES.has(t.mode) ? t.mode : 'join' },
      kicks: Array.isArray(g.kicks) ? g.kicks : []
    };
  }
  const saveGroup = (g, patch) => db.setGroup(g.id, Object.assign({}, g, patch));
  /** The owner right now, given who is still in the group. */
  function ownerOf(g, members) {
    const s = gset(g), ids = new Set(members.map(m => m.userId));
    if (s.owner && ids.has(s.owner)) return s.owner;
    const byJoin = members.slice().sort((a, b) => a.joined - b.joined || (a.userId < b.userId ? -1 : 1));
    const mod = byJoin.find(m => s.mods.includes(m.userId));
    return (mod || byJoin[0] || {}).userId || null;
  }
  /** 2 owner · 1 moderator · 0 member · -1 not in the group. */
  function grank(g, members, userId) {
    if (!members.some(m => m.userId === userId)) return -1;
    if (ownerOf(g, members) === userId) return 2;
    return gset(g).mods.includes(userId) ? 1 : 0;
  }
  /** When a member's group mute ends (0 = never), or undefined if they are not muted there. */
  function gmuteOf(g, userId, now) {
    const u = gset(g).mutes[userId];
    if (u == null) return undefined;
    return u === 0 || u > (now || Date.now()) ? u : undefined;
  }
  const userBrief = (id, viewer) => {
    const row = db.userRow(id);
    return row && Object.assign({ userId: id, username: row.username, av: row.avatar_v, role: roleOf(row), muted: mutedOf(row) }, profView(row, viewer));
  };
  const groupView = (g, viewer) => {
    const members = db.groupMembers(g.id), s = gset(g), owner = ownerOf(g, members), now = Date.now();
    const rank = grank(g, members, viewer);
    const v = {
      groupId: g.id, created: g.created, createdBy: g.createdBy, owner, mods: s.mods.filter(id => members.some(m => m.userId === id)),
      invite: s.invite, tag: s.tag, kicks: s.kicks.slice(-20),
      members: members.map(m => {
        const row = db.userRow(m.userId);
        return row && Object.assign({ userId: m.userId, username: row.username, joined: m.joined, invitedBy: m.invitedBy, via: m.via, av: row.avatar_v, role: roleOf(row), muted: mutedOf(row),
          gr: m.userId === owner ? 'owner' : s.mods.includes(m.userId) ? 'mod' : undefined, gm: gmuteOf(g, m.userId, now) },
          profView(row, viewer));
      }).filter(Boolean)
    };
    // join requests are for the people who answer them
    if (rank >= 1) v.apps = db.groupApps(g.id).map(a => Object.assign({ reason: a.reason, ts: a.ts, via: a.via }, userBrief(a.userId, viewer))).filter(a => a.username);
    return v;
  };
  const pushGroup = groupId => { for (const m of db.groupMembers(groupId)) hub.push(m.userId, { t: 'groups' }); };
  /** The tag on someone's profile, if it still stands: they are in the group and its tag is on. */
  function tagOf(row) {
    const gid = db.profile(row).gtag;
    if (!gid || !db.inGroup(gid, row.id)) return null;
    const g = db.group(gid);
    if (!g) return null;
    const t = gset(g).tag;
    if (t.vis === 'off' || !t.text) return null;
    return { groupId: gid, text: t.text, emoji: t.emoji, vis: t.vis, mode: t.mode, n: db.groupMemberCount(gid) };
  }
  /** Profiles showing this group's tag change when the tag does: clients refetch them. */
  function refreshTags(groupId) {
    for (const m of db.groupMembers(groupId)) {
      const row = db.userRow(m.userId);
      if (row && db.profile(row).gtag === groupId) { db.bumpProfile(m.userId); pushProfile(db.userRow(m.userId)); }
    }
  }
  /** Someone left or was removed: their profile stops showing the group's tag, and the group forgets their rank and mute. */
  function afterLeave(groupId, userId) {
    const row = db.userRow(userId);
    if (row && db.profile(row).gtag === groupId) { const p = Object.assign({}, db.profile(row)); delete p.gtag; db.setProfile(userId, p); pushProfile(db.userRow(userId)); }
    const g = db.group(groupId);
    if (!g) return;
    const s = gset(g), mutes = Object.assign({}, s.mutes), mods = s.mods.filter(id => id !== userId);
    delete mutes[userId];
    // a departing owner hands over for good, so ownership does not come back if they rejoin
    const owner = ownerOf(Object.assign({}, g, { owner: s.owner === userId ? null : s.owner, createdBy: null, mods }), db.groupMembers(groupId));
    saveGroup(g, { mods, mutes, owner });
  }
  /** The invite list: distinct user ids, every one of them a friend of the inviter. */
  function invitees(me, list) {
    const ids = [...new Set(asArray(list, LIMITS.groupMembers, 'invitees').map(String))];
    for (const id of ids) {
      if (id === me.id) throw bad('that is you');
      if (!db.isFriend(me.id, id)) throw new HttpError(403, 'you can only invite friends');
    }
    return ids;
  }
  function myGroup(me, id) {
    id = String(id || '');
    if (!GROUPID.test(id) || !db.inGroup(id, me.id)) throw new HttpError(404, 'you are not in that group');
    return id;
  }
  /** The group, its members and my rank in it; throws unless I am at least `need`. */
  function asRank(me, id, need) {
    id = myGroup(me, id);
    const g = db.group(id), members = db.groupMembers(id), rank = grank(g, members, me.id);
    if (rank < need) throw new HttpError(403, need >= 2 ? 'only the group owner can do that' : 'only group moderators can do that');
    return { id, g, members, rank };
  }
  /** Someone I may act on: in the group, and ranked below me. */
  function target(ctx, me, userId) {
    userId = String(userId || '');
    if (userId === me.id) throw bad('that is you');
    const r = grank(ctx.g, ctx.members, userId);
    if (r < 0) throw new HttpError(404, 'they are not in this group');
    if (r >= ctx.rank) throw new HttpError(403, r === 2 ? 'nobody can do that to the group owner' : 'only the group owner can do that to a moderator');
    return userId;
  }

  app.get('/api/groups', wrap(req => {
    const me = auth(req);
    const applied = db.appliedGroups(me.id).map(id => { const g = db.group(id); return g && { groupId: id, text: gset(g).tag.text }; }).filter(Boolean);
    return { groups: db.groupIdsOf(me.id).map(db.group).filter(Boolean).map(g => groupView(g, me.id)), applied };
  }));

  /** A new group with me in it, plus any friends invited straight away (none is fine). */
  app.post('/api/groups', limiter(60), wrap(req => {
    const me = auth(req);
    const ids = invitees(me, (req.body || {}).invite);
    if (ids.length + 1 > LIMITS.groupMembers) throw bad('groups are limited to ' + LIMITS.groupMembers + ' members');
    if (db.groupIdsOf(me.id).length >= LIMITS.groups) throw new HttpError(507, 'you are in too many groups');
    const id = db.createGroup(me.id, [me.id].concat(ids));
    pushGroup(id);
    return { group: groupView(db.group(id), me.id) };
  }));

  /** Members invite their own friends; when invites are set to moderators only, only moderators can. */
  app.post('/api/groups/invite', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const id = myGroup(me, b.group);
    const g = db.group(id);
    if (gset(g).invite === 'mods' && grank(g, db.groupMembers(id), me.id) < 1) throw new HttpError(403, 'only group moderators can invite people to this group');
    const ids = invitees(me, b.invite).filter(u => !db.inGroup(id, u));
    if (db.groupMemberCount(id) + ids.length > LIMITS.groupMembers) throw bad('groups are limited to ' + LIMITS.groupMembers + ' members');
    const added = db.addGroupMembers(id, me.id, ids);
    for (const u of added) db.delGroupApp(id, u);
    if (added.length) pushGroup(id);
    return { group: groupView(db.group(id), me.id), added };
  }));

  app.post('/api/groups/leave', wrap(req => {
    const me = auth(req);
    const id = myGroup(me, (req.body || {}).group);
    db.leaveGroup(id, me.id);
    afterLeave(id, me.id);
    pushGroup(id);
    hub.push(me.id, { t: 'groups' });
    return {};
  }));

  /** The owner makes someone a group moderator, or takes it away. */
  app.post('/api/groups/mod', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const ctx = asRank(me, b.group, 2);
    const who = target(ctx, me, b.user);
    if (typeof b.on !== 'boolean') throw bad('on must be true or false');
    const mods = gset(ctx.g).mods.filter(x => x !== who);
    if (b.on) mods.push(who);
    saveGroup(ctx.g, { mods, owner: ownerOf(ctx.g, ctx.members) });
    pushGroup(ctx.id);
    return { group: groupView(db.group(ctx.id), me.id) };
  }));

  /** Removes a member. They can come back only by a new invite or through the tag. */
  app.post('/api/groups/kick', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const ctx = asRank(me, b.group, 1);
    const who = target(ctx, me, b.user);
    db.leaveGroup(ctx.id, who);
    const g = db.group(ctx.id);
    saveGroup(g, { kicks: gset(g).kicks.concat({ userId: who, by: me.id, ts: Date.now() }).slice(-20) });
    afterLeave(ctx.id, who);
    pushGroup(ctx.id);
    hub.push(who, { t: 'groups' });
    return { group: groupView(db.group(ctx.id), me.id) };
  }));

  /** Mutes a member in this group only: `minutes` (0 = until unmuted), or `minutes: null` to unmute. */
  app.post('/api/groups/mute', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const ctx = asRank(me, b.group, 1);
    const who = target(ctx, me, b.user);
    const mutes = Object.assign({}, gset(ctx.g).mutes);
    if (b.minutes == null) delete mutes[who];
    else {
      if (!Number.isInteger(b.minutes) || b.minutes < 0 || b.minutes * 60000 > MAX_GMUTE) throw bad('a mute lasts 1 minute to a year, or 0 for until unmuted');
      mutes[who] = b.minutes ? Date.now() + b.minutes * 60000 : 0;
    }
    // expired ones go, so the list does not grow forever
    const now = Date.now();
    for (const [k, u] of Object.entries(mutes)) if (u !== 0 && u <= now) delete mutes[k];
    saveGroup(ctx.g, { mutes });
    pushGroup(ctx.id);
    return { group: groupView(db.group(ctx.id), me.id) };
  }));

  /** Moderators set who can invite, and the group's tag: its text, who can use it, and whether it joins or asks. */
  app.post('/api/groups/settings', limiter(60), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const ctx = asRank(me, b.group, 1);
    const s = gset(ctx.g), patch = {};
    if ('invite' in b) {
      if (b.invite !== 'all' && b.invite !== 'mods') throw bad('invites are all or mods');
      patch.invite = b.invite;
    }
    if ('tag' in b) {
      const t = b.tag || {}, tag = Object.assign({}, s.tag);
      if ('text' in t) {
        tag.text = profileText(t.text, 64, 'a group tag').replace(/^#/, '');
        if (/\s/.test(tag.text)) throw bad('a group tag is one word');
        if ([...tag.text].length > LIMITS.groupTag) throw bad('a group tag can be at most ' + LIMITS.groupTag + ' characters');
      }
      if ('emoji' in t) tag.emoji = checkEmoji(t.emoji);
      if ('vis' in t) { if (!TAG_VIS.has(t.vis)) throw bad('the tag is off, friends or all'); tag.vis = t.vis; }
      if ('mode' in t) { if (!TAG_MODES.has(t.mode)) throw bad('the tag is join or apply'); tag.mode = t.mode; }
      if (tag.vis !== 'off' && !tag.text) throw bad('give the tag some text before turning it on');
      patch.tag = tag;
    }
    saveGroup(ctx.g, patch);
    if (patch.tag) refreshTags(ctx.id);
    pushGroup(ctx.id);
    return { group: groupView(db.group(ctx.id), me.id) };
  }));

  /**
   * Joining through the tag on someone's profile (`via`). The tag must still be on
   * that profile; when it is set to friends, `via` must be my friend. In join mode
   * I am in at once; in apply mode my request waits for a group moderator.
   */
  app.post('/api/groups/join', limiter(30), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const via = db.userRow(String(b.via || ''));
    const t = via && tagOf(via);
    if (!t || t.groupId !== String(b.group || '')) throw new HttpError(404, 'that group tag is no longer on their profile');
    const id = t.groupId;
    if (db.inGroup(id, me.id)) throw new HttpError(409, 'you are already in this group');
    if (t.vis === 'friends' && !db.isFriend(me.id, via.id)) throw new HttpError(403, 'only friends of ' + via.username + ' can join through this tag');
    const pb = db.peer(via.id, me.id);
    if (pb && pb.state === 'blocked') throw new HttpError(403, 'you cannot join through this tag');
    if (db.groupMemberCount(id) >= LIMITS.groupMembers) throw new HttpError(409, 'this group is full');
    if (db.groupIdsOf(me.id).length >= LIMITS.groups) throw new HttpError(507, 'you are in too many groups');
    if (t.mode === 'apply') {
      const reason = profileText(b.reason, LIMITS.appReason, 'a reason');
      if (!reason) throw bad('say why you want to join');
      const apps = db.groupApps(id);
      if (!apps.some(a => a.userId === me.id) && apps.length >= LIMITS.groupApps) throw new HttpError(409, 'this group has too many requests waiting, try later');
      db.putGroupApp(id, { userId: me.id, reason, via: via.id, ts: Date.now() });
      pushGroup(id);
      hub.push(me.id, { t: 'groups' });
      return { applied: true };
    }
    db.addGroupMembers(id, null, [me.id], via.id);
    db.delGroupApp(id, me.id);
    pushGroup(id);
    return { joined: true, group: groupView(db.group(id), me.id) };
  }));

  /** I take back my own request to join. */
  app.post('/api/groups/withdraw', wrap(req => {
    const me = auth(req);
    const id = String((req.body || {}).group || '');
    if (!GROUPID.test(id) || !db.delGroupApp(id, me.id)) throw new HttpError(404, 'you have no request waiting there');
    pushGroup(id);
    hub.push(me.id, { t: 'groups' });
    return {};
  }));

  /** A group moderator lets someone in, or turns them down. */
  app.post('/api/groups/answer', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const ctx = asRank(me, b.group, 1);
    const who = String(b.user || '');
    if (typeof b.accept !== 'boolean') throw bad('accept must be true or false');
    const a = db.groupApps(ctx.id).find(x => x.userId === who);
    if (!a) throw new HttpError(404, 'that request is gone');
    if (b.accept) {
      if (!db.userRow(who)) { db.delGroupApp(ctx.id, who); throw new HttpError(404, 'that account no longer exists'); }
      if (db.groupMemberCount(ctx.id) >= LIMITS.groupMembers) throw new HttpError(409, 'this group is full');
      if (db.groupIdsOf(who).length >= LIMITS.groups) throw new HttpError(507, 'they are in too many groups');
      db.addGroupMembers(ctx.id, me.id, [who], a.via);
    }
    db.delGroupApp(ctx.id, who);
    pushGroup(ctx.id);
    hub.push(who, { t: 'groups' });
    return { group: groupView(db.group(ctx.id), me.id) };
  }));

  /* ------------------------------------------------------ discord link */
  // Only present when the server has a bot token. See discord.js for what the server can read.
  let bridge = null;
  const needBridge = () => { if (!bridge) throw new HttpError(503, 'the Discord link is not enabled on this server'); return bridge; };

  app.get('/api/discord/links', wrap(req => {
    const me = auth(req);
    return { enabled: !!bridge, links: bridge ? bridge.linksOf(me.id) : [], public: bridge ? bridge.publicLinks(me.id) : [] };
  }));
  app.post('/api/discord/join', strict, wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    // a public channel is joined by its id; anything else needs an invite code
    const l = b.link ? needBridge().joinPublic(me, String(b.link)) : needBridge().join(me, String(b.code || ''));
    hub.push(me.id, { t: 'links' });
    return { link: { linkId: l.id, guild: l.guildName, channel: l.channelName, public: l.public } };
  }));
  app.post('/api/discord/leave', wrap(req => {
    const me = auth(req);
    needBridge().leave(me, String((req.body || {}).link || ''));
    hub.push(me.id, { t: 'links' });
    return {};
  }));
  app.post('/api/discord/send', limiter(120), wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    checkMute(me);
    return needBridge().send(me, String(b.link || ''), b.text);
  }));

  app.post('/api/commit', wrap(req => {
    const me = auth(req);
    const b = req.body || {};
    const c = {
      puts: checkPuts(b.puts),
      dels: asArray(b.dels, LIMITS.puts, 'deletions').map(k => { if (typeof k !== 'string' || !BLOBKEY.test(k)) throw bad('malformed blob name'); return k; }),
      ack: asArray(b.ack, LIMITS.inbox, 'acks').map(id => { if (!Number.isInteger(id)) throw bad('malformed ack'); return id; }),
      opks: checkOpks(b.opks, LIMITS.opksPerCommit),
      // An envelope marked optional (a delivery receipt) is dropped rather than
      // failing the commit when its recipient is no longer a friend, so the
      // rest of the commit — the ratchet, the stored message, the ack — still lands.
      // `say` marks an envelope that carries something the sender wrote (a text, an image,
      // a call, a group rename); a muted sender cannot send those. The server cannot see
      // inside an envelope, so this is the client's own label, which current clients set.
      send: asArray(b.send, LIMITS.sends, 'envelopes').map(m => {
        if (!m || typeof m.to !== 'string' || typeof m.payload !== 'string') throw bad('malformed envelope');
        if (m.payload.length > LIMITS.payloadBytes) throw bad('envelope too large');
        if (m.to === me.id) throw bad('cannot send to yourself');
        if (!db.userRow(m.to)) { if (m.optional === true) return null; throw new HttpError(404, 'recipient does not exist'); }
        if (!canReach(me.id, m.to)) { if (m.optional === true) return null; throw new HttpError(403, 'you can only message friends'); }
        return { to: m.to, payload: m.payload, say: m.say === true, g: typeof m.g === 'string' && GROUPID.test(m.g) ? m.g : null };
      }).filter(Boolean)
    };
    if (c.send.some(m => m.say)) checkMute(me);
    // `g` is the client's label for an envelope sent as part of a group, like `say`
    for (const gid of new Set(c.send.filter(m => m.say && m.g).map(m => m.g))) {
      const g = db.inGroup(gid, me.id) && db.group(gid), u = g && gmuteOf(g, me.id);
      if (u !== undefined) throw Object.assign(new HttpError(403, u ? 'you are muted in this group until ' + new Date(u).toUTCString() : 'you are muted in this group'), { extra: { gmuted: u, group: gid } });
    }
    if (c.opks.length && db.prekeyCount(me.id) + c.opks.length > LIMITS.opksTotal) throw bad('too many prekeys outstanding');
    if (c.puts.length && db.blobCount(me.id) + c.puts.length > LIMITS.blobsTotal) throw new HttpError(507, 'storage quota reached');
    const sent = db.commit(me.id, c);
    for (const s of sent) hub.push(s.to, { t: 'env', env: { id: s.id, from: me.id, ts: s.ts, payload: s.payload } });
    return { sent: sent.map(s => ({ id: s.id, to: s.to, ts: s.ts })), opkCount: db.prekeyCount(me.id) };
  }));

  /** Deleting an account needs the password again, not just a live token. */
  app.post('/api/account/delete', strict, wrap(req => {
    const me = auth(req);
    if (!b64bytes((req.body || {}).auth, 32) || !checkVerifier(me.verifier, req.body.auth)) throw new HttpError(401, 'wrong password');
    const others = db.deleteUser(me.id);
    hub.revoke(me.id);
    // a moderator's appointment is by username: it must not pass to whoever takes the name next
    const was = staff.of(me.username);
    if (was && was.role === 'mod') {
      try { staff.setMod(me.username, []); } catch (e) { console.error('[marmot] could not remove deleted moderator ' + me.username + ':', e.message); }
    }
    for (const o of others) { hub.push(o, { t: 'peers' }); hub.push(o, { t: 'groups' }); }
    return {};
  }));

  admin.mount(app, { db, hub: { push: (u, m) => hub.push(u, m), pushAll: m => hub.pushAll(m), revoke: (u, why) => hub.revoke(u, why) }, staff, wrap, auth, HttpError });

  // Serving the client is a convenience; the same file works opened from disk.
  // ../client in the repo; ./client in a deployment bundle, where the server directory is the root.
  const clientFile = opts.clientFile || [path.join(__dirname, 'client', 'index.html'), path.join(__dirname, '..', 'client', 'index.html')]
    .find(f => fs.existsSync(f)) || path.join(__dirname, '..', 'client', 'index.html');

  // Auto-update: a client older than the one served here swaps itself for it at boot.
  // The version is read out of the file itself, so it always matches the html handed out.
  const readClient = clientReader(clientFile);
  app.get('/api/client/version', limiter(120), wrap((req, res) => {
    res.set('Cache-Control', 'no-store');
    return { v: readClient().v };
  }));
  app.get('/api/client', limiter(30), wrap((req, res) => {
    res.set('Cache-Control', 'no-store');
    const c = readClient();
    return { v: c.v, html: c.html };
  }));

  app.use('/api', (req, res) => res.status(404).json({ ok: false, error: 'unknown endpoint' }));

  app.get(['/', '/index.html', '/Marmot.html'], (req, res) => {
    if (!fs.existsSync(clientFile)) return res.status(404).send('client not found');
    res.set('Cache-Control', 'no-cache');
    res.sendFile(clientFile);
  });

  /* ------------------------------------------------------------- push */
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 16 * 1024 });

  const hub = {
    sockets: new Map(),   // userId -> Set<ws>
    push(userId, msg) {
      const set = this.sockets.get(userId);
      if (!set) return;
      const data = JSON.stringify(msg);
      for (const ws of set) if (ws.readyState === 1) ws.send(data);
    },
    /** Every signed-in socket, e.g. when a Discord channel becomes public. */
    pushAll(msg) {
      const data = JSON.stringify(msg);
      for (const set of this.sockets.values()) for (const ws of set) if (ws.readyState === 1) ws.send(data);
    },
    /** Revoked sockets get one notice before closing; they must not reconnect.
        `why` is 'banned' or 'ipban' when staff did it, so the client can say so. */
    revoke(userId, why) {
      const set = this.sockets.get(userId);
      if (!set) return;
      for (const ws of set) {
        if (ws.tokenHash && db.session(ws.tokenHash)) continue;   // the session that just logged in
        try { ws.send(JSON.stringify(why ? { t: 'revoked', why } : { t: 'revoked' })); ws.close(4001, 'revoked'); } catch (e) {}
      }
    }
  };

  wss.on('connection', ws => {
    ws.alive = true;
    ws.on('pong', () => { ws.alive = true; });
    const timeout = setTimeout(() => ws.close(4000, 'auth timeout'), 10000);
    ws.on('message', data => {
      let m;
      try { m = JSON.parse(data); } catch (e) { return ws.close(4000, 'bad frame'); }
      if (ws.userId) {
        // the one thing a signed-in socket says: whether its user has gone idle. All writes go through /api/commit.
        if (m.t === 'idle' && typeof m.idle === 'boolean' && ws.idle !== m.idle) { ws.idle = m.idle; presenceChanged(ws.userId, true); }
        return;
      }
      if (m.t !== 'auth' || typeof m.token !== 'string') return ws.close(4000, 'auth first');
      const hash = sha256(m.token);
      const s = db.session(hash);
      if (!s || s.expires < Date.now()) { ws.send(JSON.stringify({ t: 'revoked' })); return ws.close(4001, 'bad token'); }
      clearTimeout(timeout);
      ws.userId = s.user_id;
      ws.tokenHash = hash;
      if (!hub.sockets.has(s.user_id)) hub.sockets.set(s.user_id, new Set());
      hub.sockets.get(s.user_id).add(ws);
      db.touch(s.user_id, Date.now());
      ws.idle = m.idle === true;
      ws.send(JSON.stringify({ t: 'ready', v: VERSION, ts: Date.now() }));
      presenceChanged(s.user_id, true);
    });
    ws.on('close', () => {
      clearTimeout(timeout);
      const set = ws.userId && hub.sockets.get(ws.userId);
      if (set) { set.delete(ws); if (!set.size) hub.sockets.delete(ws.userId); presenceChanged(ws.userId); }
    });
  });

  // Keep sockets alive through load-balancer idle timeouts (60s on an ALB),
  // drop dead ones, and expire old sessions and undelivered mail.
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.alive) { ws.terminate(); continue; }
      ws.alive = false;
      try { ws.ping(); } catch (e) {}
      if (ws.userId) db.touch(ws.userId, Date.now());
    }
  }, 25000);
  const sweeper = setInterval(() => db.sweep(Date.now(), ENVELOPE_TTL), 3600 * 1000);
  heartbeat.unref(); sweeper.unref();
  const dcToken = opts.discord ? opts.discord.token : process.env.DISCORD_TOKEN;
  if (dcToken) {
    const discord = new Discord({ token: dcToken, api: opts.discord ? opts.discord.api : process.env.DISCORD_API });
    bridge = new Bridge({ db, hub, discord });
    bridge.started = bridge.start().catch(e => console.error('[discord] could not start:', e.message));
  }

  server.on('close', () => { stopped = true; clearInterval(heartbeat); clearInterval(sweeper); for (const t of prTimers.values()) clearTimeout(t); wss.close(); if (bridge) bridge.stop(); });

  return { app, server, db, hub, staff, get bridge() { return bridge; } };
}

if (require.main === module) {
  // Settings and secrets (DISCORD_TOKEN, MARMOT_DB_KEY, …) from server/.env. Real environment
  // variables win, so a host like Elastic Beanstalk can set them without a file.
  require('dotenv').config({ path: path.join(__dirname, '.env'), quiet: true });
  const port = Number(process.env.PORT) || 8080;
  const { server } = createServer();
  server.listen(port, () => console.log('[marmot] listening on http://localhost:' + port));
}

module.exports = { createServer, userIdFor };
