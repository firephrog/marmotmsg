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

const VERSION = '0.4.0';
const TOKEN_TTL = 30 * 24 * 3600 * 1000;
const ENVELOPE_TTL = 30 * 24 * 3600 * 1000;
const MIN_ITER = 300000;
const LIMITS = {
  body: '4mb', puts: 600, putBytes: 256 * 1024, sends: 32, payloadBytes: 128 * 1024,
  opksPerCommit: 200, opksTotal: 500, blobsTotal: 100000, inbox: 300,
  peers: 2000, globalPage: 50
};
const PEER_ACTIONS = new Set(['request', 'accept', 'remove', 'block', 'unblock']);
const USERNAME = /^[a-zA-Z0-9._-]{3,24}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const BLOBKEY = /^[0-9a-f]{32}$/;

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

/* ---------------------------------------------------------------- app */
function createServer(opts) {
  opts = opts || {};
  const db = opts.db || store.open(opts);
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

  const wrap = fn => (req, res) => {
    Promise.resolve().then(() => fn(req, res)).then(out => {
      if (!res.headersSent) res.json(Object.assign({ ok: true }, out));
    }).catch(err => {
      const status = err.status || (err.type === 'entity.too.large' ? 413 : 500);
      if (status === 500) console.error(err);
      res.status(status).json({ ok: false, error: status === 500 ? 'server error' : err.message });
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
    return row;
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
    return { token, userId: row.id, username: row.username, vault: db.vault(row), discoverable: !!row.discoverable };
  }));

  app.post('/api/logout', wrap(req => {
    auth(req);
    db.deleteSession(req.tokenHash);
    return {};
  }));

  app.get('/api/me', wrap(req => {
    const row = auth(req);
    const spk = db.spk(row);
    return { userId: row.id, username: row.username, created: row.created, spkId: spk.id,
      opkCount: db.prekeyCount(row.id), blobCount: db.blobCount(row.id), discoverable: !!row.discoverable };
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
    auth(req);
    const row = req.query.id ? db.userRow(String(req.query.id)) : db.userRowByName(String(req.query.username || '').trim());
    if (!row) throw new HttpError(404, 'no such user');
    const u = db.publicUser(row);
    return { user: { userId: u.userId, username: u.username, ik: u.ik, sk: u.sk } };
  }));

  /** Full prekey bundle for starting a session. Consumes one one-time prekey. */
  app.get('/api/bundle/:id', wrap(req => {
    const me = auth(req);
    const row = db.userRow(req.params.id);
    if (!row) throw new HttpError(404, 'no such user');
    if (row.id === me.id) throw bad('cannot open a session with yourself');
    // Only friends can start a session, so strangers cannot drain someone's prekeys.
    if (!db.isFriend(me.id, row.id)) throw new HttpError(403, 'you can only message friends');
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
  const peerView = p => {
    const row = db.userRow(p.peer);
    return row && { userId: row.id, username: row.username, state: p.state, since: p.since };
  };

  /** Everyone I have a relationship with: friends, requests both ways, and people I blocked. */
  app.get('/api/peers', wrap(req => {
    const me = auth(req);
    return { peers: db.peers(me.id).map(peerView).filter(Boolean) };
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
   * Nothing else lets two users talk: commits and prekey bundles check 'friend'.
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
      send: asArray(b.send, LIMITS.sends, 'envelopes').map(m => {
        if (!m || typeof m.to !== 'string' || typeof m.payload !== 'string') throw bad('malformed envelope');
        if (m.payload.length > LIMITS.payloadBytes) throw bad('envelope too large');
        if (m.to === me.id) throw bad('cannot send to yourself');
        if (!db.userRow(m.to)) { if (m.optional === true) return null; throw new HttpError(404, 'recipient does not exist'); }
        if (!db.isFriend(me.id, m.to)) { if (m.optional === true) return null; throw new HttpError(403, 'you can only message friends'); }
        return { to: m.to, payload: m.payload };
      }).filter(Boolean)
    };
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
    for (const o of others) hub.push(o, { t: 'peers' });
    return {};
  }));

  app.use('/api', (req, res) => res.status(404).json({ ok: false, error: 'unknown endpoint' }));

  // Serving the client is a convenience; the same file works opened from disk.
  // ../client in the repo; ./client in a deployment bundle, where the server directory is the root.
  const clientFile = [path.join(__dirname, 'client', 'index.html'), path.join(__dirname, '..', 'client', 'index.html')]
    .find(f => fs.existsSync(f)) || path.join(__dirname, '..', 'client', 'index.html');
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
    /** Revoked sockets get one notice before closing; they must not reconnect. */
    revoke(userId) {
      const set = this.sockets.get(userId);
      if (!set) return;
      for (const ws of set) {
        if (ws.tokenHash && db.session(ws.tokenHash)) continue;   // the session that just logged in
        try { ws.send(JSON.stringify({ t: 'revoked' })); ws.close(4001, 'revoked'); } catch (e) {}
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
      if (ws.userId) return;  // nothing else is accepted over the socket; all writes go through /api/commit
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
      ws.send(JSON.stringify({ t: 'ready', v: VERSION, ts: Date.now() }));
    });
    ws.on('close', () => {
      clearTimeout(timeout);
      const set = ws.userId && hub.sockets.get(ws.userId);
      if (set) { set.delete(ws); if (!set.size) hub.sockets.delete(ws.userId); }
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

  server.on('close', () => { clearInterval(heartbeat); clearInterval(sweeper); wss.close(); if (bridge) bridge.stop(); });

  return { app, server, db, hub, get bridge() { return bridge; } };
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
