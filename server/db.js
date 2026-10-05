'use strict';
/**
 * Storage. SQLite for now; every query is plain SQL and all access goes
 * through this module, so moving to Postgres/RDS for the Elastic Beanstalk
 * deployment is a matter of swapping the driver here.
 *
 * Plaintext columns are only the ones needed to look rows up or expire them:
 * user ids, usernames (searchable by design), the global-discovery flag,
 * prekey ids, blob names (opaque HMACs chosen by the client), peer tags (keyed
 * HMACs), envelope recipients and timestamps. Everything else is sealed with
 * seal.js.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { loadKey, sealer } = require('./seal');

const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,           -- sha256(identity keys), so it cannot be squatted
  username   TEXT NOT NULL,              -- display form
  uname      TEXT NOT NULL UNIQUE,       -- lower-cased for lookup
  created    INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL DEFAULT 0,
  salt       TEXT NOT NULL,              -- client PBKDF2 salt (public by necessity)
  iter       INTEGER NOT NULL,
  verifier   TEXT NOT NULL,              -- scrypt of the client's derived auth key
  identity   TEXT NOT NULL,              -- sealed {ik, sk}
  spk        TEXT NOT NULL,              -- sealed {id, pub, sig}
  vault      TEXT NOT NULL,              -- sealed, and already encrypted by the client
  discoverable INTEGER NOT NULL DEFAULT 0 -- listed in everyone's global peers section
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created    INTEGER NOT NULL,
  expires    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS prekeys (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  id         INTEGER NOT NULL,
  pub        TEXT NOT NULL,              -- sealed
  PRIMARY KEY (user_id, id)
);
CREATE TABLE IF NOT EXISTS blobs (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  k          TEXT NOT NULL,              -- opaque name chosen by the client
  v          TEXT NOT NULL,              -- sealed client ciphertext
  updated    INTEGER NOT NULL,
  PRIMARY KEY (user_id, k)
);
CREATE TABLE IF NOT EXISTS envelopes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  to_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  body       TEXT NOT NULL               -- sealed {from, payload}; the sender is not stored in the clear
);
CREATE INDEX IF NOT EXISTS envelopes_to ON envelopes(to_id, id);
-- Each side of a relationship is its own row. The other user's id is sealed
-- and the row is found by a keyed tag of (owner, peer), so a leaked database
-- shows how many contacts someone has but not who they are.
CREATE TABLE IF NOT EXISTS peers (
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tag        TEXT NOT NULL,              -- keyed HMAC of owner|peer
  body       TEXT NOT NULL,              -- sealed {peer, state, since}
  PRIMARY KEY (owner_id, tag)
);
-- Discord link. A linked channel is found by keyed tags of its Discord ids;
-- names, ids and the webhook credentials are sealed. Membership rows are
-- found by link (to fan out) or by a keyed tag of the user (to list theirs).
CREATE TABLE IF NOT EXISTS discord_links (
  id         TEXT PRIMARY KEY,
  chan_tag   TEXT NOT NULL UNIQUE,
  guild_tag  TEXT NOT NULL,
  body       TEXT NOT NULL,              -- sealed {guildId, channelId, guildName, channelName, webhookId, webhookToken, createdBy, filter, barred}
  created    INTEGER NOT NULL,
  public     INTEGER NOT NULL DEFAULT 0  -- any Marmot user can join without an invite code
);
CREATE INDEX IF NOT EXISTS discord_links_guild ON discord_links(guild_tag);
CREATE TABLE IF NOT EXISTS discord_invites (
  code_hash  TEXT PRIMARY KEY,           -- sha256 of the code; the code itself is shown once, in Discord
  link_id    TEXT NOT NULL REFERENCES discord_links(id) ON DELETE CASCADE,
  expires    INTEGER NOT NULL,
  uses       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS discord_members (
  link_id    TEXT NOT NULL REFERENCES discord_links(id) ON DELETE CASCADE,
  user_tag   TEXT NOT NULL,
  body       TEXT NOT NULL,              -- sealed {userId, joined}
  PRIMARY KEY (link_id, user_tag)
);
CREATE INDEX IF NOT EXISTS discord_members_user ON discord_members(user_tag);
`;

/** Columns added after a table first shipped; applied to older databases on open. */
const MIGRATIONS = [
  ['users', 'discoverable', 'ALTER TABLE users ADD COLUMN discoverable INTEGER NOT NULL DEFAULT 0'],
  ['discord_links', 'public', 'ALTER TABLE discord_links ADD COLUMN public INTEGER NOT NULL DEFAULT 0']
];

function open(opts) {
  opts = opts || {};
  const dataDir = opts.dataDir || process.env.MARMOT_DATA || path.join(__dirname, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const file = opts.file || path.join(dataDir, 'marmot.db');
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  for (const [table, col, sql] of MIGRATIONS) {
    if (!db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col)) db.exec(sql);
  }
  db.exec('CREATE INDEX IF NOT EXISTS users_discoverable ON users(discoverable, uname)');
  const S = sealer(opts.key || loadKey(dataDir));

  const q = {
    userById: db.prepare('SELECT * FROM users WHERE id = ?'),
    userByName: db.prepare('SELECT * FROM users WHERE uname = ?'),
    insertUser: db.prepare(`INSERT INTO users (id, username, uname, created, last_seen, salt, iter, verifier, identity, spk, vault)
                            VALUES (@id, @username, @uname, @created, @created, @salt, @iter, @verifier, @identity, @spk, @vault)`),
    touchUser: db.prepare('UPDATE users SET last_seen = ? WHERE id = ?'),
    deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
    insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, created, expires) VALUES (?, ?, ?, ?)'),
    session: db.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
    extendSession: db.prepare('UPDATE sessions SET expires = ? WHERE token_hash = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    deleteOtherSessions: db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?'),
    expireSessions: db.prepare('DELETE FROM sessions WHERE expires < ?'),
    insertPrekey: db.prepare('INSERT OR REPLACE INTO prekeys (user_id, id, pub) VALUES (?, ?, ?)'),
    takePrekey: db.prepare('SELECT id, pub FROM prekeys WHERE user_id = ? ORDER BY id LIMIT 1'),
    deletePrekey: db.prepare('DELETE FROM prekeys WHERE user_id = ? AND id = ?'),
    countPrekeys: db.prepare('SELECT COUNT(*) n FROM prekeys WHERE user_id = ?'),
    putBlob: db.prepare(`INSERT INTO blobs (user_id, k, v, updated) VALUES (?, ?, ?, ?)
                         ON CONFLICT (user_id, k) DO UPDATE SET v = excluded.v, updated = excluded.updated`),
    delBlob: db.prepare('DELETE FROM blobs WHERE user_id = ? AND k = ?'),
    blobs: db.prepare('SELECT k, v FROM blobs WHERE user_id = ?'),
    countBlobs: db.prepare('SELECT COUNT(*) n FROM blobs WHERE user_id = ?'),
    insertEnvelope: db.prepare('INSERT INTO envelopes (to_id, ts, body) VALUES (?, ?, ?)'),
    inbox: db.prepare('SELECT id, ts, body FROM envelopes WHERE to_id = ? ORDER BY id LIMIT ?'),
    ackEnvelope: db.prepare('DELETE FROM envelopes WHERE id = ? AND to_id = ?'),
    expireEnvelopes: db.prepare('DELETE FROM envelopes WHERE ts < ?'),
    setDiscoverable: db.prepare('UPDATE users SET discoverable = ? WHERE id = ?'),
    discoverable: db.prepare(`SELECT id, username FROM users WHERE discoverable = 1 AND id != ? AND uname LIKE ? ESCAPE '\\'
                              ORDER BY uname LIMIT ? OFFSET ?`),
    peer: db.prepare('SELECT body FROM peers WHERE owner_id = ? AND tag = ?'),
    putPeer: db.prepare(`INSERT INTO peers (owner_id, tag, body) VALUES (?, ?, ?)
                         ON CONFLICT (owner_id, tag) DO UPDATE SET body = excluded.body`),
    delPeer: db.prepare('DELETE FROM peers WHERE owner_id = ? AND tag = ?'),
    peersOf: db.prepare('SELECT tag, body FROM peers WHERE owner_id = ?'),
    countPeers: db.prepare('SELECT COUNT(*) n FROM peers WHERE owner_id = ?'),
    insertLink: db.prepare('INSERT INTO discord_links (id, chan_tag, guild_tag, body, created) VALUES (?, ?, ?, ?, ?)'),
    link: db.prepare('SELECT * FROM discord_links WHERE id = ?'),
    linkByChan: db.prepare('SELECT * FROM discord_links WHERE chan_tag = ?'),
    linksByGuild: db.prepare('SELECT * FROM discord_links WHERE guild_tag = ?'),
    updateLink: db.prepare('UPDATE discord_links SET body = ? WHERE id = ?'),
    deleteLink: db.prepare('DELETE FROM discord_links WHERE id = ?'),
    setPublic: db.prepare('UPDATE discord_links SET public = ? WHERE id = ?'),
    publicLinks: db.prepare('SELECT * FROM discord_links WHERE public = 1 ORDER BY created'),
    insertInvite: db.prepare('INSERT INTO discord_invites (code_hash, link_id, expires, uses) VALUES (?, ?, ?, ?)'),
    invite: db.prepare('SELECT * FROM discord_invites WHERE code_hash = ?'),
    useInvite: db.prepare('UPDATE discord_invites SET uses = uses - 1 WHERE code_hash = ?'),
    deleteInvite: db.prepare('DELETE FROM discord_invites WHERE code_hash = ?'),
    expireInvites: db.prepare('DELETE FROM discord_invites WHERE expires < ? OR uses <= 0'),
    putMember: db.prepare('INSERT OR IGNORE INTO discord_members (link_id, user_tag, body) VALUES (?, ?, ?)'),
    member: db.prepare('SELECT 1 FROM discord_members WHERE link_id = ? AND user_tag = ?'),
    delMember: db.prepare('DELETE FROM discord_members WHERE link_id = ? AND user_tag = ?'),
    membersOf: db.prepare('SELECT user_tag, body FROM discord_members WHERE link_id = ?'),
    countMembers: db.prepare('SELECT COUNT(*) n FROM discord_members WHERE link_id = ?'),
    linksOfUser: db.prepare('SELECT link_id FROM discord_members WHERE user_tag = ?'),
    delUserMemberships: db.prepare('DELETE FROM discord_members WHERE user_tag = ?')
  };

  const memberTag = userId => S.tag('discord-member|' + userId);
  const openLink = row => row && Object.assign({ id: row.id, created: row.created, public: !!row.public }, S.open(row.body, 'discord_links:' + row.id));
  const sealLink = (id, body) => S.seal(body, 'discord_links:' + id);
  const insertEnvelope = (to, from, payload, now) => {
    const info = q.insertEnvelope.run(to, now, S.seal({ from, payload }, 'envelopes:' + to + ':' + now));
    return { id: Number(info.lastInsertRowid), to, from, ts: now, payload };
  };

  const peerTag = (owner, peer) => S.tag(owner + '|' + peer);
  const peerCtx = (owner, tag) => 'peers:' + owner + ':' + tag;
  const getPeer = (owner, peer) => {
    const tag = peerTag(owner, peer), row = q.peer.get(owner, tag);
    return row ? S.open(row.body, peerCtx(owner, tag)) : null;
  };
  const peersOf = owner => q.peersOf.all(owner).map(r => S.open(r.body, peerCtx(owner, r.tag)));

  const publicUser = row => row && Object.assign(
    { userId: row.id, username: row.username, lastSeen: row.last_seen },
    S.open(row.identity, 'users.identity:' + row.id));

  return {
    raw: db,
    close: () => db.close(),

    /* ---- users ---- */
    userRow: id => q.userById.get(id),
    userRowByName: name => q.userByName.get(String(name).toLowerCase()),
    publicUser,
    vault: row => S.open(row.vault, 'users.vault:' + row.id),
    spk: row => S.open(row.spk, 'users.spk:' + row.id),
    touch: (id, ts) => q.touchUser.run(ts, id),
    /** Also removes the other side of every relationship; returns those users' ids. */
    deleteUser: db.transaction(id => {
      const others = peersOf(id).map(p => p.peer);
      for (const o of others) q.delPeer.run(o, peerTag(o, id));
      q.delUserMemberships.run(memberTag(id));
      q.deleteUser.run(id);
      return others;
    }),

    /* ---- peers ---- */
    setDiscoverable: (id, on) => q.setDiscoverable.run(on ? 1 : 0, id),
    discoverable(excludeId, search, limit, offset) {
      const like = '%' + String(search || '').toLowerCase().replace(/[\\%_]/g, c => '\\' + c) + '%';
      return q.discoverable.all(excludeId, like, limit, offset).map(r => ({ userId: r.id, username: r.username }));
    },
    /** One side of a relationship: {peer, state, since} or null. */
    peer: getPeer,
    peers: peersOf,
    peerCount: owner => q.countPeers.get(owner).n,
    setPeer(owner, peer, state, since) {
      const tag = peerTag(owner, peer);
      q.putPeer.run(owner, tag, S.seal({ peer, state, since: since || Date.now() }, peerCtx(owner, tag)));
    },
    delPeer: (owner, peer) => q.delPeer.run(owner, peerTag(owner, peer)),
    isFriend: (a, b) => { const p = getPeer(a, b); return !!p && p.state === 'friend'; },
    /** Runs fn inside one transaction. */
    tx: fn => db.transaction(fn)(),

    /* ---- discord link ---- */
    createLink(l) {
      const id = crypto.randomBytes(12).toString('hex');
      q.insertLink.run(id, S.tag('discord-chan|' + l.channelId), S.tag('discord-guild|' + l.guildId), sealLink(id, l), Date.now());
      return id;
    },
    link: id => openLink(q.link.get(String(id))),
    linkByChannel: channelId => openLink(q.linkByChan.get(S.tag('discord-chan|' + channelId))),
    linksByGuild: guildId => q.linksByGuild.all(S.tag('discord-guild|' + guildId)).map(openLink),
    updateLink(id, patch) {
      const l = openLink(q.link.get(id));
      const body = Object.assign({}, l, patch); delete body.id; delete body.created; delete body.public;
      q.updateLink.run(sealLink(id, body), id);
    },
    deleteLink: id => q.deleteLink.run(id),
    setPublic: (id, on) => q.setPublic.run(on ? 1 : 0, id),
    publicLinks: () => q.publicLinks.all().map(openLink),
    memberCount: linkId => q.countMembers.get(linkId).n,
    createInvite: (code, linkId, uses, expires) => q.insertInvite.run(sha(code), linkId, expires, uses),
    /** Spends one use of an invite and adds the user; returns the link, or null if the code is no good. */
    redeemInvite: db.transaction((code, userId, maxMembers) => {
      const h = sha(code), inv = q.invite.get(h);
      if (!inv || inv.expires < Date.now() || inv.uses <= 0) return null;
      const tag = memberTag(userId);
      if (q.member.get(inv.link_id, tag)) return { link: openLink(q.link.get(inv.link_id)), already: true };
      if (q.countMembers.get(inv.link_id).n >= maxMembers) throw Object.assign(new Error('this channel is full'), { status: 409 });
      q.putMember.run(inv.link_id, tag, S.seal({ userId, joined: Date.now() }, 'discord_members:' + inv.link_id + ':' + tag));
      if (inv.uses <= 1) q.deleteInvite.run(h); else q.useInvite.run(h);
      return { link: openLink(q.link.get(inv.link_id)), already: false };
    }),
    /** Joins a public channel without a code; returns {link, already}, or null if it is not public (any more). */
    joinPublic: db.transaction((linkId, userId, maxMembers) => {
      const row = q.link.get(String(linkId));
      if (!row || !row.public) return null;
      const tag = memberTag(userId);
      if (q.member.get(row.id, tag)) return { link: openLink(row), already: true };
      if (q.countMembers.get(row.id).n >= maxMembers) throw Object.assign(new Error('this channel is full'), { status: 409 });
      q.putMember.run(row.id, tag, S.seal({ userId, joined: Date.now() }, 'discord_members:' + row.id + ':' + tag));
      return { link: openLink(row), already: false };
    }),
    isMember: (linkId, userId) => !!q.member.get(linkId, memberTag(userId)),
    removeMember: (linkId, userId) => q.delMember.run(linkId, memberTag(userId)).changes > 0,
    members: linkId => q.membersOf.all(linkId).map(r => S.open(r.body, 'discord_members:' + linkId + ':' + r.user_tag).userId),
    linksOf: userId => q.linksOfUser.all(memberTag(userId)).map(r => openLink(q.link.get(r.link_id))).filter(Boolean),

    /** Server-originated envelopes (Discord traffic), stored in one transaction. */
    deliver: db.transaction(list => {
      const now = Date.now();
      return list.map(m => insertEnvelope(m.to, m.from, m.payload, now));
    }),

    /* ---- auth sessions ---- */
    createSession: (hash, userId, ttl) => { const now = Date.now(); q.insertSession.run(hash, userId, now, now + ttl); },
    session: hash => q.session.get(hash),
    extendSession: (hash, expires) => q.extendSession.run(expires, hash),
    deleteSession: hash => q.deleteSession.run(hash),
    deleteOtherSessions: (userId, keepHash) => q.deleteOtherSessions.run(userId, keepHash),

    /* ---- one-time prekeys ---- */
    addPrekeys(userId, list) {
      for (const p of list) q.insertPrekey.run(userId, p.id, S.seal(p.pub, 'prekeys:' + userId + ':' + p.id));
    },
    /** Hands out and deletes exactly one prekey, so no two initiators share it. */
    takePrekey: db.transaction(userId => {
      const row = q.takePrekey.get(userId);
      if (!row) return null;
      q.deletePrekey.run(userId, row.id);
      return { id: row.id, pub: S.open(row.pub, 'prekeys:' + userId + ':' + row.id) };
    }),
    prekeyCount: userId => q.countPrekeys.get(userId).n,

    /* ---- client-encrypted blob store ---- */
    blobs: userId => q.blobs.all(userId).map(r => ({ k: r.k, v: S.open(r.v, 'blobs:' + userId + ':' + r.k) })),
    blobCount: userId => q.countBlobs.get(userId).n,

    /* ---- mailbox ---- */
    inbox: (userId, limit) => q.inbox.all(userId, limit).map(r => {
      const b = S.open(r.body, 'envelopes:' + userId + ':' + r.ts);
      return { id: r.id, ts: r.ts, from: b.from, payload: b.payload };
    }),

    /**
     * Everything a client changes happens in one transaction: ratchet state,
     * message records, prekey deletions, mailbox acks and outgoing envelopes.
     * Either all of it lands or none does — a ratchet that advanced without its
     * envelope being stored (or vice versa) would desynchronise the session.
     */
    commit: db.transaction((userId, c) => {
      const now = Date.now();
      for (const p of c.puts) q.putBlob.run(userId, p.k, S.seal(p.v, 'blobs:' + userId + ':' + p.k), now);
      for (const k of c.dels) q.delBlob.run(userId, k);
      for (const id of c.ack) q.ackEnvelope.run(id, userId);
      for (const p of c.opks) q.insertPrekey.run(userId, p.id, S.seal(p.pub, 'prekeys:' + userId + ':' + p.id));
      const sent = [];
      for (const m of c.send) {
        const info = q.insertEnvelope.run(m.to, now, S.seal({ from: userId, payload: m.payload }, 'envelopes:' + m.to + ':' + now));
        sent.push({ id: Number(info.lastInsertRowid), to: m.to, ts: now, payload: m.payload });
      }
      return sent;
    }),

    /** Signup inserts the user, their prekeys and their first blobs together. */
    signup: db.transaction((u, opks, puts) => {
      q.insertUser.run({
        id: u.id, username: u.username, uname: u.username.toLowerCase(), created: Date.now(),
        salt: u.salt, iter: u.iter, verifier: u.verifier,
        identity: S.seal(u.identity, 'users.identity:' + u.id),
        spk: S.seal(u.spk, 'users.spk:' + u.id),
        vault: S.seal(u.vault, 'users.vault:' + u.id)
      });
      for (const p of opks) q.insertPrekey.run(u.id, p.id, S.seal(p.pub, 'prekeys:' + u.id + ':' + p.id));
      const now = Date.now();
      for (const p of puts) q.putBlob.run(u.id, p.k, S.seal(p.v, 'blobs:' + u.id + ':' + p.k), now);
    }),

    sweep(now, envelopeTtl) {
      q.expireSessions.run(now);
      q.expireEnvelopes.run(now - envelopeTtl);
      q.expireInvites.run(now);
    }
  };
}

module.exports = { open };
