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
  discoverable INTEGER NOT NULL DEFAULT 0, -- listed in everyone's global peers section
  avatar     TEXT,                       -- sealed profile picture (a small data: URL), or NULL
  avatar_v   INTEGER NOT NULL DEFAULT 0, -- when it last changed; 0 = none. Clients cache by it
  profile    TEXT,                       -- sealed {display, bio, status, accent}, or NULL
  profile_v  INTEGER NOT NULL DEFAULT 0, -- when it last changed (or the username did); clients cache by it
  presence   TEXT NOT NULL DEFAULT 'auto' -- auto | dnd | invisible: what others see while signed in
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
-- Group chats. The server knows who is in a group, because it must let
-- members who are not friends reach each other; the group's name and its
-- messages are end-to-end encrypted between the members and never stored here.
CREATE TABLE IF NOT EXISTS groups (
  id         TEXT PRIMARY KEY,
  created    INTEGER NOT NULL,
  body       TEXT NOT NULL               -- sealed {createdBy, owner, mods, mutes, invite, tag, kicks}
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id   TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_tag   TEXT NOT NULL,
  body       TEXT NOT NULL,              -- sealed {userId, joined, invitedBy}
  PRIMARY KEY (group_id, user_tag)
);
CREATE INDEX IF NOT EXISTS group_members_user ON group_members(user_tag);
-- Requests to join a group through its tag, waiting for a group moderator.
CREATE TABLE IF NOT EXISTS group_apps (
  group_id   TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_tag   TEXT NOT NULL,
  body       TEXT NOT NULL,              -- sealed {userId, reason, via, ts}
  PRIMARY KEY (group_id, user_tag)
);
CREATE INDEX IF NOT EXISTS group_apps_user ON group_apps(user_tag);
-- Moderation (see admin.js). A mute's end is plaintext so expired ones can be
-- swept; who set it and why are sealed. An IP ban is found by a keyed tag of
-- the address; the address itself is sealed, so a leaked database does not
-- list them. The log is every staff action, sealed.
CREATE TABLE IF NOT EXISTS mutes (
  user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  until      INTEGER NOT NULL,           -- ms epoch; 0 = permanent
  body       TEXT NOT NULL               -- sealed {by, reason, ts}
);
CREATE TABLE IF NOT EXISTS ip_bans (
  tag        TEXT PRIMARY KEY,           -- keyed HMAC of the address
  created    INTEGER NOT NULL,
  body       TEXT NOT NULL               -- sealed {ip, userId, username, by, reason}
);
CREATE TABLE IF NOT EXISTS mod_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  body       TEXT NOT NULL               -- sealed {by, action, target, detail}
);
-- Staff tags: short colored labels staff make and put on profiles. They are
-- shown publicly, so which user has which tag is plaintext; the label is sealed.
CREATE TABLE IF NOT EXISTS staff_tags (
  id         TEXT PRIMARY KEY,
  created    INTEGER NOT NULL,
  body       TEXT NOT NULL               -- sealed {text, color, by}
);
CREATE TABLE IF NOT EXISTS user_tags (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tag_id     TEXT NOT NULL REFERENCES staff_tags(id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  PRIMARY KEY (user_id, tag_id)
);
CREATE INDEX IF NOT EXISTS user_tags_tag ON user_tags(tag_id);
`;

/** Columns added after a table first shipped; applied to older databases on open. */
const MIGRATIONS = [
  ['users', 'discoverable', 'ALTER TABLE users ADD COLUMN discoverable INTEGER NOT NULL DEFAULT 0'],
  ['discord_links', 'public', 'ALTER TABLE discord_links ADD COLUMN public INTEGER NOT NULL DEFAULT 0'],
  ['users', 'avatar', 'ALTER TABLE users ADD COLUMN avatar TEXT'],
  ['users', 'avatar_v', 'ALTER TABLE users ADD COLUMN avatar_v INTEGER NOT NULL DEFAULT 0'],
  ['users', 'last_ip', 'ALTER TABLE users ADD COLUMN last_ip TEXT'],   // sealed; what an IP ban bans
  ['users', 'profile', 'ALTER TABLE users ADD COLUMN profile TEXT'],
  ['users', 'profile_v', 'ALTER TABLE users ADD COLUMN profile_v INTEGER NOT NULL DEFAULT 0'],
  ['users', 'presence', "ALTER TABLE users ADD COLUMN presence TEXT NOT NULL DEFAULT 'auto'"]
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
    setAvatar: db.prepare('UPDATE users SET avatar = ?, avatar_v = ? WHERE id = ?'),
    setProfile: db.prepare('UPDATE users SET profile = ?, profile_v = ? WHERE id = ?'),
    bumpProfile: db.prepare('UPDATE users SET profile_v = ? WHERE id = ?'),
    setPresence: db.prepare('UPDATE users SET presence = ? WHERE id = ?'),
    rename: db.prepare('UPDATE users SET username = ?, uname = ? WHERE id = ?'),
    discoverable: db.prepare(`SELECT id, username, avatar_v, profile, profile_v FROM users WHERE discoverable = 1 AND id != ? AND uname LIKE ? ESCAPE '\\'
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
    delUserMemberships: db.prepare('DELETE FROM discord_members WHERE user_tag = ?'),
    insertGroup: db.prepare('INSERT INTO groups (id, created, body) VALUES (?, ?, ?)'),
    group: db.prepare('SELECT * FROM groups WHERE id = ?'),
    deleteGroup: db.prepare('DELETE FROM groups WHERE id = ?'),
    putGroupMember: db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_tag, body) VALUES (?, ?, ?)'),
    groupMember: db.prepare('SELECT 1 FROM group_members WHERE group_id = ? AND user_tag = ?'),
    delGroupMember: db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_tag = ?'),
    groupMembersOf: db.prepare('SELECT user_tag, body FROM group_members WHERE group_id = ?'),
    countGroupMembers: db.prepare('SELECT COUNT(*) n FROM group_members WHERE group_id = ?'),
    groupsOfUser: db.prepare('SELECT group_id FROM group_members WHERE user_tag = ?'),
    setGroup: db.prepare('UPDATE groups SET body = ? WHERE id = ?'),
    putApp: db.prepare(`INSERT INTO group_apps (group_id, user_tag, body) VALUES (?, ?, ?)
                        ON CONFLICT (group_id, user_tag) DO UPDATE SET body = excluded.body`),
    delApp: db.prepare('DELETE FROM group_apps WHERE group_id = ? AND user_tag = ?'),
    appsOf: db.prepare('SELECT user_tag, body FROM group_apps WHERE group_id = ?'),
    appsOfUser: db.prepare('SELECT group_id FROM group_apps WHERE user_tag = ?'),
    delUserApps: db.prepare('DELETE FROM group_apps WHERE user_tag = ?'),
    searchUsers: db.prepare(`SELECT * FROM users WHERE uname LIKE ? ESCAPE '\\' ORDER BY uname LIMIT ? OFFSET ?`),
    setLastIp: db.prepare('UPDATE users SET last_ip = ? WHERE id = ?'),
    deleteSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
    mute: db.prepare('SELECT * FROM mutes WHERE user_id = ?'),
    putMute: db.prepare(`INSERT INTO mutes (user_id, until, body) VALUES (?, ?, ?)
                         ON CONFLICT (user_id) DO UPDATE SET until = excluded.until, body = excluded.body`),
    delMute: db.prepare('DELETE FROM mutes WHERE user_id = ?'),
    expireMutes: db.prepare('DELETE FROM mutes WHERE until != 0 AND until < ?'),
    ipBan: db.prepare('SELECT 1 FROM ip_bans WHERE tag = ?'),
    putIpBan: db.prepare(`INSERT INTO ip_bans (tag, created, body) VALUES (?, ?, ?)
                          ON CONFLICT (tag) DO UPDATE SET created = excluded.created, body = excluded.body`),
    delIpBan: db.prepare('DELETE FROM ip_bans WHERE tag = ?'),
    ipBans: db.prepare('SELECT * FROM ip_bans ORDER BY created DESC'),
    insertLog: db.prepare('INSERT INTO mod_log (ts, body) VALUES (?, ?)'),
    log: db.prepare('SELECT * FROM mod_log ORDER BY id DESC LIMIT ?'),
    stags: db.prepare('SELECT * FROM staff_tags ORDER BY created'),
    stag: db.prepare('SELECT * FROM staff_tags WHERE id = ?'),
    putStag: db.prepare('INSERT INTO staff_tags (id, created, body) VALUES (?, ?, ?)'),
    delStag: db.prepare('DELETE FROM staff_tags WHERE id = ?'),
    stagHolders: db.prepare('SELECT user_id FROM user_tags WHERE tag_id = ?'),
    stagCounts: db.prepare('SELECT tag_id, COUNT(*) n FROM user_tags GROUP BY tag_id'),
    userStags: db.prepare('SELECT s.* FROM user_tags u JOIN staff_tags s ON s.id = u.tag_id WHERE u.user_id = ? ORDER BY u.ts'),
    addUserStag: db.prepare('INSERT OR IGNORE INTO user_tags (user_id, tag_id, ts) VALUES (?, ?, ?)'),
    delUserStag: db.prepare('DELETE FROM user_tags WHERE user_id = ? AND tag_id = ?')
  };
  const openStag = r => r && Object.assign({ id: r.id, created: r.created }, S.open(r.body, 'staff_tags:' + r.id));

  const memberTag = userId => S.tag('discord-member|' + userId);
  const openLink = row => row && Object.assign({ id: row.id, created: row.created, public: !!row.public }, S.open(row.body, 'discord_links:' + row.id));
  const sealLink = (id, body) => S.seal(body, 'discord_links:' + id);
  const insertEnvelope = (to, from, payload, now) => {
    const info = q.insertEnvelope.run(to, now, S.seal({ from, payload }, 'envelopes:' + to + ':' + now));
    return { id: Number(info.lastInsertRowid), to, from, ts: now, payload };
  };

  const gmTag = userId => S.tag('group-member|' + userId);
  const gmCtx = (groupId, tag) => 'group_members:' + groupId + ':' + tag;
  const groupMembers = groupId => q.groupMembersOf.all(groupId).map(r => S.open(r.body, gmCtx(groupId, r.user_tag)));
  const groupIdsOf = userId => q.groupsOfUser.all(gmTag(userId)).map(r => r.group_id);
  /** Removes one member; a group nobody is left in is deleted. Returns whether they were in it. */
  const leaveGroup = (groupId, userId) => {
    const gone = q.delGroupMember.run(groupId, gmTag(userId)).changes > 0;
    if (gone && !q.countGroupMembers.get(groupId).n) q.deleteGroup.run(groupId);
    return gone;
  };

  const peerTag = (owner, peer) => S.tag(owner + '|' + peer);
  const peerCtx = (owner, tag) => 'peers:' + owner + ':' + tag;
  const getPeer = (owner, peer) => {
    const tag = peerTag(owner, peer), row = q.peer.get(owner, tag);
    return row ? S.open(row.body, peerCtx(owner, tag)) : null;
  };
  const peersOf = owner => q.peersOf.all(owner).map(r => S.open(r.body, peerCtx(owner, r.tag)));

  const openProfile = row => {
    if (!row || !row.profile) return {};
    try { return S.open(row.profile, 'users.profile:' + row.id) || {}; } catch (e) { return {}; }
  };
  /** The name to show for someone: their display name, or '' for none (show the username). */
  const displayOf = row => openProfile(row).display || '';

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
    /** Also removes the other side of every relationship and every group membership;
        returns the ids of everyone affected. */
    deleteUser: db.transaction(id => {
      const others = new Set(peersOf(id).map(p => p.peer));
      for (const o of others) q.delPeer.run(o, peerTag(o, id));
      for (const g of groupIdsOf(id)) {
        leaveGroup(g, id);
        for (const m of groupMembers(g)) others.add(m.userId);
      }
      q.delUserMemberships.run(memberTag(id));
      q.delUserApps.run(gmTag(id));
      q.deleteUser.run(id);
      return [...others];
    }),

    /* ---- peers ---- */
    setDiscoverable: (id, on) => q.setDiscoverable.run(on ? 1 : 0, id),
    discoverable(excludeId, search, limit, offset) {
      const like = '%' + String(search || '').toLowerCase().replace(/[\\%_]/g, c => '\\' + c) + '%';
      return q.discoverable.all(excludeId, like, limit, offset).map(r => ({ userId: r.id, username: r.username, av: r.avatar_v, pv: r.profile_v, dn: displayOf(r) }));
    },
    /** Sets (or, with null, clears) a profile picture; returns its new version. */
    setAvatar(id, data) {
      const v = data ? Date.now() : 0;
      q.setAvatar.run(data ? S.seal(data, 'users.avatar:' + id) : null, v, id);
      return v;
    },
    avatar: row => row.avatar ? S.open(row.avatar, 'users.avatar:' + row.id) : null,
    /** Sets a profile {display, bio, status, accent} (already checked); returns its new version. */
    setProfile(id, p) {
      const v = Date.now();
      q.setProfile.run(S.seal(p, 'users.profile:' + id), v, id);
      return v;
    },
    profile: openProfile,
    /** Moves the profile version on without changing it, so clients refetch it. */
    bumpProfile: id => { const v = Date.now(); q.bumpProfile.run(v, id); return v; },
    displayOf,
    /** auto | dnd | invisible */
    setPresence: (id, mode) => q.setPresence.run(mode, id),
    /** Changes a username, and the profile version so clients refetch it; returns that version.
        Throws a UNIQUE error if the name is taken (in any case). */
    rename: db.transaction((id, username) => {
      const v = Date.now();
      q.rename.run(username, username.toLowerCase(), id);
      q.bumpProfile.run(v, id);
      return v;
    }),
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

    /* ---- group chats ---- */
    /** Creates a group holding `members` (the creator first); returns its id. */
    createGroup: db.transaction((createdBy, members) => {
      const id = crypto.randomBytes(12).toString('hex'), now = Date.now();
      q.insertGroup.run(id, now, S.seal({ createdBy }, 'groups:' + id));
      for (const m of members) {
        const tag = gmTag(m);
        q.putGroupMember.run(id, tag, S.seal({ userId: m, joined: now, invitedBy: m === createdBy ? null : createdBy }, gmCtx(id, tag)));
      }
      return id;
    }),
    group(id) {
      const row = q.group.get(String(id));
      return row && Object.assign({ id: row.id, created: row.created }, S.open(row.body, 'groups:' + row.id));
    },
    groupMembers,
    groupIdsOf,
    groupMemberCount: groupId => q.countGroupMembers.get(groupId).n,
    inGroup: (groupId, userId) => !!q.groupMember.get(groupId, gmTag(userId)),
    /** Adds members; returns the ids that were not already in. */
    /** `via` is whose profile tag they came through, if any. */
    addGroupMembers: db.transaction((groupId, invitedBy, ids, via) => {
      const now = Date.now(), added = [];
      for (const m of ids) {
        const tag = gmTag(m), body = { userId: m, joined: now, invitedBy };
        if (via) body.via = via;
        if (q.putGroupMember.run(groupId, tag, S.seal(body, gmCtx(groupId, tag))).changes) added.push(m);
      }
      return added;
    }),
    leaveGroup: db.transaction(leaveGroup),
    /** Replaces a group's sealed settings (everything but id and created). */
    setGroup(id, body) {
      const b = Object.assign({}, body); delete b.id; delete b.created;
      q.setGroup.run(S.seal(b, 'groups:' + id), id);
    },
    /** Join requests: one per user per group, newest reason wins. */
    putGroupApp(groupId, a) { const tag = gmTag(a.userId); q.putApp.run(groupId, tag, S.seal(a, 'group_apps:' + groupId + ':' + tag)); },
    delGroupApp: (groupId, userId) => q.delApp.run(groupId, gmTag(userId)).changes > 0,
    groupApps: groupId => q.appsOf.all(groupId).map(r => S.open(r.body, 'group_apps:' + groupId + ':' + r.user_tag)),
    appliedGroups: userId => q.appsOfUser.all(gmTag(userId)).map(r => r.group_id),
    /** Whether two users are in at least one group together. */
    shareGroup: (a, b) => { const tb = gmTag(b); return groupIdsOf(a).some(g => !!q.groupMember.get(g, tb)); },
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

    /* ---- moderation ---- */
    /** Every account whose username contains `search`, for the admin panel. */
    searchUsers(search, limit, offset) {
      const like = '%' + String(search || '').toLowerCase().replace(/[\\%_]/g, c => '\\' + c) + '%';
      return q.searchUsers.all(like, limit, offset);
    },
    setLastIp: (id, ip) => q.setLastIp.run(ip ? S.seal(ip, 'users.last_ip:' + id) : null, id),
    lastIp: row => row.last_ip ? S.open(row.last_ip, 'users.last_ip:' + row.id) : null,
    deleteSessions: userId => q.deleteSessions.run(userId),
    /** The user's mute as {until, by, reason, ts} (until 0 = permanent), or null if none is in force. */
    mute(userId, now) {
      const r = q.mute.get(userId);
      if (!r || (r.until && r.until <= (now || Date.now()))) return null;
      return Object.assign({ until: r.until }, S.open(r.body, 'mutes:' + userId));
    },
    setMute: (userId, until, info) => q.putMute.run(userId, until, S.seal(info, 'mutes:' + userId)),
    clearMute: userId => q.delMute.run(userId).changes > 0,
    ipTag: ip => S.tag('ip|' + ip),
    ipBanned: ip => !!ip && !!q.ipBan.get(S.tag('ip|' + ip)),
    banIp: (ip, info) => { const tag = S.tag('ip|' + ip); q.putIpBan.run(tag, Date.now(), S.seal(Object.assign({ ip }, info), 'ip_bans:' + tag)); return tag; },
    unbanIp: tag => q.delIpBan.run(String(tag)).changes > 0,
    ipBans: () => q.ipBans.all().map(r => Object.assign({ id: r.tag, created: r.created }, S.open(r.body, 'ip_bans:' + r.tag))),
    /** Appends to the moderation log; `entry` is {by, action, target, detail}. */
    log(entry) {
      const ts = Date.now(), info = q.insertLog.run(ts, S.seal(entry, 'mod_log:' + ts));
      return Number(info.lastInsertRowid);
    },
    logs: limit => q.log.all(limit).map(r => Object.assign({ id: r.id, ts: r.ts }, S.open(r.body, 'mod_log:' + r.ts))),

    /* ---- staff tags ---- */
    /** Every tag as {id, created, text, color, by, n}, n being how many people have it. */
    staffTags() {
      const n = new Map(q.stagCounts.all().map(r => [r.tag_id, r.n]));
      return q.stags.all().map(r => Object.assign(openStag(r), { n: n.get(r.id) || 0 }));
    },
    staffTag: id => openStag(q.stag.get(String(id))),
    /** Makes a tag from {text, color, by}; returns its id. */
    addStaffTag(info) {
      const id = crypto.randomBytes(8).toString('hex');
      q.putStag.run(id, Date.now(), S.seal(info, 'staff_tags:' + id));
      return id;
    },
    /** Deletes a tag, taking it off everyone; returns the ids of the users who had it. */
    delStaffTag: db.transaction(id => {
      const had = q.stagHolders.all(id).map(r => r.user_id);
      q.delStag.run(id);
      return had;
    }),
    /** The tags on a user, oldest first, as {id, text, color}. */
    userStaffTags: userId => q.userStags.all(userId).map(r => { const t = openStag(r); return { id: t.id, text: t.text, color: t.color }; }),
    /** Puts a tag on a user or takes it off; true if that changed anything. */
    setUserStaffTag: (userId, tagId, on) => (on ? q.addUserStag.run(userId, tagId, Date.now()) : q.delUserStag.run(userId, tagId)).changes > 0,

    sweep(now, envelopeTtl) {
      q.expireSessions.run(now);
      q.expireEnvelopes.run(now - envelopeTtl);
      q.expireInvites.run(now);
      q.expireMutes.run(now);
    }
  };
}

module.exports = { open };
