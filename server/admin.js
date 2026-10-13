'use strict';
/**
 * Moderation: admins, moderators and what they can do.
 *
 * Who is staff lives in a JSON config file, admin.json in the data directory
 * (git-ignored, and kept across deploys like the database):
 *
 *   { "admins": ["firephrog"],
 *     "mods": { "someone": ["mute_short", "delete"] } }
 *
 * Admins have every permission and are only ever made by editing this file on
 * the server. Admins appoint moderators from the admin panel with any subset
 * of PERMS; the server writes those back into the same file. The file is read
 * again whenever it changes on disk, so a hand edit needs no restart.
 *
 * Staff only act on people ranked below them: an admin on mods and users, a
 * mod on users.
 *
 * What the server can and cannot do here: mutes, bans and IP bans it enforces
 * itself. Messages it cannot read — they are end-to-end encrypted — so deleting
 * or purging works like "delete for everyone": the moderator's client names
 * the messages (id and author) it sees in a chat they are in, and the server
 * sends every member a notice from "sys:mod". Clients blank a message only if
 * its author matches, so a notice cannot take out someone else's words.
 */
const fs = require('fs');
const path = require('path');

const PERMS = {
  mute_short: 'Mute for up to a week',
  mute_long: 'Mute for longer than a week, or permanently',
  ban: 'Ban: delete the account',
  ip_ban: 'IP ban: refuse connections from their address',
  delete: 'Delete a message for everyone',
  purge: 'Purge many messages at once'
};
const WEEK = 7 * 24 * 3600 * 1000;
const MAX_MUTE = 10 * 365 * 24 * 3600 * 1000;
const MAX_PURGE = 500;
const USERID = /^[0-9a-f]{32}$/;
const GROUPID = /^[0-9a-f]{24}$/;
const DEFAULT = { admins: ['firephrog'], mods: {} };

/** The staff list, re-read from disk whenever the file changes. */
class Staff {
  constructor(file) {
    this.file = file;
    this.mtime = null;
    this.cfg = { admins: [], mods: {} };
    if (!fs.existsSync(file)) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      this._write(DEFAULT);
      console.warn('[marmot] created ' + file + ' with ' + DEFAULT.admins.join(', ') + ' as admin');
    }
    this.load();
  }
  load() {
    let st;
    try { st = fs.statSync(this.file); } catch (e) { return this.cfg; }
    if (this.mtime === st.mtimeMs) return this.cfg;
    this.mtime = st.mtimeMs;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      const admins = Array.isArray(raw.admins) ? raw.admins.map(a => String(a).toLowerCase()) : [];
      const mods = {};
      for (const [name, perms] of Object.entries(raw.mods && typeof raw.mods === 'object' ? raw.mods : {})) {
        mods[name.toLowerCase()] = (Array.isArray(perms) ? perms : []).filter(p => p in PERMS);
      }
      this.cfg = { raw, admins, mods };
      this.broken = false;
    } catch (e) {
      // keep the last good list rather than dropping everyone's access over a typo
      this.broken = true;
      console.error('[marmot] ' + this.file + ' is not valid JSON, keeping the previous staff list:', e.message);
    }
    return this.cfg;
  }
  /** {role: 'admin'|'mod', perms} for a username, or null for everyone else. */
  of(username) {
    const c = this.load(), n = String(username || '').toLowerCase();
    if (c.admins.includes(n)) return { role: 'admin', perms: Object.keys(PERMS) };
    if (c.mods[n] && c.mods[n].length) return { role: 'mod', perms: c.mods[n].slice() };
    return null;
  }
  rank(username) { const s = this.of(username); return !s ? 0 : s.role === 'admin' ? 2 : 1; }
  admins() { return this.load().admins.slice(); }
  mods() { return Object.entries(this.load().mods).filter(([, p]) => p.length).map(([username, perms]) => ({ username, perms })); }
  /** Sets a moderator's permissions; an empty list removes them. */
  setMod(username, perms) {
    this.load();
    // never write over a file that could not be read: it would lose whatever the hand edit had
    if (this.broken || !this.cfg.raw) throw Object.assign(new Error('the staff config on the server could not be read — fix it first'), { status: 503 });
    const raw = Object.assign({}, this.cfg.raw);
    const mods = {};
    // keys are rewritten lower-case, so "Alice" and "alice" cannot both appear
    for (const [n, p] of Object.entries(raw.mods && typeof raw.mods === 'object' ? raw.mods : {})) mods[n.toLowerCase()] = p;
    const n = String(username).toLowerCase();
    if (perms.length) mods[n] = perms; else delete mods[n];
    raw.mods = mods;
    this._write(raw);
    this.load();
  }
  _write(obj) {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

/** `::ffff:1.2.3.4` and `1.2.3.4` are the same address. */
const normIp = ip => String(ip || '').replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, '');

/**
 * The /api/admin routes. ctx: {db, hub, staff, wrap, auth, HttpError}.
 */
function mount(app, ctx) {
  const { db, hub, staff, wrap, auth, HttpError } = ctx;
  const bad = msg => new HttpError(400, msg);
  const forbid = msg => new HttpError(403, msg || 'you do not have permission to do that');

  /** The signed-in staff member, who must hold every permission in `need`. */
  function actor(req, ...need) {
    const me = auth(req);
    const s = staff.of(me.username);
    if (!s) throw new HttpError(403, 'staff only');
    for (const p of need) if (!s.perms.includes(p)) throw forbid('you do not have the “' + PERMS[p] + '” permission');
    return Object.assign(me, { staff: s });
  }
  const adminOnly = req => { const me = actor(req); if (me.staff.role !== 'admin') throw forbid('admins only'); return me; };
  /** The user being acted on, who must rank below the actor. */
  function target(me, userId) {
    const row = db.userRow(String(userId || ''));
    if (!row) throw new HttpError(404, 'no such user');
    if (row.id === me.id) throw bad('that is you');
    if (staff.rank(row.username) >= staff.rank(me.username)) {
      throw forbid(staff.of(row.username).role === 'admin' ? 'admins cannot be moderated from here' : 'only an admin can moderate a moderator');
    }
    return row;
  }
  const log = (me, action, target, detail) => db.log({ by: me.username, action, target: target || null, detail: detail || null });
  const reason = r => String(r == null ? '' : r).trim().slice(0, 300);
  const muteLong = m => m.until === 0 || m.until - m.ts > WEEK;
  const muteView = m => m && { until: m.until, by: m.by, reason: m.reason, ts: m.ts };
  const userView = (me, row) => {
    const s = staff.of(row.username);
    const v = { userId: row.id, username: row.username, created: row.created, lastSeen: row.last_seen,
      role: s ? s.role : null, perms: s ? s.perms : [], mute: muteView(db.mute(row.id)) };
    const ip = db.lastIp(row);
    v.ipBanned = !!ip && db.ipBanned(ip);
    v.hasIp = !!ip;
    if (me.staff.role === 'admin') v.ip = ip;   // addresses are for admins' eyes only
    return v;
  };
  /** Sends server-originated envelopes and pushes them to whoever is online. */
  const deliver = list => {
    for (const s of db.deliver(list)) hub.push(s.to, { t: 'env', env: { id: s.id, from: s.from, ts: s.ts, payload: s.payload } });
  };

  app.get('/api/admin/me', wrap(req => {
    const me = actor(req);
    return { role: me.staff.role, perms: me.staff.perms, all: PERMS };
  }));

  /** Every account, not only discoverable ones. */
  app.get('/api/admin/users', wrap(req => {
    const me = actor(req);
    const search = String(req.query.q || '').trim().slice(0, 24);
    const offset = Math.max(0, Math.min(100000, parseInt(req.query.offset, 10) || 0));
    const rows = db.searchUsers(search, 50, offset);
    return { users: rows.map(r => userView(me, r)), more: rows.length === 50 };
  }));

  app.get('/api/admin/users/:id', wrap(req => {
    const me = actor(req);
    const row = db.userRow(String(req.params.id));
    if (!row) throw new HttpError(404, 'no such user');
    return { user: userView(me, row) };
  }));

  /**
   * body: {userId, minutes} or {userId, permanent: true}, plus an optional reason.
   * Up to a week needs mute_short; longer or permanent needs mute_long. Changing
   * an existing mute needs the permission for it as well as for the new one.
   */
  app.post('/api/admin/mute', wrap(req => {
    const me = actor(req);
    const b = req.body || {};
    const row = target(me, b.userId);
    const now = Date.now();
    let until;
    if (b.permanent === true) until = 0;
    else {
      const min = Number(b.minutes);
      if (!Number.isInteger(min) || min < 1 || min * 60000 > MAX_MUTE) throw bad('give a mute length in whole minutes, or make it permanent');
      until = now + min * 60000;
    }
    const long = until === 0 || until - now > WEEK;
    const had = db.mute(row.id, now);
    for (const p of new Set([long ? 'mute_long' : 'mute_short', had ? (muteLong(had) ? 'mute_long' : 'mute_short') : null])) {
      if (p && !me.staff.perms.includes(p)) throw forbid('you do not have the “' + PERMS[p] + '” permission');
    }
    const why = reason(b.reason);
    db.setMute(row.id, until, { by: me.username, reason: why, ts: now });
    log(me, 'mute', row.username, (until ? 'until ' + new Date(until).toISOString() : 'permanently') + (why ? ' · ' + why : ''));
    hub.pushAll({ t: 'roles' });
    hub.push(row.id, { t: 'me' });
    return { user: userView(me, row) };
  }));

  app.post('/api/admin/unmute', wrap(req => {
    const me = actor(req);
    const row = target(me, (req.body || {}).userId);
    const had = db.mute(row.id);
    if (had) {
      const p = muteLong(had) ? 'mute_long' : 'mute_short';
      if (!me.staff.perms.includes(p)) throw forbid('you do not have the “' + PERMS[p] + '” permission');
      db.clearMute(row.id);
      log(me, 'unmute', row.username);
    hub.pushAll({ t: 'roles' });
      hub.push(row.id, { t: 'me' });
    }
    return { user: userView(me, row) };
  }));

  /** Deletes the account outright, the same way deleting your own does. */
  app.post('/api/admin/ban', wrap(req => {
    const me = actor(req, 'ban');
    const b = req.body || {};
    const row = target(me, b.userId);
    const why = reason(b.reason);
    const others = db.deleteUser(row.id);
    hub.revoke(row.id, 'banned');
    for (const o of others) { hub.push(o, { t: 'peers' }); hub.push(o, { t: 'groups' }); }
    log(me, 'ban', row.username, why || null);
    return {};
  }));

  /** Bans the address the user last connected from, and signs them out everywhere. */
  app.post('/api/admin/ipban', wrap(req => {
    const me = actor(req, 'ip_ban');
    const b = req.body || {};
    const row = target(me, b.userId);
    const ip = db.lastIp(row);
    if (!ip) throw new HttpError(409, 'there is no address on record for them yet');
    const why = reason(b.reason);
    db.banIp(ip, { userId: row.id, username: row.username, by: me.username, reason: why });
    db.deleteSessions(row.id);
    hub.revoke(row.id, 'ipban');
    log(me, 'ipban', row.username, why || null);
    return { user: userView(me, row) };
  }));

  app.get('/api/admin/ipbans', wrap(req => {
    const me = actor(req, 'ip_ban');
    return { bans: db.ipBans().map(x => ({ id: x.id, created: x.created, username: x.username, userId: x.userId, by: x.by,
      reason: x.reason, ip: me.staff.role === 'admin' ? x.ip : undefined })) };
  }));

  app.post('/api/admin/ipbans/remove', wrap(req => {
    const me = actor(req, 'ip_ban');
    const id = String((req.body || {}).id || '');
    const ban = db.ipBans().find(x => x.id === id);
    if (!ban) throw new HttpError(404, 'no such ban');
    db.unbanIp(id);
    log(me, 'unipban', ban.username || null);
    return {};
  }));

  /**
   * Removes messages for everyone in a chat the moderator is in.
   * body: {conv, msgs: [{id, from}]} — conv is "g:<group id>" or the other
   * person's user id; `from` is each message's author. One message needs the
   * delete permission, more than one needs purge.
   */
  function removeMessages(req, purge) {
    const me = actor(req, purge ? 'purge' : 'delete');
    const b = req.body || {};
    const conv = String(b.conv || '');
    const list = Array.isArray(b.msgs) ? b.msgs : null;
    if (!list || !list.length) throw bad('no messages given');
    if (list.length > (purge ? MAX_PURGE : 1)) throw bad(purge ? 'at most ' + MAX_PURGE + ' messages at a time' : 'one message at a time — purging several needs the purge permission');
    let msgs = list.map(m => {
      if (!m || typeof m.id !== 'string' || !m.id || m.id.length > 64 || typeof m.from !== 'string' || !USERID.test(m.from)) throw bad('malformed message reference');
      return { id: m.id, from: m.from };
    });
    let sends;
    if (conv.startsWith('g:')) {
      const gid = conv.slice(2);
      if (!GROUPID.test(gid) || !db.inGroup(gid, me.id)) throw new HttpError(404, 'you are not in that group');
      sends = db.groupMembers(gid).map(m => ({ to: m.userId, conv }));
    } else {
      if (!USERID.test(conv) || !db.userRow(conv)) throw new HttpError(404, 'no such chat');
      if (conv === me.id) throw bad('that is you');
      if (msgs.some(m => m.from !== conv && m.from !== me.id)) throw bad('those messages are not from this chat');
      sends = [{ to: conv, conv: me.id }, { to: me.id, conv }];
    }
    // authors still here must rank below the moderator (their own messages are fine);
    // a purge leaves out what it may not touch, a single delete refuses
    const off = new Set();
    for (const a of new Set(msgs.map(m => m.from))) {
      if (a === me.id) continue;
      const row = db.userRow(a);
      if (row && staff.rank(row.username) >= staff.rank(me.username)) {
        if (!purge) throw forbid('you cannot remove messages from ' + row.username);
        off.add(a);
      }
    }
    const asked = msgs.length;
    msgs = msgs.filter(m => !off.has(m.from));
    if (!msgs.length) throw forbid('every one of those messages is from staff you cannot moderate');
    deliver(sends.map(s => ({ to: s.to, from: 'sys:mod', payload: JSON.stringify({ k: 'mod', t: 'del', conv: s.conv, msgs, by: me.username }) })));
    const authors = [...new Set(msgs.map(m => (db.userRow(m.from) || {}).username || 'a deleted account'))];
    log(me, purge ? 'purge' : 'delete', authors.join(', '), msgs.length + ' message' + (msgs.length === 1 ? '' : 's') + (conv.startsWith('g:') ? ' in a group' : ' in a direct chat'));
    return { removed: msgs.length, skipped: asked - msgs.length };
  }
  app.post('/api/admin/delete', wrap(req => removeMessages(req, false)));
  app.post('/api/admin/purge', wrap(req => removeMessages(req, true)));

  /* ---- admins only ---- */
  app.get('/api/admin/staff', wrap(req => {
    adminOnly(req);
    const known = name => { const r = db.userRowByName(name); return r ? { userId: r.id, username: r.username } : { userId: null, username: name }; };
    return {
      admins: staff.admins().map(known),
      mods: staff.mods().map(m => Object.assign(known(m.username), { perms: m.perms })),
      all: PERMS
    };
  }));

  /** body: {userId, perms: [...]}. An empty list removes the moderator. Admins are made in the config file only. */
  app.post('/api/admin/staff', wrap(req => {
    const me = adminOnly(req);
    const b = req.body || {};
    const row = db.userRow(String(b.userId || ''));
    if (!row) throw new HttpError(404, 'no such user');
    if (row.id === me.id) throw bad('that is you');
    if (staff.of(row.username) && staff.of(row.username).role === 'admin') throw forbid('admins are set in the server config, not here');
    if (!Array.isArray(b.perms)) throw bad('perms must be a list');
    const perms = [...new Set(b.perms.map(String))];
    for (const p of perms) if (!(p in PERMS)) throw bad('unknown permission: ' + p);
    const order = Object.keys(PERMS);
    perms.sort((x, y) => order.indexOf(x) - order.indexOf(y));
    staff.setMod(row.username, perms);
    log(me, perms.length ? 'mod' : 'unmod', row.username, perms.join(', ') || null);
    hub.push(row.id, { t: 'me' });
    // everyone showing their tag in a chat picks up the change
    hub.pushAll({ t: 'roles' });
    return { user: { userId: row.id, username: row.username, perms } };
  }));

  app.get('/api/admin/log', wrap(req => {
    adminOnly(req);
    return { log: db.logs(Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 200))) };
  }));
}

module.exports = { Staff, mount, normIp, PERMS, WEEK };
