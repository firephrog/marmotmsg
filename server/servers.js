'use strict';
/**
 * Servers: communities with text and voice channels, roles and permissions, in
 * the manner of Discord servers.
 *
 * A server is end-to-end encrypted unless its creator turned that off when making
 * it (it cannot be changed afterwards). In an encrypted server every message is
 * sealed by the sender's browser under the server's key, and this stores and
 * passes on ciphertext it cannot open ({enc: {n, iv, ct}}):
 *  - The key is made by the creator's browser. It reaches new members inside the
 *    invite: the code they are given has a second part that never comes here,
 *    and the keys are locked under it (the invite's `blob`).
 *  - Whenever someone is kicked, banned or leaves, the server is marked `stale`,
 *    and the browser of someone online who may kick, ban or manage the server
 *    makes the next key (epoch n+1) and posts here only `checks[n+1]`: an HMAC
 *    of the new key, and an HMAC of that under the previous key. Members fetch the
 *    new key from each other over their end-to-end encrypted sessions, and each
 *    one checks it against that chain, so nothing this server hands out is taken
 *    for a key. Removed members never get the new one.
 *  - Voice channel signals are sealed under the key too, so the media they set up
 *    is encrypted end to end.
 * What stays readable here: names (of the server, channels and roles), who is a
 * member, who posted when, and who replied to which message.
 * In an unencrypted server the messages are only sealed at rest (see seal.js), and
 * the client says plainly that the server can read them.
 *
 * Permissions come from roles. Every server has the @everyone role, which every
 * member has; the other roles are ranked (the list is highest first, @everyone
 * always last), and a member ranks as their highest role. Administrator turns on
 * every permission, and the owner has every permission whatever their roles.
 * Someone who manages roles can only touch roles ranked below their own highest
 * and can only switch on permissions they hold themselves; kicks, bans and role
 * changes only reach members ranked below the one doing them.
 *
 * Voice channels carry no audio through here. Who is in which voice channel is
 * kept in memory, and the browsers connect to each other with WebRTC (a full
 * mesh, as group calls do), signalling over the socket as t:'vsig', which this
 * only passes between two people in the same voice channel.
 */
const crypto = require('crypto');

// A server icon: already cropped and shrunk by the client, like a profile picture.
const ICON = /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const ICON_CHARS = 64 * 1024;
const LIMITS = {
  servers: 100, members: 1000, channels: 50, roles: 25, bans: 1000, voice: 12,
  name: 32, roleName: 24, topic: 120, text: 2000, reason: 200, page: 50, inviteHours: 24 * 30, inviteUses: 1000
};
const SERVERID = /^[0-9a-f]{24}$/;
const SUBID = /^[0-9a-f]{12}$/;
const COLOR = /^#[0-9a-fA-F]{6}$/;
const EVERYONE = 'everyone';
/** Every permission, and whether @everyone has it in a new server. */
const PERMS = {
  view: true, send: true, connect: true, invite: true,
  sendReadonly: false, deleteMsgs: false, kick: false, ban: false,
  manageChannels: false, manageRoles: false, manageServer: false, admin: false
};
const PERM_KEYS = Object.keys(PERMS);
const ALL = () => Object.fromEntries(PERM_KEYS.map(k => [k, true]));
const NONE = () => Object.fromEntries(PERM_KEYS.map(k => [k, false]));
/** Invite codes: 8 characters that cannot be misread for each other. */
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const VOICE_GRACE = 15000;
// encrypted servers: base64 fields, a key check (hex), and the invite's key blob
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const CHECK = /^[0-9a-f]{32}$/;
const ENC_CHARS = 12000, BLOB_CHARS = 64 * 1024, MAX_EPOCHS = 1000;

function mount(app, ctx) {
  const { db, hub, wrap, auth, HttpError, text, limiter, checkMute, brief } = ctx;
  const bad = msg => new HttpError(400, msg);
  const newId = () => crypto.randomBytes(6).toString('hex');
  const grace = ctx.voiceGrace != null ? ctx.voiceGrace : VOICE_GRACE;

  /* ---------------------------------------------------- permissions */
  /** The owner: as stored while they are still in it, else the longest-serving member (and that is saved). */
  function ownerOf(s) {
    if (s.owner && db.serverMember(s.id, s.owner)) return s.owner;
    const first = db.serverMembers(s.id).sort((a, b) => a.joined - b.joined || (a.userId < b.userId ? -1 : 1))[0];
    const owner = first ? first.userId : null;
    if (owner && owner !== s.owner) { s.owner = owner; db.setServer(s.id, s); }
    return owner;
  }
  /** 0 for the owner, else 1 + the position of their highest role (@everyone is last). Lower outranks higher. */
  function rankOf(s, m, owner) {
    if (m.userId === owner) return 0;
    let best = s.roles.length - 1;
    for (const id of m.roles) { const i = s.roles.findIndex(r => r.id === id); if (i >= 0 && i < best) best = i; }
    return best + 1;
  }
  function permsOf(s, m, owner) {
    if (!m) return NONE();
    if (m.userId === owner) return ALL();
    const out = NONE();
    for (const r of s.roles) if (r.id === EVERYONE || m.roles.includes(r.id)) for (const k of PERM_KEYS) if (r.perms[k]) out[k] = true;
    return out.admin ? ALL() : out;
  }
  /** The server, my membership, its owner and what I may do there; 404 unless I am in it. */
  function load(me, id) {
    id = String(id || '');
    const m = SERVERID.test(id) && db.serverMember(id, me.id);
    const s = m && db.server(id);
    if (!s) throw new HttpError(404, 'you are not in that server');
    const owner = ownerOf(s);
    return { id, s, m, owner, perms: permsOf(s, m, owner), rank: rankOf(s, m, owner), me };
  }
  function need(c, perm, what) { if (!c.perms[perm]) throw new HttpError(403, 'you do not have permission to ' + what + ' in this server'); }
  /** Someone left an encrypted server: its key has to be replaced (see /api/servers/rekey). */
  function markStale(id) {
    const s = db.server(id);
    if (s && s.e2ee && !s.stale) { s.stale = true; db.setServer(id, s); }
  }
  /** Whether the role at position i is below my highest role (the owner reaches every role). */
  const below = (c, i) => c.rank === 0 || i >= c.rank;
  /** Another member ranked below me, as {userId, joined, roles}. */
  function target(c, userId) {
    userId = String(userId || '');
    if (userId === c.me.id) throw bad('that is you');
    const t = db.serverMember(c.id, userId);
    if (!t) throw new HttpError(404, 'they are not in this server');
    if (rankOf(c.s, t, c.owner) <= c.rank) throw new HttpError(403, t.userId === c.owner ? 'nobody can do that to the server owner' : 'you can only do that to members ranked below you');
    return t;
  }
  function channelOf(c, id, kind) {
    const ch = c.s.channels.find(x => x.id === String(id || ''));
    if (!ch || (kind && ch.kind !== kind)) throw new HttpError(404, 'there is no such ' + (kind || '') + (kind ? ' ' : '') + 'channel');
    return ch;
  }

  /* ---------------------------------------------------- input */
  function nameIn(v, max, what) {
    const n = text(v, 200, what);
    if (!n) throw bad('give it a name');
    if ([...n].length > max) throw bad(what + ' can be at most ' + max + ' characters');
    return n;
  }
  /** Text channel names read like Discord's: lower case, dashes for spaces. Voice channels keep theirs as typed. */
  function chanName(v, kind) {
    let n = text(v, 200, 'a channel name');
    if (kind === 'text') n = n.toLowerCase().replace(/\s+/g, '-').replace(/[^\p{L}\p{N}_-]/gu, '').replace(/-{2,}/g, '-').replace(/^-+|-+$/g, '');
    if (!n) throw bad('give the channel a name');
    if ([...n].length > LIMITS.name) throw bad('channel names can be at most ' + LIMITS.name + ' characters');
    return n;
  }
  /** A role's permissions after a change; nobody can switch on a permission they do not hold. */
  function permsIn(c, p, cur) {
    if (!p || typeof p !== 'object' || Array.isArray(p)) throw bad('perms must be an object');
    const out = Object.assign(NONE(), cur);
    for (const k of PERM_KEYS) {
      if (!(k in p)) continue;
      if (typeof p[k] !== 'boolean') throw bad('each permission is true or false');
      if (p[k] && !out[k] && !c.perms[k]) throw new HttpError(403, 'you cannot give out a permission you do not have');
      out[k] = p[k];
    }
    return out;
  }
  const dir = v => { if (v !== -1 && v !== 1) throw bad('dir is -1 (up) or 1 (down)'); return v; };

  /* ---------------------------------------------------- views */
  /** Who someone is, for a message: no presence, which only people who can reach each other see. */
  function who(id) {
    const row = db.userRow(id);
    if (!row) return null;
    return { userId: id, username: row.username, av: row.avatar_v, pv: row.profile_v, dn: db.displayOf(row) };
  }
  function view(c) {
    const last = c.perms.view ? db.lastServerMsgs(c.id) : {};
    const v = {
      serverId: c.id, name: c.s.name, iv: c.s.iv || 0, created: c.s.created, owner: c.owner, members: db.serverMemberCount(c.id),
      me: { perms: c.perms, roles: c.m.roles, rank: c.rank, joined: c.m.joined },
      roles: c.s.roles.map(r => ({ id: r.id, name: r.name, color: r.color || '', perms: r.perms })),
      channels: c.s.channels.map(ch => Object.assign({ id: ch.id, name: ch.name, kind: ch.kind, readonly: !!ch.readonly, topic: ch.topic || '' },
        ch.kind === 'text' ? { last: last[ch.id] || 0 } : {})),
      voice: voiceIn(c.id),
      e2ee: !!c.s.e2ee
    };
    if (c.s.e2ee) Object.assign(v, { epoch: c.s.epoch, epochBy: c.s.epochBy || c.s.createdBy, checks: c.s.checks, stale: !!c.s.stale });
    if (c.perms.ban) v.bans = c.s.bans.map(b => Object.assign({ by: b.by, ts: b.ts, reason: b.reason || '' }, who(b.userId) || { userId: b.userId, username: 'deleted account' }));
    return v;
  }
  const members = id => db.serverMembers(id);
  /** Tells every member to fetch the server again (gone: it is no longer theirs to fetch). */
  function changed(id, also) {
    for (const m of members(id)) hub.push(m.userId, { t: 'server', server: id });
    for (const u of also || []) hub.push(u, { t: 'server', server: id, gone: true });
  }
  /** Only the members who can read the channels hear what is said in them. */
  function toReaders(c, msg) {
    const s = db.server(c.id) || c.s;
    for (const m of members(c.id)) if (permsOf(s, m, c.owner).view) hub.push(m.userId, msg);
  }

  /* ---------------------------------------------------- voice */
  const voice = new Map();   // userId -> {server, channel}
  const offTimers = new Map();
  function usersIn(server, channel) { const out = []; for (const [u, v] of voice) if (v.server === server && v.channel === channel) out.push(u); return out; }
  function voiceIn(server) {
    const out = {};
    for (const [u, v] of voice) if (v.server === server) (out[v.channel] = out[v.channel] || []).push(u);
    return out;
  }
  function pushVoice(server, channel) {
    if (!db.server(server)) return;
    const users = usersIn(server, channel);
    for (const m of members(server)) hub.push(m.userId, { t: 'svoice', server, channel, users });
  }
  /** Puts someone in a voice channel, or (server null) out of whichever they were in. */
  function setVoice(userId, server, channel) {
    const was = voice.get(userId);
    if (was && was.server === server && was.channel === channel) return;
    voice.delete(userId);
    if (server) voice.set(userId, { server, channel });
    if (was) pushVoice(was.server, was.channel);
    if (server) pushVoice(server, channel);
  }
  /** Takes people out of voice in one server: everyone in a channel, or one user. */
  function dropVoice(server, { channel, user } = {}) {
    for (const [u, v] of [...voice]) if (v.server === server && (!channel || v.channel === channel) && (!user || u === user)) setVoice(u, null);
  }

  /* ---------------------------------------------------- the list */
  app.get('/api/servers', wrap(req => {
    const me = auth(req);
    return { servers: db.serverIdsOf(me.id).map(id => { try { return view(load(me, id)); } catch (e) { return null; } }).filter(Boolean) };
  }));
  app.get('/api/servers/one', wrap(req => ({ server: view(load(auth(req), req.query.server)) })));

  app.get('/api/servers/members', wrap(req => {
    const me = auth(req), c = load(me, req.query.server);
    return { members: members(c.id).map(m => { const b = brief(m.userId, me.id); return b && Object.assign(b, { joined: m.joined, roles: m.roles }); }).filter(Boolean) };
  }));

  /** A new server: an @everyone role with the default permissions, #general, and a General voice channel. */
  app.post('/api/servers', limiter(20), wrap(req => {
    const me = auth(req);
    const b = req.body || {}, name = nameIn(b.name, LIMITS.name, 'a server name');
    // encrypted unless asked otherwise; the creator's browser made the first key and sends only its check
    const e2ee = b.e2ee !== false;
    if (e2ee && !CHECK.test(String(b.check || ''))) throw bad('an encrypted server needs its first key check');
    if (db.serverIdsOf(me.id).length >= LIMITS.servers) throw new HttpError(507, 'you are in too many servers');
    const id = db.createServer(me.id, Object.assign(e2ee ? { e2ee: true, epoch: 1, epochBy: me.id, checks: { 1: { c: b.check } } } : { e2ee: false }, {
      name, owner: me.id, createdBy: me.id, bans: [],
      roles: [{ id: EVERYONE, name: '@everyone', color: '', perms: Object.assign({}, PERMS) }],
      channels: [{ id: newId(), name: 'general', kind: 'text', readonly: false, topic: '' }, { id: newId(), name: 'General', kind: 'voice' }]
    }));
    hub.push(me.id, { t: 'server', server: id });
    return { server: view(load(me, id)) };
  }));

  app.post('/api/servers/settings', limiter(60), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'manageServer', 'change the settings');
    if ('name' in b) c.s.name = nameIn(b.name, LIMITS.name, 'a server name');
    db.setServer(c.id, c.s);
    changed(c.id);
    return { server: view(load(me, c.id)) };
  }));

  /** The server's icon. `iv` in the server's view changes whenever it does, so clients fetch it once per change. */
  app.get('/api/servers/icon', wrap(req => {
    const c = load(auth(req), req.query.server);
    return { iv: c.s.iv || 0, icon: c.s.iv ? db.serverIcon(c.id) : null };
  }));
  /** Sets the icon (a small square data: URL, shrunk by the client) or, with null, removes it. */
  app.post('/api/servers/icon', limiter(20), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'manageServer', 'change the icon');
    const icon = b.icon;
    if (icon !== null && (typeof icon !== 'string' || icon.length > ICON_CHARS || !ICON.test(icon))) throw bad('the icon must be a small JPEG, PNG or WebP image');
    db.setServerIcon(c.id, icon);
    c.s.iv = icon ? Math.max(Date.now(), (c.s.iv || 0) + 1) : 0;
    db.setServer(c.id, c.s);
    changed(c.id);
    return { server: view(load(me, c.id)) };
  }));

  app.post('/api/servers/delete', limiter(20), wrap(req => {
    const me = auth(req), c = load(me, (req.body || {}).server);
    if (c.owner !== me.id) throw new HttpError(403, 'only the server owner can delete it');
    const was = members(c.id).map(m => m.userId);
    dropVoice(c.id);
    db.deleteServer(c.id);
    for (const u of was) hub.push(u, { t: 'server', server: c.id, gone: true });
    return {};
  }));

  app.post('/api/servers/transfer', limiter(20), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    if (c.owner !== me.id) throw new HttpError(403, 'only the server owner can hand it over');
    const to = String(b.user || '');
    if (to === me.id || !db.serverMember(c.id, to)) throw new HttpError(404, 'they are not in this server');
    c.s.owner = to;
    db.setServer(c.id, c.s);
    changed(c.id);
    return {};
  }));

  /** The owner cannot walk away from members: they hand the server over or delete it. Alone, leaving deletes it. */
  app.post('/api/servers/leave', wrap(req => {
    const me = auth(req), c = load(me, (req.body || {}).server);
    if (c.owner === me.id && db.serverMemberCount(c.id) > 1) throw new HttpError(409, 'you own this server: hand it over to someone or delete it first');
    dropVoice(c.id, { user: me.id });
    db.leaveServer(c.id, me.id);
    markStale(c.id);
    if (db.server(c.id)) changed(c.id, [me.id]); else hub.push(me.id, { t: 'server', server: c.id, gone: true });
    return {};
  }));

  /* ---------------------------------------------------- invites */
  app.post('/api/servers/invite', limiter(30), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'invite', 'create invites');
    const hours = b.hours == null ? 24 * 7 : b.hours, uses = b.uses == null ? 0 : b.uses;
    if (!Number.isInteger(hours) || hours < 1 || hours > LIMITS.inviteHours) throw bad('an invite lasts 1 hour to ' + LIMITS.inviteHours / 24 + ' days');
    if (!Number.isInteger(uses) || uses < 0 || uses > LIMITS.inviteUses) throw bad('an invite has 1 to ' + LIMITS.inviteUses + ' uses, or 0 for no limit');
    const code = Array.from(crypto.randomBytes(8), x => CODE_CHARS[x % CODE_CHARS.length]).join('');
    const expires = Date.now() + hours * 3600 * 1000;
    // an encrypted server's keys, locked by the invite's second half (which never comes here)
    let blob = null;
    if (c.s.e2ee) {
      blob = b.blob;
      if (typeof blob !== 'string' || blob.length > BLOB_CHARS || !B64.test(blob)) throw bad('an invite to an encrypted server carries its keys');
    }
    db.createServerInvite(code, c.id, uses || 1e9, expires, blob);
    return { code: code.slice(0, 4) + '-' + code.slice(4), expires, uses };
  }));

  app.post('/api/servers/join', limiter(30), wrap(req => {
    const me = auth(req);
    const code = String((req.body || {}).code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16);
    const id = code.length === 8 && db.serverInvite(code);
    const s = id && db.server(id);
    if (!s) throw new HttpError(404, 'that invite is invalid or has expired');
    const blob = db.serverInviteBlob(code);
    if (db.serverMember(id, me.id)) return { server: view(load(me, id)), already: true, blob };
    if (s.bans.some(x => x.userId === me.id)) throw new HttpError(403, 'you are banned from this server');
    if (db.serverMemberCount(id) >= LIMITS.members) throw new HttpError(409, 'this server is full');
    if (db.serverIdsOf(me.id).length >= LIMITS.servers) throw new HttpError(507, 'you are in too many servers');
    db.tx(() => { db.putServerMember(id, { userId: me.id, joined: Date.now(), roles: [] }); db.useServerInvite(code); });
    changed(id);
    return { server: view(load(me, id)), blob };
  }));

  /* ---------------------------------------------------- members */
  /** Kicks a member, or with ban:true also keeps them from coming back. */
  app.post('/api/servers/kick', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server), ban = b.ban === true;
    need(c, ban ? 'ban' : 'kick', ban ? 'ban members' : 'kick members');
    const t = target(c, b.user), reason = text(b.reason, LIMITS.reason, 'a reason');
    dropVoice(c.id, { user: t.userId });
    db.leaveServer(c.id, t.userId);
    markStale(c.id);
    if (ban) {
      const s = db.server(c.id);
      s.bans = s.bans.filter(x => x.userId !== t.userId).concat({ userId: t.userId, by: me.id, ts: Date.now(), reason }).slice(-LIMITS.bans);
      db.setServer(c.id, s);
    }
    changed(c.id, [t.userId]);
    return {};
  }));

  app.post('/api/servers/unban', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'ban', 'ban members');
    const n = c.s.bans.length;
    c.s.bans = c.s.bans.filter(x => x.userId !== String(b.user || ''));
    if (c.s.bans.length === n) throw new HttpError(404, 'they are not banned');
    db.setServer(c.id, c.s);
    changed(c.id);
    return {};
  }));

  /** Gives a member a role or takes it away. */
  app.post('/api/servers/member-role', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'manageRoles', 'manage roles');
    if (typeof b.on !== 'boolean') throw bad('on must be true or false');
    const i = c.s.roles.findIndex(r => r.id === String(b.role || ''));
    if (i < 0 || c.s.roles[i].id === EVERYONE) throw new HttpError(404, 'there is no such role');
    if (!below(c, i)) throw new HttpError(403, 'you can only give out roles ranked below your own');
    const uid = String(b.user || '');
    const t = uid === me.id ? c.m : target(c, uid);
    const roles = t.roles.filter(r => r !== c.s.roles[i].id && c.s.roles.some(x => x.id === r));
    if (b.on) roles.push(c.s.roles[i].id);
    db.putServerMember(c.id, Object.assign({}, t, { roles }));
    changed(c.id);
    return {};
  }));

  /* ---------------------------------------------------- channels */
  /** op: create {name, kind} · update {channel, name?, readonly?, topic?} · delete {channel} · move {channel, dir} */
  app.post('/api/servers/channel', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'manageChannels', 'manage channels');
    const list = c.s.channels;
    let id;
    if (b.op === 'create') {
      if (b.kind !== 'text' && b.kind !== 'voice') throw bad('a channel is text or voice');
      if (list.length >= LIMITS.channels) throw new HttpError(409, 'a server can have at most ' + LIMITS.channels + ' channels');
      const ch = { id: id = newId(), name: chanName(b.name, b.kind), kind: b.kind };
      if (b.kind === 'text') Object.assign(ch, { readonly: b.readonly === true, topic: text(b.topic, LIMITS.topic, 'a topic') });
      list.push(ch);
    } else {
      const ch = channelOf(c, b.channel), i = list.indexOf(ch);
      id = ch.id;
      if (b.op === 'update') {
        if ('name' in b) ch.name = chanName(b.name, ch.kind);
        if ('readonly' in b) {
          if (ch.kind !== 'text') throw bad('only text channels can be read-only');
          if (typeof b.readonly !== 'boolean') throw bad('readonly must be true or false');
          ch.readonly = b.readonly;
        }
        if ('topic' in b) {
          if (ch.kind !== 'text') throw bad('only text channels have a topic');
          ch.topic = text(b.topic, LIMITS.topic, 'a topic');
        }
      } else if (b.op === 'delete') {
        list.splice(i, 1);
        if (ch.kind === 'voice') dropVoice(c.id, { channel: ch.id });
        else db.delChannelMsgs(c.id, ch.id);
      } else if (b.op === 'move') {
        const j = i + dir(b.dir);
        if (j < 0 || j >= list.length) throw bad('it cannot move further that way');
        [list[i], list[j]] = [list[j], list[i]];
      } else throw bad('op is create, update, delete or move');
    }
    db.setServer(c.id, c.s);
    changed(c.id);
    return { channel: id, server: view(load(me, c.id)) };
  }));

  /* ---------------------------------------------------- roles */
  /** op: create {name, color?, perms?} · update {role, name?, color?, perms?} · delete {role} · move {role, dir} */
  app.post('/api/servers/role', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    need(c, 'manageRoles', 'manage roles');
    const list = c.s.roles;
    const color = v => { if (v == null || v === '') return ''; if (typeof v !== 'string' || !COLOR.test(v)) throw bad('a role color looks like #f0a92a'); return v.toLowerCase(); };
    let id;
    if (b.op === 'create') {
      if (list.length >= LIMITS.roles) throw new HttpError(409, 'a server can have at most ' + LIMITS.roles + ' roles');
      const r = { id: id = newId(), name: nameIn(b.name, LIMITS.roleName, 'a role name'), color: color(b.color), perms: NONE() };
      if (b.perms != null) r.perms = permsIn(c, b.perms, r.perms);
      // new roles start at the bottom, just above @everyone
      list.splice(list.length - 1, 0, r);
    } else {
      const i = list.findIndex(r => r.id === String(b.role || ''));
      if (i < 0) throw new HttpError(404, 'there is no such role');
      const r = list[i], all = r.id === EVERYONE;
      id = r.id;
      // anyone who manages roles may set what @everyone can do; other roles must rank below their own
      if (!all && !below(c, i)) throw new HttpError(403, 'you can only change roles ranked below your own');
      if (b.op === 'update') {
        if ('name' in b) { if (all) throw bad('@everyone cannot be renamed'); r.name = nameIn(b.name, LIMITS.roleName, 'a role name'); }
        if ('color' in b) { if (all) throw bad('@everyone has no color'); r.color = color(b.color); }
        if ('perms' in b) r.perms = permsIn(c, b.perms, r.perms);
      } else if (b.op === 'delete') {
        if (all) throw bad('@everyone cannot be deleted');
        list.splice(i, 1);
        for (const m of members(c.id)) if (m.roles.includes(r.id)) db.putServerMember(c.id, Object.assign({}, m, { roles: m.roles.filter(x => x !== r.id) }));
      } else if (b.op === 'move') {
        const j = i + dir(b.dir);
        if (all || j < 0 || j >= list.length - 1) throw bad('it cannot move further that way');
        if (!below(c, j)) throw new HttpError(403, 'you can only move roles below your own');
        [list[i], list[j]] = [list[j], list[i]];
      } else throw bad('op is create, update, delete or move');
    }
    db.setServer(c.id, c.s);
    changed(c.id);
    return { role: id, server: view(load(me, c.id)) };
  }));

  /* ---------------------------------------------------- keys */
  /** The next key of an encrypted server. Only its checks come here: `check` is an HMAC
      of the new key, `auth` an HMAC of that under the previous key, so members can tell
      the key they are later handed is the one a member made. `epoch` is the current one
      plus 1; two browsers racing to replace the key get one 409. */
  app.post('/api/servers/rekey', limiter(60), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    if (!c.s.e2ee) throw bad('this server is not end-to-end encrypted');
    if (!(c.perms.kick || c.perms.ban || c.perms.manageServer)) throw new HttpError(403, 'you do not have permission to replace the key in this server');
    if (b.epoch !== c.s.epoch + 1) throw new HttpError(409, 'the key was already replaced');
    if (c.s.epoch >= MAX_EPOCHS) throw new HttpError(507, 'this server has replaced its key too many times');
    if (!CHECK.test(String(b.check || '')) || !CHECK.test(String(b.auth || ''))) throw bad('check and auth are 32 hex characters');
    c.s.epoch = b.epoch;
    c.s.checks[b.epoch] = { c: b.check, a: b.auth };
    c.s.epochBy = me.id;
    c.s.stale = false;
    db.setServer(c.id, c.s);
    changed(c.id);
    return { server: view(load(me, c.id)) };
  }));

  /* ---------------------------------------------------- messages */
  app.get('/api/servers/messages', wrap(req => {
    const me = auth(req), c = load(me, req.query.server), ch = channelOf(c, req.query.channel, 'text');
    if (!c.perms.view) throw new HttpError(403, 'you do not have permission to read messages in this server');
    const before = Number(req.query.before) > 0 ? Math.floor(Number(req.query.before)) : Number.MAX_SAFE_INTEGER;
    const rows = db.serverMsgs(c.id, ch.id, before, LIMITS.page + 1);
    const list = rows.slice(0, LIMITS.page).reverse(), users = new Map();
    for (const m of list) for (const u of [m.from, m.re && m.re.from]) if (u && !users.has(u)) users.set(u, who(u));
    return { msgs: list.map(m => m.enc ? { id: m.id, from: m.from, ts: m.ts, enc: m.enc, re: m.re } : { id: m.id, from: m.from, ts: m.ts, text: m.text, re: m.re }), more: rows.length > LIMITS.page, users: [...users.values()].filter(Boolean) };
  }));

  app.post('/api/servers/send', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server), ch = channelOf(c, b.channel, 'text');
    if (!c.perms.view || !c.perms.send) throw new HttpError(403, 'you do not have permission to send messages in this server');
    if (ch.readonly && !c.perms.sendReadonly) throw new HttpError(403, 'this channel is read-only');
    checkMute(me);
    // encrypted: only ciphertext under one of the server's keys (the reply's quote rides inside it)
    let t, enc;
    if (c.s.e2ee) {
      const e = b.enc;
      if (!e || typeof e !== 'object' || !Number.isInteger(e.n) || e.n < 1 || e.n > c.s.epoch ||
        typeof e.iv !== 'string' || e.iv.length !== 16 || !B64.test(e.iv) ||
        typeof e.ct !== 'string' || !e.ct || e.ct.length > ENC_CHARS || !B64.test(e.ct)) throw bad('this server is end-to-end encrypted: send the message sealed');
      enc = { n: e.n, iv: e.iv, ct: e.ct };
    } else {
      t = text(b.text, LIMITS.text, 'a message', true);
      if (!t) throw bad('the message is empty');
    }
    let re;
    if (b.re != null) {
      const o = Number.isSafeInteger(b.re) && db.serverMsg(c.id, b.re);
      if (o && o.channel === ch.id) re = enc ? { id: o.id, from: o.from } : { id: o.id, from: o.from, t: String(o.text || '').slice(0, 120) };
    }
    const body = Object.assign({ from: me.id }, enc ? { enc } : { text: t }, re ? { re } : {});
    const m = db.addServerMsg(c.id, ch.id, body);
    const msg = Object.assign({ id: m.id, from: me.id, ts: m.ts }, enc ? { enc } : { text: t }, { re });
    toReaders(c, { t: 'smsg', server: c.id, channel: ch.id, msg, user: who(me.id) });
    return { msg };
  }));

  /** Anyone can delete their own messages; deleting other people's takes the delete messages permission. */
  app.post('/api/servers/msg-delete', limiter(120), wrap(req => {
    const me = auth(req), b = req.body || {}, c = load(me, b.server);
    const m = Number.isSafeInteger(b.id) && db.serverMsg(c.id, b.id);
    if (!m) throw new HttpError(404, 'that message is gone');
    if (m.from !== me.id && !(c.perms.view && c.perms.deleteMsgs)) throw new HttpError(403, 'you can only delete your own messages here');
    db.delServerMsg(c.id, m.id);
    toReaders(c, { t: 'sdel', server: c.id, channel: m.channel, id: m.id });
    return {};
  }));

  /* ---------------------------------------------------- voice */
  /** Joins a voice channel ({server, channel}), leaving any other; {channel: null} leaves. Returns who is in it.
      A leave can name the channel it means (`was`), so one that arrives after a switch to another channel does nothing. */
  app.post('/api/servers/voice', limiter(60), wrap(req => {
    const me = auth(req), b = req.body || {};
    if (b.channel == null) {
      const v = voice.get(me.id);
      if (v && (b.was == null || v.channel === String(b.was))) setVoice(me.id, null);
      return { users: [] };
    }
    const c = load(me, b.server), ch = channelOf(c, b.channel, 'voice');
    if (!c.perms.connect) throw new HttpError(403, 'you do not have permission to join voice channels in this server');
    const here = usersIn(c.id, ch.id).filter(u => u !== me.id);
    if (here.length >= LIMITS.voice) throw new HttpError(409, 'this voice channel is full');
    clearTimeout(offTimers.get(me.id)); offTimers.delete(me.id);
    setVoice(me.id, c.id, ch.id);
    return { users: usersIn(c.id, ch.id) };
  }));

  /** A call signal over the socket, passed on only between two people in the same voice channel. */
  function signal(ws, m) {
    if (typeof m.to !== 'string' || m.to === ws.userId || !m.sig || typeof m.sig !== 'object' || Array.isArray(m.sig)) return;
    const now = Date.now();
    if (!ws.vs || now - ws.vs.at >= 1000) ws.vs = { at: now, n: 0 };
    if (++ws.vs.n > 60) return;
    const a = voice.get(ws.userId), z = voice.get(m.to);
    if (!a || !z || a.server !== z.server || a.channel !== z.channel || m.sig.chan !== a.channel) return;
    hub.push(m.to, { t: 'vsig', from: ws.userId, sig: m.sig });
  }
  const sameVoice = (a, b) => { const x = voice.get(a), y = voice.get(b); return !!x && !!y && x.server === y.server && x.channel === y.channel; };
  /** The last socket of someone in voice closed: they are taken out unless they are back within the grace. */
  function offline(userId) {
    if (!voice.has(userId)) return;
    clearTimeout(offTimers.get(userId));
    const t = setTimeout(() => { offTimers.delete(userId); if (!hub.online(userId)) setVoice(userId, null); }, grace);
    if (t.unref) t.unref();
    offTimers.set(userId, t);
  }
  /** An account was deleted: it is gone from voice, and the servers it was in hear about it. */
  function userGone(userId, serverIds) {
    setVoice(userId, null);
    for (const id of serverIds) if (db.server(id)) changed(id);
  }
  function stop() { for (const t of offTimers.values()) clearTimeout(t); offTimers.clear(); }

  return { signal, sameVoice, offline, userGone, stop };
}

module.exports = { mount, PERMS, LIMITS };
