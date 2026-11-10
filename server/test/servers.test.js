'use strict';
/**
 * Servers: channels, roles and permissions, invites, kicks and bans, and voice
 * channel signalling — the real client engine (lifted from client/index.html, as
 * in e2e.test.js) against a real server.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');
const { createServer } = require('../server');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'client', 'index.html'), 'utf8');
const core = html.split('/*<marmot-core>*/')[1].split('/*</marmot-core>*/')[0];
const { MarmotClient } = new Function(core + '\nreturn {MarmotClient};')();

const PASS = 'correct horse battery';
let srv, base, dataDir;
const clients = [];

function client() {
  const c = new MarmotClient({ WebSocket, iter: 300000 });
  c.setServer(base);
  clients.push(c);
  return c;
}
async function waitFor(fn, what, ms) {
  const end = Date.now() + (ms || 8000);
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for ' + what);
    await new Promise(r => setTimeout(r, 25));
  }
}
const live = c => waitFor(() => c.wsState === 'live', 'socket');
const rejects = (p, status, re) => assert.rejects(p, e => e.status === status && (!re || re.test(e.message)));
async function users(...names) {
  const out = names.map(() => client());
  await Promise.all(out.map((c, i) => c.signup(names[i], PASS)));
  await Promise.all(out.map(live));
  return out;
}
const textChan = (c, sid, name) => c.srv(sid).channels.find(x => x.kind === 'text' && (!name || x.name === name));
const role = (c, sid, name) => c.srv(sid).roles.find(r => r.name === name);

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-servers-'));
  const adminFile = path.join(dataDir, 'admin.json');
  fs.writeFileSync(adminFile, JSON.stringify({ admins: [], mods: {} }));
  srv = createServer({ dataDir, adminFile, key: Buffer.alloc(32, 7), authPerMinute: 1000, offlineGrace: 0, voiceGrace: 50 });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('create, invite, join, talk, history and read-only channels', async () => {
  const [own, mem, out] = await users('sv-own', 'sv-mem', 'sv-out');
  const s = await own.createServer('The Den', { e2ee: false });
  const sid = s.serverId;
  assert.equal(s.name, 'The Den');
  assert.deepEqual(s.channels.map(c => [c.name, c.kind]), [['general', 'text'], ['General', 'voice']]);
  assert.equal(s.roles.length, 1);
  assert.equal(s.roles[0].id, 'everyone');
  assert.equal(s.me.perms.admin, true, 'the owner can do everything');
  const general = textChan(own, sid).id;

  // outsiders can do nothing
  await rejects(out.api('GET', '/api/servers/messages?server=' + sid + '&channel=' + general), 404);
  await rejects(out.sendServer(sid, general, 'hi'), 404);

  const inv = await own.createInvite(sid, { hours: 1, uses: 1 });
  assert.match(inv.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  const joined = await mem.joinServer(inv.code.toLowerCase());
  assert.equal(joined.serverId, sid);
  assert.equal(joined.me.perms.send, true);
  assert.equal(joined.me.perms.deleteMsgs, false);
  // a one-use code is spent
  await rejects(out.joinServer(inv.code), 404, /invalid or has expired/);
  await waitFor(() => own.srv(sid).members === 2, 'member count pushed');

  // messages reach everyone who can read, live and in the history
  await mem.loadChannel(sid, general);
  await own.loadChannel(sid, general);
  const m1 = await own.sendServer(sid, general, 'hello @sv-mem');
  await waitFor(() => mem.chan(sid, general).msgs.some(m => m.id === m1.id), 'message pushed');
  assert.equal(mem.spingCount(sid, general), 1, 'a mention counts');
  assert.equal(mem.sunread(sid, general), true);
  mem.markRead(sid, general);
  assert.equal(mem.sunread(sid, general), false);
  assert.equal(mem.spingCount(sid), 0);
  const m2 = await mem.sendServer(sid, general, 'hi back', m1.id);
  assert.deepEqual(m2.re, { id: m1.id, from: own.me.userId, t: 'hello @sv-mem' });
  mem.schan.clear();
  await mem.loadChannel(sid, general);
  assert.deepEqual(mem.chan(sid, general).msgs.map(m => m.text), ['hello @sv-mem', 'hi back']);
  assert.equal(mem.username(own.me.userId), 'sv-own', 'authors come with the history');

  // history pages back
  for (let i = 0; i < 55; i++) await own.api('POST', '/api/servers/send', { server: sid, channel: general, text: 'n' + i });
  const pageA = client(); await pageA.login('sv-own', PASS);
  await pageA.loadChannel(sid, general);
  assert.equal(pageA.chan(sid, general).msgs.length, 50);
  assert.equal(pageA.chan(sid, general).more, true);
  await pageA.loadChannel(sid, general, true);
  assert.equal(pageA.chan(sid, general).msgs.length, 57);
  assert.equal(pageA.chan(sid, general).more, false);
  assert.equal(pageA.chan(sid, general).msgs[0].text, 'hello @sv-mem');

  // read-only: only those who may send in read-only channels post there
  const r = await pageA.serverOp('channel', { server: sid, op: 'create', name: 'Announcements Here', kind: 'text' });
  const ann = r.channel;
  assert.equal(textChan(pageA, sid, 'announcements-here').id, ann, 'text channel names read like Discord');
  await pageA.serverOp('channel', { server: sid, op: 'update', channel: ann, readonly: true, topic: 'news' });
  await waitFor(() => { const c = mem.srv(sid).channels.find(x => x.id === ann); return c && c.readonly; }, 'read-only pushed');
  await rejects(mem.sendServer(sid, ann, 'can I?'), 403, /read-only/);
  await pageA.sendServer(sid, ann, 'news!');
  // a role that may post in read-only channels
  const rr = await pageA.serverOp('role', { server: sid, op: 'create', name: 'Herald', color: '#ff8800', perms: { sendReadonly: true } });
  await pageA.serverOp('member-role', { server: sid, user: mem.me.userId, role: rr.role, on: true });
  await waitFor(() => mem.srv(sid).me.perms.sendReadonly, 'perm pushed');
  await mem.sendServer(sid, ann, 'heralding');
});

test('roles: hierarchy, grants limited to what you hold, admin, delete and view', async () => {
  const [own, mod, mem] = await users('rl-own', 'rl-mod', 'rl-mem');
  const sid = (await own.createServer('Roles')).serverId;
  const code = (await own.createInvite(sid)).code;
  await mod.joinServer(code); await mem.joinServer(code);
  const general = textChan(own, sid).id;

  const modR = (await own.serverOp('role', { server: sid, op: 'create', name: 'Mod', perms: { manageRoles: true, kick: true, deleteMsgs: true } })).role;
  const helperR = (await own.serverOp('role', { server: sid, op: 'create', name: 'Helper' })).role;
  // new roles go to the bottom: Helper is below Mod
  assert.deepEqual(own.srv(sid).roles.map(r => r.name), ['Mod', 'Helper', '@everyone']);
  await own.serverOp('member-role', { server: sid, user: mod.me.userId, role: modR, on: true });
  await waitFor(() => mod.srv(sid).me.perms.manageRoles, 'mod perms');

  // a mod manages roles below theirs, not their own or above
  await mod.serverOp('role', { server: sid, op: 'update', role: helperR, name: 'Helpers' });
  await rejects(mod.serverOp('role', { server: sid, op: 'update', role: modR, name: 'Boss' }), 403, /below your own/);
  await rejects(mod.serverOp('role', { server: sid, op: 'move', role: helperR, dir: -1 }), 403);
  // and cannot hand out what they do not hold
  await rejects(mod.serverOp('role', { server: sid, op: 'update', role: helperR, perms: { ban: true } }), 403, /do not have/);
  await mod.serverOp('role', { server: sid, op: 'update', role: helperR, perms: { kick: true } });
  await mod.serverOp('member-role', { server: sid, user: mem.me.userId, role: helperR, on: true });
  await rejects(mod.serverOp('member-role', { server: sid, user: mem.me.userId, role: modR, on: true }), 403);
  // ranks: the helper cannot kick the mod; nobody touches the owner
  await waitFor(() => mem.srv(sid).me.perms.kick, 'helper perms');
  await rejects(mem.serverOp('kick', { server: sid, user: mod.me.userId }), 403, /below you/);
  await rejects(mod.serverOp('kick', { server: sid, user: own.me.userId }), 403, /owner/);
  // @everyone is editable by anyone who manages roles, but not deletable
  await mod.serverOp('role', { server: sid, op: 'update', role: 'everyone', perms: { invite: false } });
  await rejects(mod.serverOp('role', { server: sid, op: 'delete', role: 'everyone' }), 400);
  await rejects(own.serverOp('role', { server: sid, op: 'delete', role: 'everyone' }), 400);

  // delete messages: own always, others' with the permission
  await mem.loadChannel(sid, general);
  const a = await own.sendServer(sid, general, 'owner says');
  const b = await mem.sendServer(sid, general, 'member says');
  await rejects(mem.deleteServerMsg(sid, general, a.id), 403);
  await mem.deleteServerMsg(sid, general, b.id);
  await mod.deleteServerMsg(sid, general, a.id);
  await waitFor(() => !mem.chan(sid, general).msgs.some(m => m.id === a.id), 'delete pushed');

  // read messages off for everyone: history and live messages stop, unless a role gives it back
  await own.serverOp('role', { server: sid, op: 'update', role: 'everyone', perms: { view: false } });
  await waitFor(() => !mem.srv(sid).me.perms.view, 'view off');
  await rejects(mem.loadChannel(sid, general), 403);
  await rejects(mem.api('GET', '/api/servers/messages?server=' + sid + '&channel=' + general), 403, /read messages/);
  await rejects(mem.sendServer(sid, general, 'blind'), 403);
  const seen = [];
  mem.on('smsg', (s, c, m) => seen.push(m.text));
  await own.sendServer(sid, general, 'secret');
  // administrator turns everything back on
  await own.serverOp('role', { server: sid, op: 'update', role: helperR, perms: { admin: true } });
  await waitFor(() => mem.srv(sid).me.perms.view && mem.srv(sid).me.perms.ban, 'admin perms');
  await own.sendServer(sid, general, 'visible');
  await waitFor(() => seen.includes('visible'), 'message after admin');
  assert.ok(!seen.includes('secret'), 'nothing reached someone who could not read');

  // deleting a role takes it off everyone
  await own.serverOp('role', { server: sid, op: 'delete', role: helperR });
  await waitFor(() => !mem.srv(sid).me.perms.view, 'role gone');
  assert.deepEqual(mem.srv(sid).me.roles, []);
});

test('kick, ban, unban, leaving, handing over and deleting', async () => {
  const [own, a, b] = await users('kb-own', 'kb-a', 'kb-b');
  const sid = (await own.createServer('Kicks')).serverId;
  const code = (await own.createInvite(sid)).code;
  await a.joinServer(code); await b.joinServer(code);

  await own.serverOp('kick', { server: sid, user: a.me.userId });
  await waitFor(() => !a.srv(sid), 'kicked member forgets the server');
  await a.joinServer(code);   // a kick is not a ban
  await own.serverOp('kick', { server: sid, user: a.me.userId, ban: true, reason: 'spam' });
  await waitFor(() => !a.srv(sid), 'banned member forgets the server');
  await rejects(a.joinServer(code), 403, /banned/);
  assert.deepEqual(own.srv(sid).bans.map(x => [x.username, x.reason]), [['kb-a', 'spam']]);
  await rejects(b.serverOp('unban', { server: sid, user: a.me.userId }), 403);
  await own.serverOp('unban', { server: sid, user: a.me.userId });
  await a.joinServer(code);

  // the owner cannot just leave; handing over works; then they can
  await rejects(own.leaveServer(sid), 409, /hand it over/);
  await own.serverOp('transfer', { server: sid, user: b.me.userId });
  await waitFor(() => b.srv(sid) && b.srv(sid).owner === b.me.userId, 'new owner');
  await rejects(own.deleteServer(sid), 403);
  await own.leaveServer(sid);
  assert.equal(own.srv(sid), null);
  await waitFor(() => b.srv(sid).members === 2, 'leave pushed');

  await b.deleteServer(sid);
  await waitFor(() => !a.srv(sid), 'deleted server pushed');
  await rejects(a.joinServer(code), 404);
});

test('channels: create, rename, move, delete takes its history', async () => {
  const [own, mem] = await users('ch-own', 'ch-mem');
  const sid = (await own.createServer('Chans')).serverId;
  await mem.joinServer((await own.createInvite(sid)).code);
  await rejects(mem.serverOp('channel', { server: sid, op: 'create', name: 'x', kind: 'text' }), 403, /manage channels/);
  const v = (await own.serverOp('channel', { server: sid, op: 'create', name: 'Gaming Room', kind: 'voice' })).channel;
  assert.equal(own.srv(sid).channels.find(c => c.id === v).name, 'Gaming Room', 'voice channels keep their names');
  await rejects(own.serverOp('channel', { server: sid, op: 'update', channel: v, readonly: true }), 400);
  await own.serverOp('channel', { server: sid, op: 'move', channel: v, dir: -1 });
  assert.deepEqual(own.srv(sid).channels.map(c => c.name), ['general', 'Gaming Room', 'General']);
  const general = textChan(own, sid).id;
  await own.sendServer(sid, general, 'gone soon');
  await own.serverOp('channel', { server: sid, op: 'delete', channel: general });
  await waitFor(() => !mem.srv(sid).channels.some(c => c.id === general), 'delete pushed');
  await rejects(mem.api('GET', '/api/servers/messages?server=' + sid + '&channel=' + general), 404);
  assert.equal(srv.db.raw.prepare('SELECT COUNT(*) n FROM server_msgs WHERE server_id = ?').get(sid).n, 0);
});

test('voice channels: who is in them, and signals only pass between people in the same one', async () => {
  const [a, b, c] = await users('vc-a', 'vc-b', 'vc-c');
  const sid = (await a.createServer('Voice')).serverId;
  const code = (await a.createInvite(sid)).code;
  await b.joinServer(code); await c.joinServer(code);
  const vch = a.srv(sid).channels.find(x => x.kind === 'voice').id;

  // joining is the server's part; the WebRTC side needs a browser, so it is driven by hand here
  const join = (x, ch) => x.api('POST', '/api/servers/voice', { server: sid, channel: ch });
  assert.deepEqual((await join(a, vch)).users, [a.me.userId]);
  assert.deepEqual((await join(b, vch)).users.sort(), [a.me.userId, b.me.userId].sort());
  await waitFor(() => c.voiceUsers(sid, vch).length === 2, 'voice list pushed');

  const got = new Map([[a, []], [b, []], [c, []]]);
  for (const x of [a, b, c]) x.voice._signal = (from, s, ts, via) => got.get(x).push({ from, s, via });
  const sig = { k: 'call', t: 'media', call: 'vc:' + vch, chan: vch, muted: true };
  await a._vsig(b.me.userId, sig);
  await waitFor(() => got.get(b).length === 1, 'signal relayed');
  assert.equal(got.get(b)[0].from, a.me.userId);
  assert.equal(got.get(b)[0].via, 'vsig');
  // c is not in the channel: nothing reaches them, and nothing from them gets through
  await a._vsig(c.me.userId, sig);
  await c._vsig(a.me.userId, sig);
  // a signal naming another channel is dropped too
  await a._vsig(b.me.userId, Object.assign({}, sig, { chan: 'ffffffffffff' }));
  await new Promise(r => setTimeout(r, 200));
  assert.equal(got.get(c).length, 0);
  assert.equal(got.get(a).length, 0);
  assert.equal(got.get(b).length, 1);

  // a late leave for another channel does nothing; a leave for this one does
  await b.api('POST', '/api/servers/voice', { channel: null, was: 'ffffffffffff' });
  assert.equal(a.voiceUsers(sid, vch).length, 2);
  await b.api('POST', '/api/servers/voice', { channel: null, was: vch });
  await waitFor(() => a.voiceUsers(sid, vch).length === 1, 'leave pushed');

  // losing the connection takes you out after the grace
  await join(b, vch);
  await waitFor(() => a.voiceUsers(sid, vch).length === 2, 'rejoin pushed');
  b._reset();
  await waitFor(() => a.voiceUsers(sid, vch).length === 1, 'dropped after disconnect');

  // the voice permission
  await a.serverOp('role', { server: sid, op: 'update', role: 'everyone', perms: { connect: false } });
  await rejects(join(c, vch), 403, /voice/);
});

test('a signal over the socket is never taken for a ratchet one, nor the other way round', async () => {
  const [a] = await users('vs-a');
  const v = a.voice, sent = [];
  a._vsig = (to, sig) => { sent.push(sig); return Promise.resolve(); };
  // a voice channel signal that came through the ratchet is ignored; an ordinary one through the socket is too
  v._signal('x'.repeat(32), { k: 'call', t: 'offer', call: 'vc:aaaaaaaaaaaa', chan: 'aaaaaaaaaaaa', sdp: 'v=0' }, Date.now());
  v._signal('x'.repeat(32), { k: 'call', t: 'offer', call: 'abc', sdp: 'v=0', ring: true }, Date.now(), 'vsig');
  assert.equal(v.call, null);
  assert.equal(sent.length, 0);
  // an offer for a voice channel this side is not in never rings: it is turned away
  v._signal('x'.repeat(32), { k: 'call', t: 'offer', call: 'vc:aaaaaaaaaaaa', chan: 'aaaaaaaaaaaa', sdp: 'v=0', ring: true }, Date.now(), 'vsig');
  assert.equal(v.call, null);
  assert.deepEqual(sent, [{ k: 'call', t: 'end', call: 'vc:aaaaaaaaaaaa', chan: 'aaaaaaaaaaaa' }]);
});

test('deleting an account takes it out of its servers', async () => {
  const [own, mem] = await users('dl-own', 'dl-mem');
  const sid = (await own.createServer('Gone')).serverId;
  await mem.joinServer((await own.createInvite(sid)).code);
  await waitFor(() => own.srv(sid).members === 2, 'joined');
  await mem.deleteAccount(PASS);
  await waitFor(() => own.srv(sid).members === 1, 'member gone');
  // the last member deleting their account deletes the server
  await own.deleteAccount(PASS);
  assert.equal(srv.db.server(sid), undefined);
});

test('server icons: set by whoever manages the server, fetched once per change, removed', async () => {
  const [own, bob] = await users('icon_own', 'icon_bob');
  const sid = (await own.createServer('Icons')).serverId;
  await bob.joinServer((await own.createInvite(sid)).code);
  assert.equal(own.srv(sid).iv, 0);
  assert.equal(bob.serverIcon(sid), null);
  const pic = 'data:image/png;base64,' + Buffer.from('not really a png').toString('base64');
  await rejects(bob.setServerIcon(sid, pic), 403);
  await rejects(own.setServerIcon(sid, 'data:text/html;base64,PGI+'), 400);
  await rejects(own.setServerIcon(sid, 'data:image/png;base64,' + 'A'.repeat(70000)), 400);
  await own.setServerIcon(sid, pic);
  assert.ok(own.srv(sid).iv > 0);
  assert.equal(own.serverIcon(sid), pic);
  // bob hears the server changed, and fetches the icon the first time it is asked for
  await waitFor(() => bob.srv(sid).iv === own.srv(sid).iv, 'the new icon version');
  bob.serverIcon(sid);
  assert.equal(await waitFor(() => bob.serverIcon(sid), 'the icon'), pic);
  await own.setServerIcon(sid, null);
  await waitFor(() => bob.srv(sid).iv === 0, 'the icon removed');
  assert.equal(bob.serverIcon(sid), null);
  const r = await bob.api('GET', '/api/servers/icon?server=' + sid);
  assert.equal(r.iv, 0);
  assert.equal(r.icon, null);
});

test('end-to-end encrypted servers: the server only ever holds ciphertext, and keys follow who is in', async () => {
  const [own, mem, late, kicked] = await users('e2-own', 'e2-mem', 'e2-late', 'e2-kicked');
  const s = await own.createServer('Vault');
  const sid = s.serverId, general = textChan(own, sid).id;
  assert.equal(s.e2ee, true, 'encrypted by default');
  assert.equal(s.epoch, 1);
  assert.equal(own.skeyState(sid), 'ok');

  // the invite's second half never goes to the server, and unlocks the key
  const inv = await own.createInvite(sid);
  assert.match(inv.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-7]{26}$/);
  await mem.joinServer(inv.code);
  assert.equal(mem.skeyState(sid), 'ok');
  await kicked.joinServer(inv.code);
  // a code without its second half lets you in, but not read
  const half = inv.code.split('-').slice(0, 2).join('-');
  const [blind] = await users('e2-blind');
  await blind.joinServer(half);
  assert.equal(blind.skeyState(sid), 'none');
  await rejects(blind.sendServer(sid, general, 'hello?'), undefined);

  // messages: plaintext only in the browsers
  await mem.loadChannel(sid, general);
  const m1 = await own.sendServer(sid, general, 'secret plans @e2-mem');
  await waitFor(() => mem.chan(sid, general).msgs.some(m => m.id === m1.id && m.text === 'secret plans @e2-mem'), 'message opened');
  assert.equal(mem.spingCount(sid, general), 1, 'mentions still count');
  const m2 = await mem.sendServer(sid, general, 'agreed', m1.id);
  assert.equal(m2.re.t, 'secret plans @e2-mem', 'the quote rides inside the ciphertext');
  const raw = await own.api('GET', '/api/servers/messages?server=' + sid + '&channel=' + general);
  assert.ok(raw.msgs.every(m => m.enc && m.text === undefined), 'the server hands out only ciphertext');
  assert.equal(raw.msgs[1].re.t, undefined, 'the server cannot quote');
  const stored = JSON.stringify(srv.db.serverMsgs(sid, general, Number.MAX_SAFE_INTEGER, 10));
  assert.ok(!stored.includes('secret plans') && !stored.includes('agreed'), 'nor does it store any plaintext');
  await rejects(own.api('POST', '/api/servers/send', { server: sid, channel: general, text: 'in the clear' }), 400, /encrypted/);
  // a message moved to another channel, or credited to someone else, does not open
  const forged = { id: 999, from: mem.me.userId, ts: Date.now(), enc: raw.msgs[0].enc };
  await own._sopen(sid, general, forged);
  assert.equal(forged.bad, true);

  // the server cannot hand out a key of its own: it has to match the chain
  assert.equal(await mem._takeKeys(sid, { 2: Buffer.alloc(32, 9).toString('base64') }, false), 0);

  // a kick makes the key stale; the owner's browser replaces it, and the others fetch the new one
  await own.serverOp('kick', { server: sid, user: kicked.me.userId });
  await waitFor(() => own.srv(sid).epoch === 2 && !own.srv(sid).stale, 'the key replaced');
  await waitFor(() => own.skeyState(sid) === 'ok', 'the new key saved');
  await waitFor(() => mem.srv(sid).epoch === 2, 'the new epoch pushed');
  await waitFor(() => mem.skeyState(sid) === 'ok', 'the new key fetched from a member', 15000);
  const m3 = await own.sendServer(sid, general, 'after the kick');
  assert.equal(m3.enc.n, 2);
  await waitFor(() => mem.chan(sid, general).msgs.some(m => m.id === m3.id && m.text === 'after the kick'), 'new-epoch message opened');
  // the kicked member never gets it: they hold only the old key, and are not a member
  assert.equal(await kicked._takeKeys(sid, {}, false), 0);
  assert.ok(!kicked._skeys(sid)[2]);

  // someone joining with an invite made before the change reads it all, old and new
  await late.joinServer(inv.code);
  await waitFor(() => late.skeyState(sid) === 'ok', 'the current key fetched', 15000);
  await late.loadChannel(sid, general);
  await waitFor(() => late.chan(sid, general).msgs.filter(m => !m.locked).length === 3, 'history opened');
  assert.deepEqual(late.chan(sid, general).msgs.map(m => m.text), ['secret plans @e2-mem', 'agreed', 'after the kick']);

  // only someone who can replace the key may, and only to the next epoch
  await rejects(mem.api('POST', '/api/servers/rekey', { server: sid, epoch: 3, check: 'a'.repeat(32), auth: 'b'.repeat(32) }), 403);
  await rejects(own.api('POST', '/api/servers/rekey', { server: sid, epoch: 9, check: 'a'.repeat(32), auth: 'b'.repeat(32) }), 409);
  // an unencrypted server says so in its view and takes plaintext
  const plain = await own.createServer('Open', { e2ee: false });
  assert.equal(plain.e2ee, false);
  assert.equal(plain.checks, undefined);
});
