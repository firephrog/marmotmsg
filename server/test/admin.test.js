'use strict';
/**
 * Moderation: the staff config, mutes, message removal, bans and IP bans,
 * with the real client engine against a real server (see e2e.test.js).
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
let srv, base, dataDir, adminFile;
const clients = [];

function client() {
  const c = new MarmotClient({ WebSocket, iter: 300000 });
  c.setServer(base);
  c.out = null;
  c.on('signedout', why => { c.out = why; });
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
async function befriend(a, b) {
  await a.requestFriend(b.me.username);
  await b.loadPeers();
  await b.peerAction('accept', a.me.userId);
  await a.loadPeers();
}
const rejects = (p, status, re) => assert.rejects(p, e => e.status === status && (!re || re.test(e.message)));

let boss, mod, alice, bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-admin-'));
  adminFile = path.join(dataDir, 'admin.json');
  srv = createServer({ dataDir, key: Buffer.alloc(32, 9), authPerMinute: 1000 });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
  boss = client(); mod = client(); alice = client(); bob = client();
  await boss.signup('FirePhrog', PASS);
  await mod.signup('modguy', PASS);
  await alice.signup('alice', PASS);
  await bob.signup('bob', PASS);
  await Promise.all([boss, mod, alice, bob].map(live));
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('the config is created with firephrog as admin, and nobody else is staff', async () => {
  assert.deepEqual(JSON.parse(fs.readFileSync(adminFile, 'utf8')), { admins: ['firephrog'], mods: {} });
  await boss.refreshStanding();
  assert.equal(boss.staff.role, 'admin');
  assert.ok(boss.can('ip_ban') && boss.can('purge'));
  await mod.refreshStanding();
  assert.equal(mod.staff, null);
  await rejects(mod.admin('GET', '/me'), 403, /staff only/);
});

test('admins appoint moderators with chosen permissions, but never admins', async () => {
  await boss.admin('POST', '/staff', { userId: mod.me.userId, perms: ['delete', 'mute_short'] });
  assert.deepEqual(JSON.parse(fs.readFileSync(adminFile, 'utf8')).mods, { modguy: ['mute_short', 'delete'] });
  // the push tells the new moderator straight away
  await waitFor(() => mod.can('delete'), 'mod to learn their role');
  assert.equal(mod.staff.role, 'mod');
  assert.equal(mod.can('ban'), false);

  await rejects(mod.admin('POST', '/staff', { userId: alice.me.userId, perms: ['delete'] }), 403, /admins only/);
  await rejects(boss.admin('POST', '/staff', { userId: alice.me.userId, perms: ['admin'] }), 400, /unknown permission/);
  const st = await boss.admin('GET', '/staff');
  assert.deepEqual(st.admins.map(a => a.username), ['FirePhrog']);
  assert.deepEqual(st.mods.map(m => [m.username, m.perms]), [['modguy', ['mute_short', 'delete']]]);

  // a hand edit to the file is picked up without a restart
  const cfg = JSON.parse(fs.readFileSync(adminFile, 'utf8'));
  cfg.mods.modguy.push('purge');
  fs.writeFileSync(adminFile, JSON.stringify(cfg));
  fs.utimesSync(adminFile, new Date(), new Date(Date.now() + 5000));
  await mod.refreshStanding();
  assert.ok(mod.can('purge'));
});

test('staff only act on people ranked below them', async () => {
  await rejects(mod.admin('POST', '/mute', { userId: boss.me.userId, minutes: 10 }), 403, /admins/);
  await rejects(boss.admin('POST', '/mute', { userId: boss.me.userId, minutes: 10 }), 400, /that is you/);
  await rejects(mod.admin('POST', '/ban', { userId: alice.me.userId }), 403, /permission/);
  await rejects(mod.admin('POST', '/ipban', { userId: alice.me.userId }), 403, /permission/);
});

test('a mute stops a user saying anything until it is lifted, and long mutes need their own permission', async () => {
  await befriend(alice, bob);
  await rejects(mod.admin('POST', '/mute', { userId: alice.me.userId, minutes: 8 * 24 * 60 }), 403, /longer than a week/);
  await rejects(mod.admin('POST', '/mute', { userId: alice.me.userId, permanent: true }), 403, /longer than a week/);
  const r = await mod.admin('POST', '/mute', { userId: alice.me.userId, minutes: 60, reason: 'spam' });
  assert.equal(r.user.mute.reason, 'spam');
  await waitFor(() => alice.muted(), 'alice to learn she is muted');
  // her friends see it too, to tag her in chats
  await waitFor(() => bob.isMuted(alice.me.userId), 'bob to see alice is muted');

  await rejects(alice.sendText(bob.me.userId, 'let me talk'), 403, /muted until/);
  // she still receives, and her receipts still go out
  await bob.sendText(alice.me.userId, 'hi alice');
  await waitFor(() => alice.thread(bob.me.userId).some(m => m.text === 'hi alice'), 'alice to receive');
  await waitFor(() => bob.thread(alice.me.userId).some(m => m.text === 'hi alice' && m.state === 'delivered'), 'the receipt');

  // an admin's permanent mute cannot be undone by a mod without mute_long
  await boss.admin('POST', '/mute', { userId: alice.me.userId, permanent: true });
  await rejects(mod.admin('POST', '/unmute', { userId: alice.me.userId }), 403, /longer than a week/);
  await boss.admin('POST', '/unmute', { userId: alice.me.userId });
  await waitFor(() => !alice.muted(), 'alice to be unmuted');
  await waitFor(() => !bob.isMuted(alice.me.userId), 'bob to see the mute lifted');
  await alice.sendText(bob.me.userId, 'back again');
  await waitFor(() => bob.thread(alice.me.userId).some(m => m.text === 'back again'), 'bob to receive');
});

test('moderators delete and purge messages for everyone in a chat they are in', async () => {
  await befriend(alice, mod);
  const gid = await alice.createGroup('lobby', [bob.me.userId, mod.me.userId]);
  await waitFor(() => mod.group(gid) && bob.group(gid), 'everyone to be in the group');
  // members see who is staff, to tag them in the chat
  assert.equal(bob.role(mod.me.userId), 'mod');
  assert.equal(bob.role(alice.me.userId), null);
  assert.equal(alice.role(mod.me.userId), 'mod');   // as a friend, too
  const conv = 'g:' + gid;
  const ids = [];
  for (const t of ['one', 'two', 'three']) ids.push(await alice.sendText(conv, t));
  const bad = await bob.sendText(conv, 'bob says');
  await waitFor(() => mod.thread(conv).filter(m => m.dir === 'in').length === 4, 'mod to have every message');

  await mod.modRemove(conv, [ids[0]]);
  const gone = c => { const m = c.get('msg:' + conv + ':' + ids[0]); return m && m.deleted && m.mod === 'modguy'; };
  await waitFor(() => gone(alice) && gone(bob) && gone(mod), 'the message to go for everyone');

  // a notice naming the wrong author blanks nothing
  await mod.admin('POST', '/delete', { conv, msgs: [{ id: bad, from: alice.me.userId }] });
  await new Promise(r => setTimeout(r, 300));
  assert.equal(bob.get('msg:' + conv + ':' + bad).deleted, undefined);

  await mod.modRemove(conv, [ids[1], ids[2], bad]);
  await waitFor(() => [ids[1], ids[2], bad].every(id => alice.get('msg:' + conv + ':' + id).deleted), 'the purge');

  // not in the chat, not their call
  const other = await bob.createGroup('elsewhere', []);
  await rejects(mod.admin('POST', '/delete', { conv: 'g:' + other, msgs: [{ id: 'x', from: bob.me.userId }] }), 404);
  // messages from the admin are off limits to a mod
  await rejects(mod.admin('POST', '/delete', { conv: boss.me.userId, msgs: [{ id: 'x', from: boss.me.userId }] }), 403);
});

test('staff run commands from a chat, and nothing is sent to it', async () => {
  const conv = bob.me.userId;   // boss is not bob's friend: commands work in any chat
  const r = await boss.runCommand(conv, '/mute 1w @alice "spamming the lobby"');
  assert.match(r.text, /muted alice for 1 week — spamming the lobby/);
  await waitFor(() => alice.muted(), 'alice to be muted');
  const m = srv.db.mute(alice.me.userId);
  assert.equal(m.reason, 'spamming the lobby');
  assert.ok(Math.abs(m.until - Date.now() - 7 * 864e5) < 60000);
  await boss.runCommand(conv, '/unmute @alice');
  await waitFor(() => !alice.muted(), 'alice to be unmuted');

  await assert.rejects(boss.runCommand(conv, '/mute @alice'), /for how long/);
  await assert.rejects(boss.runCommand(conv, '/ban'), /say who/);
  await assert.rejects(boss.runCommand(conv, '/ban @nobody_here'), /no such user/);
  await assert.rejects(alice.runCommand(conv, '/ban @bob'), /only staff/);
  // a mod's command is held to their permissions like the panel is
  await assert.rejects(mod.runCommand(conv, '/ban @alice'), /permission/);
  assert.equal(await boss.runCommand(conv, 'just a message'), null);
  assert.deepEqual(await alice.runCommand(conv, '/help'), { help: true });

  const dave = client();
  await dave.signup('dave', PASS);
  assert.match((await boss.runCommand(conv, '/ban @dave "alt account"')).text, /banned dave/);
  assert.equal(srv.db.userRowByName('dave'), undefined);
});

test('@username pings are picked out of messages', async () => {
  assert.equal(bob.pings('hey @BOB, look'), true);
  assert.equal(bob.pings('mail bob@example.com'), false);
  assert.equal(bob.pings('@bobby'), false);
  assert.equal(bob.pings('see you @bob.'), true);
  // a ping that arrives marks the chat
  await alice.sendText(bob.me.userId, 'ping @bob');
  await waitFor(() => bob.pinged.has(alice.me.userId), 'the chat to be marked');
});

test('the log records what staff did', async () => {
  const { log } = await boss.admin('GET', '/log');
  const acts = log.map(e => e.action);
  for (const a of ['mod', 'mute', 'unmute', 'delete', 'purge']) assert.ok(acts.includes(a), a);
  await rejects(mod.admin('GET', '/log'), 403, /admins only/);
});

test('a ban deletes the account and signs it out', async () => {
  const carol = client();
  await carol.signup('carol', PASS);
  await live(carol);
  await boss.admin('POST', '/ban', { userId: carol.me.userId, reason: 'spam' });
  await waitFor(() => carol.out, 'carol to be signed out');
  assert.match(carol.out, /removed by a moderator/);
  assert.equal(srv.db.userRowByName('carol'), undefined);
});

test('a moderator who deletes their account loses the appointment', async () => {
  const temp = client();
  await temp.signup('tempmod', PASS);
  await boss.admin('POST', '/staff', { userId: temp.me.userId, perms: ['delete'] });
  await temp.deleteAccount(PASS);
  assert.equal(JSON.parse(fs.readFileSync(adminFile, 'utf8')).mods.tempmod, undefined);
});

test('an IP ban signs the user out and refuses their address', async () => {
  // every test client shares 127.0.0.1, so this goes last
  const r = await boss.admin('POST', '/ipban', { userId: bob.me.userId, reason: 'evading' });
  assert.equal(r.user.ipBanned, true);
  await waitFor(() => bob.out, 'bob to be signed out');
  const res = await fetch(base + '/api/health');
  assert.equal(res.status, 403);
  assert.equal((await res.json()).banned, true);
  const [ban] = srv.db.ipBans();
  assert.equal(ban.ip, '127.0.0.1');
  srv.db.unbanIp(ban.id);
  assert.equal((await fetch(base + '/api/health')).status, 200);
});
