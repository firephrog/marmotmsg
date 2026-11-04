'use strict';
/**
 * Group roles and the group tag: the real client engine (lifted from
 * client/index.html, as in e2e.test.js) against a real server.
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
async function befriend(a, b) {
  await a.requestFriend(b.me.username);
  await b.loadPeers();
  await b.peerAction('accept', a.me.userId);
  await a.loadPeers();
}
const rejects = (p, status, re) => assert.rejects(p, e => e.status === status && (!re || re.test(e.message)));
const texts = (c, conv) => c.thread(conv).filter(m => m.dir !== 'sys').map(m => m.text);

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-groups-'));
  const adminFile = path.join(dataDir, 'admin.json');
  fs.writeFileSync(adminFile, JSON.stringify({ admins: ['rootadmin'], mods: {} }));
  srv = createServer({ dataDir, adminFile, key: Buffer.alloc(32, 9), authPerMinute: 1000, offlineGrace: 0 });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('group roles: owner appoints mods, mods mute and kick below them, invite policy', async () => {
  const own = client(), mo = client(), mem = client(), out = client();
  await own.signup('own', PASS); await mo.signup('moe', PASS); await mem.signup('mem', PASS); await out.signup('out', PASS);
  await Promise.all([own, mo, mem, out].map(live));
  await befriend(own, mo); await befriend(own, mem); await befriend(mem, out);
  const gid = await own.createGroup('den', [mo.me.userId, mem.me.userId]);
  const conv = 'g:' + gid;
  await waitFor(() => mo.group(gid) && mem.group(gid), 'group');

  assert.equal(own.groupRole(gid), 'owner');
  assert.equal(own.groupRank(gid), 2);
  assert.equal(mem.groupRank(gid), 0);

  // only the owner makes mods
  await rejects(mem.setGroupMod(gid, mo.me.userId, true), 403, /owner/);
  await own.setGroupMod(gid, mo.me.userId, true);
  await waitFor(() => mem.groupRole(gid, mo.me.userId) === 'mod', 'mod pushed');

  // a mod cannot act on the owner, a member cannot act on anyone
  await rejects(mo.muteInGroup(gid, own.me.userId, 10), 403, /owner/);
  await rejects(mem.muteInGroup(gid, mo.me.userId, 10), 403, /moderators/);

  // a mute in the group: the server refuses what they say there, everyone else drops it too
  await mo.muteInGroup(gid, mem.me.userId, 60);
  await waitFor(() => mem.groupMuted(gid), 'mute pushed');
  await assert.rejects(mem.sendText(conv, 'let me talk'), /muted in this group/);
  // but a direct chat with a friend is unaffected
  await mem.sendText(own.me.userId, 'still here');
  await waitFor(() => texts(own, mem.me.userId).includes('still here'), 'dm while group-muted');
  await mo.muteInGroup(gid, mem.me.userId, null);
  await waitFor(() => !mem.groupMuted(gid), 'unmute pushed');
  await mem.sendText(conv, 'back');
  await waitFor(() => texts(own, conv).includes('back'), 'text after unmute');

  // invites limited to mods
  await rejects(mem.groupSettings(gid, { invite: 'mods' }), 403);
  await mo.groupSettings(gid, { invite: 'mods' });
  await waitFor(() => mem.group(gid).invite === 'mods', 'settings pushed');
  assert.equal(mem.canInvite(gid), false);
  await rejects(mem.inviteToGroup(gid, [out.me.userId]), 403, /moderators/);

  // kicks: a mod removes a member; the member is told
  await mo.kickFromGroup(gid, mem.me.userId);
  await waitFor(() => !mem.group(gid), 'kicked member loses the group');
  await waitFor(() => own.thread(conv).some(m => m.text === 'mem was removed by moe'), 'kick line');
  assert.ok(mem.thread(conv).some(m => m.text === 'you are no longer in this group'));

  // the owner leaving hands the group to the mod
  await own.leaveGroup(gid);
  await waitFor(() => mo.groupRole(gid) === 'owner', 'ownership passes');
});

test('group tags: off by default, friends-only or everyone, join or apply', async () => {
  const boss = client(), pal = client(), str = client();
  await boss.signup('boss', PASS); await pal.signup('pal', PASS); await str.signup('str', PASS);
  await Promise.all([boss, pal, str].map(live));
  await befriend(boss, pal);
  const gid = await boss.createGroup('club', []);

  // off: nothing to show
  assert.equal(boss.group(gid).tag.vis, 'off');
  await rejects(boss.showTag(gid), 409, /no tag/);
  await rejects(boss.groupSettings(gid, { tag: { vis: 'all' } }), 400, /text/);
  await rejects(boss.groupSettings(gid, { tag: { text: 'two words' } }), 400, /one word/);
  await rejects(boss.groupSettings(gid, { tag: { text: 'CLUBS' } }), 400, /at most 4/);
  await rejects(boss.groupSettings(gid, { tag: { text: 'CLUB', emoji: 'ab' } }), 400, /emoji/);
  await rejects(boss.groupSettings(gid, { tag: { text: 'CLUB', emoji: '🐀🐀' } }), 400, /emoji/);

  // friends only, join
  await boss.groupSettings(gid, { tag: { text: 'CLUB', emoji: '🐀', vis: 'friends', mode: 'join' } });
  await boss.showTag(gid);
  assert.equal(boss.myTag().text, 'CLUB');
  const seen = await waitFor(() => { const p = str.profile(boss.me.userId); return p && p.tag; }, 'tag on profile');
  assert.deepEqual([seen.text, seen.emoji, seen.vis, seen.mode], ['CLUB', '🐀', 'friends', 'join']);
  await rejects(str.joinByTag(gid, boss.me.userId), 403, /friends of boss/);
  await pal.joinByTag(gid, boss.me.userId);
  assert.ok(pal.group(gid));
  await waitFor(() => boss.thread('g:' + gid).some(m => m.text === 'pal joined through your group tag'), 'join line');

  // everyone, apply: a request with a reason waits for a mod
  await boss.groupSettings(gid, { tag: { vis: 'all', mode: 'apply' } });
  // str cannot reach boss, so nothing is pushed: opening the profile fetches it fresh
  assert.equal((await str.fetchProfile(boss.me.userId)).tag.mode, 'apply');
  await rejects(str.joinByTag(gid, boss.me.userId, ''), 400, /why/);
  const r = await str.joinByTag(gid, boss.me.userId, 'i like clubs');
  assert.equal(r.applied, true);
  assert.ok(str.applied.has(gid));
  assert.equal(str.group(gid), null);
  await waitFor(() => (boss.group(gid).apps || []).some(a => a.userId === str.me.userId && a.reason === 'i like clubs'), 'request reaches the owner');
  assert.equal(pal.group(gid).apps, undefined);   // members do not see requests
  await rejects(pal.answerApp(gid, str.me.userId, true), 403);
  await boss.answerApp(gid, str.me.userId, true);
  await waitFor(() => str.group(gid) && !str.applied.has(gid), 'let in');

  // turning the tag off takes it off profiles
  await boss.groupSettings(gid, { tag: { vis: 'off' } });
  await waitFor(() => { const p = pal.profile(boss.me.userId); return p && !p.tag; }, 'tag gone');
  await rejects(pal.api('POST', '/api/groups/join', { group: gid, via: boss.me.userId }), 404);
});
