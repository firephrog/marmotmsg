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

test('sender keys: one ciphertext per group message, fanned out, rotated when someone leaves', async () => {
  const a = client(), b = client(), c = client(), x = client();
  await a.signup('ska', PASS); await b.signup('skb', PASS); await c.signup('skc', PASS); await x.signup('skx', PASS);
  await Promise.all([a, b, c, x].map(live));
  await befriend(a, b); await befriend(a, c); await befriend(a, x);
  const gid = await a.createGroup('keys', [b.me.userId, c.me.userId]);
  const conv = 'g:' + gid;
  await waitFor(() => b.group(gid) && c.group(gid), 'group');

  // watch what a commits
  const commits = [];
  const api = a.api.bind(a);
  a.api = (m, p, body) => { if (p === '/api/commit') commits.push(body); return api(m, p, body); };
  const sends = () => commits.flatMap(x => x.send || []);

  commits.length = 0;
  await a.sendText(conv, 'first');
  await waitFor(() => texts(b, conv).includes('first') && texts(c, conv).includes('first'), 'first message');
  // the group message itself is a single envelope for both members
  const shared = sends().filter(s => Array.isArray(s.to));
  assert.equal(shared.length, 1);
  assert.deepEqual([...shared[0].to].sort(), [b.me.userId, c.me.userId].sort());
  const env = JSON.parse(shared[0].payload);
  assert.equal(env.v, 2); assert.equal(env.g, gid); assert.ok(Number.isInteger(env.n));
  assert.ok(!/first/.test(shared[0].payload));

  // the key went out once: the next message is nothing but the one shared envelope
  commits.length = 0;
  await a.sendText(conv, 'second');
  await waitFor(() => texts(b, conv).includes('second') && texts(c, conv).includes('second'), 'second message');
  const skdmMsgs = sends().filter(s => !Array.isArray(s.to) && s.g === gid);
  assert.equal(skdmMsgs.length, 0);
  assert.equal(JSON.parse(sends().find(s => Array.isArray(s.to)).payload).n, env.n + 1);
  // receipts still come back pairwise
  await waitFor(() => { const m = a.thread(conv).find(m => m.text === 'second'); return m && (m.got || []).length === 2; }, 'receipts');

  // b and c are not friends, yet they read each other through the group
  await c.sendText(conv, 'from c');
  await waitFor(() => texts(b, conv).includes('from c') && texts(a, conv).includes('from c'), 'c to the group');

  // the server only fans out to members of the named group
  await rejects(a.api('POST', '/api/commit', { send: [{ to: [x.me.userId], payload: '{}', g: gid }] }), 404);
  await rejects(a.api('POST', '/api/commit', { send: [{ to: [b.me.userId], payload: '{}' }] }), 400, /name its group/);
  await rejects(x.api('POST', '/api/commit', { send: [{ to: [a.me.userId], payload: '{}', g: gid }] }), 404);

  // c is removed: a's next message is under a new key c never gets
  const kid = a.get('skout:' + gid).kid;
  await a.kickFromGroup(gid, c.me.userId);
  await waitFor(() => !c.group(gid), 'c removed');
  commits.length = 0;
  await a.sendText(conv, 'after c');
  await waitFor(() => texts(b, conv).includes('after c'), 'message after removal');
  const now = a.get('skout:' + gid);
  assert.notEqual(now.kid, kid);
  assert.deepEqual(now.sent, [b.me.userId]);
  assert.ok(sends().every(s => s.to !== c.me.userId && !(Array.isArray(s.to) && s.to.includes(c.me.userId))));
  assert.ok(!texts(c, conv).includes('after c'));

  // b loses a's key: the message cannot be read, b asks, and a's next one carries the key again
  b._del('skin:' + gid + ':' + a.me.userId);
  await a.sendText(conv, 'lost');
  await waitFor(() => b.thread(conv).some(m => m.dir === 'sys' && /could not be decrypted \(no key/.test(m.text)), 'undecryptable line');
  await waitFor(() => !a.get('skout:' + gid).sent.includes(b.me.userId), 'key request reaches a');
  await a.sendText(conv, 'found');
  await waitFor(() => texts(b, conv).includes('found'), 'readable again');
});

test('a client older than Sender Keys is told to update when it sends in a group', async () => {
  const a = client(), b = client();
  await a.signup('olda', PASS); await b.signup('oldb', PASS);
  await Promise.all([a, b].map(live));
  await befriend(a, b);
  const gid = await a.createGroup('', [b.me.userId]);
  // what a 0.6.2 client sends: one pairwise copy per member, labelled with the group, and no protocol header
  const old = body => fetch(base + '/api/commit', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + a.token }, body: JSON.stringify(body) })
    .then(async r => ({ status: r.status, body: await r.json() }));
  const r = await old({ send: [{ to: b.me.userId, payload: '{}', optional: true, say: true, g: gid }] });
  assert.equal(r.status, 426);
  assert.equal(r.body.error, 'Your client is using the old group chat protocol, please update your client');
  assert.equal(r.body.outdated, true);
  // it can still talk outside groups
  assert.equal((await old({ send: [{ to: b.me.userId, payload: '{}' }] })).status, 200);

  // a current client is told the same way if the server ever needs a newer protocol
  const seen = [];
  a.on('outdated', m => seen.push(m));
  const prev = globalThis.fetch;
  globalThis.fetch = (u, o) => prev(u, Object.assign({}, o, { headers: Object.assign({}, o.headers, { 'X-Marmot-Proto': '1' }) }));
  try { await assert.rejects(a.sendText('g:' + gid, 'hello'), /old group chat protocol/); }
  finally { globalThis.fetch = prev; }
  assert.deepEqual(seen, ['Your client is using the old group chat protocol, please update your client']);
  await a.sendText('g:' + gid, 'hello');
  await waitFor(() => texts(b, 'g:' + gid).includes('hello'), 'current client sends');
});
