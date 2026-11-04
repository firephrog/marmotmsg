'use strict';
/**
 * Profiles, presence and username changes: the real client engine (lifted from
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
let srv, base, dataDir, adminFile;
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

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-profile-'));
  adminFile = path.join(dataDir, 'admin.json');
  fs.writeFileSync(adminFile, JSON.stringify({ admins: ['rootadmin'], mods: { helper: ['mute_short'] } }));
  srv = createServer({ dataDir, adminFile, key: Buffer.alloc(32, 5), authPerMinute: 1000, offlineGrace: 0 });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('profiles: set, cleaned up, seen by friends, pushed when they change', async () => {
  const ann = client(), ben = client();
  await ann.signup('ann', PASS);
  await ben.signup('ben', PASS);
  await Promise.all([live(ann), live(ben)]);
  await befriend(ann, ben);

  assert.equal(ben.displayName(ann.me.userId), 'ann');
  const p = await ann.setProfile({ display: '  Ann ‮Lee\n ', bio: 'line one\r\n\n\n\nline two', status: 'on a train 🚆', accent: '#3E63DD' });
  // bidi overrides and line breaks out of the name, runs of blank lines squeezed in the bio
  assert.deepEqual(p, { display: 'Ann Lee', bio: 'line one\n\nline two', status: 'on a train 🚆', accent: '#3e63dd' });

  // ben hears about it over the socket: the name and status straight away, the rest on request
  await waitFor(() => ben.displayName(ann.me.userId) === 'Ann Lee', 'display name push');
  assert.equal(ben.status(ann.me.userId), 'on a train 🚆');
  assert.equal(ben.username(ann.me.userId), 'ann');
  assert.equal(ben.profile(ann.me.userId), null);   // not fetched yet
  const full = await waitFor(() => ben.profile(ann.me.userId), 'profile fetch');
  assert.equal(full.bio, 'line one\n\nline two');
  assert.equal(full.accent, '#3e63dd');
  assert.ok(full.created > 0);

  // partial updates keep the rest; the version moves, so ben fetches again
  await ann.setProfile({ status: '' });
  await waitFor(() => ben.status(ann.me.userId) === '', 'status cleared');
  await waitFor(() => { const x = ben.profile(ann.me.userId); return x && x.status === '' && x.bio === 'line one\n\nline two'; }, 'refetch');

  await rejects(ann.setProfile({ display: 'x'.repeat(33) }), 400, /at most 32/);
  await rejects(ann.setProfile({ accent: 'red' }), 400, /accent/);
  await rejects(ann.setProfile({ bio: 7 }), 400, /text/);

  // a fresh sign-in gets its own profile back
  const again = client();
  await again.login('ann', PASS);
  assert.equal(again.myProfile.display, 'Ann Lee');
  assert.equal(again.displayName(again.me.userId), 'Ann Lee');
});

test('presence: online, idle, do not disturb, invisible and offline, only for people who can reach you', async () => {
  const cat = client(), dan = client(), eve = client();
  await cat.signup('cat', PASS);
  await dan.signup('dan', PASS);
  await eve.signup('eve', PASS);
  await Promise.all([live(cat), live(dan), live(eve)]);
  await befriend(cat, dan);
  const catId = cat.me.userId;

  assert.equal(dan.presence(catId), 'online');
  assert.equal(cat.presence(catId), 'online');

  cat.setIdle(true);
  await waitFor(() => dan.presence(catId) === 'idle', 'idle');
  cat.setIdle(false);
  await waitFor(() => dan.presence(catId) === 'online', 'back from idle');

  await cat.setPresence('dnd');
  await waitFor(() => dan.presence(catId) === 'dnd', 'dnd');
  assert.equal(cat.presence(catId), 'dnd');
  await cat.setPresence('invisible');
  await waitFor(() => dan.presence(catId) === 'offline', 'invisible looks offline');
  assert.equal(cat.presence(catId), 'invisible');
  await rejects(cat.setPresence('away'), undefined);
  await cat.setPresence('auto');
  await waitFor(() => dan.presence(catId) === 'online', 'visible again');

  // a stranger sees the name but never the presence, in a lookup or a profile
  await eve.pinUser('cat');
  const view = (await eve.api('GET', '/api/profile/' + catId)).user;
  assert.equal(view.pr, null);
  assert.equal(eve.presence(catId), null);
  // and a stranger's socket is never told when it moves
  let told = false;
  eve.ws.addEventListener('message', ev => { if (JSON.parse(ev.data).t === 'presence') told = true; });

  // signing out (closing the socket) is offline, for those who can see
  cat._reset();
  await waitFor(() => dan.presence(catId) === 'offline', 'offline');
  assert.equal(told, false);

  // a fresh login starts online; the mode chosen earlier sticks
  const cat2 = client();
  await cat2.login('cat', PASS);
  await live(cat2);
  await waitFor(() => dan.presence(catId) === 'online', 'online again');
  await cat2.setPresence('dnd');
  const cat3 = client();
  await cat3.login('cat', PASS);
  assert.equal(cat3.presenceMode, 'dnd');
  await live(cat3);
  await waitFor(() => dan.presence(catId) === 'dnd', 'dnd after login');

  // unfriending: the peers list no longer carries it
  await cat3.peerAction('remove', dan.me.userId);
  await waitFor(() => dan.presence(catId) === null, 'presence hidden after unfriend');
});

test('changing a username keeps friends and chats, and takes the password', async () => {
  const fay = client(), gus = client(), hal = client();
  await fay.signup('fay', PASS);
  await gus.signup('gus', PASS);
  await hal.signup('hal', PASS);
  await Promise.all([live(fay), live(gus)]);
  await befriend(fay, gus);
  await fay.sendText(gus.me.userId, 'hi gus');
  await waitFor(() => gus.thread(fay.me.userId).some(m => m.text === 'hi gus'), 'message');

  await rejects(fay.rename('fay2', 'wrong password!'), 403, /wrong password/);
  assert.ok(fay.token, 'a wrong password does not sign out');
  await rejects(fay.rename('hal', PASS), 409, /taken/);
  await rejects(fay.rename('HAL', PASS), 409, /taken/);
  await rejects(fay.rename('no spaces', PASS), 400);
  await rejects(fay.rename('helper', PASS), 409, /reserved/);     // a moderator in the config, not yet signed up
  await rejects(fay.rename('RootAdmin', PASS), 409, /reserved/);

  assert.equal(await fay.rename('Faye', PASS), 'Faye');
  assert.equal(fay.me.username, 'Faye');
  await waitFor(() => gus.username(fay.me.userId) === 'Faye', 'rename push');
  assert.equal(gus.displayName(fay.me.userId), 'Faye');
  // case-only changes are allowed
  assert.equal(await fay.rename('faye', PASS), 'faye');

  // same account, same keys, same friendship: messages still flow both ways
  await gus.sendText(fay.me.userId, 'nice name');
  await waitFor(() => fay.thread(gus.me.userId).some(m => m.text === 'nice name'), 'message after rename');
  assert.equal(gus.relation(fay.me.userId), 'friend');

  // the old name is free, and the new one logs in
  assert.equal((await hal.api('GET', '/api/available?username=fay')).free, true);
  await rejects(client().login('fay', PASS), 404);
  const fayId = fay.me.userId, back = client();
  await back.login('faye', PASS);   // signs the first device out
  assert.equal(back.me.userId, fayId);
  assert.ok(back.thread(gus.me.userId).some(m => m.text === 'nice name'));
});

test('staff and renames: admins cannot, a moderator keeps their permissions under the new name', async () => {
  const root = client(), helper = client();
  await root.signup('rootadmin', PASS);
  await helper.signup('helper', PASS);
  assert.equal(srv.staff.of('helper').role, 'mod');
  await rejects(root.rename('newroot', PASS), 403, /server config/);

  await helper.rename('helper2', PASS);
  assert.equal(srv.staff.of('helper'), null);
  assert.deepEqual(srv.staff.of('helper2'), { role: 'mod', perms: ['mute_short'] });
  // the rename is in the moderation log
  const log = srv.db.logs(5);
  assert.ok(log.some(e => e.action === 'rename' && e.by === 'helper2' && e.target === 'helper'));
});
