'use strict';
/**
 * End-to-end tests: the real client engine (lifted verbatim from the
 * <marmot-core> section of client/index.html) talking to a real server over
 * HTTP and WebSocket, backed by a throwaway database.
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
const { MarmotClient, Ratchet, Acct, Tx } = new Function(core + '\nreturn {MarmotClient,Ratchet,Acct,Tx};')();

const PASS = 'correct horse battery';
const ITER = 300000;   // the server's floor; real clients use 600k
let srv, base, dataDir;
const clients = [];

function client(opts) {
  const c = new MarmotClient(Object.assign({ WebSocket, iter: ITER }, opts));
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
const texts = (c, peer) => c.thread(peer).filter(m => m.dir !== 'sys').map(m => m.text);
const live = c => waitFor(() => c.wsState === 'live', 'socket');
/** a asks b by username and b accepts; returns b's user id. */
async function befriend(a, b, name) {
  const p = await a.requestFriend(name || b.me.username);
  assert.equal(p.state, 'outgoing');
  await b.loadPeers();
  await b.peerAction('accept', a.me.userId);
  await a.loadPeers();
  assert.equal(a.relation(b.me.userId), 'friend');
  return p.userId;
}

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-test-'));
  srv = createServer({ dataDir, key: Buffer.alloc(32, 7), authPerMinute: 1000 });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('signup, first contact, delivery receipts and replies', async () => {
  const alice = client(), bob = client();
  await alice.signup('alice', PASS);
  await bob.signup('Bob', PASS);
  await Promise.all([live(alice), live(bob)]);
  assert.equal(srv.db.prekeyCount(bob.me.userId), 50);

  const bobId = await befriend(alice, bob, 'bob');      // lookup is case-insensitive
  assert.equal(bobId, bob.me.userId);
  await alice.sendText(bobId, 'hello bob');

  await waitFor(() => texts(bob, alice.me.userId).length === 1, 'bob to receive');
  assert.deepEqual(texts(bob, alice.me.userId), ['hello bob']);
  assert.equal(bob.displayName(alice.me.userId), 'alice');
  // the handshake consumed exactly one of bob's one-time prekeys, and bob deleted its private half
  assert.equal(srv.db.prekeyCount(bob.me.userId), 49);
  assert.equal([...bob.recs.keys()].filter(k => k.startsWith('opk:')).length, 49);

  await waitFor(() => alice.thread(bobId)[0].state === 'delivered', 'receipt');
  assert.equal(alice.sessionState(bobId), 'established');

  // several ratchet turns in both directions
  for (let i = 0; i < 3; i++) {
    await bob.sendText(alice.me.userId, 'reply ' + i);
    await alice.sendText(bobId, 'again ' + i);
  }
  await waitFor(() => texts(alice, bobId).length === 7 && texts(bob, alice.me.userId).length === 7, 'all messages');
  assert.deepEqual(texts(bob, alice.me.userId), ['hello bob', 'reply 0', 'again 0', 'reply 1', 'again 1', 'reply 2', 'again 2']);
  assert.equal(bob.unread.get(alice.me.userId), 4);

  // both sides compute the same safety number
  assert.equal(await alice.safetyNumber(bobId), await bob.safetyNumber(alice.me.userId));
  assert.match(await alice.safetyNumber(bobId), /^(\d{5} ){11}\d{5}$/);
});

test('offline delivery, and history + ratchet survive signing in on a new device', async () => {
  const carol = client(), dave = client();
  await carol.signup('carol', PASS);
  await dave.signup('dave', PASS);
  const daveId = await befriend(carol, dave);
  await carol.sendText(daveId, 'one');
  await waitFor(() => texts(dave, carol.me.userId).length === 1, 'dave online receive');

  dave._reset();                                        // dave closes the tab
  await carol.sendText(daveId, 'two (while you were away)');
  await carol.sendText(daveId, 'three');

  const dave2 = client();
  await dave2.login('dave', PASS);
  assert.equal(dave2.me.userId, daveId);
  await waitFor(() => texts(dave2, carol.me.userId).length === 3, 'mailbox drain on new device');
  assert.deepEqual(texts(dave2, carol.me.userId), ['one', 'two (while you were away)', 'three']);

  // the restored ratchet keeps working in both directions
  await dave2.sendText(carol.me.userId, 'back');
  await waitFor(() => texts(carol, daveId).includes('back'), 'carol receives from new device');
  await waitFor(() => carol.thread(daveId).every(m => m.dir !== 'out' || m.state === 'delivered'), 'all delivered');

  // signing in on a third device revokes the second
  let reason = null;
  dave2.on('signedout', r => { reason = r; });
  const dave3 = client();
  await dave3.login('dave', PASS);
  await waitFor(() => reason, 'revocation');
  assert.match(reason, /another device/);
  assert.equal(dave2.token, null);

  // resume (tab reload) from the saved session
  const saved = dave3.session();
  const dave4 = client();
  await dave4.resume(saved);
  assert.deepEqual(texts(dave4, carol.me.userId), ['one', 'two (while you were away)', 'three', 'back']);
});

test('simultaneous first messages converge on one session', async () => {
  const erin = client(), finn = client();
  await erin.signup('erin', PASS);
  await finn.signup('finn', PASS);
  await Promise.all([live(erin), live(finn)]);
  const finnId = await befriend(erin, finn), erinId = erin.me.userId;
  await Promise.all([erin.sendText(finnId, 'erin first'), finn.sendText(erinId, 'finn first')]);
  await waitFor(() => texts(erin, finnId).length === 2 && texts(finn, erinId).length === 2, 'crossed handshakes');
  for (let i = 0; i < 3; i++) {
    await erin.sendText(finnId, 'e' + i);
    await finn.sendText(erinId, 'f' + i);
  }
  await waitFor(() => texts(erin, finnId).length === 8 && texts(finn, erinId).length === 8, 'post-convergence traffic');
  const sys = [...erin.thread(finnId), ...finn.thread(erinId)].filter(m => m.dir === 'sys');
  assert.deepEqual(sys, [], 'no decryption failures');
});

test('wrong password, taken usernames and weak passwords are refused', async () => {
  const g = client();
  await assert.rejects(g.login('alice', 'not the password'), /wrong username or password/);
  await assert.rejects(client().signup('ALICE', PASS), /taken/);
  await assert.rejects(client().signup('newuser', 'short'), /at least 10/);
  await assert.rejects(client().signup('x', PASS), /3-24/);
  await assert.rejects(client().login('nobody-here', PASS), /no such account/);
});

test('ratchet: out-of-order delivery, tampering, replayed handshakes', async () => {
  const mk = async () => {
    const id = await Acct.newIdentity();
    return { userId: await Acct.userId(id.ik.pub, id.sk.pub), ik: id.ik, sk: id.sk, spk: id.spk };
  };
  const a = await mk(), b = await mk();
  const [opk] = await Acct.opks(1, 1);
  const bundle = { ik: b.ik.pub, sk: b.sk.pub, spk: { id: 1, pub: b.spk.pub, sig: b.spk.sig }, opk: { id: 1, pub: opk.pub } };
  let ra = Ratchet.install(Ratchet.empty(), await Ratchet.initiate(a, bundle));
  const envs = [];
  for (let i = 0; i < 4; i++) { const o = await Ratchet.encrypt(ra, { n: i }); ra = o.rec; envs.push(o.env); }
  const ctx = { me: b, peerId: a.userId, spk: id => (id === 1 ? b.spk : null), opk: id => (id === 1 ? opk : null) };

  let rb = Ratchet.empty();
  const got = [];
  for (const i of [2, 0, 3, 1]) { const o = await Ratchet.decrypt(rb, envs[i], ctx); rb = o.rec; got.push(o.inner.n); }
  assert.deepEqual(got, [2, 0, 3, 1]);

  // a frame that was already opened cannot be opened again (its key is gone)
  await assert.rejects(Ratchet.decrypt(rb, envs[2], Object.assign({}, ctx, { opk: () => null })));

  // a tampered frame fails and leaves the state untouched
  const o = await Ratchet.encrypt(ra, { n: 9 });
  const bad = JSON.parse(JSON.stringify(o.env));
  bad.ct = bad.ct.slice(0, -4) + (bad.ct.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
  const before = JSON.stringify(rb);
  await assert.rejects(Ratchet.decrypt(rb, bad, ctx));
  assert.equal(JSON.stringify(rb), before);
  assert.equal((await Ratchet.decrypt(rb, o.env, ctx)).inner.n, 9);

  // replaying the handshake into a fresh session record is refused
  const fresh = Object.assign(Ratchet.empty(), { eks: rb.eks });
  await assert.rejects(Ratchet.decrypt(fresh, envs[0], ctx), /replayed handshake/);

  // a handshake claiming someone else's identity is refused
  await assert.rejects(Ratchet.decrypt(Ratchet.empty(), envs[0], Object.assign({}, ctx, { peerId: 'f'.repeat(32) })), /do not belong/);
});

test('prekeys are replenished when they run low', async () => {
  const hana = client({ opkBatch: 22 });
  await hana.signup('hana', PASS);
  await live(hana);
  const others = [];
  for (let i = 0; i < 3; i++) { const o = client(); await o.signup('sender' + i, PASS); others.push(o); }
  for (const o of others) {
    const userId = await befriend(o, hana);
    await o.sendText(userId, 'hi from ' + o.me.username);
  }
  // 22 - 3 = 19 < 20 triggers a push, and hana uploads another batch
  await waitFor(() => srv.db.prekeyCount(hana.me.userId) >= 41, 'replenish');
  await waitFor(() => texts(hana, others[2].me.userId).length === 1, 'hana receives');
});

test('the database holds no plaintext', async () => {
  const ivy = client(), jon = client();
  await ivy.signup('ivy', PASS);
  await jon.signup('jon', PASS);
  const secret = 'the eagle lands at midnight';
  const userId = await befriend(ivy, jon);
  await ivy.sendText(userId, secret);
  await waitFor(() => texts(jon, ivy.me.userId).length === 1, 'delivery');
  jon._reset();
  await ivy.sendText(userId, secret + ' (queued)');   // sits in the mailbox

  srv.db.raw.pragma('wal_checkpoint(TRUNCATE)');
  const file = fs.readFileSync(path.join(dataDir, 'marmot.db')).toString('latin1');
  assert.ok(!file.includes('eagle'), 'message text');
  assert.ok(!file.includes(ivy.me.ik.pub), 'identity keys are sealed');
  assert.ok(!file.includes(ivy.me.userId + '","payload'), 'envelope senders are sealed');
  assert.ok(!file.includes(userId + '","state'), 'relationships are sealed');
  for (const t of ['users', 'blobs', 'envelopes', 'prekeys', 'peers']) {
    const col = { users: 'vault', blobs: 'v', envelopes: 'body', prekeys: 'pub', peers: 'body' }[t];
    for (const r of srv.db.raw.prepare(`SELECT ${col} c FROM ${t}`).all()) assert.ok(r.c.startsWith('v1.'), t + ' sealed');
  }
});

test('account deletion needs the password and removes everything', async () => {
  const kim = client();
  await kim.signup('kim', PASS);
  const id = kim.me.userId;
  await assert.rejects(kim.deleteAccount('wrong password!'), /wrong password/);
  await kim.deleteAccount(PASS);
  assert.equal(srv.db.userRow(id), undefined);
  assert.equal(srv.db.raw.prepare('SELECT COUNT(*) n FROM blobs WHERE user_id = ?').get(id).n, 0);
  await assert.rejects(client().login('kim', PASS), /no such account/);
});

test('strangers cannot message or fetch bundles; requests, decline, crossing requests, unfriend', async () => {
  const lia = client(), max = client();
  await lia.signup('lia', PASS);
  await max.signup('max', PASS);
  await Promise.all([live(lia), live(max)]);

  // not friends: the client refuses, and so does the server underneath it
  await lia.pinUser('max');
  await assert.rejects(lia.sendText(max.me.userId, 'hi'), /only message friends/);
  await assert.rejects(lia.api('GET', '/api/bundle/' + max.me.userId), /only message friends/);
  await assert.rejects(lia.api('POST', '/api/commit', { send: [{ to: max.me.userId, payload: '{}' }] }), /only message friends/);

  // a request shows up live on the other side
  const events = [];
  max.on('peer', (kind, p) => events.push(kind + ':' + p.username));
  await lia.requestFriend('MAX');
  await waitFor(() => max.relation(lia.me.userId) === 'incoming', 'request pushed');
  assert.deepEqual(events, ['request:lia']);
  assert.equal(lia.relation(max.me.userId), 'outgoing');

  // declining removes both sides
  await max.peerAction('remove', lia.me.userId);
  await waitFor(() => lia.relation(max.me.userId) === 'none', 'decline pushed');

  // crossing requests become a friendship
  await lia.requestFriend('max');
  await max.requestFriend('lia');
  assert.equal(max.relation(lia.me.userId), 'friend');
  await waitFor(() => lia.relation(max.me.userId) === 'friend', 'accept pushed');
  await lia.sendText(max.me.userId, 'now we can talk');
  await waitFor(() => texts(max, lia.me.userId).length === 1, 'delivery');
  await waitFor(() => lia.thread(max.me.userId)[0].state === 'delivered', 'receipt');

  // after unfriending neither side can send
  await max.peerAction('remove', lia.me.userId);
  await waitFor(() => lia.relation(max.me.userId) === 'none', 'unfriend pushed');
  await assert.rejects(lia.sendText(max.me.userId, 'still there?'), /only message friends/);
  assert.equal(srv.db.peers(lia.me.userId).length, 0);
  assert.equal(srv.db.peers(max.me.userId).length, 0);
});

test('a message from someone who unfriended you meanwhile is still processed', async () => {
  const ned = client(), ola = client();
  await ned.signup('ned', PASS);
  await ola.signup('ola', PASS);
  await befriend(ned, ola);
  const olaId = ola.me.userId;
  ola._reset();                                    // ola is offline
  await ned.sendText(olaId, 'bye');
  await ned.peerAction('remove', olaId);
  const ola2 = client();
  await ola2.login('ola', PASS);
  // the receipt is dropped by the server instead of failing the whole commit
  await waitFor(() => texts(ola2, ned.me.userId).length === 1, 'delivery');
  await waitFor(() => srv.db.inbox(ola2.me.userId, 10).length === 0, 'mailbox acked');
});

test('blocking hides requests, and unblocking surfaces them', async () => {
  const pam = client(), quinn = client();
  await pam.signup('pam', PASS);
  await quinn.signup('quinn', PASS);
  await Promise.all([live(pam), live(quinn)]);
  await befriend(pam, quinn);
  await quinn.peerAction('block', pam.me.userId);
  await waitFor(() => pam.relation(quinn.me.userId) === 'none', 'block removes the friendship');
  assert.equal(quinn.relation(pam.me.userId), 'blocked');

  // pam's new request never reaches quinn
  await pam.requestFriend('quinn');
  assert.equal(pam.relation(quinn.me.userId), 'outgoing');
  await quinn.loadPeers();
  assert.equal(quinn.relation(pam.me.userId), 'blocked');
  await assert.rejects(quinn.requestFriend('pam'), /unblock them first/);

  await quinn.peerAction('unblock', pam.me.userId);
  assert.equal(quinn.relation(pam.me.userId), 'incoming');
  await quinn.peerAction('accept', pam.me.userId);
  await waitFor(() => pam.relation(quinn.me.userId) === 'friend', 'friends again');
});

test('global discovery is off by default and opt-in', async () => {
  const rae = client(), sol = client(), tom = client();
  await rae.signup('rae', PASS);
  await sol.signup('sol', PASS);
  await tom.signup('tom', PASS);
  const names = async (c, q) => (await c.discover(q)).users.map(u => u.username);

  assert.equal(rae.discoverable, false);
  assert.ok(!(await names(sol, '')).includes('rae'));
  await rae.setDiscoverable(true);
  assert.ok((await names(sol, '')).includes('rae'));
  assert.deepEqual(await names(sol, 'ra'), ['rae']);
  assert.ok(!(await names(rae, '')).includes('rae'), 'you are not listed to yourself');
  assert.deepEqual(await names(sol, '%'), [], 'LIKE wildcards are literal');

  // someone rae blocked does not see her
  await rae.peerAction('block', tom.me.userId);
  assert.ok(!(await names(tom, '')).includes('rae'));

  // the flag survives a fresh sign-in
  rae._reset();
  const rae2 = client();
  await rae2.login('rae', PASS);
  assert.equal(rae2.discoverable, true);
  await rae2.setDiscoverable(false);
  assert.ok(!(await names(sol, '')).includes('rae'));
});

test('deleting an account removes the other side of its relationships', async () => {
  const uma = client(), val = client();
  await uma.signup('uma', PASS);
  await val.signup('val', PASS);
  await live(val);
  await befriend(uma, val);
  await uma.deleteAccount(PASS);
  await waitFor(() => val.peers.size === 0, 'val updated');
  assert.equal(srv.db.peers(val.me.userId).length, 0);
});

test('group chats: empty groups, invites, names, members who are not friends, leaving', async () => {
  const gia = client(), hal = client(), kit = client(), joe = client();
  await gia.signup('gia', PASS);
  await hal.signup('hal', PASS);
  await kit.signup('kit', PASS);
  await joe.signup('joe', PASS);
  await Promise.all([gia, hal, kit, joe].map(live));
  await befriend(gia, hal);
  await befriend(gia, kit);
  await befriend(hal, joe);                        // joe knows hal, nobody else

  // an empty group, named, then a friend invited into it
  const gid = await gia.createGroup('rats', []);
  const conv = 'g:' + gid;
  assert.equal(gia.displayName(conv), 'rats');
  assert.equal(gia.group(gid).members.length, 1);
  await gia.sendText(conv, 'talking to myself');
  assert.deepEqual(texts(gia, conv), ['talking to myself']);

  // only friends can be invited, and outsiders cannot see in
  await assert.rejects(gia.inviteToGroup(gid, [joe.me.userId]), /only invite friends/);
  await assert.rejects(joe.api('POST', '/api/groups/invite', { group: gid, invite: [hal.me.userId] }), /not in that group/);
  assert.deepEqual(await gia.inviteToGroup(gid, [hal.me.userId, kit.me.userId]), [hal.me.userId, kit.me.userId]);

  // newcomers learn the name from the inviter, end to end
  await waitFor(() => hal.displayName(conv) === 'rats' && kit.displayName(conv) === 'rats', 'name to reach the invitees');
  assert.ok(hal.thread(conv).some(m => m.dir === 'sys' && m.text === 'gia added you'));
  assert.ok(!hal.thread(conv).some(m => m.text === 'talking to myself'), 'history from before joining is not shared');

  // hal and kit are not friends, but can talk inside the group
  assert.equal(hal.relation(kit.me.userId), 'none');
  await hal.sendText(conv, 'hi all');
  await waitFor(() => texts(gia, conv).includes('hi all') && texts(kit, conv).includes('hi all'), 'group message fan-out');
  assert.equal(kit.thread(conv).find(m => m.text === 'hi all').from, hal.me.userId);
  assert.equal(kit.displayName(hal.me.userId), 'hal');
  await waitFor(() => (hal.thread(conv).find(m => m.text === 'hi all').got || []).length === 2, 'receipts from both');
  // ...but not outside it
  await assert.rejects(hal.sendText(kit.me.userId, 'psst'), /only message friends/);

  // hal invites his own friend joe, and renames the group for everyone
  await hal.inviteToGroup(gid, [joe.me.userId]);
  await waitFor(() => joe.displayName(conv) === 'rats', 'joe learns the name');
  await waitFor(() => kit.thread(conv).some(m => m.text === 'hal added joe'), 'join line');
  await hal.renameGroup(gid, 'burrow');
  await waitFor(() => [gia, kit, joe].every(c => c.displayName(conv) === 'burrow'), 'rename');
  assert.ok(gia.thread(conv).some(m => m.text === 'hal renamed the group to “burrow”'));
  await joe.sendText(conv, 'thanks hal');
  await waitFor(() => [gia, hal, kit].every(c => texts(c, conv).includes('thanks hal')), 'joe reaches everyone');

  // the server never sees the name or the text
  const dump = JSON.stringify(srv.db.raw.prepare('SELECT * FROM group_members').all()) + JSON.stringify(srv.db.raw.prepare('SELECT * FROM groups').all());
  assert.ok(!/burrow|thanks hal/.test(dump));
  assert.ok(!dump.includes(gia.me.userId) && !dump.includes(joe.me.userId), 'member ids are sealed');

  // leaving: kit goes, and is then cut off from members she is not friends with
  await kit.leaveGroup(gid);
  assert.equal(kit.group(gid), null);
  assert.ok(kit.thread(conv).some(m => m.text === 'you left this group'));
  await assert.rejects(kit.sendText(conv, 'wait'), /not in this group/);
  await assert.rejects(kit.api('GET', '/api/bundle/' + joe.me.userId), /only message friends/);
  await waitFor(() => gia.group(gid).members.length === 3 && gia.thread(conv).some(m => m.text === 'kit left'), 'leave pushed');
  await gia.sendText(conv, 'bye kit');
  await waitFor(() => texts(joe, conv).includes('bye kit'), 'after kit left');
  assert.ok(!texts(kit, conv).includes('bye kit'));

  // the last one out deletes the group
  for (const c of [gia, hal, joe]) await c.leaveGroup(gid);
  assert.equal(srv.db.group(gid), undefined);
});

test('replies quote the original; deletes for me and for everyone', async () => {
  const ivy = client(), max = client(), sol = client();
  await ivy.signup('quill', PASS);
  await max.signup('quoter', PASS);
  await sol.signup('quoted', PASS);
  await Promise.all([ivy, max, sol].map(live));
  await befriend(ivy, max);
  await befriend(ivy, sol);
  const I = ivy.me.userId, X = max.me.userId;

  // a reply carries the quoted message end to end
  const q = await ivy.sendText(X, 'what time?');
  await waitFor(() => texts(max, I).includes('what time?'), 'question');
  await max.sendText(I, 'noon', undefined, q);
  await waitFor(() => texts(ivy, X).includes('noon'), 'reply');
  const got = ivy.thread(X).find(m => m.text === 'noon');
  assert.deepEqual(got.re, { id: q, from: I, t: 'what time?' });
  assert.deepEqual(max.thread(I).find(m => m.text === 'noon').re, got.re);

  // delete for me touches only my copy
  await ivy.deleteMessage(X, got.id, false);
  assert.ok(!texts(ivy, X).includes('noon'));
  assert.ok(texts(max, I).includes('noon'));

  // delete for everyone leaves a placeholder on both sides; nobody can delete someone else's for everyone
  const oops = await ivy.sendText(X, 'wrong chat');
  await waitFor(() => texts(max, I).includes('wrong chat'), 'oops');
  await assert.rejects(max.deleteMessage(I, oops, true), /your own/);
  await ivy.deleteMessage(X, oops, true);
  await waitFor(() => max.thread(I).some(m => m.id === oops && m.deleted && m.text === ''), 'tombstone at max');
  assert.ok(ivy.thread(X).find(m => m.id === oops).deleted);
  // a forged delete for a message the sender did not write is ignored
  await max._sendInner(I, { k: 'del', id: q });
  await max.sendText(I, 'still here');
  await waitFor(() => texts(ivy, X).includes('still here'), 'after forged delete');
  assert.equal(ivy.thread(X).find(m => m.id === q).text, 'what time?');

  // groups: replies, and only the author can take a message back
  const gid = await ivy.createGroup('plans', [X, sol.me.userId]);
  const conv = 'g:' + gid;
  await waitFor(() => max.group(gid) && sol.group(gid), 'group');
  const g1 = await max.sendText(conv, 'pizza?');
  await waitFor(() => texts(sol, conv).includes('pizza?') && texts(ivy, conv).includes('pizza?'), 'group msg');
  await sol.sendText(conv, 'yes', undefined, g1);
  await waitFor(() => (ivy.thread(conv).find(m => m.text === 'yes') || {}).re, 'group reply');
  assert.equal(ivy.thread(conv).find(m => m.text === 'yes').re.from, X);
  await sol._sendGroup(gid, { k: 'del', g: gid, id: g1 });
  await max.deleteMessage(conv, g1, true);
  await waitFor(() => [ivy, sol].every(c => c.thread(conv).find(m => m.id === g1).deleted), 'group tombstones');
  assert.ok(max.thread(conv).find(m => m.id === g1).deleted);

  // the server never sees replies or deletes in the clear
  const dump = JSON.stringify(srv.db.raw.prepare('SELECT * FROM envelopes').all()) + JSON.stringify(srv.db.raw.prepare('SELECT * FROM blobs').all());
  assert.ok(!/pizza|what time|"del"/.test(dump));
});

test('profile pictures and group icons', async () => {
  const PIC = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
  const PIC2 = PIC.replace('ErkJggg==', 'ErkJgga=');
  const una = client(), vic = client(), wes = client();
  await una.signup('una', PASS);
  await vic.signup('vic', PASS);
  await wes.signup('wes', PASS);
  await Promise.all([una, vic, wes].map(live));
  await befriend(una, vic);
  await befriend(una, wes);

  // only small images are accepted
  await assert.rejects(una.api('POST', '/api/me/avatar', { avatar: 'data:text/html;base64,PGI+' }), /small JPEG, PNG or WebP/);
  await assert.rejects(una.api('POST', '/api/me/avatar', { avatar: 'data:image/png;base64,' + 'A'.repeat(70000) }), /small JPEG, PNG or WebP/);

  // friends hear about a new picture over the socket, then fetch it once
  assert.equal(vic.avatar(una.me.userId), null);
  await una.setAvatar(PIC);
  assert.equal(una.avatar(una.me.userId), PIC);
  await waitFor(() => vic.avatar(una.me.userId) === PIC, 'vic to fetch the picture');
  // it is sealed at rest
  assert.ok(!JSON.stringify(srv.db.raw.prepare('SELECT avatar FROM users').all()).includes('iVBORw0KGgo'));
  // a fresh sign-in learns it from the peer list
  const vic2 = client();
  await vic2.login('vic', PASS);
  await vic2.loadPeers();
  await waitFor(() => vic2.avatar(una.me.userId) === PIC, 'a new session to see it');
  await una.setAvatar(null);
  assert.equal(vic.me, null, 'signing in elsewhere ended the first session');
  await waitFor(() => vic2.avatar(una.me.userId) === null, 'removal to reach friends');

  // group icons travel end to end, like the name, including to people invited later
  const gid = await una.createGroup('den', [vic2.me.userId]);
  const conv = 'g:' + gid;
  await waitFor(() => vic2.displayName(conv) === 'den', 'vic joins');
  await assert.rejects(una.setGroupIcon(gid, 'data:text/html;base64,PGI+'), /supported format/);
  await una.setGroupIcon(gid, PIC2);
  await waitFor(() => vic2.groupIcon(gid) === PIC2, 'icon to reach vic');
  assert.ok(vic2.thread(conv).some(m => m.text === 'una changed the group icon'));
  await una.inviteToGroup(gid, [wes.me.userId]);
  await waitFor(() => wes.groupIcon(gid) === PIC2, 'a newcomer to learn the icon');
  const dump = JSON.stringify(srv.db.raw.prepare('SELECT * FROM groups').all()) + JSON.stringify(srv.db.raw.prepare('SELECT * FROM group_members').all());
  assert.ok(!dump.includes('iVBORw0KGgo'));
  // a member who missed the icon (an older client acked it unread) gets it back from the next text
  const tx = new Tx(vic2);
  await tx.del('gicon:' + gid);
  await tx.commit();
  assert.equal(vic2.groupIcon(gid), null);
  await una.sendText(conv, 'still here?');
  await waitFor(() => vic2.groupIcon(gid) === PIC2, 'the missed icon to be resent');
  assert.equal(vic2.thread(conv).filter(m => m.text === 'una changed the group icon').length, 1, 'a resend is not announced again');

  await vic2.setGroupIcon(gid, '');
  await waitFor(() => una.groupIcon(gid) === null && wes.groupIcon(gid) === null, 'icon removal');
});

test('images in messages, end to end, at the largest size allowed', async () => {
  const xan = client(), yul = client(), zed = client();
  await xan.signup('xan', PASS);
  await yul.signup('yul', PASS);
  await zed.signup('zed', PASS);
  await Promise.all([xan, yul, zed].map(live));
  const yulId = await befriend(xan, yul);
  await befriend(xan, zed);

  // the worst case: an image at the size cap and a caption of 3-byte characters at its cap
  const head = 'data:image/webp;base64,';
  const big = { img: head + 'Q'.repeat(84000 - head.length), w: 1600, h: 1200 };
  const caption = '€'.repeat(2000);
  await xan.sendText(yulId, caption, undefined, undefined, big);
  await waitFor(() => yul.thread(xan.me.userId).some(m => m.img === big.img), 'yul to get the image');
  const got = yul.thread(xan.me.userId).find(m => m.img);
  assert.equal(got.text, caption);
  assert.equal(got.w, 1600);
  assert.equal(xan.thread(yulId).find(m => m.img).state, 'delivered');

  // too large, or not an image, is refused before anything is sent
  await assert.rejects(xan.sendText(yulId, '', undefined, undefined, { img: big.img + 'QQQQ' }), /too large/);
  await assert.rejects(xan.sendText(yulId, '', undefined, undefined, { img: 'data:text/html;base64,PGI+' }), /too large or not/);
  await assert.rejects(xan.sendText(yulId, '€'.repeat(2001), undefined, undefined, big), /captions are limited/);

  // a bare image (no caption) to a group; replies quote it as a photo
  const gid = await xan.createGroup('pics', [yulId, zed.me.userId]);
  const conv = 'g:' + gid;
  await waitFor(() => zed.group(gid), 'zed joins');
  const small = { img: head + 'AAAA', w: 4, h: 3 };
  const id = await xan.sendText(conv, '', undefined, undefined, small);
  await waitFor(() => [yul, zed].every(c => c.thread(conv).some(m => m.img === small.img)), 'group image fan-out');
  await zed.sendText(conv, 'nice', undefined, id);
  await waitFor(() => xan.thread(conv).some(m => m.text === 'nice' && m.re && m.re.t === '📷 photo'), 'reply quoting the photo');

  // deleting for everyone drops the image from every copy
  await xan.deleteMessage(conv, id, true);
  await waitFor(() => [yul, zed].every(c => { const m = c.thread(conv).find(x => x.id === id); return m && m.deleted && !m.img; }), 'image tombstoned');
  assert.ok(!xan.thread(conv).find(x => x.id === id).img);
});

test('step 1 databases are migrated', async () => {
  const Database = require('better-sqlite3');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-mig-'));
  const old = new Database(path.join(dir, 'marmot.db'));
  old.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, uname TEXT NOT NULL UNIQUE, created INTEGER NOT NULL,
    last_seen INTEGER NOT NULL DEFAULT 0, salt TEXT NOT NULL, iter INTEGER NOT NULL, verifier TEXT NOT NULL,
    identity TEXT NOT NULL, spk TEXT NOT NULL, vault TEXT NOT NULL)`);
  old.close();
  const db = require('../db').open({ dataDir: dir, key: Buffer.alloc(32, 1) });
  assert.ok(db.raw.prepare('PRAGMA table_info(users)').all().some(c => c.name === 'discoverable'));
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
