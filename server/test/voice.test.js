'use strict';
/**
 * Voice call signalling: real clients (the <marmot-core> code from
 * client/Marmot.html) calling each other through a real server. Node has no
 * WebRTC, so a fake RTCPeerConnection stands in for the browser's media stack.
 * Everything else is real: the offer and answer travel as Double Ratchet
 * messages through /api/commit and the socket.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');
const { createServer } = require('../server');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'client', 'Marmot.html'), 'utf8');
const core = html.split('/*<marmot-core>*/')[1].split('/*</marmot-core>*/')[0];
const { MarmotClient } = new Function(core + '\nreturn {MarmotClient};')();

const PASS = 'correct horse battery';
let srv, base, dataDir;
const clients = [];
const pushed = [];   // every envelope payload the server pushed

/** Connects as soon as both descriptions are set, like two browsers on one LAN. */
class FakePC {
  constructor(cfg) {
    this.cfg = cfg; this.connectionState = 'new'; this.iceGatheringState = 'new';
    this.localDescription = null; this.remoteDescription = null; this.tracks = [];
    this.fp = crypto.randomBytes(16).toString('hex').toUpperCase().match(/../g).join(':');
  }
  addTrack(t) { this.tracks.push(t); }
  _sdp(type) { return 'v=0\r\no=- ' + type + '\r\na=fingerprint:sha-256 ' + this.fp + '\r\na=setup:actpass\r\n'; }
  async createOffer() { return { type: 'offer', sdp: this._sdp('offer') }; }
  async createAnswer() { return { type: 'answer', sdp: this._sdp('answer') }; }
  async setLocalDescription(d) { this._open(); this.localDescription = d; this.iceGatheringState = 'complete'; this._connect(); }
  async setRemoteDescription(d) { this._open(); this.remoteDescription = d; this._connect(); }
  _open() { if (this.connectionState === 'closed') throw new Error('peer connection is closed'); }
  _connect() {
    if (!this.localDescription || !this.remoteDescription) return;
    setTimeout(() => {
      if (this.connectionState === 'closed') return;
      this.connectionState = 'connected';
      if (this.ontrack) this.ontrack({ streams: [{ remoteOf: this.remoteDescription.sdp }] });
      if (this.onconnectionstatechange) this.onconnectionstatechange();
    }, 10);
  }
  /** Test hook: the network drops. */
  drop() { this.connectionState = 'failed'; if (this.onconnectionstatechange) this.onconnectionstatechange(); }
  close() { this.connectionState = 'closed'; }
}
const mics = [];
async function getUserMedia(c) {
  assert.equal(c.audio && typeof c.audio, 'object');
  const track = { enabled: true, stopped: false, stop() { this.stopped = true; } };
  mics.push(track);
  return { getTracks: () => [track] };
}

function client(opts) {
  const c = new MarmotClient(Object.assign({ WebSocket, iter: 300000, RTCPeerConnection: FakePC, getUserMedia }, opts));
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
    await new Promise(r => setTimeout(r, 20));
  }
}
const live = c => waitFor(() => c.wsState === 'live', 'socket');
const sys = (c, peer) => c.thread(peer).filter(m => m.dir === 'sys').map(m => m.text);
const state = c => c.voice.call && c.voice.call.state;
async function pair(a, b, opts) {
  const x = client(opts), y = client(opts);
  await x.signup(a, PASS);
  await y.signup(b, PASS);
  await Promise.all([live(x), live(y)]);
  await x.requestFriend(b);
  await y.loadPeers();
  await y.peerAction('accept', x.me.userId);
  await x.loadPeers();
  return [x, y];
}

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-voice-'));
  srv = createServer({ dataDir, key: Buffer.alloc(32, 9), authPerMinute: 1000,
    ice: { stun: ['stun:stun.example:3478'], turn: ['turn:turn.example:3478'], secret: 'turn-secret' } });
  const push = srv.hub.push.bind(srv.hub);
  srv.hub.push = (to, msg) => { if (msg.t === 'env') pushed.push(msg.env.payload); return push(to, msg); };
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('a call rings, connects end to end, mutes and hangs up', async () => {
  const [ana, ben] = await pair('ana', 'ben');
  const benId = ben.me.userId, anaId = ana.me.userId;
  const call = await ana.voice.start(benId);
  assert.equal(call.state, 'calling');
  await waitFor(() => state(ben) === 'ringing', 'ben rings');
  assert.equal(ben.voice.call.peer, anaId);
  assert.equal(ben.voice.call.id, call.id);

  await ben.voice.accept();
  await waitFor(() => state(ana) === 'active' && state(ben) === 'active', 'both connected');

  // each side's DTLS fingerprint reached the other intact...
  const pa = ana.voice.call.pc, pb = ben.voice.call.pc;
  assert.equal(pb.remoteDescription.sdp, pa.localDescription.sdp);
  assert.equal(pa.remoteDescription.sdp, pb.localDescription.sdp);
  assert.match(pb.remoteDescription.sdp, new RegExp(pa.fp));
  // ...and the server only ever relayed ratchet ciphertext
  assert.ok(pushed.length >= 2);
  for (const p of pushed) {
    assert.ok(!p.includes('fingerprint') && !p.includes(pa.fp) && !p.includes(pb.fp), 'SDP is not visible to the server');
    assert.equal(JSON.parse(p).v, 1);
  }
  // the ICE config came from the server, with a TURN credential minted from the secret
  const turn = pa.cfg.iceServers.find(s => s.username);
  assert.equal(turn.credential, crypto.createHmac('sha1', 'turn-secret').update(turn.username).digest('base64'));

  ana.voice.setMuted(true);
  assert.equal(pa.tracks[0].enabled, false);
  ana.voice.setMuted(false);
  assert.equal(pa.tracks[0].enabled, true);

  await ana.voice.hangup();
  await waitFor(() => !ben.voice.call, 'ben hung up too');
  assert.equal(ana.voice.call, null);
  assert.equal(pa.connectionState, 'closed');
  assert.equal(pb.connectionState, 'closed');
  assert.ok(pa.tracks[0].stopped && pb.tracks[0].stopped, 'microphones released');
  await waitFor(() => sys(ana, benId).length && sys(ben, anaId).length, 'call history');
  assert.match(sys(ana, benId)[0], /^voice call · 0:0\d$/);
  assert.match(sys(ben, anaId)[0], /^voice call · 0:0\d$/);
  assert.equal(ben.unread.get(anaId) || 0, 0, 'an answered call is not unread');
});

test('declining, and cancelling before an answer', async () => {
  const [cy, dee] = await pair('cyd', 'dee');
  await cy.voice.start(dee.me.userId);
  await waitFor(() => state(dee) === 'ringing', 'ringing');
  await dee.voice.decline();
  await waitFor(() => !cy.voice.call, 'caller told');
  await waitFor(() => sys(cy, dee.me.userId).length, 'history');
  assert.deepEqual(sys(cy, dee.me.userId), ['voice call declined']);
  assert.deepEqual(sys(dee, cy.me.userId), ['declined voice call']);

  await cy.voice.start(dee.me.userId);
  await waitFor(() => state(dee) === 'ringing', 'ringing again');
  await cy.voice.hangup();
  await waitFor(() => !dee.voice.call, 'ringing stops');
  await waitFor(() => sys(dee, cy.me.userId).length === 2, 'missed call logged');
  assert.equal(sys(cy, dee.me.userId)[1], 'cancelled voice call');
  assert.equal(sys(dee, cy.me.userId)[1], 'missed voice call');
  assert.equal(dee.unread.get(cy.me.userId), 1);
});

test('a call to someone offline is a missed call when they come back, and never rings', async () => {
  const [eve, fox] = await pair('eve', 'fox', { ring: 300 });
  const foxId = fox.me.userId;
  fox._reset();
  await eve.voice.start(foxId);
  await waitFor(() => !eve.voice.call, 'rings out');
  await waitFor(() => sys(eve, foxId).length, 'caller history');
  assert.deepEqual(sys(eve, foxId), ['no answer']);

  const fox2 = client({ ring: 300 });
  let rang = false;
  fox2.on('call', c => { if (c) rang = true; });
  await fox2.login('fox', PASS);
  await waitFor(() => sys(fox2, eve.me.userId).length, 'missed call');
  assert.deepEqual(sys(fox2, eve.me.userId), ['missed voice call']);
  assert.equal(fox2.unread.get(eve.me.userId), 1);
  await new Promise(r => setTimeout(r, 100));
  assert.equal(rang, false);
  assert.equal(fox2.voice.call, null);
});

test('a second caller gets busy; strangers cannot call', async () => {
  const [gil, hal] = await pair('gil', 'hal');
  const ida = client();
  await ida.signup('ida', PASS);
  await live(ida);
  await ida.requestFriend('gil');
  await gil.loadPeers();
  await gil.peerAction('accept', ida.me.userId);
  await ida.loadPeers();

  await gil.voice.start(hal.me.userId);
  await waitFor(() => state(hal) === 'ringing', 'ringing');
  await hal.voice.accept();
  await waitFor(() => state(gil) === 'active', 'connected');

  await ida.voice.start(gil.me.userId);
  await waitFor(() => !ida.voice.call, 'busy');
  await waitFor(() => sys(ida, gil.me.userId).length && sys(gil, ida.me.userId).length, 'history');
  assert.deepEqual(sys(ida, gil.me.userId), ['they were on another call']);
  assert.deepEqual(sys(gil, ida.me.userId), ['missed voice call (you were on another call)']);
  assert.equal(state(gil), 'active', 'the first call is untouched');
  await assert.rejects(gil.voice.start(ida.me.userId), /already in a call/);

  // a dropped connection ends the call on that side, and tells the other
  gil.voice.call.pc.drop();
  await waitFor(() => !gil.voice.call && !hal.voice.call, 'both ended');
  await waitFor(() => sys(gil, hal.me.userId).length, 'history');
  assert.match(sys(gil, hal.me.userId)[0], /connection lost$/);

  const jo = client();
  await jo.signup('joe', PASS);
  await jo.pinUser('gil');
  await assert.rejects(jo.voice.start(gil.me.userId), /only call friends/);
  assert.equal(jo.voice.call, null);
});

test('two friends calling each other at once end up in one call', async () => {
  const [kai, lou] = await pair('kai', 'lou');
  await Promise.all([kai.voice.start(lou.me.userId), lou.voice.start(kai.me.userId)]);
  await waitFor(() => state(kai) === 'active' && state(lou) === 'active', 'one call');
  assert.equal(kai.voice.call.id, lou.voice.call.id);
  await lou.voice.hangup();
  await waitFor(() => !kai.voice.call, 'ended');
  await waitFor(() => sys(kai, lou.me.userId).length && sys(lou, kai.me.userId).length, 'history');
  assert.equal(sys(kai, lou.me.userId).length, 1);
  assert.equal(sys(lou, kai.me.userId).length, 1);
});

test('ICE config without a relay', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-ice-'));
  const s = createServer({ dataDir: dir, key: Buffer.alloc(32, 3), ice: { stun: [], turn: [], secret: '' } });
  await new Promise(r => s.server.listen(0, '127.0.0.1', r));
  const c = new MarmotClient({ iter: 300000 });
  c.setServer('http://127.0.0.1:' + s.server.address().port);
  await c.signup('solo', PASS);
  const r = await c.api('GET', '/api/ice');
  assert.deepEqual(r.iceServers, []);
  assert.equal(r.relay, false);
  c._reset();
  await new Promise(r2 => s.server.close(r2));
  s.db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
