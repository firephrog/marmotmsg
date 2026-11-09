'use strict';
/**
 * Voice call signalling: real clients (the <marmot-core> code from
 * client/index.html) calling each other through a real server. Node has no
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

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'client', 'index.html'), 'utf8');
const core = html.split('/*<marmot-core>*/')[1].split('/*</marmot-core>*/')[0];
const { MarmotClient } = new Function(core + '\nreturn {MarmotClient};')();

const PASS = 'correct horse battery';
let srv, base, dataDir;
const clients = [];
const pushed = [];   // every envelope payload the server pushed

class FakeTx {
  constructor(kind, direction) {
    this.kind = kind; this.direction = direction; this.currentDirection = null;
    this.receiver = { track: { kind } };
    const sender = this.sender = { track: null, async replaceTrack(t) { sender.track = t; } };
  }
}
/** Connects as soon as both descriptions are set, like two browsers on one LAN.
    Transceivers follow unified plan closely enough for the camera/screen wiring:
    one m= line each, matched by position, addTrack reusing an offered audio section. */
class FakePC {
  constructor(cfg) {
    this.cfg = cfg; this.connectionState = 'new'; this.iceGatheringState = 'new';
    this.localDescription = null; this.remoteDescription = null; this.tracks = []; this.tx = [];
    this.fp = crypto.randomBytes(16).toString('hex').toUpperCase().match(/../g).join(':');
  }
  addTrack(t) {
    this.tracks.push(t);
    let x = this.tx.find(x => x.kind === 'audio' && !x.sender.track);
    if (!x) this.tx.push(x = new FakeTx('audio', 'sendrecv'));
    x.sender.track = t; x.direction = 'sendrecv';
  }
  addTransceiver(kind, o) { const x = new FakeTx(kind, o.direction); this.tx.push(x); return x; }
  getTransceivers() { return this.tx; }
  _sdp(type) {
    return 'v=0\r\no=- ' + type + '\r\na=fingerprint:sha-256 ' + this.fp + '\r\na=setup:actpass\r\n' +
      this.tx.map(x => 'm=' + x.kind + ' ' + x.direction + '\r\n').join('');
  }
  async createOffer() { return { type: 'offer', sdp: this._sdp('offer') }; }
  async createAnswer() { return { type: 'answer', sdp: this._sdp('answer') }; }
  async setLocalDescription(d) { this._open(); this.localDescription = d; this.iceGatheringState = 'complete'; this._connect(); }
  async setRemoteDescription(d) {
    this._open(); this.remoteDescription = d;
    const m = [...d.sdp.matchAll(/^m=(\w+) (\w+)/gm)];
    if (d.type === 'offer') for (const [, kind] of m) this.tx.push(new FakeTx(kind, 'recvonly'));
    else this.tx.forEach((x, i) => { x.currentDirection = m[i] && m[i][2] === 'sendrecv' && x.direction === 'sendrecv' ? 'sendrecv' : 'sendonly'; });
    this._connect();
  }
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
const fakeTrack = kind => ({ kind, enabled: true, stopped: false, stop() { this.stopped = true; } });
async function getUserMedia(c) {
  if (c.video) { assert.equal(c.audio, false); const t = fakeTrack('camera'); return { getTracks: () => [t] }; }
  assert.equal(c.audio && typeof c.audio, 'object');
  const track = fakeTrack('audio');
  mics.push(track);
  return { getTracks: () => [track] };
}
async function getDisplayMedia(c) {
  assert.ok(c.video);
  const t = fakeTrack('screen');
  return { getTracks: () => [t] };
}

function client(opts) {
  const c = new MarmotClient(Object.assign({ WebSocket, iter: 300000, RTCPeerConnection: FakePC, getUserMedia, getDisplayMedia }, opts));
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

test('camera and screen share switch on and off mid-call without renegotiating', async () => {
  const [mo, ned] = await pair('moe', 'ned');
  await mo.voice.start(ned.me.userId);
  await waitFor(() => state(ned) === 'ringing', 'ringing');
  await ned.voice.accept();
  await waitFor(() => state(mo) === 'active' && state(ned) === 'active', 'connected');
  const pa = mo.voice.call.pc, pb = ned.voice.call.pc;
  const offer = pb.remoteDescription.sdp;
  assert.deepEqual(pa.tx.map(x => x.kind), ['audio', 'video', 'video']);
  assert.deepEqual(pb.tx.map(x => x.kind), ['audio', 'video', 'video'], 'the answer reuses the offered sections');
  assert.ok(mo.voice.canVideo() && ned.voice.canVideo() && ned.voice.canScreen());

  await mo.voice.setCamera(true);
  assert.equal(pa.tx[1].sender.track.kind, 'camera');
  await waitFor(() => ned.voice.call.peerCam, 'ned sees the camera');
  assert.equal(ned.voice.call.peerScreen, false);

  await ned.voice.setScreen(true);
  const screen = pb.tx[2].sender.track;
  assert.equal(screen.kind, 'screen');
  await waitFor(() => mo.voice.call.peerScreen, 'moe sees the screen');
  // stopping from the browser's own "stop sharing" control
  screen.onended();
  await waitFor(() => !mo.voice.call.peerScreen, 'share ended');
  assert.equal(ned.voice.call.screen, false);
  assert.ok(screen.stopped);
  assert.equal(pb.tx[2].sender.track, null);

  const cam = pa.tx[1].sender.track;
  await mo.voice.setCamera(false);
  assert.ok(cam.stopped, 'camera light goes off');
  assert.equal(pa.tx[1].sender.track, null);
  await waitFor(() => !ned.voice.call.peerCam, 'camera off');
  assert.equal(pb.remoteDescription.sdp, offer, 'no second offer');

  await mo.voice.setCamera(true);
  const cam2 = pa.tx[1].sender.track;
  await mo.voice.hangup();
  await waitFor(() => !ned.voice.call, 'ended');
  assert.ok(cam2.stopped, 'hanging up releases the camera');
});

test('a voice-only answer from an older client keeps video off', async () => {
  // older clients only ever addTrack the microphone, and never touch transceiver directions
  class OldPC extends FakePC {}
  OldPC.prototype.getTransceivers = undefined;
  const [oz, pip] = await pair('ozz', 'pip');
  pip.voice.RTC = OldPC;
  await oz.voice.start(pip.me.userId);
  await waitFor(() => state(pip) === 'ringing', 'ringing');
  await pip.voice.accept();
  await waitFor(() => state(oz) === 'active' && state(pip) === 'active', 'connected');
  await waitFor(() => !oz.voice.canVideo(), 'video dropped');
  assert.equal(pip.voice.canVideo(), false);
  await assert.rejects(oz.voice.setCamera(true), /voice only/);
  await oz.voice.hangup();
  await waitFor(() => !pip.voice.call, 'ended');
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

/* ------------------------------------------------- socket relay fallback */
/** ICE never gets anywhere: no direct path, no TURN. */
class DeadPC extends FakePC {
  _connect() {
    if (!this.localDescription || !this.remoteDescription) return;
    setTimeout(() => { if (this.connectionState !== 'closed') this.drop(); }, 10);
  }
}
/** Stands in for RelayAudio: what the microphone "says" is whatever the test sends. */
function fakeRelay(codecs) {
  const opened = [];
  return {
    opened,
    codecs: async () => codecs,
    context: () => ({ closed: false, async close() { this.closed = true; } }),
    async open({ codec, stream, ctx, send }) {
      const m = { codec, stream, ctx, send, heard: [], closed: false, play(p) { m.heard.push(Buffer.from(p).toString()); }, close() { m.closed = true; } };
      opened.push(m);
      return m;
    }
  };
}
const relayed = [];   // every relay frame the server forwarded
function tapRelay(c) {
  const ws = c.ws, on = ws.onmessage;
  ws.onmessage = ev => { const m = JSON.parse(ev.data); if (m.t === 'vr') relayed.push(m); on(ev); };
}

test('when ICE fails, the call carries on over the socket, encrypted end to end', async () => {
  const ra = fakeRelay(['opus', 'pcmu']), rb = fakeRelay(['pcmu']);
  const [quin, rex] = await pair('quin', 'rex', { RTCPeerConnection: DeadPC, connectWait: 3000 });
  quin.voice.relayMedia = ra; rex.voice.relayMedia = rb;
  tapRelay(quin); tapRelay(rex);
  await quin.voice.start(rex.me.userId);
  await waitFor(() => state(rex) === 'ringing', 'ringing');
  await rex.voice.accept();
  await waitFor(() => ra.opened.length && rb.opened.length, 'both switched to the relay');
  const qa = ra.opened[0], rb0 = rb.opened[0];
  assert.equal(qa.codec, 'pcmu', 'the first of the caller\'s codecs the callee can play');
  assert.equal(rb0.codec, 'pcmu');
  assert.ok(quin.voice.call.relay && rex.voice.call.relay);
  assert.equal(quin.voice.call.pc, null, 'the dead peer connection is closed');
  assert.ok(qa.ctx && qa.stream, 'the relay gets the microphone and the call\'s audio context');
  assert.equal(quin.voice.canVideo(), false);
  await assert.rejects(quin.voice.setCamera(true), /voice only/);
  assert.equal(state(quin), 'connecting', 'not active until audio arrives');

  for (let i = 0; i < 3; i++) qa.send(new TextEncoder().encode('hello ' + i));
  rb0.send(new TextEncoder().encode('hi back'));
  await waitFor(() => rb0.heard.length === 3 && qa.heard.length === 1, 'audio both ways');
  assert.deepEqual(rb0.heard, ['hello 0', 'hello 1', 'hello 2']);
  assert.deepEqual(qa.heard, ['hi back']);
  await waitFor(() => state(quin) === 'active' && state(rex) === 'active', 'both active');
  // the server forwarded ciphertext only
  assert.ok(relayed.length >= 4);
  for (const m of relayed) assert.ok(!Buffer.from(m.d, 'base64').toString().includes('hello') && !Buffer.from(m.d, 'base64').toString().includes('hi back'));
  assert.equal(relayed.find(m => m.to), undefined, 'the recipient sees who it is from, not a forwarding address');

  // a replayed frame, and one that does not open, are dropped
  const old = relayed.find(m => m.from === quin.me.userId);
  rex.voice._relayIn(old);
  rex.voice._relayIn(Object.assign({}, old, { n: 99, d: old.d.slice(0, -4) + 'AAAA' }));
  await new Promise(r => setTimeout(r, 100));
  assert.equal(rb0.heard.length, 3);

  quin.voice.setMuted(true);
  assert.equal(qa.stream.getTracks()[0].enabled, false, 'mute still silences the microphone');

  await quin.voice.hangup();
  await waitFor(() => !rex.voice.call, 'ended');
  assert.ok(qa.closed && rb0.closed && qa.ctx.closed, 'relay audio and contexts closed');
  await waitFor(() => sys(quin, rex.me.userId).length, 'history');
  assert.match(sys(quin, rex.me.userId)[0], /^voice call · 0:0\d$/);
});

test('relay frames only reach someone the sender can reach, and are rate limited', async () => {
  const [sal, tam] = await pair('sal', 'tam');
  const uma = client();
  await uma.signup('uma', PASS);
  await live(uma);
  const got = [];
  const on = sal.ws.onmessage;
  sal.ws.onmessage = ev => { const m = JSON.parse(ev.data); if (m.t === 'vr') got.push(m); on(ev); };
  const frame = (n) => ({ t: 'vr', to: sal.me.userId, call: 'c1', n, d: 'AAAA' });
  uma.ws.send(JSON.stringify(frame(0)));               // a stranger
  for (let i = 0; i < 150; i++) tam.ws.send(JSON.stringify(frame(i)));   // a friend, past the limit
  await new Promise(r => setTimeout(r, 300));
  assert.ok(got.every(m => m.from === tam.me.userId), 'nothing from the stranger');
  assert.ok(got.length > 0 && got.length <= 100, 'at most 100 frames a second: ' + got.length);
});

test('without a relay on both sides, a failed connection is still a lost call', async () => {
  const [vic, wes] = await pair('vic', 'wes', { RTCPeerConnection: DeadPC, connectWait: 3000 });
  vic.voice.relayMedia = fakeRelay(['opus']);   // wes cannot relay
  await vic.voice.start(wes.me.userId);
  await waitFor(() => state(wes) === 'ringing', 'ringing');
  await wes.voice.accept();
  await waitFor(() => !vic.voice.call && !wes.voice.call, 'both ended');
  await waitFor(() => sys(vic, wes.me.userId).length, 'history');
  assert.equal(sys(vic, wes.me.userId)[0], 'voice call failed: could not connect');
});

test('the instance relay config file feeds /api/ice', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-turnfile-'));
  const file = path.join(dir, 'turn.json');
  const saved = { TURN_CONFIG: process.env.TURN_CONFIG, TURN_URLS: process.env.TURN_URLS, TURN_SECRET: process.env.TURN_SECRET, STUN_URLS: process.env.STUN_URLS };
  process.env.TURN_CONFIG = file; delete process.env.TURN_URLS; delete process.env.TURN_SECRET; process.env.STUN_URLS = '';
  const s = createServer({ dataDir: dir, key: Buffer.alloc(32, 4) });
  try {
    await new Promise(r => s.server.listen(0, '127.0.0.1', r));
    const c = new MarmotClient({ iter: 300000 });
    c.setServer('http://127.0.0.1:' + s.server.address().port);
    await c.signup('filey', PASS);
    assert.equal((await c.api('GET', '/api/ice')).relay, false, 'no file yet');
    fs.writeFileSync(file, JSON.stringify({ urls: ['turn:t.example:3478?transport=udp', 'turns:t.example:5349?transport=tcp'], secret: 's3cret' }));
    const r = await c.api('GET', '/api/ice');
    assert.equal(r.relay, true, 'picked up without a restart');
    const t = r.iceServers.find(x => x.username);
    assert.deepEqual(t.urls, ['turn:t.example:3478?transport=udp', 'turns:t.example:5349?transport=tcp']);
    assert.equal(t.credential, crypto.createHmac('sha1', 's3cret').update(t.username).digest('base64'));
    c._reset();
  } finally {
    for (const [k, v] of Object.entries(saved)) if (v == null) delete process.env[k]; else process.env[k] = v;
    await new Promise(r2 => s.server.close(r2));
    s.db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------ group calls */
async function befriend(a, b) {
  await a.requestFriend(b.me.username);
  await b.loadPeers();
  await b.peerAction('accept', a.me.userId);
  await a.loadPeers();
}
/** An owner friends with everyone else, who are not friends with each other, all in one group. */
async function crew(names, opts) {
  const cs = names.map(() => client(opts));
  for (let i = 0; i < cs.length; i++) await cs[i].signup(names[i], PASS);
  await Promise.all(cs.map(live));
  for (const c of cs.slice(1)) await befriend(cs[0], c);
  const gid = await cs[0].createGroup('crew', cs.slice(1).map(c => c.me.userId));
  await waitFor(() => cs.every(c => c.group(gid) && c.group(gid).members.length === cs.length), 'group');
  return [gid, ...cs];
}
const linkTo = (c, other) => c.voice.call && c.voice.call.links.get(other.me.userId);
const up = (c, ...others) => others.every(o => { const l = linkTo(c, o); return l && l.state === 'active'; });
const gsys = (c, gid) => c.thread('g:' + gid).filter(m => m.dir === 'sys' && /call/.test(m.text)).map(m => m.text);

test('a group call rings who was picked, joins everyone up, takes invites and outlasts whoever leaves', async () => {
  const [gid, ann, bea, cal, dan] = await crew(['gann', 'gbea', 'gcal', 'gdan']);
  assert.equal(bea.isFriend(cal.me.userId), false, 'members need not be friends');
  const call = await ann.voice.start('g:' + gid, [bea.me.userId, cal.me.userId]);
  assert.equal(call.group, gid);
  assert.equal(call.state, 'calling');
  await waitFor(() => state(bea) === 'ringing' && state(cal) === 'ringing', 'both ring');
  assert.equal(bea.voice.call.group, gid);
  assert.equal(bea.voice.call.peer, ann.me.userId, 'rung by ann');
  assert.equal(dan.voice.call, null, 'dan was not picked');

  await bea.voice.accept();
  await waitFor(() => up(ann, bea) && up(bea, ann), 'ann and bea');
  assert.equal(state(ann), 'active');
  await cal.voice.accept();
  // cal only answered ann; the roster gets bea and cal connected to each other
  await waitFor(() => up(ann, bea, cal) && up(bea, ann, cal) && up(cal, ann, bea), 'full mesh');
  const bc = linkTo(bea, cal).pc, cb = linkTo(cal, bea).pc;
  assert.equal(cb.remoteDescription.sdp, bc.localDescription.sdp, 'bea and cal negotiated directly');
  for (const p of pushed) assert.ok(!p.includes(bc.fp) && !p.includes(cb.fp), 'SDP is not visible to the server');

  // mute and camera show on everyone else's side
  bea.voice.setMuted(true);
  await waitFor(() => linkTo(ann, bea).peerMuted && linkTo(cal, bea).peerMuted, 'mute seen');
  assert.equal(linkTo(bea, ann).pc.tracks[0].enabled, false);
  await cal.voice.setCamera(true);
  await waitFor(() => linkTo(ann, cal).peerCam && linkTo(bea, cal).peerCam, 'camera seen');
  const cam = linkTo(cal, ann).tx.cam.sender.track;
  assert.equal(cam.kind, 'camera');
  assert.equal(linkTo(cal, bea).tx.cam.sender.track, cam, 'one camera on every connection');

  // anyone in the call can ring someone else in; they meet everyone
  assert.equal(await bea.voice.invite([dan.me.userId, cal.me.userId]), 1, 'cal is already in');
  await waitFor(() => state(dan) === 'ringing', 'dan rings');
  assert.equal(dan.voice.call.peer, bea.me.userId);
  await dan.voice.accept();
  await waitFor(() => up(dan, ann, bea, cal) && up(ann, dan) && up(bea, dan) && up(cal, dan), 'dan meshed');
  // what was already on reaches the newcomer too
  await waitFor(() => linkTo(dan, cal).peerCam && linkTo(dan, bea).peerMuted, 'newcomer sees camera and mute');
  assert.equal(linkTo(cal, dan).tx.cam.sender.track, cam);

  // leaving takes one person out; the rest carry on
  await bea.voice.hangup();
  await waitFor(() => !linkTo(ann, bea) && !linkTo(cal, bea) && !linkTo(dan, bea), 'bea gone');
  assert.equal(bea.voice.call, null);
  assert.equal(state(ann), 'active');
  assert.equal(ann.voice.call.links.size, 2);
  await ann.voice.hangup();
  await cal.voice.hangup();
  await waitFor(() => !dan.voice.call, 'the last one left alone hangs up');
  assert.ok(cam.stopped, 'camera released');
  for (const c of [ann, bea, cal, dan]) {
    await waitFor(() => gsys(c, gid).length, 'history');
    assert.match(gsys(c, gid)[0], /^group call · 0:0\d$/);
    assert.equal(c.unread.get('g:' + gid) || 0, 0);
  }
});

test('group calls: declines, misses, quiet offers, strangers to the group and muted members', async () => {
  const [gid, eli, fay, gus] = await crew(['geli', 'gfay', 'ggus'], { ring: 1500 });
  await eli.voice.start('g:' + gid, [fay.me.userId, gus.me.userId]);
  await waitFor(() => state(fay) === 'ringing' && state(gus) === 'ringing', 'ringing');
  await fay.voice.decline();
  await waitFor(() => !eli.voice.call && !gus.voice.call, 'rings out');
  await waitFor(() => gsys(eli, gid).length && gsys(fay, gid).length && gsys(gus, gid).length, 'history');
  assert.deepEqual(gsys(eli, gid), ['no one joined the group call']);
  assert.deepEqual(gsys(fay, gid), ['declined group call']);
  assert.deepEqual(gsys(gus, gid), ['missed group call from geli']);
  assert.equal(gus.unread.get('g:' + gid), 1);

  // an offer that only joins up a call (no ring) never rings someone who is not in it
  await eli.voice._sig(fay.me.userId, 'not-a-call', gid, 'offer', { sdp: 'v=0' });
  await new Promise(r => setTimeout(r, 300));
  assert.equal(fay.voice.call, null);

  // only members can be called, and only members can ring
  const out = client();
  await out.signup('gout', PASS);
  await live(out);
  await befriend(out, eli);
  await assert.rejects(eli.voice.start('g:' + gid, [out.me.userId]), /pick someone/);
  await assert.rejects(out.voice.start('g:' + gid, [eli.me.userId]), /not in this group/);

  // a member muted in the group cannot ring it
  await eli.muteInGroup(gid, gus.me.userId, 10);
  await waitFor(() => gus.groupMuteEnd(gid) !== undefined, 'mute pushed');
  await assert.rejects(gus.voice.start('g:' + gid, [eli.me.userId]), /muted/);
  assert.equal(gus.voice.call, null);
  await new Promise(r => setTimeout(r, 200));
  assert.equal(eli.voice.call, null);
});
