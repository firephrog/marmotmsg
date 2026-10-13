'use strict';
/**
 * Auto-update: the server hands out the client it serves and the version read
 * out of it, and the client file carries what an update needs.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createServer } = require('../server');

const clientPath = path.join(__dirname, '..', '..', 'client', 'index.html');
const html = fs.readFileSync(clientPath, 'utf8');
const VERSION = html.match(/const VERSION='([\d.]+)'/)[1];

let srv, base, dataDir, clientFile;
const get = async p => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-update-'));
  clientFile = path.join(dataDir, 'index.html');
  fs.writeFileSync(clientFile, html);
  srv = createServer({ dataDir, key: Buffer.alloc(32, 7), clientFile });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
});
test.after(async () => {
  await new Promise(r => srv.server.close(r));
  srv.db.close && srv.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('the version is read out of the served client', async () => {
  const r = await get('/api/client/version');
  assert.equal(r.status, 200);
  assert.equal(r.body.v, VERSION);
});

test('the client comes whole over the api', async () => {
  const r = await get('/api/client');
  assert.equal(r.body.v, VERSION);
  assert.equal(r.body.html, html);
});

test('a changed client file is picked up without a restart', async () => {
  fs.writeFileSync(clientFile, html.replace("const VERSION='" + VERSION + "'", "const VERSION='99.0.0'") + '\n');
  assert.equal((await get('/api/client/version')).body.v, '99.0.0');
  assert.match((await get('/api/client')).body.html, /const VERSION='99\.0\.0'/);
  fs.writeFileSync(clientFile, html);
});

test('server and client versions move together', async () => {
  assert.equal((await get('/api/health')).body.v, VERSION);
  assert.equal(require('../package.json').version, VERSION);
});

test('the patch notes are data, and the newest is this version', () => {
  const m = html.match(/<script type="application\/json" id="patchNotes">([\s\S]*?)<\/script>/);
  assert.ok(m, 'patch notes block');
  const notes = JSON.parse(m[1]);
  assert.equal(notes[0].v, VERSION);
  for (const n of notes) {
    assert.equal(typeof n.v, 'string');
    for (const k of ['features', 'fixes']) if (n[k]) assert.ok(n[k].every(x => typeof x === 'string'));
  }
});

test('the client script declares nothing global, so an update can be written over it', () => {
  const main = html.match(/<script>([\s\S]*?)<\/script>/)[1].trim();
  const body = main.replace(/^'use strict';\s*/, '').replace(/^\/\*[\s\S]*?\*\/\s*/, '');
  assert.ok(body.startsWith('{'), 'opens with a block');
  assert.ok(body.endsWith('}'), 'closes the block');
  new Function(main);   // and parses
});
