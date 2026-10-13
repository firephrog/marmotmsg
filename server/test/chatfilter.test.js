'use strict';
/**
 * The reader's chat filter (chatFilter and MarmotClient#filtered in the
 * <marmot-core> section of client/index.html): what each level catches,
 * what it lets through, and that only other people's messages are checked.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'client', 'index.html'), 'utf8');
const core = html.split('/*<marmot-core>*/')[1].split('/*</marmot-core>*/')[0];
const { chatFilter, MarmotClient } = new Function(core + '\nreturn {chatFilter, MarmotClient};')();

const LEVELS = ['none', 'slurs', 'swears', 'strict'];
/** The lowest level that catches text, or null if none does. */
const caughtFrom = text => LEVELS.find(l => chatFilter.test(l, text)) || null;

test('each level catches what it should, and the levels above it do too', () => {
  const want = {
    'you n1gger': 'slurs', 'what a retard': 'slurs',
    'what the fuck': 'swears', 'fuuuuck': 'swears', 'sh1t happens': 'swears', 'damn it': 'swears',
    'wtf is this': 'strict', 'stfu': 'strict', 'f**k off': 'strict', 'sh*t': 'strict', 'f***ing hell': 'strict',
    'f u c k': 'strict', 's.h.i.t': 'strict', 'fu-ck': 'strict'
  };
  for (const [text, from] of Object.entries(want)) {
    assert.equal(caughtFrom(text), from, text);
    for (const l of LEVELS.slice(LEVELS.indexOf(from))) assert.ok(chatFilter.test(l, text), text + ' at ' + l);
  }
});

test('ordinary text gets through even on strict', () => {
  for (const text of ['hello there', 'classic Scunthorpe assassin', 'kung fu', 'I a m here', 'that is a b c',
    '*hugs*', '**bold**', 'grass', 'lol idk', '#hashtag', 'a* search', ''])
    assert.equal(chatFilter.test('strict', text), false, text);
});

test('only messages from other people are filtered, at the saved level', () => {
  const c = new MarmotClient({ WebSocket });
  const msg = { dir: 'in', text: 'what the fuck' };
  assert.deepEqual(c.filter(), { level: 'none', action: 'hide' });
  assert.equal(c.filtered(msg), false);
  c.recs.set('pref:filter', { level: 'swears', action: 'delete' });
  assert.deepEqual(c.filter(), { level: 'swears', action: 'delete' });
  assert.equal(c.filtered(msg), true);
  assert.equal(c.filtered({ dir: 'out', text: 'what the fuck' }), false);
  assert.equal(c.filtered({ dir: 'in', text: 'what the fuck', deleted: true }), false);
  c.recs.set('pref:filter', { level: 'slurs', action: 'hide' });
  assert.equal(c.filtered(msg), false, 'a changed level is not answered from the memo');
  c.recs.set('pref:filter', { level: 'bogus', action: 'nope' });
  assert.deepEqual(c.filter(), { level: 'none', action: 'hide' });
});
