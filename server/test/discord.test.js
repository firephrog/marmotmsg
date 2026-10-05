'use strict';
/**
 * Discord link: real clients and a real server, with a fake Discord on the
 * other side of the bridge.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');
const { createServer } = require('../server');
const { fakeDiscord } = require('./fake-discord');
const { hookName, displayText, normCode } = require('../discord');
const F = require('../filter');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'client', 'index.html'), 'utf8');
const core = html.split('/*<marmot-core>*/')[1].split('/*</marmot-core>*/')[0];
const { MarmotClient } = new Function(core + '\nreturn {MarmotClient};')();

const PASS = 'correct horse battery';
const TOKEN = 'fake-bot-token';
let srv, base, dataDir, dc;
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
const chat = (c, linkId) => c.thread('dc:' + linkId).map(m => (m.dir === 'sys' ? '* ' : (m.author || 'me') + ': ') + m.text);
const jake = { id: '9001', username: 'jake', global_name: 'Jake' };

test.before(async () => {
  dc = await fakeDiscord(TOKEN);
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-dc-'));
  srv = createServer({ dataDir, key: Buffer.alloc(32, 9), authPerMinute: 1000, discord: { token: TOKEN, api: dc.api } });
  await new Promise(r => srv.server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + srv.server.address().port;
  await dc.ready();
});
test.after(async () => {
  for (const c of clients) c._reset();
  await new Promise(r => srv.server.close(r));
  srv.db.close();
  await dc.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('the bot identifies with the message-content intent and registers /marmot', () => {
  assert.ok(dc.st.intents & (1 << 15));
  assert.equal(dc.st.commands[0].name, 'marmot');
  assert.deepEqual(dc.st.commands[0].options.map(o => o.name), ['link', 'unlink', 'invite', 'members', 'kick', 'public', 'filter']);
});

test('link, invite, join, and messages both ways', async () => {
  assert.match(await dc.slash('c1', 'link', {}, '0'), /Manage Server/, 'non-moderators are refused');
  assert.match(await dc.slash('c1', 'invite'), /not linked/);
  assert.match(await dc.slash('c1', 'link'), /Linked \*\*#general\*\*/);
  assert.match(await dc.slash('c1', 'link'), /already linked/);
  const code = /`([A-Z0-9]{5}-[A-Z0-9]{5})`/.exec(await dc.slash('c1', 'invite', { uses: 2 }))[1];

  const amy = client(), ben = client(), cal = client();
  await amy.signup('amy', PASS); await ben.signup('ben', PASS); await cal.signup('cal', PASS);
  await Promise.all([live(amy), live(ben), live(cal)]);
  await amy.loadLinks();
  assert.equal(amy.discordEnabled, true);
  assert.equal(amy.links.size, 0);

  await assert.rejects(amy.joinDiscord('AAAAA-BBBBB'), /not valid/);
  const link = await amy.joinDiscord(code.toLowerCase().replace('-', ' '));   // case and separators don't matter
  assert.deepEqual([link.guild, link.channel], ['Rat Den', 'general']);
  await ben.joinDiscord(code);
  await assert.rejects(cal.joinDiscord(code), /not valid/, 'two uses, both spent');
  const L = link.linkId;
  assert.equal(amy.displayName('dc:' + L), '#general');
  assert.ok(amy.conversations().some(c => c.id === 'dc:' + L));
  await waitFor(() => chat(amy, L).includes('* ben joined from Marmot'), 'join notice on Marmot');
  await waitFor(() => dc.st.posts.some(p => p.content === '**ben** joined from Marmot'), 'join notice on Discord');

  // Discord → Marmot, with mentions made readable
  dc.say('c1', jake, 'hey <@42> and <@9999>', { member: { nick: 'jakey' }, mentions: [{ id: '42', username: 'amy_dc', global_name: 'Amy D' }] });
  await waitFor(() => chat(ben, L).includes('jakey: hey @Amy D and @someone'), 'ben receives');
  await waitFor(() => chat(amy, L).includes('jakey: hey @Amy D and @someone'), 'amy receives');
  assert.equal(amy.unread.get('dc:' + L), 1);

  // Marmot → Discord: posted as "amy · marmot", relayed to ben, and the gateway echo is not delivered back
  const before = dc.st.posts.length;
  await amy.sendText('dc:' + L, 'hi @everyone from marmot');
  const post = dc.st.posts[before];
  assert.equal(post.author.username, 'amy · marmot');
  assert.equal(post.content, 'hi @everyone from marmot');
  assert.deepEqual(post.allowed_mentions, { parse: [] }, 'nobody gets pinged');
  await waitFor(() => chat(ben, L).includes('amy: hi @everyone from marmot'), 'ben sees amy');
  await new Promise(r => setTimeout(r, 200));
  assert.equal(chat(amy, L).filter(t => t.includes('from marmot')).length, 1, 'no echo');
  assert.equal(amy.thread('dc:' + L).find(m => m.dir === 'out').state, 'sent');

  // ben is offline when a message arrives, and gets it on his next sign-in
  ben._reset();
  dc.say('c1', jake, 'while you were out');
  await waitFor(() => chat(amy, L).includes('Jake: while you were out'), 'amy receives');
  const ben2 = client();
  await ben2.login('ben', PASS);
  await waitFor(() => chat(ben2, L).includes('Jake: while you were out'), 'mailbox delivery');
  assert.ok(ben2.links.has(L));

  // other channels and bots are ignored
  dc.say('c2', jake, 'not bridged');
  dc.say('c1', { id: 'bot1', username: 'Marmot', bot: true }, 'my own words');
  await new Promise(r => setTimeout(r, 200));
  assert.ok(!chat(amy, L).some(t => /not bridged|own words/.test(t)));

  assert.match(await dc.slash('c1', 'members'), /\(2\): `amy`, `ben`/);

  // kick
  assert.match(await dc.slash('c1', 'kick', { username: 'ben' }), /Removed `ben`/);
  await waitFor(() => !ben2.links.has(L), 'ben loses the channel');
  await waitFor(() => chat(ben2, L).includes('* a Discord moderator removed you from this channel'), 'ben told');
  await assert.rejects(ben2.sendText('dc:' + L, 'let me back'), /not in this channel/);
  await assert.rejects(ben2.api('POST', '/api/discord/send', { link: L, text: 'sneaky' }), /not in this channel/);

  // leave
  await ben2.joinDiscord(/`([A-Z0-9]{5}-[A-Z0-9]{5})`/.exec(await dc.slash('c1', 'invite'))[1]);
  await ben2.leaveDiscord(L);
  await waitFor(() => dc.st.posts.some(p => p.content === '**ben** left'), 'leave notice on Discord');
  await waitFor(() => chat(amy, L).includes('* ben left'), 'amy told');

  // unlink
  assert.match(await dc.slash('c1', 'unlink'), /Unlinked/);
  await waitFor(() => amy.links.size === 0, 'amy loses the channel');
  assert.ok(chat(amy, L).some(t => t.startsWith('* this channel is no longer linked')));
  assert.equal(srv.db.linkByChannel('c1'), undefined);
});

test('a webhook deleted in Discord is recreated on the next send', async () => {
  await dc.slash('c2', 'link');
  const code = /`([A-Z0-9]{5}-[A-Z0-9]{5})`/.exec(await dc.slash('c2', 'invite'))[1];
  const dee = client();
  await dee.signup('dee', PASS);
  const { linkId } = await dee.joinDiscord(code);
  await waitFor(() => dc.st.posts.some(p => p.content === '**dee** joined from Marmot'), 'join notice');
  dc.st.hooks.clear();
  // two posts notice the missing webhook at once; only one replacement is made
  await Promise.all([dee.sendText('dc:' + linkId, 'still works'), srv.bridge.post(srv.db.link(linkId), { content: 'notice', username: 'Marmot' })]);
  assert.ok(dc.st.posts.slice(-2).some(p => p.content === 'still works'));
  assert.equal(dc.st.hooks.size, 1);
  assert.ok(srv.db.link(linkId).webhookId === [...dc.st.hooks.keys()][0]);
});

test('deleting the Discord channel unlinks it; account deletion drops memberships', async () => {
  const eve = client(), fay = client();
  await eve.signup('eve', PASS); await fay.signup('fay', PASS);
  await live(eve);
  const code = /`([A-Z0-9]{5}-[A-Z0-9]{5})`/.exec(await dc.slash('c2', 'invite', { uses: 5 }))[1];
  const { linkId } = await eve.joinDiscord(code);
  await fay.joinDiscord(code);
  const fayId = fay.me.userId;
  assert.equal(srv.db.members(linkId).length, 3);
  await fay.deleteAccount(PASS);
  const left = srv.db.members(linkId);
  assert.ok(!left.includes(fayId) && left.includes(eve.me.userId) && left.length === 2, 'dee and eve remain');
  dc.dispatch('CHANNEL_DELETE', { id: 'c2', guild_id: 'g1' });
  await waitFor(() => eve.links.size === 0, 'eve loses the channel');
});

test('/marmot filter and /marmot public', async () => {
  dc.st.channels.c3 = { id: 'c3', name: 'lobby', guild_id: 'g1' };
  await dc.slash('c3', 'link');
  assert.match(await dc.slash('c3', 'public', { enabled: true }), /needs a chat filter/, 'no filter, no public');
  assert.match(await dc.slash('c3', 'filter'), /Level:\*\* off/);
  assert.match(await dc.slash('c3', 'filter', { level: 'standard', add: 'pineapple, durian*' }), /updated[\s\S]*`pineapple`, `durian\*`/);

  const hal = client(), ivy = client(), joy = client(), shitlord = client();
  await hal.signup('hal', PASS); await ivy.signup('ivy', PASS); await joy.signup('joy', PASS); await shitlord.signup('shitlord', PASS);
  await Promise.all([live(hal), live(ivy)]);
  await hal.loadLinks();
  assert.equal(hal.publicLinks.length, 0);
  await assert.rejects(hal.joinPublic(srv.db.linkByChannel('c3').id), /not public/);

  assert.match(await dc.slash('c3', 'public', { enabled: true }), /now public/);
  await waitFor(() => hal.publicLinks.length === 1, 'everyone online hears about it');
  await waitFor(() => dc.st.posts.some(p => p.channel_id === 'c3' && /public on Marmot/.test(p.content)), 'Discord is told');
  assert.match(await dc.slash('c3', 'filter', { level: 'off', remove: 'pineapple, durian*' }), /can't be turned off/);
  assert.match(await dc.slash('c3', 'public', { enabled: true }), /already public/);

  const L = hal.publicLinks[0].linkId;
  assert.deepEqual([hal.publicLinks[0].guild, hal.publicLinks[0].channel], ['Rat Den', 'lobby']);
  await hal.joinPublic(L);
  await ivy.loadLinks();
  await ivy.joinPublic(L);
  await assert.rejects(shitlord.joinPublic(L), /username is not allowed/);
  assert.ok(hal.links.has(L));

  // censor mode: the word is starred on Discord, for other members, and in the sender's own history
  const said = 'what the f*****, I love p******** and d******. Scunthorpe is fine';
  const before = dc.st.posts.length;
  await hal.sendText('dc:' + L, 'what the fuuuck, I love pineapple and durians. Scunthorpe is fine');
  assert.equal(dc.st.posts[before].content, said);
  await waitFor(() => chat(ivy, L).includes('hal: ' + said), 'ivy sees the censored text');
  assert.ok(chat(hal, L).includes('me: ' + said));

  // block mode and links
  await dc.slash('c3', 'filter', { mode: 'block', links: true });
  await assert.rejects(hal.sendText('dc:' + L, 'oh sh1t'), /filter blocked/);
  await assert.rejects(hal.sendText('dc:' + L, 'see https://example.com'), /links are not allowed/);
  assert.equal(dc.st.posts.length, before + 1, 'nothing more reached Discord');
  await hal.sendText('dc:' + L, 'all good here');

  // a kick sticks for the public list; an invite code lets them back
  await dc.slash('c3', 'kick', { username: 'ivy' });
  await waitFor(() => !ivy.links.has(L), 'ivy removed');
  await assert.rejects(ivy.joinPublic(L), /removed you/);
  await ivy.joinDiscord(/`([A-Z0-9]{5}-[A-Z0-9]{5})`/.exec(await dc.slash('c3', 'invite'))[1]);
  assert.ok(ivy.links.has(L));

  // back to invite-only: members stay, nobody new gets in without a code
  assert.match(await dc.slash('c3', 'public', { enabled: false }), /invite-only again/);
  await waitFor(() => hal.publicLinks.length === 0, 'the public list empties');
  await joy.loadLinks();
  await assert.rejects(joy.joinPublic(L), /not public/);
  assert.equal(srv.db.members(L).length, 2);
  assert.match(await dc.slash('c3', 'filter', { level: 'off', mode: 'censor', links: false, remove: 'pineapple, durian*' }), /needs a chat filter|needs a filter/);
});

test('filter matching', () => {
  const f = { level: 'slurs', mode: 'censor', words: ['ass'], links: false };
  assert.equal(F.check(f, 'as you wish, asss, class, a$$').text, 'as you wish, a***, class, a**');
  assert.equal(F.check({ level: 'strict' }, 'bob has boobs').text, 'bob has b****');
  assert.equal(F.check({ level: 'off' }, 'fuck').text, 'fuck');
  assert.deepEqual(F.parseWords('Foo, b@r*  ,,'), { ok: ['foo', 'bar*'], bad: [] });
  assert.equal(F.isActive({}), false);
  assert.equal(F.isActive({ links: true }), true);
});

test('the database holds no Discord plaintext at rest', async () => {
  srv.db.raw.pragma('wal_checkpoint(TRUNCATE)');
  const file = fs.readFileSync(path.join(dataDir, 'marmot.db')).toString('latin1');
  for (const s of ['Rat Den', 'while you were out', 'jakey', 'lobby', 'pineapple']) assert.ok(!file.includes(s), s);
});

test('helpers', () => {
  assert.equal(hookName('discordfan'), 'd​iscordfan · marmot');
  assert.equal(normCode('abcde-fghij'), 'ABCDEFGHIJ');
  assert.equal(displayText({ content: 'look <:blob:123>', attachments: [{ url: 'https://cdn/x.png' }] }), 'look :blob:\nhttps://cdn/x.png');
});

test('without a bot token the Discord endpoints say so', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marmot-nodc-'));
  const plain = createServer({ dataDir: dir, key: Buffer.alloc(32, 3), authPerMinute: 1000 });
  await new Promise(r => plain.server.listen(0, '127.0.0.1', r));
  const c = new MarmotClient({ iter: 300000 });
  c.setServer('http://127.0.0.1:' + plain.server.address().port);
  await c.signup('gus', PASS);
  await c.loadLinks();
  assert.equal(c.discordEnabled, false);
  await assert.rejects(c.joinDiscord('AAAAA-BBBBB'), /not enabled/);
  c._reset();
  await new Promise(r => plain.server.close(r));
  plain.db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
