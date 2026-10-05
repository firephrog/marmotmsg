'use strict';
/**
 * Discord link: bridges a Discord channel with Marmot users who joined it by
 * invite code.
 *
 * Trust: this part of the server reads bridged messages in plaintext. Discord
 * has no end-to-end encryption, so somebody has to translate, and here it is
 * the server. Marmot → Discord text is posted through a channel webhook as
 * "<username> · marmot"; Discord → Marmot text is fanned out to members as
 * server-originated envelopes (from "dc:<linkId>") through the ordinary
 * mailbox, so offline members get it when they come back. Clients label these
 * chats as not end-to-end encrypted.
 *
 * The Discord side is a small gateway + REST client rather than a library, so
 * the tests can run it against a fake Discord.
 */
const crypto = require('crypto');
const WebSocket = require('ws');
const F = require('./filter');

const API = 'https://discord.com/api/v10';
// GUILDS | GUILD_MESSAGES | MESSAGE_CONTENT (privileged: enable it in the developer portal)
const INTENTS = (1 << 0) | (1 << 9) | (1 << 15);
const ADMINISTRATOR = 1n << 3n, MANAGE_GUILD = 1n << 5n;
const FATAL_CLOSE = {
  4004: 'the bot token was rejected',
  4013: 'invalid gateway intents',
  4014: 'the Message Content intent is not enabled — turn it on under Bot in the Discord developer portal'
};
const MAX_TEXT = 2000;           // Discord's message limit
const MAX_MEMBERS = 500;         // Marmot users per linked channel
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ------------------------------------------------------------ the bot */
class Discord {
  constructor({ token, api, log }) {
    this.token = token;
    this.api = (api || API).replace(/\/+$/, '');
    this.log = log || console;
    this.handlers = new Map();
    this.ws = null; this.seq = null; this.user = null; this.appId = null;
    this.ready = false; this.stopped = false; this.backoff = 1000;
  }
  on(ev, fn) { if (!this.handlers.has(ev)) this.handlers.set(ev, []); this.handlers.get(ev).push(fn); return this; }
  emit(ev, d) {
    for (const fn of this.handlers.get(ev) || []) {
      Promise.resolve().then(() => fn(d)).catch(e => this.log.error('[discord] ' + ev + ' handler:', e.message));
    }
  }

  async rest(method, path, body, attempt) {
    attempt = attempt || 0;
    const res = await fetch(this.api + path, {
      method,
      headers: { Authorization: 'Bot ' + this.token, 'Content-Type': 'application/json', 'User-Agent': 'DiscordBot (marmot, 0.3)' },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await res.text();
    let j = null; try { j = text ? JSON.parse(text) : null; } catch (e) {}
    if (res.status === 429 && attempt < 3) {
      await sleep(Math.min(10, (j && j.retry_after) || 1) * 1000);
      return this.rest(method, path, body, attempt + 1);
    }
    if (!res.ok) {
      const err = new Error('Discord ' + method + ' ' + path.split('?')[0].replace(/\/[\w-]{40,}/g, '/…') + ' failed: ' + res.status + (j && j.message ? ' ' + j.message : ''));
      err.status = res.status; err.code = j && j.code;
      throw err;
    }
    return j;
  }

  async start() {
    const g = await this.rest('GET', '/gateway/bot');
    this.gateway = g.url + (g.url.includes('?') ? '&' : '?') + 'v=10&encoding=json';
    this._connect();
  }
  stop() { this.stopped = true; clearInterval(this._beat); if (this.ws) this.ws.terminate(); }

  _send(op, d) { if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify({ op, d })); }
  _connect() {
    const ws = new WebSocket(this.gateway);
    this.ws = ws;
    let acked = true;
    ws.on('message', data => {
      let p; try { p = JSON.parse(data); } catch (e) { return; }
      if (p.s != null) this.seq = p.s;
      switch (p.op) {
        case 10:   // hello: heartbeat on its interval, then identify (no resume: a reconnect re-identifies)
          clearInterval(this._beat);
          this._beat = setInterval(() => {
            if (!acked) { ws.terminate(); return; }   // zombie connection
            acked = false; this._send(1, this.seq);
          }, p.d.heartbeat_interval);
          this._send(2, { token: this.token, intents: INTENTS, properties: { os: process.platform, browser: 'marmot', device: 'marmot' } });
          break;
        case 11: acked = true; break;
        case 1: this._send(1, this.seq); break;
        case 7: ws.close(4000, 'reconnect requested'); break;
        case 9: setTimeout(() => ws.close(4000, 'invalid session'), 1000 + Math.random() * 4000); break;
        case 0:
          if (p.t === 'READY') {
            this.user = p.d.user; this.appId = p.d.application && p.d.application.id;
            this.ready = true; this.backoff = 1000;
            this.log.log('[discord] connected as ' + p.d.user.username);
          }
          this.emit(p.t, p.d);
          break;
      }
    });
    ws.on('error', e => this.log.warn('[discord] gateway error:', e.message));
    ws.on('close', code => {
      clearInterval(this._beat);
      this.ready = false;
      if (this.ws !== ws || this.stopped) return;
      if (FATAL_CLOSE[code]) { this.log.error('[discord] stopped: ' + FATAL_CLOSE[code]); return; }
      setTimeout(() => this._connect(), this.backoff);
      this.backoff = Math.min(60000, this.backoff * 2);
    });
  }
}

/* --------------------------------------------------------- the bridge */
const COMMAND = {
  name: 'marmot', type: 1, description: 'Bridge this channel with Marmot',
  default_member_permissions: String(MANAGE_GUILD), contexts: [0],
  options: [
    { type: 1, name: 'link', description: 'Bridge this channel to Marmot' },
    { type: 1, name: 'unlink', description: 'Stop bridging this channel and remove its Marmot members' },
    { type: 1, name: 'invite', description: 'Create an invite code that lets Marmot users join this channel', options: [
      { type: 4, name: 'uses', description: 'How many people can use it (default 1)', min_value: 1, max_value: 100 },
      { type: 4, name: 'hours', description: 'Hours until it expires (default 24)', min_value: 1, max_value: 720 }] },
    { type: 1, name: 'members', description: 'List the Marmot users in this channel' },
    { type: 1, name: 'kick', description: 'Remove a Marmot user from this channel', options: [
      { type: 3, name: 'username', description: 'Their Marmot username', required: true }] },
    { type: 1, name: 'public', description: 'Let every Marmot user join this channel without an invite (needs /marmot filter)', options: [
      { type: 5, name: 'enabled', description: 'On: anyone on Marmot can join and post. Off: invite codes only', required: true }] },
    { type: 1, name: 'filter', description: 'Show or change the chat filter for messages from Marmot', options: [
      { type: 3, name: 'level', description: 'Built-in word list', choices: [
        { name: 'off', value: 'off' }, { name: 'slurs only', value: 'slurs' },
        { name: 'slurs and swearing', value: 'standard' }, { name: 'strict: also mild language', value: 'strict' }] },
      { type: 3, name: 'mode', description: 'What happens to a caught message', choices: [
        { name: 'censor the word', value: 'censor' }, { name: 'block the message', value: 'block' }] },
      { type: 3, name: 'add', description: 'Words to add, separated by commas; end one with * to match words starting with it', max_length: 1000 },
      { type: 3, name: 'remove', description: 'Words to remove, separated by commas', max_length: 1000 },
      { type: 5, name: 'links', description: 'Block messages that contain links' }] }
  ]
};

/** Invite codes: 10 characters of base32, shown as XXXXX-XXXXX; case and dashes don't matter. */
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newCode() {
  const b = crypto.randomBytes(10);
  let s = ''; for (let i = 0; i < 10; i++) s += ALPHA[b[i] % 32];
  return s.slice(0, 5) + '-' + s.slice(5);
}
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

/** Webhook names may not contain "discord" or "clyde"; break them up rather than refuse. */
const hookName = name => (String(name).replace(/(discord|clyde)/gi, m => m[0] + '​' + m.slice(1)) + ' · marmot').slice(0, 80);

function displayText(m) {
  const who = u => (u.member && u.member.nick) || u.global_name || u.username;
  let t = String(m.content || '')
    .replace(/<@!?(\d+)>/g, (x, id) => { const u = (m.mentions || []).find(u => u.id === id); return u ? '@' + who(u) : '@someone'; })
    .replace(/<@&\d+>/g, '@role')
    .replace(/<a?(:\w+:)\d+>/g, '$1');
  for (const a of m.attachments || []) t += (t ? '\n' : '') + a.url;
  if (!t && (m.sticker_items || []).length) t = '[sticker: ' + m.sticker_items[0].name + ']';
  return t;
}

class Bridge {
  constructor({ db, hub, discord, log }) {
    this.db = db; this.hub = hub; this.discord = discord; this.log = log || console;
  }

  async start() {
    const d = this.discord;
    d.on('READY', () => this.registerCommands());
    d.on('MESSAGE_CREATE', m => this.onMessage(m));
    d.on('INTERACTION_CREATE', i => this.onInteraction(i));
    d.on('CHANNEL_DELETE', c => { const l = this.db.linkByChannel(c.id); if (l) this.unlink(l, 'the Discord channel was deleted'); });
    d.on('GUILD_DELETE', g => { if (!g.unavailable) for (const l of this.db.linksByGuild(g.id)) this.unlink(l, 'the Marmot bot was removed from the Discord server'); });
    await d.start();
  }
  stop() { this.discord.stop(); }

  async registerCommands() {
    await this.discord.rest('PUT', '/applications/' + this.discord.appId + '/commands', [COMMAND]);
  }

  /* ---- fan-out to Marmot ---- */
  deliver(linkId, payload, exceptUserId) {
    const to = this.db.members(linkId).filter(u => u !== exceptUserId);
    const from = 'dc:' + linkId, body = JSON.stringify(Object.assign({ k: 'dc', link: linkId }, payload));
    for (const s of this.db.deliver(to.map(u => ({ to: u, from, payload: body })))) {
      this.hub.push(s.to, { t: 'env', env: { id: s.id, from, ts: s.ts, payload: s.payload } });
    }
  }
  /** Removes a link, telling its Marmot members first. */
  unlink(link, why) {
    const members = this.db.members(link.id);
    this.deliver(link.id, { t: 'sys', text: 'this channel is no longer linked: ' + why, gone: true });
    this.db.deleteLink(link.id);
    for (const u of members) this.hub.push(u, { t: 'links' });
    this.discord.rest('DELETE', '/webhooks/' + link.webhookId).catch(() => {});
  }

  /* ---- Discord → Marmot ---- */
  onMessage(m) {
    if (!m.guild_id) return;
    const link = this.db.linkByChannel(m.channel_id);
    if (!link) return;
    if (m.webhook_id && m.webhook_id === link.webhookId) return;      // our own relay of a Marmot message
    if (this.discord.user && m.author && m.author.id === this.discord.user.id) return;
    if (m.type !== 0 && m.type !== 19) return;                        // plain messages and replies
    const text = displayText(m);
    if (!text) return;
    const author = (m.member && m.member.nick) || m.author.global_name || m.author.username;
    this.deliver(link.id, { t: 'msg', id: m.id, author, text: text.slice(0, 8000), ts: Date.parse(m.timestamp) || Date.now(), src: 'discord' });
  }

  /* ---- Marmot → Discord ---- */
  async post(link, body) {
    const path = l => '/webhooks/' + l.webhookId + '/' + l.webhookToken + '?wait=true';
    try { return await this.discord.rest('POST', path(link), body); }
    catch (e) {
      if (e.status !== 404) throw e;
      // someone deleted the webhook in Discord: make a new one and try once more
      return this.discord.rest('POST', path(await this.rehook(link)), body);
    }
  }
  /** One replacement webhook per link, however many posts notice the old one is gone. */
  rehook(stale) {
    this._rehooks = this._rehooks || new Map();
    if (this._rehooks.has(stale.id)) return this._rehooks.get(stale.id);
    const p = (async () => {
      const cur = this.db.link(stale.id);
      if (!cur) throw Object.assign(new Error('link removed'), { status: 404 });
      if (cur.webhookId !== stale.webhookId) return cur;              // already replaced
      const h = await this.discord.rest('POST', '/channels/' + cur.channelId + '/webhooks', { name: 'Marmot' });
      this.db.updateLink(cur.id, { webhookId: h.id, webhookToken: h.token });
      return Object.assign({}, cur, { webhookId: h.id, webhookToken: h.token });
    })().finally(() => this._rehooks.delete(stale.id));
    this._rehooks.set(stale.id, p);
    return p;
  }
  async send(user, linkId, text) {
    const link = this.db.link(linkId);
    if (!link || !this.db.isMember(linkId, user.id)) throw Object.assign(new Error('you are not in this channel'), { status: 403 });
    text = String(text || '');
    if (!text.trim()) throw Object.assign(new Error('empty message'), { status: 400 });
    if (text.length > MAX_TEXT) throw Object.assign(new Error('Discord messages are limited to ' + MAX_TEXT + ' characters'), { status: 400 });
    const f = F.check(link.filter, text);
    if (!f.ok) throw Object.assign(new Error(f.reason), { status: 400 });
    text = f.text;
    let msg;
    try { msg = await this.post(link, { content: text, username: hookName(this.shownName(link, user)), allowed_mentions: { parse: [] } }); }
    catch (e) { this.log.warn('[discord] send failed:', e.message); throw Object.assign(new Error('Discord did not accept the message'), { status: 502 }); }
    const ts = Date.parse(msg.timestamp) || Date.now();
    this.deliver(linkId, { t: 'msg', id: msg.id, author: user.username, text, ts, src: 'marmot' }, user.id);
    return { id: msg.id, ts, text };
  }
  /** A username as Discord sees it: starred where it trips the channel's filter. */
  shownName(link, user) {
    return F.check(Object.assign(F.normalize(link.filter), { mode: 'censor', links: false }), user.username).text;
  }

  join(user, code) {
    const r = this.db.redeemInvite(normCode(code), user.id, MAX_MEMBERS);
    if (!r) throw Object.assign(new Error('that invite code is not valid or has expired'), { status: 404 });
    // an invite from a moderator overrides an earlier kick
    if ((r.link.barred || []).includes(user.id)) this.db.updateLink(r.link.id, { barred: r.link.barred.filter(u => u !== user.id) });
    if (!r.already) this.joined(r.link, user);
    return r.link;
  }
  /** Joins a public channel: no code, but the channel's filter has to accept the username. */
  joinPublic(user, linkId) {
    const link = this.db.link(linkId);
    const no = () => Object.assign(new Error('that channel is not public'), { status: 404 });
    if (!link || !link.public) throw no();
    if ((link.barred || []).includes(user.id)) throw Object.assign(new Error('a Discord moderator removed you from this channel; ask them for an invite code'), { status: 403 });
    if (F.catches(link.filter, user.username)) throw Object.assign(new Error('your username is not allowed by this channel\'s chat filter'), { status: 403 });
    const r = this.db.joinPublic(link.id, user.id, MAX_MEMBERS);
    if (!r) throw no();
    if (!r.already) this.joined(r.link, user);
    return r.link;
  }
  joined(link, user) {
    this.deliver(link.id, { t: 'sys', text: user.username + ' joined from Marmot' }, user.id);
    this.post(link, { content: '**' + this.shownName(link, user) + '** joined from Marmot', username: 'Marmot', allowed_mentions: { parse: [] } })
      .catch(e => this.log.warn('[discord] join notice:', e.message));
  }
  /** Public channels for the Discord tab, and whether this user is already in each. */
  publicLinks(userId) {
    return this.db.publicLinks().map(l => ({ linkId: l.id, guild: l.guildName, channel: l.channelName,
      members: this.db.memberCount(l.id), joined: this.db.isMember(l.id, userId) }));
  }
  leave(user, linkId) {
    const link = this.db.link(linkId);
    if (!link || !this.db.removeMember(linkId, user.id)) return;
    this.deliver(linkId, { t: 'sys', text: user.username + ' left' });
    this.post(link, { content: '**' + this.shownName(link, user) + '** left', username: 'Marmot', allowed_mentions: { parse: [] } }).catch(() => {});
  }
  linksOf(userId) {
    return this.db.linksOf(userId).map(l => ({ linkId: l.id, guild: l.guildName, channel: l.channelName, public: l.public }));
  }

  /* ---- slash commands ---- */
  async onInteraction(i) {
    if (i.type !== 2 || !i.data || i.data.name !== 'marmot') return;
    const d = this.discord;
    const reply = content => d.rest('PATCH', '/webhooks/' + d.appId + '/' + i.token + '/messages/@original', { content, allowed_mentions: { parse: [] } });
    // acknowledge within Discord's 3 seconds, privately, then answer
    await d.rest('POST', '/interactions/' + i.id + '/' + i.token + '/callback', { type: 5, data: { flags: 64 } });
    try {
      await reply(await this.command(i));
    } catch (e) {
      this.log.warn('[discord] /marmot failed:', e.message);
      await reply(e.status === 403 ? 'I am missing a permission here: I need **Manage Webhooks**, **View Channel** and **Send Messages** in this channel.' : 'Something went wrong: ' + e.message).catch(() => {});
    }
  }

  async command(i) {
    const perms = BigInt((i.member && i.member.permissions) || 0);
    if (!(perms & (MANAGE_GUILD | ADMINISTRATOR))) return 'You need the **Manage Server** permission to use this.';
    const sub = (i.data.options || [])[0] || {};
    const opt = Object.fromEntries((sub.options || []).map(o => [o.name, o.value]));
    const channelId = i.channel_id || (i.channel && i.channel.id);
    const link = this.db.linkByChannel(channelId);
    const need = 'This channel is not linked. Use `/marmot link` first.';
    switch (sub.name) {
      case 'link': {
        if (link) return 'This channel is already linked to Marmot.';
        const hook = await this.discord.rest('POST', '/channels/' + channelId + '/webhooks', { name: 'Marmot' });
        const guild = await this.discord.rest('GET', '/guilds/' + i.guild_id).catch(() => ({ name: 'Discord server' }));
        const chan = i.channel && i.channel.name ? i.channel : await this.discord.rest('GET', '/channels/' + channelId);
        this.db.createLink({ guildId: i.guild_id, channelId, guildName: guild.name, channelName: chan.name,
          webhookId: hook.id, webhookToken: hook.token, createdBy: (i.member && i.member.user && i.member.user.id) || null });
        return 'Linked **#' + chan.name + '** to Marmot. Marmot users can join with a code from `/marmot invite`.\n' +
          '-# Messages here are relayed through the Marmot server, which can read them.';
      }
      case 'unlink':
        if (!link) return need;
        this.unlink(link, 'a Discord moderator unlinked it');
        return 'Unlinked. Marmot users in this channel were removed.';
      case 'invite': {
        if (!link) return need;
        const uses = opt.uses || 1, hours = opt.hours || 24, code = newCode();
        const expires = Date.now() + hours * 3600 * 1000;
        this.db.createInvite(normCode(code), link.id, uses, expires);
        return 'Invite code: `' + code + '`\n' + uses + ' use' + (uses === 1 ? '' : 's') + ', expires <t:' + Math.floor(expires / 1000) + ':R>. ' +
          'In Marmot: **Discord → + JOIN**. Only share it with the people you want here.';
      }
      case 'members': {
        if (!link) return need;
        const names = this.db.members(link.id).map(u => { const r = this.db.userRow(u); return r && r.username; }).filter(Boolean).sort();
        return names.length ? 'Marmot users here (' + names.length + '): ' + names.map(n => '`' + n + '`').join(', ') : 'No Marmot users have joined yet.';
      }
      case 'kick': {
        if (!link) return need;
        const row = this.db.userRowByName(String(opt.username || '').trim());
        if (!row || !this.db.removeMember(link.id, row.id)) return 'No Marmot user called `' + opt.username + '` is in this channel.';
        const body = JSON.stringify({ k: 'dc', link: link.id, t: 'sys', text: 'a Discord moderator removed you from this channel', gone: true });
        for (const s of this.db.deliver([{ to: row.id, from: 'dc:' + link.id, payload: body }])) {
          this.hub.push(s.to, { t: 'env', env: { id: s.id, from: s.from, ts: s.ts, payload: s.payload } });
        }
        this.hub.push(row.id, { t: 'links' });
        this.deliver(link.id, { t: 'sys', text: row.username + ' was removed by a Discord moderator' });
        // kept while the channel is invite-only too, so making it public later doesn't let them straight back in
        if (!(link.barred || []).includes(row.id)) this.db.updateLink(link.id, { barred: (link.barred || []).concat(row.id).slice(-5000) });
        return 'Removed `' + row.username + '`.' + (link.public ? ' They can\'t rejoin from the public list; a code from `/marmot invite` would let them back.' : '');
      }
      case 'filter': {
        if (!link) return need;
        const cur = F.normalize(link.filter), next = Object.assign({}, cur, { words: cur.words.slice() });
        if (opt.level !== undefined) next.level = opt.level;
        if (opt.mode !== undefined) next.mode = opt.mode;
        if (opt.links !== undefined) next.links = !!opt.links;
        const notes = [];
        if (opt.remove !== undefined) {
          const { ok } = F.parseWords(opt.remove), before = next.words.length;
          next.words = next.words.filter(w => !ok.includes(w));
          if (next.words.length === before && ok.length) notes.push('None of those words were on the list.');
        }
        if (opt.add !== undefined) {
          const { ok, bad } = F.parseWords(opt.add);
          next.words = [...new Set(next.words.concat(ok))];
          if (bad.length) notes.push('Skipped (too long or no letters): ' + bad.map(w => '`' + w.slice(0, 50) + '`').join(', '));
        }
        if (next.words.length > F.MAX_WORDS) return 'The filter holds at most ' + F.MAX_WORDS + ' extra words; remove some first.';
        const changed = JSON.stringify(next) !== JSON.stringify(cur);
        if (changed && link.public && !F.isActive(next)) return 'This channel is public, so its filter can\'t be turned off. Use `/marmot public enabled:False` first.';
        if (changed) this.db.updateLink(link.id, { filter: next });
        return (changed ? 'Chat filter updated for messages from Marmot:\n' : 'Chat filter for messages from Marmot:\n') + F.describe(next) +
          (notes.length ? '\n' + notes.join('\n') : '') +
          (F.isActive(next) ? '' : '\n-# A public channel needs a filter: set a level, add words, or block links.');
      }
      case 'public': {
        if (!link) return need;
        const on = !!opt.enabled;
        if (on === link.public) return 'This channel is already ' + (on ? 'public' : 'invite-only') + ' on Marmot.';
        if (on && !F.isActive(link.filter)) return 'A public channel needs a chat filter. Set one up first, for example `/marmot filter level:slurs and swearing`, then run this again.';
        this.db.setPublic(link.id, on);
        if (this.hub.pushAll) this.hub.pushAll({ t: 'links' });
        this.post(link, { content: on ? 'This channel is now **public on Marmot**: any Marmot user can join and post here.' : 'This channel is **invite-only** on Marmot again.',
          username: 'Marmot', allowed_mentions: { parse: [] } }).catch(e => this.log.warn('[discord] public notice:', e.message));
        return on
          ? 'This channel is now public: every Marmot user can find it under **Discord** and join without a code.\n' + F.describe(link.filter) +
            '\n-# `/marmot kick` also stops someone rejoining from the public list.'
          : 'This channel is invite-only again. Marmot users already here stay; use `/marmot kick` to remove anyone.';
      }
    }
    return 'Unknown command.';
  }
}

module.exports = { Discord, Bridge, normCode, newCode, hookName, displayText, MAX_TEXT };
