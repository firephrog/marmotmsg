'use strict';
/**
 * A stand-in for the slice of Discord the bridge uses: a few REST routes and
 * a gateway that speaks hello / identify / heartbeat / dispatch. Tests drive
 * it as Discord users and moderators would.
 */
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const { WebSocketServer } = require('ws');

let n = 0;
const snowflake = () => String(BigInt(Date.now()) * 4194304n + BigInt(++n));

async function fakeDiscord(token) {
  const app = express();
  app.use(express.json());
  const st = {
    guilds: { g1: { id: 'g1', name: 'Rat Den' } },
    channels: { c1: { id: 'c1', name: 'general', guild_id: 'g1' }, c2: { id: 'c2', name: 'random', guild_id: 'g1' } },
    hooks: new Map(), posts: [], commands: null, sockets: new Set(), seq: 0, waiting: new Map(), ready: null
  };
  let onReady; st.ready = new Promise(r => { onReady = r; });

  const dispatch = (t, d) => { for (const ws of st.sockets) ws.send(JSON.stringify({ op: 0, t, s: ++st.seq, d })); };

  // execute-webhook carries its own token in the path; everything else needs the bot token
  app.use((req, res, next) => {
    if (/^\/webhooks\/\d+\/[^/]+$/.test(req.path) && req.method === 'POST') return next();
    if (req.get('authorization') !== 'Bot ' + token) return res.status(401).json({ message: '401: Unauthorized' });
    next();
  });
  app.get('/gateway/bot', (req, res) => res.json({ url: 'ws://127.0.0.1:' + server.address().port + '/gw' }));
  app.put('/applications/:app/commands', (req, res) => { st.commands = req.body; onReady(); res.json(req.body); });
  app.get('/guilds/:id', (req, res) => st.guilds[req.params.id] ? res.json(st.guilds[req.params.id]) : res.status(404).json({ message: 'Unknown Guild' }));
  app.get('/channels/:id', (req, res) => st.channels[req.params.id] ? res.json(st.channels[req.params.id]) : res.status(404).json({ message: 'Unknown Channel' }));
  app.post('/channels/:id/webhooks', (req, res) => {
    const h = { id: snowflake(), token: crypto.randomBytes(30).toString('base64url'), channel_id: req.params.id, name: req.body.name };
    st.hooks.set(h.id, h);
    res.json(h);
  });
  app.delete('/webhooks/:id', (req, res) => { st.hooks.delete(req.params.id); res.sendStatus(204); });
  app.post('/webhooks/:id/:token', (req, res) => {
    const h = st.hooks.get(req.params.id);
    if (!h || h.token !== req.params.token) return res.status(404).json({ message: 'Unknown Webhook', code: 10015 });
    const ch = st.channels[h.channel_id];
    const msg = { id: snowflake(), type: 0, channel_id: ch.id, guild_id: ch.guild_id, webhook_id: h.id, content: req.body.content,
      author: { id: h.id, username: req.body.username || h.name, bot: true }, timestamp: new Date().toISOString(),
      allowed_mentions: req.body.allowed_mentions };
    st.posts.push(msg);
    dispatch('MESSAGE_CREATE', msg);
    res.json(msg);
  });
  app.post('/interactions/:id/:token/callback', (req, res) => res.sendStatus(204));
  app.patch('/webhooks/:app/:token/messages/@original', (req, res) => {
    const w = st.waiting.get(req.params.token);
    if (w) { st.waiting.delete(req.params.token); w(req.body.content); }
    res.json({ id: snowflake(), content: req.body.content });
  });

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/gw' });
  wss.on('connection', ws => {
    ws.send(JSON.stringify({ op: 10, d: { heartbeat_interval: 45000 } }));
    ws.on('message', data => {
      const p = JSON.parse(data);
      if (p.op === 1) ws.send(JSON.stringify({ op: 11 }));
      if (p.op === 2) {
        if (p.d.token !== token) return ws.close(4004, 'Authentication failed');
        st.intents = p.d.intents;
        st.sockets.add(ws);
        ws.send(JSON.stringify({ op: 0, t: 'READY', s: ++st.seq, d: { user: { id: 'bot1', username: 'Marmot' }, application: { id: 'app1' }, session_id: 's1' } }));
      }
    });
    ws.on('close', () => st.sockets.delete(ws));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));

  return {
    st,
    api: 'http://127.0.0.1:' + server.address().port,
    ready: () => st.ready,
    /** A Discord user posts in a channel. */
    say(channelId, user, content, extra) {
      const ch = st.channels[channelId];
      const msg = Object.assign({ id: snowflake(), type: 0, channel_id: channelId, guild_id: ch.guild_id, content, author: user,
        timestamp: new Date().toISOString(), mentions: [], attachments: [] }, extra);
      dispatch('MESSAGE_CREATE', msg);
      return msg;
    },
    /** A member runs /marmot <sub>; resolves with the bot's (private) reply. */
    slash(channelId, sub, options, permissions) {
      const tok = crypto.randomBytes(16).toString('hex');
      const p = new Promise(r => st.waiting.set(tok, r));
      dispatch('INTERACTION_CREATE', {
        id: snowflake(), token: tok, type: 2, guild_id: st.channels[channelId].guild_id, channel_id: channelId,
        channel: { id: channelId, name: st.channels[channelId].name },
        member: { permissions: permissions == null ? '32' : permissions, user: { id: 'mod1', username: 'mod' } },
        data: { name: 'marmot', options: [{ type: 1, name: sub, options: Object.entries(options || {}).map(([name, value]) => ({ name, value })) }] }
      });
      return p;
    },
    dispatch,
    close: () => { for (const ws of st.sockets) ws.terminate(); wss.close(); return new Promise(r => server.close(r)); }
  };
}

module.exports = { fakeDiscord };
