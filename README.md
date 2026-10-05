# Marmot

A browser messenger using the Signal protocol. The client is one standalone HTML file. The server is a
small Node service that holds accounts, prekeys, an encrypted mailbox and an encrypted copy of each
user's chats.

A browser based messanging app, built inside a singular HTML file. Uses the Signal protocol to keep messages secure, and also offers a Discord bot to link Discord channels to Marmot users.

```
client/index.html     the whole client: UI, protocol, account crypto, engine
server/server.js       HTTP API + WebSocket push
server/db.js           SQL storage (SQLite)
server/seal.js         at-rest column encryption
server/discord.js      Discord link: a small gateway + REST bot and the bridge
server/test/           end-to-end tests that run the client's own core code
```

## Run it

```
cd server
npm install
npm start               # http://localhost:8080
npm test
```

Open `http://localhost:8080`, or open `client/index.html` straight from disk and enter the server
address on the login screen. To give people a copy that connects automatically, set the `SERVER`
constant near the top of the client script.

Configuration comes from environment variables. When you run `npm start`, they are read from
`server/.env` (copy `server/.env.example`). To configure these, copy `server/.env.example`, rename it to .env, and fill in the necessary info.

| variable | meaning |
|---|---|
| `PORT` | listen port (default 8080) |
| `MARMOT_DATA` | data directory (default `server/data`) |
| `MARMOT_DB_KEY` | 32-byte at-rest key, hex or base64. Required when `NODE_ENV=production`. In development a key file is generated next to the database. Lose it and the database is unreadable. |
| `TRUST_PROXY` | set behind a load balancer so rate limits see real client IPs |
| `DISCORD_TOKEN` | bot token. Turns on the Discord link. Leave it unset and the link is off. |
| `STUN_URLS` | comma-separated STUN servers for voice calls. Default `stun:stun.l.google.com:19302`; set it empty for none. |
| `TURN_URLS`, `TURN_SECRET` | a TURN relay for calls that can't connect directly. `TURN_SECRET` is coturn's `static-auth-secret`. |

## Protocol

- **X3DH** with X25519: identity key, a signed prekey (Ed25519 signature), and one-time prekeys.
  The server hands out each one-time prekey once and deletes it. The client tops the supply back up
  when it falls below 20.
- **Double Ratchet**: HKDF-SHA256 root chain and HMAC-SHA256 symmetric chains. Payloads use
  AES-256-GCM, with both identity keys and the header as associated data. Out-of-order messages work
  through stored skipped-message keys. Superseded sessions are kept, so two people who start a chat at
  the same moment converge on one session instead of losing messages.
- **Identity**: a user id is `sha256(identity key ‖ signing key)`. Clients check every bundle and
  every inbound handshake against that hash, so the server cannot swap keys under an existing id.
  **Verify** shows a 60-digit safety number for comparing out of band.
- **Replay protection**: a handshake whose ephemeral key was already accepted is refused.
- Signal signs with the same Curve25519 key it uses for DH (XEdDSA). WebCrypto has no XEdDSA, so a
  Marmot identity is a pair: one X25519 key and one Ed25519 key.

## Peers

Nobody can message you, or fetch your prekey bundle to start a session, unless you are friends. The
server enforces this for every envelope and bundle, not just the client.

- **Find people** by exact username (works for everyone), or in the **Global** section of Peers,
  which lists only users who turned on **global discovery** in Settings. It is off by default.
- **Friend requests**: request, accept, decline/cancel, remove. If two people request each other,
  they become friends.
- **Block**: removes the friendship and takes you out of their global list. Their later requests
  are stored on their side only and never reach you. If you unblock them, a pending request
  appears.
- Delivery receipts to someone who has just unfriended you are dropped, not refused, so a message
  that was already in flight still gets processed.

Each side of a relationship is its own row, holding the other user's id and the state, all sealed.
Rows are looked up by a keyed HMAC of the pair, so a leaked database shows how many contacts
someone has but not who they are. The server needs to know relationships in order to enforce
them, so they are not client-encrypted the way chats are.

## Discord link

A Discord channel can be bridged to Marmot. Marmot users join it with an invite code and it shows up
as a conversation. Their messages appear in Discord under their own name as `alice · marmot`.

**These chats are not end-to-end encrypted.** Discord can't do end-to-end encryption, so the Marmot
server relays bridged messages in plaintext, and the client says so in every Discord chat. The
server can read Discord chats; it still can't read one-to-one Marmot chats. At rest, bridged
messages, channel names and webhook credentials are sealed like the rest of the database.

Discord commands (`/marmot …`, for members with **Manage Server**; replies are only visible to
whoever ran the command):

| command | does |
|---|---|
| `/marmot link` | bridge this channel (creates a webhook named Marmot) |
| `/marmot invite [uses] [hours]` | an invite code: 1 use and 24 hours by default |
| `/marmot members` | list the Marmot users in this channel |
| `/marmot kick <username>` | remove a Marmot user (they also can't rejoin from the public list) |
| `/marmot filter [level] [mode] [add] [remove] [links]` | show or change this channel's chat filter |
| `/marmot public <enabled>` | let every Marmot user join without an invite code; needs a filter first |
| `/marmot unlink` | stop bridging; Marmot members are removed |

In Marmot, the **Discord** tab lists each linked server with the channels you are in, and a
**PUBLIC** group of channels anyone can join with one click. **+ JOIN** takes an invite code.
**LEAVE** is in the chat header.

**Chat filter.** Each linked channel has a filter for what Marmot users post into Discord, set with
`/marmot filter`:

- `level`: a built-in word list. `off`, `slurs only`, `slurs and swearing`, or `strict` (also mild
  language). Each level includes the ones before it.
- `mode`: `censor the word` (it reaches Discord as `f***`) or `block the message` (the sender gets an
  error and nothing is posted).
- `add` / `remove`: your own words, separated by commas. End a word with `*` to also catch words that
  start with it (`spam*` catches `spammer`).
- `links`: block messages that contain links.

Run it with no options to see the current settings. Words match whole words, after folding case,
look-alike characters (`sh!t`, `a$$`) and stretched letters (`fuuuck`), so `class` and `Scunthorpe`
get through. A username the filter catches is starred where Discord shows it, and can't join a
public channel at all. Discord → Marmot messages are not filtered.

**Public channels.** `/marmot public enabled:True` lists the channel for every Marmot user and posts
a notice in the channel. It is refused until the filter does something (a level other than `off`,
at least one word, or links blocked), and while a channel is public its filter can't be turned off.
`enabled:False` makes it invite-only again; people already in it stay. Someone removed with
`/marmot kick` can't come back from the public list; an invite code from a moderator lets them back.
Discord messages reach offline members through the normal mailbox. Mentions, custom emoji and
attachments come through as text and links. Edits, deletes and reactions don't carry over yet.

### Setting up the bot

1. At https://discord.com/developers/applications create an application, then go to **Bot**:
   reset and copy the token, and turn on **Message Content Intent**.
2. Invite it to a server (replace `APP_ID`). The permissions are View Channels, Send Messages,
   Read Message History and Manage Webhooks:
   `https://discord.com/oauth2/authorize?client_id=APP_ID&scope=bot+applications.commands&permissions=536939520`
3. Start the server with `DISCORD_TOKEN=...`. The log shows `[discord] connected as …`, and
   `/marmot` is registered globally. Discord can take a few minutes to show a new command for the
   first time.

The bot connects outbound to Discord's gateway, so it needs no public URL. Only one server process
should run the bot (see step 6).

## Voice calls

Friends can call each other: **CALL** in a chat header or on their profile. One call at a time. While
a call is up, a bar across the top of the window shows it, so it stays in place when you switch screens.

- **Audio** is WebRTC, which always encrypts media as **DTLS-SRTP**: SRTP with keys from a DTLS
  handshake between the two browsers.
- **Why the server can't listen in**: each side's DTLS certificate fingerprint is in its offer or
  answer, and those travel as ordinary Double Ratchet messages (`{k:'call', t:'offer'|'answer'|
  'decline'|'busy'|'end'}`). The server relays them but can't read or change them, so it can't
  swap in its own certificate and sit in the middle. If you have verified someone's safety number,
  that covers your calls with them too.
- **Network**: browsers connect directly when they can, using STUN to find their public
  addresses. A TURN relay, if you configure one, only forwards SRTP it can't decrypt. Its
  credentials come from `/api/ice`, minted from `TURN_SECRET` and valid for 6 hours. A direct
  connection shows each side's IP address to the other, as with any peer-to-peer call.
- **History**: every call leaves one line in the chat ("voice call · 2:31", "missed voice call",
  "no answer", …). A call that is still in the mailbox past its 45-second ring time, because you
  were offline, appears as a missed call and does not ring.
- **Busy and crossed calls**: a second caller gets "busy". If two friends call each other at the
  same moment, the call from the lower user id goes ahead and the other side answers it
  automatically.
- **Requirements**: the microphone needs a secure page, so open Marmot over `https://` or from
  `http://localhost`. Closing the tab mid-call drops the call; the other side
  notices within about 10 seconds.

Without a TURN relay, some calls won't connect: for example, both people behind strict NATs, or
on some mobile networks. Run [coturn](https://github.com/coturn/coturn) with `use-auth-secret`
before relying on calls in production.

## Accounts and storage

The password never leaves the browser. PBKDF2 (600k iterations) plus HKDF splits it into two keys:

- an **auth key**. The server stores only an scrypt verifier of it.
- a **vault key**. The server never sees it. It decrypts the vault, which holds the identity private
  keys and a random **data key**.

Everything else the server keeps for a user is a blob encrypted with that data key: ratchet state,
message history, one-time prekey privates and pinned peer identities. Each blob is stored under an
HMAC of its name. Signing in on another browser therefore restores the full history and live
sessions.

Every state change is one atomic `/api/commit`. It carries the advanced ratchet, the stored message,
the outgoing envelope (including the delivery receipt), the spent prekey and the mailbox ack. Either
all of them land or none do, so a crash or network failure cannot desynchronise a session or drop a
message.

The server encrypts every sensitive column a second time (AES-256-GCM, bound to its row): vaults,
identity keys, prekeys, blobs, and envelopes including their sender. A leaked database file shows
usernames, recipients, timestamps and row counts, nothing more.

**One active device per account.** Signing in revokes the other sessions, because two devices
advancing the same ratchet would fork it. Reloading a tab keeps the session. Closing the tab forgets
it.

## Status: step 4 of `marmot.md`

Done:

- **Step 1**: accounts (sign up, log in, resume, log out, delete), X3DH + Double Ratchet
  messaging, offline delivery, receipts, safety-number verification, and the encrypted server
  store.
- **Step 2**: peers. Friend requests, blocking, opt-in global discovery, messaging only between
  friends, and a Peers screen. On phones the rail is replaced by tabs. Databases from step 1 are
  migrated when the server opens them. Conversations from step 1 stay readable, but both people
  have to become friends before either can send again.
- **Step 3**: Discord link. Channel bridge, invite codes, moderator commands, offline delivery, and
  a webhook that is recreated if someone deletes it. Tested against a fake Discord
  (`server/test/fake-discord.js`), not yet against the real one.
- **Step 4**: one-to-one voice calls. DTLS-SRTP audio with signalling over the Double Ratchet,
  ringing, accept/decline, mute, busy, crossed calls, missed calls and call history. The signalling
  is tested through the real server with a stand-in for WebRTC (`server/test/voice.test.js`).
  Calls have also been checked in two headless Chrome sessions with fake microphones: DTLS
  connected, audio flowed both ways, and the fingerprints matched. Not yet tested across real
  NATs or through a TURN relay.

Deliberately minimal until later steps:

- **Finishing touches (step 5)**: group calls, picking a microphone, a relay-only mode that hides
  your IP from the person you call, signed-prekey rotation, password change, "remember this device",
  typing indicators, browser notifications, accent settings, prekey-drain rate limiting.
- **EB (step 6)**: move `db.js` to Postgres/RDS and put `MARMOT_DB_KEY` and `DISCORD_TOKEN` in
  Secrets Manager. The ALB idle timeout is already covered by a 25 s WebSocket ping. With more than
  one instance, exactly one should run the Discord bot, because each connected bot relays every
  message, and WebSocket pushes need a shared hub. Calls need a TURN server (coturn on EC2 or a
  hosted TURN service), with `TURN_SECRET` in Secrets Manager.
