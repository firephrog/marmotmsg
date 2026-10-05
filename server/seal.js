'use strict';
/**
 * At-rest encryption for every sensitive column.
 *
 * Most of what Marmot stores is already ciphertext the server cannot read
 * (ratchet envelopes, password-wrapped vaults, client-encrypted blobs). This
 * layer seals it a second time under a server-held key so that a leaked
 * database file or backup reveals nothing beyond row counts and timestamps —
 * not even who sent a given envelope or which public keys belong to whom.
 *
 * Each value is bound to its row with AES-GCM associated data, so a sealed
 * value copied into another row (or another column) fails to open.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function loadKey(dataDir) {
  const env = process.env.MARMOT_DB_KEY;
  if (env) {
    const raw = /^[0-9a-f]{64}$/i.test(env) ? Buffer.from(env, 'hex') : Buffer.from(env, 'base64');
    if (raw.length !== 32) throw new Error('MARMOT_DB_KEY must be 32 bytes, hex or base64');
    return raw;
  }
  if (process.env.NODE_ENV === 'production') throw new Error('MARMOT_DB_KEY is required in production');
  // Development convenience: a key file next to the database. Losing it makes
  // the database unreadable, which is the point — so it is never regenerated
  // over an existing one.
  const file = path.join(dataDir, 'db.key');
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  const raw = crypto.randomBytes(32);
  fs.writeFileSync(file, raw.toString('hex'), { mode: 0o600 });
  console.warn('[marmot] generated a development database key at', file, '— set MARMOT_DB_KEY in production');
  return raw;
}

function sealer(key) {
  // A separate key for keyed lookup tags, so an index column can be searched
  // by exact value without revealing what it indexes.
  const tagKey = crypto.createHmac('sha256', key).update('marmot-index-v1').digest();
  return {
    tag(str) {
      return crypto.createHmac('sha256', tagKey).update(str, 'utf8').digest('hex').slice(0, 32);
    },
    seal(value, ctx) {
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(Buffer.from(ctx, 'utf8'));
      const ct = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final()]);
      return 'v1.' + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
    },
    open(sealed, ctx) {
      if (typeof sealed !== 'string' || !sealed.startsWith('v1.')) throw new Error('unsealed value in database');
      const buf = Buffer.from(sealed.slice(3), 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
      d.setAAD(Buffer.from(ctx, 'utf8'));
      d.setAuthTag(buf.subarray(12, 28));
      return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8'));
    }
  };
}

module.exports = { loadKey, sealer };
