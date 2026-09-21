#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { hashApiKey, parseKeyRegistry } from '../utils/apiKeys.js';

const [command, owner, digest] = process.argv.slice(2);
const file = process.env.RPC_KEYS_FILE;
if (!file || !path.isAbsolute(file) || !['issue', 'revoke-owner', 'revoke-key'].includes(command) ||
    !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(owner || '') ||
    (command === 'revoke-key' && !/^[a-f0-9]{64}$/.test(digest || ''))) {
  console.error('Set RPC_KEYS_FILE to an absolute path. Usage: node scripts/manage-keys.js issue|revoke-owner <owner> OR revoke-key <owner> <digest>');
  process.exit(1);
}
let lock;
let temporary;
try {
  // A second operator must retry instead of silently overwriting another change.
  lock = fs.openSync(`${file}.lock`, 'wx', 0o600);
  let entries;
  try { entries = [...parseKeyRegistry(fs.readFileSync(file, 'utf8'))].map(([digest, data]) => ({ digest, ...data })); }
  catch (error) {
    if (error.code !== 'ENOENT' || command !== 'issue') throw error;
    entries = [];
  }
  let token;
  if (command === 'issue') {
    token = randomBytes(32).toString('hex');
    entries.push({ digest: hashApiKey(token), owner });
  } else {
    const retained = entries.filter(entry => entry.owner !== owner ||
      (command === 'revoke-key' && entry.digest !== digest));
    if (retained.length === entries.length) throw new Error('No matching token');
    entries = retained;
  }
  temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(entries, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  fs.renameSync(temporary, file);
  // Raw token appears once on stdout; registry contains only its SHA-256 digest.
  if (token) process.stdout.write(token + '\n');
  console.error(command === 'issue' ? 'Issued token. Deliver privately; do not put it in frontend code.' : 'Revoked. New requests are denied after the next registry refresh (normally within 5 seconds).');
} catch (error) {
  console.error(error.code === 'EEXIST' ? 'Registry locked; another update may be running.' : error.message);
  process.exitCode = 1;
} finally {
  if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
  if (lock !== undefined) { fs.closeSync(lock); fs.unlinkSync(`${file}.lock`); }
}
