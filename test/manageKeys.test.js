import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createApiKeyStore } from '../utils/apiKeys.js';

test('operator CLI issues hashed tokens, supports rotation, and revokes individual keys or owners', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rpc-key-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'registry.json');
  const run = (...args) => spawnSync(process.execPath, ['scripts/manage-keys.js', ...args], {
    env: { ...process.env, RPC_KEYS_FILE: file }, encoding: 'utf8',
  });
  const issue = run('issue', 'alice'); assert.equal(issue.status, 0);
  const first = issue.stdout.trim(); assert.match(first, /^[a-f0-9]{64}$/);
  const second = run('issue', 'alice').stdout.trim();
  assert.notEqual(first, second);
  const content = await readFile(file, 'utf8');
  assert.equal(content.includes(first), false);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  const store = createApiKeyStore({ file }); await store.refresh();
  const resolve = key => store.resolve({ headers: { 'x-api-key': key } });
  assert.equal(resolve(first).owner, 'alice'); assert.equal(resolve(second).owner, 'alice');
  const digest = JSON.parse(content)[0].digest;
  assert.equal(run('revoke-key', 'alice', digest).status, 0);
  await store.refresh(); assert.equal(resolve(first).status, 'invalid'); assert.equal(resolve(second).status, 'valid');
  assert.equal(run('revoke-owner', 'alice').status, 0);
  await store.refresh(); assert.equal(resolve(second).status, 'invalid');
  await writeFile(file + '.lock', '');
  assert.equal(run('issue', 'bob').status, 1);
  assert.equal(await readFile(file, 'utf8'), '[]\n');
});
