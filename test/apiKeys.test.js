import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiKeyStore, hashApiKey, parseKeyRegistry } from '../utils/apiKeys.js';

const key = 'ab'.repeat(32);
const request = { headers: { 'x-api-key': key } };
const registry = JSON.stringify([{ digest: hashApiKey(key), owner: 'alice' }]);

test('only operator registry digests authorize; public token-manager shape fails closed', async () => {
  let raw = registry;
  const store = createApiKeyStore({ file: 'mock', read: async () => raw });
  assert.equal(store.resolve(request).status, 'unavailable');
  await store.refresh();
  assert.deepEqual(store.resolve(request), { status: 'valid', owner: 'alice' });
  raw = JSON.stringify([{ keyValue: key, ethereumAddress: '0xabc' }]);
  await store.refresh();
  assert.equal(store.resolve(request).status, 'unavailable');
  assert.equal(store.status().keyCount, 0);
});

test('revocation, failed refresh, staleness, and recovery', async () => {
  let time = 0, raw = registry, fail = false;
  const store = createApiKeyStore({ file: 'mock', now: () => time,
    read: async () => { if (fail) throw new Error('unreadable'); return raw; } });
  await store.refresh();
  time = 15000;
  assert.equal(store.resolve(request).status, 'unavailable');
  await store.refresh();
  assert.equal(store.resolve(request).status, 'valid');
  raw = '[]'; await store.refresh();
  assert.equal(store.resolve(request).status, 'invalid');
  raw = registry; await store.refresh();
  fail = true; await store.refresh();
  assert.equal(store.resolve(request).status, 'unavailable');
  fail = false; await store.refresh();
  assert.equal(store.resolve(request).status, 'valid');
});

test('missing, empty, malformed and conflicting credentials are distinct', async () => {
  const store = createApiKeyStore({ file: 'mock', read: async () => registry });
  await store.refresh();
  assert.equal(store.resolve({ headers: {} }).status, 'none');
  for (const value of ['', 'ab'.repeat(8), [key], key.toUpperCase()]) {
    assert.equal(store.resolve({ headers: { 'x-api-key': value } }).status, 'invalid');
  }
  assert.equal(store.resolve({ params: { key }, headers: {} }).status, 'valid');
  assert.equal(store.resolve({ params: { key }, headers: { 'x-api-key': 'cd'.repeat(32) } }).status, 'invalid');
  assert.equal(JSON.stringify(store.status()).includes(key), false);
  assert.throws(() => parseKeyRegistry(JSON.stringify([{ digest: hashApiKey(key), owner: '' }])));
});

test('overlapping refreshes share one read and stale pending reads cannot authorize', async () => {
  let resolveRead, time = 0, reads = 0;
  const store = createApiKeyStore({ file: 'mock', now: () => time, read: () => {
    reads++; return new Promise(resolve => { resolveRead = resolve; });
  } });
  const first = store.refresh(), second = store.refresh();
  assert.equal(reads, 1); resolveRead(registry); await Promise.all([first, second]);
  const pending = store.refresh(); time = 15000;
  assert.equal(store.resolve(request).status, 'unavailable');
  resolveRead('[]'); await pending;
  assert.equal(store.resolve(request).status, 'invalid');
});
