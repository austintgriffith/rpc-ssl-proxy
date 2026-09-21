import test from 'node:test';
import assert from 'node:assert/strict';
import { createKeyRateLimiter } from '../utils/keyRateLimiter.js';

test('owner and global admission is atomic; release is idempotent', () => {
  const limiter = createKeyRateLimiter({ ownerConcurrency: 2, globalConcurrency: 3 });
  const a = limiter.admit('alice', 100, 2);
  assert.equal(a.ok, true);
  assert.equal(limiter.admit('alice', 100, 1).ok, false);
  assert.equal(limiter.admit('bob', 100, 2).ok, false);
  const b = limiter.admit('bob', 100, 1); assert.equal(b.ok, true);
  assert.equal(limiter.status().inFlight, 3);
  a.release(); a.release(); b.release();
  assert.equal(limiter.status().inFlight, 0);
});

test('failed work remains charged, owner rotation cannot reset budget, global budget applies', () => {
  const limiter = createKeyRateLimiter({ ownerLimit: 100, globalLimit: 150 });
  const a = limiter.admit('alice', 100, 1); a.release();
  assert.equal(limiter.admit('alice', 1, 1).ok, false);
  assert.equal(limiter.admit('bob', 51, 1).ok, false);
  assert.equal(limiter.admit('bob', 50, 1).ok, true);
});

test('hour rollover decays usage, backwards clock does not clear counters', () => {
  let time = 0;
  const limiter = createKeyRateLimiter({ now: () => time, ownerLimit: 100 });
  limiter.admit('alice', 100, 1).release();
  time = 3600000;
  assert.equal(limiter.admit('alice', 1, 1).ok, false);
  time += 1800000;
  limiter.admit('alice', 50, 1).release();
  time = 0;
  assert.equal(limiter.admit('alice', 1, 1).ok, false);
  time = 4 * 3600000;
  assert.equal(limiter.admit('alice', 100, 1).ok, true);
});
