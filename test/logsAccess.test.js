import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once, EventEmitter } from 'node:events';
import express from 'express';
import { registerRpcRoutes } from '../utils/rpcRoutes.js';
import { createApiKeyStore, hashApiKey } from '../utils/apiKeys.js';
import { createKeyRateLimiter } from '../utils/keyRateLimiter.js';
import { createLogsForwarder } from '../utils/logsAccess.js';

const alice = 'ab'.repeat(32), rotated = 'bc'.repeat(32), bob = 'cd'.repeat(32);
const entries = [{ key: alice, owner: 'alice' }, { key: rotated, owner: 'alice' }, { key: bob, owner: 'bob' }];
const log = (id = 1) => ({ jsonrpc: '2.0', id, method: 'eth_getLogs', params: [{ fromBlock: '0x1', toBlock: '0x2' }] });
const result = body => Array.isArray(body) ? body.map(c => ({ jsonrpc: '2.0', id: c.id, result: [] })) : { jsonrpc: '2.0', id: body.id, result: [] };

async function fixture(t, options = {}) {
  const seen = [], events = new EventEmitter();
  const upstream = http.createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = JSON.parse(raw);
    const record = { body, headers: req.headers, res };
    seen.push(record); events.emit('received', record);
    if (!options.hold) { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(result(body))); }
  });
  upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
  let registry = entries.map(({ key, owner }) => ({ digest: hashApiKey(key), owner }));
  const store = createApiKeyStore({ file: 'mock', read: async () => JSON.stringify(registry) });
  await store.refresh();
  const limiter = createKeyRateLimiter(options.limits);
  const app = express(); app.set('trust proxy', false); app.use(express.json());
  app.use((req, res, next) => { res.once('close', () => events.emit('clientClosed')); next(); });
  let legacyCalls = 0;
  const transport = createLogsForwarder({ url: `http://127.0.0.1:${upstream.address().port}`, timeoutMs: options.timeoutMs ?? 2000, maxResponseBytes: options.maxResponseBytes ?? 10000 });
  registerRpcRoutes(app, { store, limiter, enabled: options.enabled ?? true,
    isBlacklisted: () => options.blacklisted ?? false,
    forward: body => transport(body).finally(() => setImmediate(() => events.emit('settled'))),
    legacyHandler: (req, res) => { legacyCalls++; res.json(result(req.body)); },
  });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.closeAllConnections(); upstream.closeAllConnections();
    await Promise.all([new Promise(r => server.close(r)), new Promise(r => upstream.close(r))]);
  });
  return { seen, events, limiter, url, store,
    get legacyCalls() { return legacyCalls; },
    async revoke(owner) { registry = registry.filter(e => e.owner !== owner); await store.refresh(); },
    async post(body = log(), key = alice, path = '/', extraHeaders = {}) {
      const response = await fetch(url + path, { method: 'POST', headers: { 'content-type': 'application/json', ...(key === null ? {} : { 'x-api-key': key }), ...extraHeaders }, body: JSON.stringify(body) });
      return { status: response.status, body: await response.json(), headers: response.headers };
    },
  };
}

test('real HTTP routes support header/path tokens, mixed batches, and strip credentials', async t => {
  const f = await fixture(t);
  assert.equal((await f.post()).status, 200);
  assert.equal((await f.post(log(2), null, `/v1/${alice}`)).status, 200);
  const mixed = [log(3), { jsonrpc: '2.0', id: 4, method: 'eth_blockNumber', params: [] }];
  const response = await f.post(mixed, alice, '/', { cookie: 'secret', authorization: 'Bearer secret', origin: 'forged', 'x-admin-key': 'secret' });
  assert.deepEqual(response.body.map(r => r.id), [3, 4]);
  assert.deepEqual(f.seen[2].body, mixed);
  for (const header of ['x-api-key', 'x-admin-key', 'cookie', 'authorization', 'origin']) assert.equal(f.seen[2].headers[header], undefined);
  assert.equal(f.legacyCalls, 0);
  assert.equal(f.limiter.status().inFlight, 0);
});

test('anonymous/bad/revoked tokens and disabled/blacklisted access never forward logs', async t => {
  const f = await fixture(t);
  assert.equal((await f.post(log(), null)).status, 401);
  assert.equal((await f.post(log(), '')).status, 401);
  assert.equal((await f.post(log(), 'ef'.repeat(32))).status, 401);
  await f.revoke('alice'); assert.equal((await f.post()).status, 401);
  assert.equal(f.seen.length, 0);
  const disabled = await fixture(t, { enabled: false });
  assert.equal((await disabled.post()).status, 503);
  const blocked = await fixture(t, { blacklisted: true });
  assert.equal((await blocked.post()).status, 403);
  assert.equal(disabled.seen.length + blocked.seen.length, 0);
});

test('ordinary requests still use legacy path, even with a valid token', async t => {
  const f = await fixture(t);
  const ordinary = { jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] };
  await f.post(ordinary, null); await f.post(ordinary);
  assert.equal(f.legacyCalls, 2); assert.equal(f.seen.length, 0);
});

test('batch rejections have every request ID and perform no partial work', async t => {
  const f = await fixture(t);
  const bad = log(2); bad.params[0].toBlock = 'latest';
  const response = await f.post([log(1), bad]);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(r => r.id), [1, 2]);
  assert.ok(response.body.every(r => r.error.code === -32602));
  const tooMany = await f.post([log(1), log(2), log(3)]);
  assert.equal(tooMany.status, 429); assert.equal(tooMany.body.length, 3);
  assert.equal(f.seen.length, 0);
});

test('disconnect holds slots; rotating a token does not bypass owner/global caps', async t => {
  const f = await fixture(t, { hold: true, limits: { ownerConcurrency: 1, globalConcurrency: 1 } });
  const received = once(f.events, 'received');
  const client = http.request(f.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': alice } });
  client.on('error', () => {}); client.end(JSON.stringify(log()));
  const [record] = await received;
  const closed = once(f.events, 'clientClosed'); client.destroy(); await closed;
  assert.equal(f.limiter.status().inFlight, 1);
  assert.equal((await f.post(log(2), rotated)).status, 429);
  assert.equal((await f.post(log(3), bob)).status, 429);
  assert.equal(f.seen.length, 1);
  // A subsequent request can proceed only once the upstream response settles.
  const settled = once(f.events, 'settled');
  record.res.end(JSON.stringify(result(log())));
  await settled;
  assert.equal(f.limiter.status().inFlight, 0);
});

test('timeout is charged and never retries or enters legacy fallback', async t => {
  const f = await fixture(t, { hold: true, timeoutMs: 40, limits: { ownerLimit: 100 } });
  assert.equal((await f.post()).status, 502);
  assert.equal(f.limiter.status().inFlight, 0);
  assert.equal((await f.post(log(2), rotated)).status, 429);
  assert.equal(f.seen.length, 1); assert.equal(f.legacyCalls, 0);
});

test('oversized responses fail within cap and release slots without retry', async t => {
  const f = await fixture(t, { maxResponseBytes: 10 });
  assert.equal((await f.post()).status, 502);
  assert.equal(f.limiter.status().inFlight, 0);
  assert.equal(f.seen.length, 1); assert.equal(f.legacyCalls, 0);
});

test('malformed mixed batch methods cannot crash admission', async t => {
  const f = await fixture(t);
  const response = await f.post([log(1), { jsonrpc: '2.0', id: 2, method: { toString: 'bad' } }]);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(r => r.error.code), [-32600, -32600]);
  assert.equal(f.seen.length, 0);
});
