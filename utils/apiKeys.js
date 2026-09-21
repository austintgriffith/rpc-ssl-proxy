import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export const hashApiKey = key => createHash('sha256').update(key).digest('hex');
const HEX = /^[a-f0-9]{64}$/;

// Only an operator-managed local file is trusted. The public token manager's
// Firestore collection is deliberately not an authority for privileged access.
export function parseKeyRegistry(raw) {
  const entries = JSON.parse(raw);
  if (!Array.isArray(entries)) throw new Error('Key registry must be an array');
  const keys = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry.digest !== 'string' || !HEX.test(entry.digest) || typeof entry.owner !== 'string' ||
        !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(entry.owner) || keys.has(entry.digest)) {
      throw new Error('Invalid or duplicate key registry entry');
    }
    keys.set(entry.digest, { owner: entry.owner });
  }
  return keys;
}

export function createApiKeyStore({ file, now = Date.now, read = readFile,
  maxAgeMs = 15000, refreshMs = 5000 } = {}) {
  let keys = new Map();
  let refreshedAt = null;
  let timer;
  let pending;
  let failed = false;
  async function refresh() {
    if (pending) return pending;
    pending = (async () => {
      try {
        if (!file) throw new Error('Key registry not configured');
        const next = parseKeyRegistry(await read(file, 'utf8'));
        keys = next;
        refreshedAt = now();
        failed = false;
      } catch {
        // Never preserve revoked credentials when refreshing fails.
        keys = new Map();
        refreshedAt = null;
        failed = true;
      }
    })();
    try { await pending; } finally { pending = undefined; }
  }
  function resolve(req) {
    const path = req.params?.key;
    const header = req.headers?.['x-api-key'];
    if (path === undefined && header === undefined) return { status: 'none' };
    if (path !== undefined && header !== undefined && path !== header) return { status: 'invalid' };
    const raw = path ?? header;
    if (typeof raw !== 'string' || !HEX.test(raw)) return { status: 'invalid' };
    if (refreshedAt === null || now() - refreshedAt >= maxAgeMs || now() < refreshedAt) {
      return { status: 'unavailable' };
    }
    const entry = keys.get(hashApiKey(raw));
    return entry ? { status: 'valid', owner: entry.owner } : { status: 'invalid' };
  }
  return {
    resolve, refresh,
    async start() {
      await refresh();
      if (!timer) { timer = setInterval(refresh, refreshMs); timer.unref(); }
    },
    stop() { clearInterval(timer); timer = undefined; },
    status() {
      return { ready: refreshedAt !== null && now() >= refreshedAt && now() - refreshedAt < maxAgeMs,
        keyCount: keys.size, refreshedAt, failed };
    },
  };
}
