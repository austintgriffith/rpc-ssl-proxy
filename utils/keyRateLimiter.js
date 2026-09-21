import { apiKeyRateLimitPerHour, getLogsMaxInFlightPerOwner,
  getLogsMaxInFlightGlobal, getLogsGlobalUnitsPerHour } from '../config.js';

// One instance per proxy process, shared by all tokens. Owners retain their
// counters when a key is rotated. Multiple processes require a shared limiter.
export function createKeyRateLimiter({ now = Date.now, ownerLimit = apiKeyRateLimitPerHour,
  globalLimit = getLogsGlobalUnitsPerHour, ownerConcurrency = getLogsMaxInFlightPerOwner,
  globalConcurrency = getLogsMaxInFlightGlobal } = {}) {
  const HOUR = 3600000;
  let hour = null, current = new Map(), previous = new Map();
  let globalCurrent = 0, globalPrevious = 0, totalInFlight = 0;
  const active = new Map();
  function roll(t) {
    const next = Math.floor(t / HOUR) * HOUR;
    if (hour === null) hour = next;
    if (next > hour) {
      const adjacent = next - hour === HOUR;
      previous = adjacent ? current : new Map();
      globalPrevious = adjacent ? globalCurrent : 0;
      current = new Map(); globalCurrent = 0; hour = next;
    }
  }
  return {
    admit(owner, units, slots) {
      if (!Number.isSafeInteger(units) || units <= 0 || !Number.isSafeInteger(slots) || slots <= 0) {
        throw new Error('Invalid admission cost');
      }
      const t = now(); roll(t);
      const weight = Math.min(1, Math.max(0, 1 - (t - hour) / HOUR));
      const used = (current.get(owner) || 0) + (previous.get(owner) || 0) * weight;
      if (used + units > ownerLimit || globalCurrent + globalPrevious * weight + units > globalLimit) {
        // Conservative delay: by then both current buckets have expired.
        return { ok: false, retryAfter: Math.max(1, Math.ceil((hour + 2 * HOUR - t) / 1000)), reason: 'Log request budget exhausted' };
      }
      const inFlight = active.get(owner) || 0;
      if (inFlight + slots > ownerConcurrency || totalInFlight + slots > globalConcurrency) {
        return { ok: false, retryAfter: 1, reason: 'Too many active log requests' };
      }
      current.set(owner, (current.get(owner) || 0) + units);
      globalCurrent += units;
      active.set(owner, inFlight + slots); totalInFlight += slots;
      let released = false;
      return { ok: true, release() {
        if (released) return;
        released = true;
        totalInFlight -= slots;
        const remaining = active.get(owner) - slots;
        if (remaining) active.set(owner, remaining); else active.delete(owner);
      } };
    },
    status() { return { inFlight: totalInFlight, activeOwners: active.size, ownerConcurrency, globalConcurrency }; },
  };
}
