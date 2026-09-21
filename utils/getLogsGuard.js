import { getLogsMaxBlockRange } from '../config.js';

const hash = value => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
const address = value => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
const quantity = value => typeof value === 'string' && /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,15})$/.test(value);

export function checkGetLogsParams(params, maxRange = getLogsMaxBlockRange) {
  const bad = message => ({ ok: false, message: `eth_getLogs: ${message}` });
  if (!Array.isArray(params) || params.length !== 1 || !params[0] ||
      typeof params[0] !== 'object' || Array.isArray(params[0])) return bad('provide one filter object');
  const f = params[0];
  if (Object.keys(f).some(k => !['fromBlock', 'toBlock', 'blockHash', 'address', 'topics'].includes(k))) {
    return bad('unsupported filter field');
  }
  if (f.address !== undefined && !(address(f.address) || (Array.isArray(f.address) &&
      f.address.length > 0 && f.address.length <= 20 && f.address.every(address)))) return bad('invalid address filter (max 20 addresses)');
  if (f.topics !== undefined && !(Array.isArray(f.topics) && f.topics.length <= 4 &&
      f.topics.every(t => t === null || hash(t) || (Array.isArray(t) && t.length > 0 &&
        t.length <= 20 && t.every(hash))))) return bad('invalid topics (max 4 positions, 20 alternatives each)');
  if (Object.hasOwn(f, 'blockHash')) {
    if (!hash(f.blockHash) || Object.hasOwn(f, 'fromBlock') || Object.hasOwn(f, 'toBlock')) {
      return bad('blockHash must be a 32-byte hash without fromBlock or toBlock');
    }
    return { ok: true, range: 1 };
  }
  // Check exactly what is forwarded: no moving tags or inferred defaults.
  if (!quantity(f.fromBlock) || !quantity(f.toBlock)) {
    return bad('provide explicit hex fromBlock and toBlock; moving tags are not supported');
  }
  const from = BigInt(f.fromBlock), to = BigInt(f.toBlock);
  if (from > to) return bad('fromBlock is after toBlock');
  const range = to - from + 1n;
  if (range > BigInt(maxRange)) return bad(`block range exceeds maximum of ${maxRange}`);
  return { ok: true, range: Number(range) };
}
