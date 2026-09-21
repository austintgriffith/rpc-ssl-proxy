import https from 'node:https';
import axios from 'axios';
import { checkGetLogsParams } from './getLogsGuard.js';
import { createKeyRateLimiter } from './keyRateLimiter.js';
import { defaultRequestCount, methodRequestCounts } from '../config.js';

// Credentials, cookies, spoofed origin and forwarding headers never reach nodes.
export const upstreamHeaders = () => ({ 'Content-Type': 'application/json', 'User-Agent': 'BG-RPC-Proxy' });

export function createLogsForwarder({ url, timeoutMs = 10000, maxResponseBytes = 5 * 1024 * 1024 }) {
  const agent = new https.Agent({ rejectUnauthorized: true });
  return async body => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await axios.post(url, body, {
        headers: upstreamHeaders(), signal: controller.signal, timeout: timeoutMs,
        maxRedirects: 0, maxContentLength: maxResponseBytes, maxBodyLength: 100 * 1024,
        httpsAgent: agent, responseType: 'json',
      });
    } finally { clearTimeout(timer); }
  };
}

export function sendRpcErrors(res, body, status, code, message) {
  const error = call => ({ jsonrpc: '2.0', id: call?.id ?? null, error: { code, message } });
  const calls = Array.isArray(body) ? body : [body];
  const responses = calls.filter(call => Object.hasOwn(call || {}, 'id')).map(error);
  if (!responses.length) return res.status(204).end();
  return res.status(status).json(Array.isArray(body) ? responses : responses[0]);
}

// Install on the RPC routes before the legacy forwarding handler. Only batches
// containing getLogs take this path; ordinary RPC keeps its existing IP limits.
export function createLogsAccess({ store, forward, enabled = false,
  limiter = createKeyRateLimiter(), isBlacklisted = () => false }) {
  return async (req, res, next) => {
    const calls = Array.isArray(req.body) ? req.body : [req.body];
    const logs = calls.filter(call => call?.method === 'eth_getLogs');
    const identity = store.resolve(req);
    if (identity.status === 'unavailable') return sendRpcErrors(res, req.body, 503, -32001, 'Token registry unavailable');
    if (identity.status === 'invalid') return sendRpcErrors(res, req.body, 401, -32001, 'Invalid API token');
    if (!logs.length) return next();
    const reject = (status, code, message) => sendRpcErrors(res, req.body, status, code, message);
    if (!enabled) return reject(503, -32005, 'Log access is disabled');
    if (isBlacklisted(req.ip)) return reject(403, -32001, 'Access denied');
    if (identity.status !== 'valid') return reject(401, -32001, 'eth_getLogs requires an operator-issued token');
    if (calls.some(call => typeof call?.method !== 'string')) return reject(200, -32600, 'Method must be a string');
    if (calls.length > 20) return reject(200, -32602, 'Maximum batch size is 20');
    for (const call of logs) {
      const verdict = checkGetLogsParams(call.params);
      if (!verdict.ok) return reject(200, -32602, verdict.message);
    }
    const units = calls.reduce((sum, call) => sum +
      (Object.hasOwn(methodRequestCounts, call.method) ? methodRequestCounts[call.method] : defaultRequestCount), 0);
    const admission = limiter.admit(identity.owner, units, logs.length);
    if (!admission.ok) {
      res.set('Retry-After', String(admission.retryAfter));
      return reject(429, -32005, admission.reason);
    }
    try {
      // Keep the reservation after a client disconnects: upstream may still be
      // executing. Only upstream completion/timeout releases it. Never retry or
      // touch the ordinary RPC circuit breaker, and never use paid fallback.
      const response = await forward(req.body);
      if (!res.destroyed) res.status(response.status).send(response.data);
    } catch {
      if (!res.destroyed) reject(502, -32002, 'Log upstream failed, timed out, or exceeded the response limit');
    } finally { admission.release(); }
  };
}
