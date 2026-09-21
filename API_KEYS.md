# Trusted eth_getLogs access — local revision

This replaces the closed PR's Firestore signup integration. Only an operator can
issue access, using a local JSON registry. Signing in with a wallet or minting a
key in `rpc-token-manager` grants no access here. The nodes repository is unchanged.

## Enable only after staging verification

Log access defaults to **off**. This implementation supports **one proxy process**.
Owner/global counters are in memory and reset on restart. Do not use PM2 cluster
mode, replicas, or rolling overlapping processes: they multiply the limits.
A shared atomic limiter and persistent budgets are required before scaling out.

1. Use Node 20+ and install dependencies. Run `npm test`.
2. Configure `RPC_KEYS_FILE` as an absolute path outside the repository, for example
   `/etc/bg-rpc/rpc-keys.json`. Create its parent directory with appropriate ownership.
   The proxy needs read access; restrict writes to the operator account. The file
   contains an array of `{ "digest": "<sha256 hex>", "owner": "<stable owner slug>" }`.
3. Issue a staging token using the CLI below.
4. Verify the actual downstream path supports explicit-range `eth_getLogs`, has
   execution deadlines, and cannot bypass this gateway from the public internet.
   Confirm downstream pool/cache components do not retry logs into paid providers.
   This gateway never invokes its own fallback for logs, but cannot control a
   downstream service's fallback policy.
5. Measure broad/dense and sparse log queries at the limits below, verify node
   recovery after timeouts, and tune limits to actual capacity. Proxy timeouts
   bound the gateway's wait, not necessarily a node's execution after disconnection.
6. Set `RPC_GET_LOGS_ENABLED=true`, restart the single process, and verify approved,
   unapproved, revoked, over-budget, and disconnected callers in staging.

No staging deployment, live chain call, or capacity measurement was performed as
part of this local revision. An operator must confirm these before enabling it.
Existing TLS verification bypasses were removed: use valid upstream certificates
or configure the correct CA (`NODE_EXTRA_CA_CERTS`) instead of disabling verification.

## Issue and revoke tokens

Set `RPC_KEYS_FILE` in the shell running these commands as well as the proxy's env.
The CLI does not load `.env` automatically.

```sh
export RPC_KEYS_FILE=/etc/bg-rpc/rpc-keys.json
node scripts/manage-keys.js issue spencer
node scripts/manage-keys.js revoke-key spencer <digest-from-registry>
node scripts/manage-keys.js revoke-owner spencer
```

`issue` prints a random 256-bit token once. Give it privately to its owner and keep
it server-side. Browser bundles and public RPC URLs expose tokens to other people.
The registry stores only SHA-256 digests, not usable tokens. Reissuing with the
**same owner** preserves that owner's existing usage allowance within the process.
Only create a new owner for a genuinely separate approved person/project.

Updates use a lock and atomic rename with mode 0600. A lock left after a crashed
CLI requires the operator to confirm no update is running before removing it.
Revocation prevents new requests after the next refresh (normally 5 seconds);
in-flight work is not retroactively canceled. Failed reads clear access immediately;
a stalled refresh denies access once the last successful snapshot is 15 seconds old.
An empty array revokes all keys. Setting `RPC_GET_LOGS_ENABLED=false` and restarting
disables log access entirely. Do not place the registry in Git or share it with the
public signup service.

## Requests

Use `POST /` with `X-Api-Key: <token>`, or `POST /v1/<token>` for clients needing a
URL. Prefer the header; redact token-bearing paths in any external access logs.
Conflicting path/header tokens are rejected. Missing or invalid tokens never grant
log access. Valid tokens do not exempt ordinary requests from existing IP limits.

Each log filter must use explicit hex `fromBlock` and `toBlock`, or a valid 32-byte
`blockHash` without either range field. Moving tags (`latest`, `safe`, `finalized`,
`pending`) and omitted ranges are rejected. Fetch `eth_blockNumber` separately and
paginate explicit ranges. This version deliberately does not guess tag heights.

Single requests and mixed batches are supported. If any log filter is invalid or
admission fails, the entire batch is rejected with one error per request ID; none
is forwarded. The existing validator still rejects notifications (requests without
IDs); this revision does not add notification support.

## Starting limits

| Control | Default |
| --- | --- |
| Inclusive block range | 2,000 |
| Active log calls per owner, across all their tokens | 2 |
| Active log calls across the single proxy process | 4 |
| Weighted units per owner per approximate rolling hour | 50,000 |
| Weighted units globally per approximate rolling hour | 100,000 |
| Cost of each log call, including failed upstream work | 100 |
| Maximum batch items | 20 |
| Maximum addresses / alternatives per topic | 20 / 20 |
| Upstream total deadline | 10 seconds |
| Maximum upstream response bytes | 5 MiB |

Hourly limits approximate a rolling window using two weighted hour buckets. They
are not a substitute for concurrency controls or a durable billing quota. A small
block range can still be expensive. No claim of production capacity is implied.

Batches containing logs use the bounded primary-only path. Other items in such a
batch are charged using `config.js` method weights. Ordinary batches use the legacy
path. Disconnected clients retain their reservations until upstream completion or
timeout. There are no gateway retries, no paid fallback, and no changes to the
ordinary RPC circuit breaker from log traffic. Credential and caller identity
headers are not forwarded to upstreams.

`/status` and `/proxy` now require the existing admin key, since their old responses
exposed upstream URLs. `/status` includes token registry health and active log
reservations. Existing anonymous Origin bypasses and other anonymous limiter
limitations are outside this change and still require separate work.

## Verification

`npm test` runs unit tests and real local HTTP integration tests against a fake
upstream, using the same route registration, validator, access handler and Axios
transport used by production. No Firebase, production database, live RPC, TLS
listener on 443, or real token is needed. Tests cover issuing/revoking/rotating
keys, stale registries, shared budgets, exact ranges, batches, disconnects,
timeouts, response limits, and credential stripping.
