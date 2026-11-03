# Architecture

```
MCP client ──stdio──┐
                    ├─► mcp-server (binary `memcached-mcp`) ──► memcached-core ──► memcached / mcrouter
MCP client ──HTTP───┘        │  tools, auth, audit,                (async text/meta client)
  (Streamable HTTP)          │  target policy, limits
Prometheus ──GET /metrics────┘
```

## Crates

| Crate | Role | I/O |
| --- | --- | --- |
| `memcached-protocol` | Encodes commands and parses replies (text protocol, meta commands, `stats`, metadump). Validates everything that is placed on a command line. | none |
| `memcached-core` | Async `Client` over TCP: timeouts, reply size limits, capability probing, key sampling. A failed read marks the connection unusable. | TCP |
| `mcrouter` | Parses the running mcrouter config and `stats`, interprets route traces, reasons about failover (with a confidence level), and adds mcrouter RCA, sanitized topology snapshots, and the cluster topology/health model. | none |
| `diagnostics` | Pure rules over `stats` output: hit ratio, evictions, memory, connections, node comparison, key inventory, Prometheus text, the versioned node RCA layer, bounded incident snapshot/diff, the cache-efficiency advisor, the safe remediation advisor, and historical anomaly detection. | none |
| `mcp-server` | The binary. MCP tools (rmcp), HTTP transport (axum), tokens and permissions, audit log, target policy, request limits, `/metrics`. | stdio, HTTP, TCP |

Keeping `memcached-protocol`, `mcrouter` and `diagnostics` free of I/O means every rule and parser
is covered by unit tests without a server.

## Request path (HTTP)

1. `require_known_host`: the `Host` header must be loopback, the configured names or the Service
   names. (Not applied to `/healthz`.)
2. `require_token`: bearer token looked up in the current token store (constant-time comparison
   over all entries). Failed attempts are audited, throttled to 20 lines per second.
3. Per-user concurrency permit for POSTs and `/metrics` GETs
   (`MEMCACHED_MCP_HTTP_MAX_CONCURRENT`, 429 when exhausted). A `GET /mcp` event stream is
   bounded by the session cap instead.
4. `cap_sessions` for requests that open a session (global and per-user caps, 503 when reached).
   Check-and-create is one atomic reservation, so concurrent initializes cannot pass the same
   count.
5. Tool connections also draw from a process-wide upstream budget
   (`MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS`, default 64); when it is exhausted the tool fails
   closed instead of opening another connection.
6. `/metrics` has its own process-wide request cap, bounded fan-out, overall deadline and a
   singleflight TTL cache. Its target connections do not consume the tool budget, so a slow
   scrape cannot starve tool calls.
7. rmcp's Streamable HTTP service dispatches to the tool.
8. The tool checks the permission, then the allowlist, then validates arguments, then connects
   through `target::open`, which resolves the name with a deadline, refuses blocked addresses and
   connects to the address it checked.
9. `diagnose_node_rca` enriches one node snapshot with structured evidence; `mcrouter_diagnose_rca`
   reuses the router config/stats plus bounded destination probes and reports partial coverage.
   Both are pure analyses after collection and return bounded, versioned JSON.
10. Snapshot capture stores selected numeric metrics plus the RCA/topology result; comparison is
    pure and stateless. No snapshot is written to disk and no background collector exists.
11. `analyze_cluster_topology` fetches only explicitly supplied, allowlisted mcrouter configs and
    stats, maps destinations through the configured destination map/allowlist, probes unique
    backends with bounded fan-out, and builds a deterministic router/pool/destination/backend model.
    It performs no discovery or network scanning.

Token file reloads run in a background task every 5 seconds and swap an `Arc` under a lock; a file
that does not parse is reported and ignored.

## Concurrency model

- One memcached connection per tool call (no pool); a connection is dropped after the call.
  Multi-node tools open up to 16 at a time, and the process-wide
  `MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS` budget caps the total. A hostname's usable IPv4/IPv6
  addresses are interleaved while preserving resolver order within each family; DNS lookup and
  connection attempts share one bounded budget, and a process-wide DNS lookup semaphore caps
  blocking-pool work. Every command has a 60-second whole-operation deadline in addition to
  per-read timeouts; every tool also has a whole-call deadline (65 s single-node, 120 s multi-node,
  overridable for tests/deployments).
- POST request bodies have a deadline wrapper so slow-drip clients cannot hold a permit; GET SSE
  response streams are unaffected. TCP header-read and idle-connection limits are delegated to the
  production reverse proxy/ingress.
- `/metrics` fans out with a small bound (16 by default), holds at most 4 scrapes process-wide,
  enforces an 8 s overall deadline and caches a successful body for 5 s; one refresh runs at a
  time (singleflight).
- Large upstream replies draw from one process-wide reservation budget
  (`MEMCACHED_MCP_MEMORY_BUDGET_MB`, default 96 MiB): value buffers, STAT maps, metadump scans,
  `/metrics` replies and the cached `/metrics` body. A reservation is taken before the allocation
  and released by RAII; exhaustion fails that operation closed. The budget does not account for
  every byte in the process (JSON-RPC/HTTP copies, allocator slack and the runtime are outside it).
- Sessions are held by rmcp's local session manager in memory. Limits (sessions, requests per
  user) are per process. A per-user/global reservation is taken before a session is created and
  released if the request never produces a session id.
- Shutdown: SIGTERM/SIGINT stop accepting, give in-flight requests 10 seconds, then exit.

## Data the server keeps

None on disk except the optional audit log. Nothing is cached between calls. Values are never
returned by any tool.
