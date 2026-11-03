# MemCacheRoute MCP Server

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20HTTP-green.svg)](https://modelcontextprotocol.io/)

**Understand your cache. Trace your routes. Diagnose with confidence.**

A community-maintained [Model Context Protocol](https://modelcontextprotocol.io/) server for
[Memcached](https://memcached.org/) and [mcrouter](https://github.com/facebook/mcrouter). It gives
Claude and other MCP clients read-only access to cache statistics, RCA, capacity/slab/timeline
analysis, cluster comparison, mcrouter routing/TKO/migration advice, bounded resources and reusable
prompts. It is **read-only by default**; writes are opt-in, prefix-limited and audited.

> This is not an official Memcached, Meta or Anthropic product.

> **Name and compatibility.** The project is **MemCacheRoute MCP Server**. The executable
> (`memcached-mcp`), environment variables (`MEMCACHED_MCP_*`), MCP tool names, Helm chart name
> (`memcached-mcp`) and image repository keep their original identifiers so existing scripts and
> deployments continue to work. The crates.io package names are project-owned `memcache-route-*`
> names; the application package is `memcache-route-mcp-server`. The MCP `serverInfo.name` is
> `memcache-route-mcp-server`; tool names, arguments, schemas and transport behavior are unchanged.

Status: early alpha (`0.1.0-alpha.10`). See [COMPATIBILITY.md](COMPATIBILITY.md) for what has actually been tested.

## ✨ Features

- **Read-only diagnostics by default** for Memcached 1.4/1.5/1.6 and mcrouter 34.x.
- **Root-cause and incident analysis**: versioned RCA, snapshots, diffs, timelines and cache-efficiency advice.
- **Capacity and slab evidence**: headroom, eviction pressure, chunk waste, segmented-LRU settings and extstore fields.
- **Cluster and routing intelligence**: explicit cluster comparison, structural mcrouter impact, failover/TKO evidence and migration advice.
- **MCP-native**: bounded resources, static investigation prompts and `server_info` structured output.
- **Safe transport**: stdio or Streamable HTTP, bearer tokens/per-user permissions, allowlists, deadlines, memory budgets and audit redaction.
- **Cross-platform delivery**: Linux, macOS and Windows binaries; non-root `scratch` container and Helm chart.

## 🚀 Quick Start

Build the server and run it over stdio against an allowlisted Memcached node:

```bash
cargo build --release --locked -p memcache-route-mcp-server
MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 ./target/release/memcached-mcp
```

Register it with Claude Code:

```bash
claude mcp add memcache-route -e MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 -- /path/to/memcached-mcp
```

See [Install](#-installation), [Remote use](#-remote-use-streamable-http) and
[docs/TOOLS.md](docs/TOOLS.md) for the full catalogue and limits.

## 🔒 Security

- **Read-only by default.** Write tools (`set_key`, `delete_key`, `touch_key`) are not even listed unless `MEMCACHED_MCP_ALLOW_WRITE=1`. There is no flush tool.
- **Write prefixes.** With `MEMCACHED_MCP_WRITE_PREFIX` (comma-separated, e.g. `tmp:,scratch:`) writes are limited to keys starting with one of the prefixes; others are refused before any connection is made. Without it, any key on an allowlisted server can be written and the server warns at startup.
- **Audit trail.** Writes, rejected targets and denied requests are logged as JSON lines (with the calling user in HTTP mode) to `MEMCACHED_MCP_AUDIT_LOG` (or stderr). Key names and outcomes are recorded, never values or tokens. Reads are not audited.
- **Authenticated over HTTP.** The HTTP transport requires a bearer token (see below); stdio relies on whoever can start the process.
- **Allowlist.** The server only connects to `host:port` pairs listed in `MEMCACHED_MCP_ALLOWLIST` (comma-separated). With an empty list every target is rejected.
- **Key sampling is opt-in and private by default.** `sample_keys` exists only with `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1` and then returns prefix totals, not key names. Individual key names additionally need `MEMCACHED_MCP_ALLOW_KEY_NAMES=1`. The audit log records that a sample ran, never which keys it saw.
- **No values.** `get_key_metadata` returns metadata (existence, size, flags and, where supported, TTL and access info), never the value. On classic servers the value is read in bounded chunks and discarded, not allocated.
- **Bounded replies.** Untrusted server replies have byte budgets as well as line limits: `stats` 8 MiB, non-uniform metadump 16 MiB, uniform scan 64 MiB, values 16 MiB. Each command also has a 60-second total deadline, so a slow-dripping server cannot hold a request open forever. An oversized, malformed or timed-out reply is rejected and its connection retired; partial replies are never returned as complete data. A process-wide reservation budget (`MEMCACHED_MCP_MEMORY_BUDGET_MB`, default 96 MiB) is taken before the large reply buffers and maps; it is a reservation limit, not an absolute RSS cap. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md#response-size-limits).
- **Capability probing.** Features are detected by asking the server (`version`, `mn`), not guessed from the version number.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## 🛠️ Tools

| Tool | What it does |
| --- | --- |
| `server_info` | Version and whether meta commands are supported |
| `get_stats` | `stats`, optionally a group (`settings`, `items`, `slabs`, ...) |
| `get_key_metadata` | Does a key exist; size and flags, plus TTL, last access, fetched-before and CAS on servers with meta commands |
| `diagnose_node` | Hit ratio, evictions vs memory, connection limits, eviction skew |
| `diagnose_node_rca` | Versioned, evidence-based root-cause hypotheses for one node, with confidence, alternatives and checks |
| `advise_cache_efficiency` | Read-only efficiency advice with evidence, confidence, risks and validation steps |
| `advise_safe_remediation` | Human-approved remediation guidance from existing findings; no commands or changes |
| `analyze_snapshot_history` | Deterministic anomaly detection over user-supplied snapshots; no collection |
| `plan_cache_capacity` | Capacity/workload facts and observed snapshot deltas; no forecast or time-to-exhaustion |
| `analyze_slab_fragmentation` | Slab/chunk efficiency, eviction/OOM, LRU settings and extstore pressure |
| `analyze_incident_timeline` | Chronological incident intervals from supplied snapshots |
| `analyze_mcrouter_routing` | Route-handle inventory, structural risks and config impact; no simulation |
| `analyze_mcrouter_tko` | Soft/hard TKO evidence, destination health, queue/failover metrics |
| `compare_cache_clusters` | Compare supplied Memcached/mcrouter cluster snapshots |
| `advise_cache_migration` | Structural routing/capacity/version/warmup/rollback advice |
| `analyze_memcached_proxy` | Built-in-proxy stats/settings (1.6.23+); no Lua execution |
| `capture_node_snapshot` | Timestamped, bounded incident snapshot with selected metrics and RCA; no file writes |
| `compare_incident_snapshots` | Deterministic diff of two supplied snapshots, including resets and rate suppression rules |
| `compare_nodes` | Outlier item counts and hit ratios across 3+ nodes |
| `mcrouter_get_stats` | mcrouter stats and destination health |
| `mcrouter_inspect_config` | Running mcrouter config: pools, servers, config problems |
| `mcrouter_compare_destinations` | Looks at each memcached behind an mcrouter and flags outliers and per-node problems (needs `MEMCACHED_MCP_DEST_MAP`) |
| `mcrouter_diagnose_failover` | Is there a failover handle, is anything down, and what that means for reads and writes |
| `mcrouter_diagnose_rca` | Correlates router config/stats with reachable destination stats; reports partial topology coverage and uncertainty |
| `analyze_cluster_topology` | Explicit-router topology model with pools, destinations, shared/unreachable backends and coverage |
| `capture_mcrouter_snapshot` | Timestamped snapshot with opaque topology IDs, destination coverage and RCA; no raw config |
| `mcrouter_trace_key_route` | Which destination a key routes to (asks mcrouter itself); says so when the destination is down |
| `sample_keys` | What is stored: items, bytes and never-fetched counts per key prefix, from the LRU crawler's metadata dump. Only with `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1` |
| `set_key`, `delete_key`, `touch_key` | Writes; only with `MEMCACHED_MCP_ALLOW_WRITE=1` |

`sample_keys` puts load on the server (it uses the LRU crawler), reads at most `max_scan` items (10,000 by default, 100,000 at most) and says so when it stopped early. The crawler's order is not random, so a partial scan is biased. Pass `uniform: true` to read the whole dump instead and keep a random sample of `max_scan` items: the totals are then scaled-up estimates for the whole cache (a full crawl, capped at 2 million items, 64 MiB or 60 seconds; if the cap is hit the result says it is not random). It needs the crawler to be enabled, which it is on 1.5 and 1.6 but not by default on 1.4 (`-o lru_crawler`).

Full schemas, limits and safety properties for the diagnostic tools are in
[docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md); the permissions matrix and tool contracts are in
[docs/TOOLS.md](docs/TOOLS.md).

Diagnostic thresholds are heuristics and have not been tuned on production traffic. Looking up a key's metadata still counts in the server's global `get_hits`/`get_misses` totals, though it leaves the item's LRU position and fetched-before state alone.

## 🔧 Remote use (Streamable HTTP)

By default the server speaks MCP over stdio. For shared or remote use, run it as an HTTP service:

```
MEMCACHED_MCP_HTTP_TOKEN="<at least 24 random characters>" MEMCACHED_MCP_ALLOWLIST=... memcached-mcp --http 127.0.0.1:8080
```

The endpoint is `/mcp`. Clients must send `Authorization: Bearer <token>` (the scheme is case-insensitive); requests without it get 401 and are written to the audit log (peer address only, never the token).

- The token is mandatory; the server refuses to start without one of at least 24 characters.
- There is no TLS. Binding to anything other than loopback is refused unless `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`, because the token would cross the network in clear text. Put a TLS-terminating proxy in front and bind to loopback.
- `Host` headers are checked against loopback names on every route (including `/metrics`) to block DNS rebinding. Behind a proxy, list the public hostnames in `MEMCACHED_MCP_HTTP_ALLOWED_HOSTS` (comma-separated).
- At most 256 sessions can be open at once (`MEMCACHED_MCP_HTTP_MAX_SESSIONS` changes it); further `initialize` requests get `503` with `Retry-After`. Idle sessions are dropped after 5 minutes, so the slots free up on their own.
- Each user (token) may have 16 requests in flight at once (`MEMCACHED_MCP_HTTP_MAX_CONCURRENT` changes it); more get `429` with `Retry-After`. This covers tool POSTs and `/metrics` scrapes; a long-lived `GET /mcp` event stream is bounded by the session cap instead. Every tool call opens its own connection to memcached, so this bounds what one token can do to a server. Open sessions are also capped per user (32, `MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER`), so one token cannot use up the global cap. A process-wide `MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS` budget (default 64) bounds all tool connections and fails closed when exhausted. A separate process-wide reservation budget, `MEMCACHED_MCP_MEMORY_BUDGET_MB` (default 96), is taken before large reply buffers, STAT maps, metadump scans and the cached `/metrics` body; it fails closed and is a reservation limit, not an absolute process memory cap.
- Failed logins are written to the audit log, at most 20 lines per second; the rest are summarised in one line, so a flood of bad tokens cannot fill the disk. All audit output has a 100-line/second process-wide backstop, fields are clipped, and multi-address allowlist denials are aggregated into one line.
- A single shared token means one identity with full access. For per-user access see below.

### Per-user tokens and permissions

Instead of `MEMCACHED_MCP_HTTP_TOKEN`, point `MEMCACHED_MCP_HTTP_TOKEN_FILE` at a JSON file of users (set one of the two, not both). Only SHA-256 hashes of the tokens are stored. Issue a token with:

```
memcached-mcp new-token alice read,metrics        # never expires
memcached-mcp new-token alice read,metrics 30     # stops working after 30 days
```

It prints the token once (give it to Alice) and the entry to add to the file:

```json
{"users": [{"name": "alice", "token_sha256": "...", "permissions": ["read", "metrics"], "expires_at": 1795000000}]}
```

`expires_at` is optional, in unix seconds. From that moment the token is refused exactly like an unknown one (401, audited), and the server warns at startup about users whose token has already expired. To rotate, issue a new token, replace the user's entry; no restart is needed (see below).

| Permission | Allows |
| --- | --- |
| `read` | every read-only tool, including the mcrouter ones, except `sample_keys` |
| `sample` | `sample_keys` (prefix totals) |
| `key_names` | key names from `sample_keys` (also needs `sample`) |
| `write` | `set_key`, `delete_key`, `touch_key` |
| `metrics` | `/metrics` |

A permission never widens the server-wide switches: writes still need `MEMCACHED_MCP_ALLOW_WRITE=1` (and the prefix limit), sampling still needs `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1`. The audit log records the user name on every entry, including denials. The file is re-read every 5 seconds while the server runs, so adding, changing or removing a user (revocation) takes effect without a restart, including for open sessions on their next request. Removing a user or rotating their token also closes that user's open sessions; an empty `users` list on reload revokes everyone (at startup it is still an error). If an edit does not parse, the server logs it to the audit log and keeps the previous users. Tokens are 256 random bits, so a fast hash is enough.

### Prometheus metrics

In HTTP mode the server can also expose memcached counters at `/metrics`, so Prometheus keeps the history and you get trends and alerting without this project storing anything:

```
MEMCACHED_MCP_METRICS_TARGETS="10.0.1.5:11211,10.0.1.6:11211"   # each must also be in MEMCACHED_MCP_ALLOWLIST
```

```yaml
scrape_configs:
  - job_name: memcached
    authorization: { credentials: "<the same token>" }
    static_configs: [{ targets: ["127.0.0.1:8080"] }]
```

`/metrics` uses the same bearer token and is absent unless targets are configured. It exports raw counters and gauges (`memcached_get_hits_total`, `memcached_evictions_total`, `memcached_used_bytes`, ...) labelled by `instance`, plus `memcached_up` (0 when a target is unreachable). Ratios and rates are left to PromQL, e.g. `rate(memcached_get_hits_total[5m]) / (rate(memcached_get_hits_total[5m]) + rate(memcached_get_misses_total[5m]))`. Scrapes are not written to the audit log. mcrouter instances can be added with `MEMCACHED_MCP_MCROUTER_METRICS_TARGETS` (also allowlisted); they export `mcrouter_up`, destination counts (`mcrouter_destinations`, `_up`, `_down`, `_suspect`), client connections, routed get/set/delete counts, queue depth and memory. mcrouter's `stats` has no per-destination detail, so with `MEMCACHED_MCP_DEST_MAP` set the server reads each mcrouter's pools and probes every mapped, allowlisted destination itself, exporting `mcrouter_destination_up{instance,destination}`. That is reachability from the MCP server's network position, not mcrouter's own view, and unmapped destinations are left out. It costs one connection per destination per scrape.

Scrapes are protected against stampedes and slow upstreams: a process-wide request cap (default 4, `429` above), bounded fan-out (16), an 8 s overall deadline (`503` above), a 5 s successful-body cache with singleflight, a 64 KiB stats / 256 KiB mcrouter-config per-target budget. Concurrent callers share one refresh; a failed refresh never serves an expired body. A target that cannot be read is `memcached_up 0`/`mcrouter_up 0`, never healthy. `memcached_mcp_metrics_cache_age_seconds` and `last_refresh_timestamp_seconds` expose freshness; see [docs/CONFIGURATION.md](docs/CONFIGURATION.md#metrics-resource-and-freshness-semantics) for tuning. The output is expected to pass `promtool check metrics`; this is not run in CI.

## 🧭 mcrouter destinations

mcrouter names its destinations as it sees them (often container or service names such as `mc-a:11211`), which this server may not be able to resolve. To inspect the memcached nodes behind an mcrouter, map those names to reachable addresses, and allowlist the addresses too:

```
MEMCACHED_MCP_DEST_MAP="mc-a:11211=10.0.1.5:11211,mc-b:11211=10.0.1.6:11211"
MEMCACHED_MCP_ALLOWLIST="10.0.0.9:5000,10.0.1.5:11211,10.0.1.6:11211"
```

Destinations without a mapping are reported as `unmapped` rather than guessed.

## 🚀 Installation

Download a binary for Linux, macOS or Windows from the releases page, or build from source:

```
cargo build --release -p memcache-route-mcp-server
```

### From crates.io

The application crate is `memcache-route-mcp-server`; the installed binary remains `memcached-mcp`.
After the crates.io publication is approved:

```
cargo install memcache-route-mcp-server --locked
```

## 🐳 Docker

```
docker build -t memcached-mcp .
```

The image is a single static binary on `scratch` (about 7 MB), running as user 65532 with no shell. stdio is the default:

```
docker run -i --rm -e MEMCACHED_MCP_ALLOWLIST=cache:11211 memcached-mcp
```

For HTTP, the process has to bind `0.0.0.0` inside the container, which the server refuses unless `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`. Publish the port on loopback only, or put a TLS proxy in front:

```
docker run -d -p 127.0.0.1:8080:8080 \
  -e MEMCACHED_MCP_ALLOWLIST=cache:11211 -e MEMCACHED_MCP_HTTP_TOKEN=... \
  -e MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1 memcached-mcp --http 0.0.0.0:8080
```

Both modes were tried against a memcached on the same Docker network. The image is built in CI but
not published anywhere. The builder is pinned by version and digest. The alpha.9 image was rebuilt
locally and scanned with Syft/Trivy (0 vulnerabilities, 0 secrets); a Cosign blob signature was
verified (transparency-logged, not an image signature), but there is no CI-backed image
signature/provenance or published image yet. See
[docs/CONTAINER-SECURITY.md](docs/CONTAINER-SECURITY.md).

## ☸️ Kubernetes (Helm)

A chart is in `deploy/helm/memcached-mcp`. It runs the HTTP transport as a non-root, read-only-filesystem pod, refuses to render without an allowlist and an existing Secret holding the credentials, and validates critical values with `values.schema.json`:

```
kubectl create secret generic memcached-mcp-auth --from-file=tokens.json
helm install mcp deploy/helm/memcached-mcp \
  --set image.repository=registry.example.com/memcached-mcp \
  --set image.digest=sha256:<64-hex> \
  --set 'allowlist={memcached-0.memcached:11211}' \
  --set auth.existingSecret=memcached-mcp-auth
```

The pod speaks plain HTTP, so expose the Service only through a TLS-terminating ingress and add its public name to `allowedHosts` (the Service's own DNS names, such as `mcp-memcached-mcp.<namespace>.svc`, are accepted automatically so in-cluster clients and Prometheus work). The chart sets startup/readiness/liveness probes, a rolling update with `maxUnavailable: 0`, a 30 s termination grace period, and a PDB when more than one replica is used. To limit who can reach the pod, set `networkPolicy.enabled=true` and list the allowed peers in `networkPolicy.allowFrom`; egress isolation is opt-in through `networkPolicy.egress` because the chart does not know your memcached/mcrouter labels. Session affinity is enabled by default because MCP sessions are per-pod; HPA is off by default because scale-down loses sessions. Production install, upgrade, rollback, token-rotation and incident steps are in [docs/OPERATIONS.md](docs/OPERATIONS.md). An earlier revision of the chart was installed on a local kind cluster to check that the pod starts with the read-only filesystem, that the token file mounts, and that clients using the Service DNS name get through the Host check. The current chart was subsequently installed on a local kind v1.37.0 cluster with Secret mode/fsGroup, read-only rootfs, probes, non-root execution and working token authentication; NetworkPolicy/CNI enforcement, PDB/HPA behavior, production ingress and token rotation were not exercised. It has not run on a production cluster. The image is not published, so you have to build and push it yourself.

## 💬 Use with Claude Code

```
claude mcp add memcache-route -e MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 -- /path/to/memcached-mcp
```

## 🧪 Development

```
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Live tests are skipped unless pointed at a server. Start the test servers and set the variables:

```
docker compose -f tests/compat/docker-compose.yml up -d
MEMCACHED_ADDR=127.0.0.1:11216 MEMCACHED_SMALL_ADDR=127.0.0.1:11217 MCROUTER_ADDR=127.0.0.1:11218 cargo test
```

The dead-destination test needs `mc-a` stopped first (CI does this too):

```
docker compose -f tests/compat/docker-compose.yml stop mc-a
MCROUTER_PLAIN_ADDR=127.0.0.1:11218 MCROUTER_FAILOVER_ADDR=127.0.0.1:11222 cargo test -p memcache-route-mcrouter --test failover
```

Layout: `memcached-protocol` (codec, no I/O), `memcached-core` (client), `diagnostics` and `mcrouter` (pure analysis), `mcp-server` (the binary).

## 🐛 Troubleshooting

| Symptom | What to check |
|---|---|
| Server not listed in the client | Give the client the absolute path to the `memcached-mcp` binary; GUI clients often do not inherit `PATH` |
| `ALLOWLIST` / target rejected | Add the exact `host:port` to `MEMCACHED_MCP_ALLOWLIST`; an empty list rejects everything |
| `401` / `forbidden` over HTTP | Check the bearer token, its permissions and expiry; `read` is required for diagnostic tools |
| TLS or certificate errors | The server has no in-process TLS. Terminate TLS at a proxy and set `MEMCACHED_MCP_HTTP_ALLOWED_HOSTS` |
| Timeouts or `exceeded` errors | Check upstream reachability, dead destinations and the tool/connection deadlines |
| `sample_keys` unavailable | It is opt-in: set `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1`; key names also need `MEMCACHED_MCP_ALLOW_KEY_NAMES=1` |

## 📝 Notes

- This is an early alpha (`0.1.0-alpha.10`); diagnostic thresholds are heuristics and have not been tuned on production traffic.
- The server never executes remediation, Lua or proxy configuration. Migration and routing advice are evidence-limited and require human approval.
- Offline routing simulation is unsupported; use live `mcrouter_trace_key_route` and normal change control.
- See [COMPATIBILITY.md](COMPATIBILITY.md) and [docs/RELEASE-READINESS.md](docs/RELEASE-READINESS.md) for tested scope and remaining release gates.

## 📄 License

[Apache-2.0](LICENSE): free to use, modify and distribute under the terms of the license.
