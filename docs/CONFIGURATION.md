# Configuration reference

The server is configured entirely from the environment. Flags are limited to `--http ADDR:PORT`
and the `new-token` subcommand.

## Target policy

A tool may only connect to a `host:port` that appears **exactly** in
`MEMCACHED_MCP_ALLOWLIST` (comma-separated; names are not normalised). With an empty list every
target is rejected. Entries are validated at startup with a strict parser: a missing port, port
0/over 65535, a URL/scheme, path, userinfo, whitespace, malformed DNS label, or an unbracketed
IPv6 literal is an error. Bracketed IPv6 (`[::1]:11211`) is accepted. A literal link-local,
unspecified or multicast address is refused.

When a target is a hostname, it is resolved at connect time with a deadline. All usable A/AAAA
addresses are checked and tried in resolver order (bounded to 16), so an unreachable IPv6 record
does not make a healthy IPv4 address unusable. The connection always goes to an address that was
checked, not to a second DNS lookup. Link-local, unspecified and multicast addresses (cloud
metadata endpoints) are refused even if the name resolves to one. Loopback and private ranges are
allowed because that is where memcached normally runs. `MEMCACHED_MCP_ALLOW_LINK_LOCAL=1` lifts the
link-local check for a deliberate setup.

## HTTP transport

| Variable | Meaning |
| --- | --- |
| `MEMCACHED_MCP_HTTP_TOKEN` | One shared token (at least 24 characters) with full access |
| `MEMCACHED_MCP_HTTP_TOKEN_FILE` | JSON file of per-user hashed tokens; set one of the two, not both |
| `MEMCACHED_MCP_HTTP_ALLOWED_HOSTS` | Extra accepted `Host` names (the Service's own names are added by the Helm chart) |
| `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT` | Required to bind anywhere other than loopback; there is no TLS in the binary |
| `MEMCACHED_MCP_HTTP_MAX_SESSIONS` | Global open-session cap (default 256) |
| `MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER` | Per-user open-session cap (default 32) |
| `MEMCACHED_MCP_HTTP_MAX_CONCURRENT` | Per-user in-flight POST/`/metrics` cap (default 16) |
| `MEMCACHED_MCP_HTTP_BODY_TIMEOUT_MS` | Deadline for reading a POST body (default 30000; must be positive) |
| `MEMCACHED_MCP_TOOL_TIMEOUT_MS` | Whole-call deadline for single-node tools (default 65000) |
| `MEMCACHED_MCP_MULTI_TOOL_TIMEOUT_MS` | Whole-call deadline for multi-node/mcrouter tools (default 120000) |

`/healthz` is open (no token, no `Host` check) and returns `ok`; it is meant for probes. Every
other route requires a bearer token and an accepted `Host` header. `GET /mcp` is a long-lived SSE
stream and is bounded by the session cap, not by the in-flight request cap. `GET /metrics` does
count against the in-flight cap because each scrape connects to the configured targets.

A POST body is wrapped in a deadline that starts when the body is first read; a client that drips
its JSON body cannot hold a request permit forever. GET SSE response streams are not affected.
TCP header-read and idle-connection limits are deliberately delegated to a mandatory production
reverse proxy/ingress; this binary does not expose a per-connection accept cap.

Token files are re-read every 5 seconds. An empty `users` list revokes everyone; a file that does
not parse is reported in the audit log and the previous users stay in force. Removing a user or
changing that user's token hash closes the user's open sessions; an expired token's sessions are
closed on the same reload tick. Existing sessions cannot be used with a revoked token: every
request is authenticated against the current token store.

## Response size limits

The client treats a reply as untrusted input. These limits apply per command, not only per line:

| Reply | Limit | Behaviour on overflow |
| --- | --- | --- |
| Single response line | 16 KiB | Protocol error; connection retired |
| `stats` reply (all lines) | 8 MiB | Error; connection retired; no partial map |
| Non-uniform `lru_crawler metadump` | 16 MiB | Error; connection retired; no partial dump |
| Uniform metadump scan | 64 MiB, plus 2M items / 60 s | Sample is returned with `complete: false` |
| Value read (`get`) | 16 MiB per value plus its CRLF | Error before allocation; connection retired |
| Metadata read on classic servers | 16 MiB total plus CRLF | Value is discarded in 8 KiB chunks, not allocated |

`stats` also caps the number of lines at 100,000. A malformed, timed-out or over-budget reply
retires the connection so the next command cannot consume leftover bytes. Each command also has a
**60-second total operation deadline** (`DEFAULT_OPERATION_DEADLINE`): a server that drips `STAT`
or metadump lines slowly cannot hold the request open indefinitely. Per-read timeouts still apply.
`sample_keys` reports an incomplete sample (rather than complete data) when a uniform scan hits a
limit; uniform sampling keeps at most 100,000 entries.

Response lines must be newline-terminated. A single-key get rejects a mismatched `VALUE` key and
more than one `VALUE` block. `mg` metadata rejects negative size/flags/age and TTL values below
`-1`. Metadump rejects empty/duplicate fields, invalid `fetch` values and expiry below `-1`.
mcrouter configs are capped at 1 MiB, 1,024 pools and 4,096 servers per pool; destination maps are
capped at 64 KiB/4,096 entries; route answers are capped at 512 bytes.

The DNS resolver has a process-wide concurrency cap of 16. DNS lookup and all address connection
attempts share one global `2 × OP_TIMEOUT` budget, so a single target cannot hold an upstream
permit for two independent full timeouts. IPv4 and IPv6 addresses are interleaved while resolver
order is preserved within each family.

## Process-wide memory budget

| Variable | Meaning |
| --- | --- |
| `MEMCACHED_MCP_MEMORY_BUDGET_MB` | Reservation budget shared by every tool and `/metrics` refresh (default 96 MiB; must be positive) |

Before a large allocation, the client reserves its size from one process-wide budget. Reservations
cover:

- value buffers (`get`, including the connection's mcrouter config read), reserved before the
  `Vec` is allocated;
- `stats` maps, reserved in 64 KiB growth steps on top of the raw line bytes plus 192 bytes per
  entry for key/value headers and map nodes;
- non-uniform metadump (16 MiB) and uniform metadump scans (64 MiB), reserved before the first
  line;
- `/metrics` stats/config replies, and the cached successful body for as long as the cache entry
  lives;
- an estimated pretty-JSON copy for `get_stats` and `mcrouter_get_stats` (six times the map
  payload, covering worst-case JSON control-character escaping).

Reservations are RAII handles: a timeout, malformed reply, cancellation (dropping the future) or
panic releases them. Exhaustion fails the operation closed — a tool returns an error, `/metrics`
returns 503 — and never returns partial data. A reply that does not fit is rejected whole.

This is a **reservation budget, not an absolute process memory limit**. The pretty-JSON estimate
is approximate; the second JSON-RPC framing copy, HTTP response bodies, allocator slack, the MCP
session machinery and request bodies are outside it. One serialized copy can be larger than the
raw bytes it was reserved for. The 96 MiB default is not a proof that a 256 MiB container is
sufficient; measure the real workload.

The HTTP transport additionally caps open sessions per user/globally and in-flight POST and
`/metrics` requests; see above.

## Tools and limits

| Variable | Meaning |
| --- | --- |
| `MEMCACHED_MCP_ALLOW_WRITE=1` | Register `set_key`, `delete_key`, `touch_key` |
| `MEMCACHED_MCP_WRITE_PREFIX` | Comma-separated key prefixes that writes may touch |
| `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1` | Enable `sample_keys` (prefix totals) |
| `MEMCACHED_MCP_ALLOW_KEY_NAMES=1` | Allow `sample_keys` to return individual key names |
| `MEMCACHED_MCP_DEST_MAP` | mcrouter destination name to reachable `host:port` mappings |
| `MEMCACHED_MCP_AUDIT_LOG` | Append-only JSON-lines audit file; stderr when unset |

`set_key` accepts a value of at most 1 MiB and `ttl_seconds` in `0..=2592000` (30 days). A larger
TTL would be read by memcached as a unix timestamp. Keys are 1-250 bytes with no spaces or control
characters.

Audit output is bounded: at most 100 lines per second process-wide, 20 per identity, with a
bounded 4,096-line writer queue (failed authentication has its own 20/s cap). Fields are clipped to
256 bytes, and `compare_nodes` / `mcrouter_compare_destinations` emit one summary line for all
denied addresses instead of one per address. `record` performs a non-blocking queue send; a
dedicated writer thread persists lines. Queue pressure, throttling and writer errors are counted,
reported at powers of two on stderr, and exported as
`memcached_mcp_audit_dropped_total` / `memcached_mcp_audit_write_errors_total` when `/metrics` is
enabled. Dropped lines are not a substitute for durable shipping, so use a log collector. The
audit line never contains values or tokens.

## Metrics

| Variable | Meaning |
| --- | --- |
| `MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS` | Process-wide cap for tool/upstream connections (default 64); `/metrics` uses its own bounded fan-out |
| `MEMCACHED_MCP_METRICS_TARGETS` | memcached targets exposed on `/metrics` (also allowlisted) |
| `MEMCACHED_MCP_MCROUTER_METRICS_TARGETS` | mcrouter targets exposed on `/metrics` (also allowlisted) |
| `MEMCACHED_MCP_METRICS_MAX_CONCURRENT` | Process-wide `/metrics` requests in flight (default 4; 429 above) |
| `MEMCACHED_MCP_METRICS_FANOUT` | Upstream tasks one refresh holds at once (default 16) |
| `MEMCACHED_MCP_METRICS_TIMEOUT_MS` | Overall refresh deadline (default 8000 ms; 503 above) |
| `MEMCACHED_MCP_METRICS_CACHE_MS` | Successful-body cache TTL (default 5000 ms; 0 disables) |

`/metrics` is absent unless at least one list is set. It uses the same bearer token and requires
the `metrics` permission. Scrapes are not written to the audit log. Destination probes only cover
entries in `MEMCACHED_MCP_DEST_MAP` whose address is also in the allowlist.

### `/metrics` resource and freshness semantics

- Each target has a 3 s per-target deadline and a **64 KiB stats / 256 KiB mcrouter config** response
  budget. The whole refresh also has the `MEMCACHED_MCP_METRICS_TIMEOUT_MS` deadline; on expiry
  the request returns **503**, never a healthy-looking partial body. An over-budget target is
  treated as failed (`*_up 0`).
- At most `MEMCACHED_MCP_METRICS_FANOUT` upstream tasks run at once. A 256-node list is read in
  bounded waves, not one task per node. `/metrics` connections are separate from the tool
  `MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS` budget, but their reply and cached-body reservations
  come from the same `MEMCACHED_MCP_MEMORY_BUDGET_MB` budget as tool calls.
- A successful body is cached for `MEMCACHED_MCP_METRICS_CACHE_MS`. Concurrent requests share one
  in-flight refresh (**singleflight**); a request that arrives within the TTL is served from the
  cache. A failed refresh never serves an expired cached body. If the budget cannot hold the
  cached body, the refresh fails with **503** instead of caching unaccounted memory.
- A target that cannot be scraped is `memcached_up 0` / `mcrouter_up 0`; it is never reported as
  healthy. Target failures do not turn the whole request into 503 unless the overall deadline is
  hit.
- The response includes internal metrics:
  `memcached_mcp_metrics_cache_hits_total`, `..._cache_misses_total`,
  `..._scrapes_total`, `..._scrape_errors_total`, `..._requests_rejected_total`,
  `..._cache_age_seconds`, `..._last_refresh_timestamp_seconds`,
  `memcached_mcp_memory_budget_bytes` and `..._budget_available_bytes`. Use
  `cache_age_seconds` to judge freshness; cached values are at most
  `MEMCACHED_MCP_METRICS_CACHE_MS` old. The budget gauges report reservations, not process RSS.
- A request over the process-wide `MEMCACHED_MCP_METRICS_MAX_CONCURRENT` limit gets **429** with
  `Retry-After: 1`.


## See also

- [README](../README.md) for the safety model and tool descriptions.
- [DEPLOYMENT](DEPLOYMENT.md) for the Docker and Helm paths.
- [TOOLS](TOOLS.md) for the permissions matrix.
- [OPERATIONS](OPERATIONS.md) for the production runbook and load laboratory.
- [DIAGNOSTICS](DIAGNOSTICS.md) for diagnostic schemas and limits.
