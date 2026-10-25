# memcached-mcp

An [MCP](https://modelcontextprotocol.io) server for Memcached and mcrouter, written in Rust. It gives an AI assistant a safe way to inspect cache servers and diagnose problems. Read-only by default.

Status: early. See [COMPATIBILITY.md](COMPATIBILITY.md) for what has actually been tested.

## Safety model

- **Read-only by default.** Write tools (`set_key`, `delete_key`, `touch_key`) are not even listed unless `MEMCACHED_MCP_ALLOW_WRITE=1`. There is no flush tool.
- **Write prefixes.** With `MEMCACHED_MCP_WRITE_PREFIX` (comma-separated, e.g. `tmp:,scratch:`) writes are limited to keys starting with one of the prefixes; others are refused before any connection is made. Without it, any key on an allowlisted server can be written and the server warns at startup.
- **Audit trail.** Writes and rejected targets are logged as JSON lines to `MEMCACHED_MCP_AUDIT_LOG` (or stderr). Key names and outcomes are recorded, never values. Reads are not audited.
- **Authenticated over HTTP.** The HTTP transport requires a bearer token (see below); stdio relies on whoever can start the process.
- **Allowlist.** The server only connects to `host:port` pairs listed in `MEMCACHED_MCP_ALLOWLIST` (comma-separated). With an empty list every target is rejected.
- **No values.** `get_key_metadata` returns metadata (existence, size, flags and, where supported, TTL and access info), never the value.
- **Capability probing.** Features are detected by asking the server (`version`, `mn`), not guessed from the version number.

## Tools

| Tool | What it does |
| --- | --- |
| `server_info` | Version and whether meta commands are supported |
| `get_stats` | `stats`, optionally a group (`settings`, `items`, `slabs`, ...) |
| `get_key_metadata` | Does a key exist; size and flags, plus TTL, last access, fetched-before and CAS on servers with meta commands |
| `diagnose_node` | Hit ratio, evictions vs memory, connection limits, eviction skew |
| `compare_nodes` | Outlier item counts and hit ratios across 3+ nodes |
| `mcrouter_get_stats` | mcrouter stats and destination health |
| `mcrouter_inspect_config` | Running mcrouter config: pools, servers, config problems |
| `mcrouter_compare_destinations` | Looks at each memcached behind an mcrouter and flags outliers and per-node problems (needs `MEMCACHED_MCP_DEST_MAP`) |
| `mcrouter_diagnose_failover` | Is there a failover handle, is anything down, and what that means for reads and writes |
| `mcrouter_trace_key_route` | Which destination a key routes to (asks mcrouter itself); says so when the destination is down |
| `set_key`, `delete_key`, `touch_key` | Writes; only with `MEMCACHED_MCP_ALLOW_WRITE=1` |

Diagnostic thresholds are heuristics and have not been tuned on production traffic. Looking up a key's metadata still counts in the server's global `get_hits`/`get_misses` totals, though it leaves the item's LRU position and fetched-before state alone.

## Remote use (Streamable HTTP)

By default the server speaks MCP over stdio. For shared or remote use, run it as an HTTP service:

```
MEMCACHED_MCP_HTTP_TOKEN="<at least 24 random characters>" MEMCACHED_MCP_ALLOWLIST=... memcached-mcp --http 127.0.0.1:8080
```

The endpoint is `/mcp`. Clients must send `Authorization: Bearer <token>`; requests without it get 401 and are written to the audit log (peer address only, never the token).

- The token is mandatory; the server refuses to start without one of at least 24 characters.
- There is no TLS. Binding to anything other than loopback is refused unless `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`, because the token would cross the network in clear text. Put a TLS-terminating proxy in front and bind to loopback.
- `Host` headers are checked against loopback names to block DNS rebinding. Behind a proxy, list the public hostnames in `MEMCACHED_MCP_HTTP_ALLOWED_HOSTS` (comma-separated).
- One shared token means one identity: the audit log does not say which user did what. Per-user auth and RBAC are not implemented.

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

`/metrics` uses the same bearer token and is absent unless targets are configured. It exports raw counters and gauges (`memcached_get_hits_total`, `memcached_evictions_total`, `memcached_used_bytes`, ...) labelled by `instance`, plus `memcached_up` (0 when a target is unreachable). Ratios and rates are left to PromQL, e.g. `rate(memcached_get_hits_total[5m]) / (rate(memcached_get_hits_total[5m]) + rate(memcached_get_misses_total[5m]))`. Scrapes are not written to the audit log. mcrouter targets are not exported yet, only memcached servers. The output passes `promtool check metrics`.

## mcrouter destinations

mcrouter names its destinations as it sees them (often container or service names such as `mc-a:11211`), which this server may not be able to resolve. To inspect the memcached nodes behind an mcrouter, map those names to reachable addresses, and allowlist the addresses too:

```
MEMCACHED_MCP_DEST_MAP="mc-a:11211=10.0.1.5:11211,mc-b:11211=10.0.1.6:11211"
MEMCACHED_MCP_ALLOWLIST="10.0.0.9:5000,10.0.1.5:11211,10.0.1.6:11211"
```

Destinations without a mapping are reported as `unmapped` rather than guessed.

## Install

Download a binary for Linux, macOS or Windows from the releases page, or build from source:

```
cargo build --release -p mcp-server
```

## Use with Claude Code

```
claude mcp add memcached -e MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 -- /path/to/memcached-mcp
```

## Develop

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
MCROUTER_PLAIN_ADDR=127.0.0.1:11218 MCROUTER_FAILOVER_ADDR=127.0.0.1:11222 cargo test -p mcrouter --test failover
```

Layout: `memcached-protocol` (codec, no I/O), `memcached-core` (client), `diagnostics` and `mcrouter` (pure analysis), `mcp-server` (the binary).
