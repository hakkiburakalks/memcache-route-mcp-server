# memcached-mcp

An [MCP](https://modelcontextprotocol.io) server for Memcached and mcrouter, written in Rust. It gives an AI assistant a safe way to inspect cache servers and diagnose problems. Read-only by default.

Status: early. See [COMPATIBILITY.md](COMPATIBILITY.md) for what has actually been tested.

## Safety model

- **Read-only by default.** Write tools (`set_key`, `delete_key`, `touch_key`) are not even listed unless `MEMCACHED_MCP_ALLOW_WRITE=1`. There is no flush tool.
- **Write prefixes.** With `MEMCACHED_MCP_WRITE_PREFIX` (comma-separated, e.g. `tmp:,scratch:`) writes are limited to keys starting with one of the prefixes; others are refused before any connection is made. Without it, any key on an allowlisted server can be written and the server warns at startup.
- **Audit trail.** Writes and rejected targets are logged as JSON lines to `MEMCACHED_MCP_AUDIT_LOG` (or stderr). Key names and outcomes are recorded, never values. Reads are not audited.
- **Allowlist.** The server only connects to `host:port` pairs listed in `MEMCACHED_MCP_ALLOWLIST` (comma-separated). With an empty list every target is rejected.
- **No values.** `get_key_metadata` returns existence, flags and size, never the value.
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

Diagnostic thresholds are heuristics and have not been tuned on production traffic.

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

Layout: `memcached-protocol` (codec, no I/O), `memcached-core` (client), `diagnostics` and `mcrouter` (pure analysis), `mcp-server` (the binary).
