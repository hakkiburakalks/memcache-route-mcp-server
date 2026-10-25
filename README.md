# memcached-mcp

An [MCP](https://modelcontextprotocol.io) server for Memcached and mcrouter, written in Rust. It gives an AI assistant a safe way to inspect cache servers and diagnose problems. Read-only by default.

Status: early. See [COMPATIBILITY.md](COMPATIBILITY.md) for what has actually been tested.

## Safety model

- **Read-only by default.** Write tools (`set_key`, `delete_key`, `touch_key`) are not even listed unless `MEMCACHED_MCP_ALLOW_WRITE=1`. There is no flush tool.
- **Audit trail.** Writes and rejected targets are logged as JSON lines to `MEMCACHED_MCP_AUDIT_LOG` (or stderr). Key names and outcomes are recorded, never values. Reads are not audited.
- **Allowlist.** The server only connects to `host:port` pairs listed in `MEMCACHED_MCP_ALLOWLIST` (comma-separated). With an empty list every target is rejected.
- **No values.** `get_key_metadata` returns existence, flags and size, never the value.
- **Capability probing.** Features are detected by asking the server (`version`, `mn`), not guessed from the version number.

## Tools

| Tool | What it does |
| --- | --- |
| `server_info` | Version and whether meta commands are supported |
| `get_stats` | `stats`, optionally a group (`settings`, `items`, `slabs`, ...) |
| `get_key_metadata` | Does a key exist; flags and size |
| `diagnose_node` | Hit ratio, evictions vs memory, connection limits, eviction skew |
| `compare_nodes` | Outlier item counts and hit ratios across 3+ nodes |
| `mcrouter_get_stats` | mcrouter stats and destination health |
| `mcrouter_inspect_config` | Running mcrouter config: pools, servers, config problems |
| `mcrouter_trace_key_route` | Which destination a key routes to (asks mcrouter itself) |
| `set_key`, `delete_key`, `touch_key` | Writes; only with `MEMCACHED_MCP_ALLOW_WRITE=1` |

Diagnostic thresholds are heuristics and have not been tuned on production traffic.

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
