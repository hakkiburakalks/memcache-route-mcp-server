# memcached-mcp-server

Rust MCP server for Memcached/mcrouter ops + diagnostics. Plan: `C:\Users\burak\.claude\plans\optimized-booping-rivest.md`.

## Layout
- Cargo workspace; crates under `crates/`.
- `memcached-protocol`: pure codec (no I/O). Text protocol in `src/text.rs`. Meta/binary not yet written.
- `memcached-core`: tokio `Client` (one connection, no pool yet), `probe()` for capabilities. Live test in `tests/live.rs` needs `MEMCACHED_ADDR`.
- `diagnostics`: pure rules over `stats` maps (`analyze_node`, `compare_nodes`); thresholds are heuristics, tested with fixtures.
- `mcp-server`: bin `memcached-mcp`, rmcp 3.7 stdio. Tools: server_info, get_stats, get_key_metadata, diagnose_node, compare_nodes. Targets must be in `MEMCACHED_MCP_ALLOWLIST`.
- CI: `.github/workflows/ci.yml` (Linux+macOS build, memcached 1.4/1.5/1.6 matrix). `COMPATIBILITY.md` lists only CI-verified versions.

## Invariants
- Protocol crate stays I/O-free; policy (timeouts, allowlist, read-only) lives above it.
- Capability detection by probing (`version`, `stats settings`, `mn`), never by version number alone.
- Read-only by default; writes need explicit flag. Values redacted by default; credentials never logged.
- Priority order: text + meta protocol first, binary/SASL later. Generic memcached before mcrouter.
- Platforms: Linux and macOS first, Windows later. No Unix-only code outside `cfg` gates.

See `mem:tech_stack`, `mem:suggested_commands`, `mem:conventions`, `mem:task_completion`.
