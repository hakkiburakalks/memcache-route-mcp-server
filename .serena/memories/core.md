# memcached-mcp-server

Rust MCP server for Memcached/mcrouter ops + diagnostics. Plan: `C:\Users\burak\.claude\plans\optimized-booping-rivest.md`.

## Layout
- Cargo workspace; crates under `crates/`.
- `memcached-protocol`: pure codec (no I/O). Text protocol in `src/text.rs`. Meta/binary not yet written.
- Planned: `memcached-core` (tokio client, pool, capability probe), `diagnostics`, `mcp-server` (rmcp).

## Invariants
- Protocol crate stays I/O-free; policy (timeouts, allowlist, read-only) lives above it.
- Capability detection by probing (`version`, `stats settings`, `mn`), never by version number alone.
- Read-only by default; writes need explicit flag. Values redacted by default; credentials never logged.
- Priority order: text + meta protocol first, binary/SASL later. Generic memcached before mcrouter.
- Platforms: Linux and macOS first, Windows later. No Unix-only code outside `cfg` gates.

See `mem:tech_stack`, `mem:suggested_commands`, `mem:conventions`, `mem:task_completion`.
