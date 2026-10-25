# memcached-mcp-server

Rust MCP server for Memcached/mcrouter ops + diagnostics. Repo: github.com/hakkiburakalks/memcached-mcp-server (private). Tag `v0.1.0-alpha.1` released; later work is untagged. Plan: `C:\Users\burak\.claude\plans\optimized-booping-rivest.md`.

## Layout (crates under `crates/`)
- `memcached-protocol`: pure codec, no I/O. `src/text.rs`: text protocol + `mg`/`mn` meta get. Binary protocol and SASL not written.
- `memcached-core`: tokio `Client` (one connection per call, deliberately no pool), `probe()` capabilities, `meta_info()` via `mg ... u`.
- `diagnostics`: pure rules over `stats` maps (`analyze_node`, `compare_nodes`) + `prometheus::render`. Thresholds are heuristics.
- `mcrouter`: pure analysis of mcrouter output (config via `__mcrouter__.preprocessed_config`, stats, failover diagnosis, route trace, `parse_dest_map`).
- `mcp-server`: bin `memcached-mcp` (rmcp 3.7). stdio by default, `--http ADDR` for Streamable HTTP (`src/http.rs`, axum). `src/audit.rs` = JSON audit log.
- Tests: unit tests inline; `e2e` needs `MEMCACHED_ADDR`; live tests are env-gated and skip when unset (`MEMCACHED_ADDR`, `MEMCACHED_SMALL_ADDR`, `MCROUTER_ADDR`, `MCROUTER_PLAIN_ADDR`+`MCROUTER_FAILOVER_ADDR`, `MCROUTER_BACKENDS`). Topology: `tests/compat/docker-compose.yml`.
- CI `.github/workflows/ci.yml`: Linux+macOS build; memcached 1.4/1.5/1.6 matrix; mcrouter job (stops `mc-a` for the failover test). `release.yml`: 5 targets, tag `v*` publishes (tags containing `-` are prereleases).

## Invariants
- Protocol crate stays I/O-free; policy (timeouts, allowlist, write gating) lives in `mcp-server`.
- Capability detection by probing (`mn`), never by version number. 1.5.22 answers `mg` partially but rejects `mn`: treated as no meta.
- Read-only by default: write tools (`set_key`/`delete_key`/`touch_key`) are only registered with `MEMCACHED_MCP_ALLOW_WRITE=1`; `MEMCACHED_MCP_WRITE_PREFIX` limits keys. No flush tool. Values never returned or logged; audit logs writes + denied targets only.
- Opt-in features: `sample_keys` (`MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1`, prefix totals only; key names need `MEMCACHED_MCP_ALLOW_KEY_NAMES=1`). Never put key names in the audit log. metadump times (`exp`, `la`) are absolute server-clock unix times; do not mix with local clock.
- Every connection goes through `MemcachedServer::connect` (allowlist). `MEMCACHED_MCP_DEST_MAP` and `MEMCACHED_MCP_METRICS_TARGETS` must not bypass it.
- HTTP: bearer token mandatory (>=24 chars), non-loopback bind refused without `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`, no TLS in-process.
- rmcp processes requests concurrently: tests piping several calls at once see out-of-order replies; space them out.
- Don't claim behaviour that was not observed: mcrouter claims come from measurements on 34.0.0 (see `COMPATIBILITY.md`).
- Platforms: Linux and macOS first, Windows built and smoke-tested too. No Unix-only code outside `cfg` gates.

## Known gaps
- `crates/mcp-server/tests/e2e.rs` drives the real binary (stdio + HTTP) in CI; also mcrouter tools incl. compare_destinations (healthy topology, needs `MCROUTER_ADDR` + `MCROUTER_BACKENDS`). Not automated: mcrouter tools with a dead destination over MCP, concurrent/long HTTP sessions.
- Per-user RBAC (auth.rs, MEMCACHED_MCP_HTTP_TOKEN_FILE, `new-token`) exists for HTTP only; stdio is trusted. No token expiry/rotation. `sample_keys` cannot sample randomly (crawler order).

See `mem:tech_stack`, `mem:suggested_commands`, `mem:conventions`, `mem:task_completion`.
