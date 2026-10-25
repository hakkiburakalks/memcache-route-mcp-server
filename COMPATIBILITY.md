# Compatibility

"Verified" means the `live` integration test passes in CI against that server image. Everything else is a target, not a guarantee.

| Server | Status | Notes |
| --- | --- | --- |
| memcached 1.6.x | Verified (1.6.45) | Meta commands detected via `mn` |
| memcached 1.5.x | Verified (1.5.22) | Meta not used: 1.5.22 answers `mg` with a partial early implementation and rejects `mn`, so the probe reports no meta support |
| memcached 1.4.x | Verified (1.4.39) | No meta commands |
| memcached 1.2 / 1.3 | Untested | Experimental, no real-server tests yet |
| mcrouter | Verified (34.0.0) | Config, stats, route tracing and failover behaviour via the memcached protocol (see below) |
| AWS ElastiCache | Not tested | |

Key metadata (TTL, last access, fetched-before, CAS) comes from `mg` on servers where the `mn` probe succeeds (1.6.x here); older servers report only flags and size.

Capabilities are probed at runtime (`version`, `mn`), not inferred from the version number.

## Host platforms

| Platform | Status |
| --- | --- |
| Linux | CI build and test; release binaries (x86_64, aarch64, musl) are built but have not been run |
| macOS | CI build and test; release binaries (Apple Silicon, Intel) are built but have not been run |
| Windows | Developed and tested locally; release binary is built in CI and was smoke-tested once by hand (alpha.1). The test suite does not run on Windows in CI |

## mcrouter behaviour observed with a dead destination (34.0.0)

With a plain `PoolRoute`, once a destination is marked down: writes to its keys fail with `SERVER_ERROR unavailable`, reads return `END` (indistinguishable from a miss), and `__mcrouter__.route` returns an empty destination. With a `FailoverRoute`, the same writes are stored on the backup. The first request after the failure is slow (seconds) while mcrouter waits out its connect timeout. These come from one mcrouter version and one topology; other route handles may differ.

## What is and is not covered by automated tests

Automated in CI: protocol codec and the diagnostic rules (unit tests); the client, capability probe and `mg` metadata against memcached 1.4/1.5/1.6; eviction diagnosis on a 4 MB server; mcrouter config, route tracing and dead-destination behaviour with and without failover; and end-to-end tests that start the real `memcached-mcp` binary against memcached 1.4/1.5/1.6 and drive it over stdio and HTTP (write tools hidden by default, allowlist, write gating and key prefixes, audit log, bearer-token and Host checks, `/metrics`, refusal to start unsafely).

Not covered by an automated end-to-end test: `mcrouter_compare_destinations` (verified by hand on a three-node topology), the mcrouter tool wiring over MCP (its analysis is tested), and concurrent or long-running HTTP sessions. The Linux and macOS release binaries have never been executed.
