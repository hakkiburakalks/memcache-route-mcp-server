# Compatibility

"Verified" means the `live` integration test has passed against that server image, in CI or in the
isolated compatibility matrix described in [docs/RELEASE-READINESS.md](docs/RELEASE-READINESS.md).
CI pins the patch versions below and the mcrouter image digest. Everything else is a target, not a
guarantee.

| Server | Status | Notes |
| --- | --- | --- |
| memcached 1.6.x | Verified (1.6.45) | Meta commands detected via `mn` |
| memcached 1.5.x | Verified (1.5.22) | Meta not used: 1.5.22 answers `mg` with a partial early implementation and rejects `mn`, so the probe reports no meta support |
| memcached 1.4.x | Verified (1.4.39) | No meta commands |
| memcached 1.2 / 1.3 | Untested | Experimental, no real-server tests yet |
| mcrouter | Verified (34.0.0) | Config, stats, route tracing and failover behaviour via the memcached protocol (see below) |
| AWS ElastiCache | Not tested | |
| Docker | Image builds in CI; stdio and HTTP modes run against a memcached on the same Docker network (by hand) | |
| Kubernetes | Manual kind smoke test | The chart is linted/rendered in CI and was installed on a local kind cluster; it has not run on a production cluster or in CI |

Key metadata (TTL, last access, fetched-before, CAS) comes from `mg` on servers where the `mn` probe succeeds (1.6.x here); older servers report only flags and size.

`lru_crawler metadump` (used by `sample_keys`) differs by version: 1.4.39 refuses it unless started with `-o lru_crawler`; 1.5.22 streams entries then `END`; 1.6.45 sends `OK` first and adds a `flags` field. Aborting a dump part-way left the server healthy in a manual test on 1.6.45.

Capabilities are probed at runtime (`version`, `mn`), not inferred from the version number.

## Host platforms

| Platform | Status |
| --- | --- |
| Linux | CI build and test; release binaries (x86_64, aarch64, musl) are built and smoke-tested by the release workflow, but have not been run against a live server on those platforms |
| macOS | CI build and test; release binaries (Apple Silicon, Intel) are built and smoke-tested by the release workflow, but have not been run against a live server on those platforms |
| Windows | Developed and tested locally; the release binary is built and smoke-tested by the release workflow. The test suite does not run on Windows in CI |

## mcrouter behaviour observed with a dead destination (34.0.0)

With a plain `PoolRoute`, once a destination is marked down: writes to its keys fail with `SERVER_ERROR unavailable`, reads return `END` (indistinguishable from a miss), and `__mcrouter__.route` returns an empty destination. With a `FailoverRoute`, the same writes are stored on the backup. The first request after the failure is slow (seconds) while mcrouter waits out its connect timeout. These come from one mcrouter version and one topology; other route handles may differ.

## What is and is not covered by automated tests

Automated in CI: protocol codec and the diagnostic rules (unit tests); the client, capability probe and `mg` metadata against memcached 1.4/1.5/1.6; eviction diagnosis on a 4 MB server; mcrouter config, route tracing and dead-destination behaviour with and without failover; and end-to-end tests that start the real `memcached-mcp` binary against memcached 1.4/1.5/1.6 and drive it over stdio and HTTP (write tools hidden by default, allowlist, write gating and key prefixes, audit log, bearer-token and Host checks, `/metrics`, refusal to start unsafely).

Also automated: the mcrouter tools over MCP against a healthy three-node topology, including `mcrouter_compare_destinations` with a full mapping, a missing mapping, and a mapping outside the allowlist.

Not covered by an automated end-to-end test: `mcrouter_compare_destinations` and the other mcrouter tools while a destination is down (the analysis itself is tested), and long-running HTTP sessions. Concurrent HTTP session-cap behavior is covered by the security regression tests. The release binaries are smoke-tested by the release workflow; they are not exercised against a live server on Linux or macOS.
