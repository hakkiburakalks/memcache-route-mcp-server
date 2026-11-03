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

## Feature and version coverage matrix

Status is scoped to this repository's declared support, not to every feature of the upstream
projects. `SUPPORTED` means implemented with automated regression coverage; live evidence is noted
separately. New analyzers that have unit tests but no live run are `PARTIAL` or `NOT VERIFIED`.

| Area | Status | Evidence / limitation |
| --- | --- | --- |
| Memcached 1.4 / 1.5 / 1.6 text protocol and stats | **SUPPORTED** | Live matrix: 1.4.39, 1.5.22, 1.6.45 (core + e2e) |
| Capability probing by `version`/`mn` | **SUPPORTED** | Live on all three versions; 1.5.22 meta partial/rejected |
| Meta text protocol safe diagnostics | **SUPPORTED** | 1.6.45 live; `mg` metadata; 1.4/1.5 correctly fall back |
| CAS, TTL, last-access, fetched-before, stale flag | **PARTIAL** | TTL/CAS/access/fetched tested live; new stale (`X`) flag is unit-tested only |
| Segmented LRU settings and slab layout | **PARTIAL** | Live 1.4.39/1.5.22/1.6.45: config/slab stats and chunk waste supported; runtime HOT/WARM/COLD/TEMP population is not exposed by stable stats |
| Extstore pressure | **PARTIAL** | Reported when `stats` exposes `extstore_*`; not live-validated |
| Capacity planner (`plan_cache_capacity`) | **PARTIAL** | Live 1.4.39/1.5.22/1.6.45 healthy, actionable, insufficient-evidence and observed-delta cases; no forecast/time-to-exhaustion by design |
| Incident timeline (`analyze_incident_timeline`) | **PARTIAL** | Live three-snapshot history on 1.6.45: 2 intervals, 22 events and 4 anomalies; synthetic lab workload only |
| mcrouter config/stats/route traces/failover | **SUPPORTED** | mcrouter 34.0.0 live; dead-destination and failover tests |
| mcrouter route-handle inventory / structural impact | **PARTIAL** | Known handles + risks + config comparison; custom/inline constructs are UNKNOWN and flagged |
| Consistent-hash/routing simulation | **MISSING / UNSUPPORTED** | No validated offline simulator; live `mcrouter_trace_key_route` is the supported evidence path |
| Advanced mcrouter TKO / health analysis | **PARTIAL** | Live mcrouter 34.0.0: healthy, one destination down+suspect, no-failover critical finding, failover inference, and observed recovery to healthy; exact transition durations unavailable |
| Prefix, shadow, migrate, warm-up, rate-limit config detection | **PARTIAL** | Structural detection only; behavior not simulated |
| BigValue, asynclog, reliable-delete, SSL/IPv6 behavior | **MISSING / PARTIAL** | Not modelled as behavior; SSL/protocol markers only |
| Memcached built-in proxy (1.6.23+) | **SUPPORTED (live)** | Official 1.6.45 proxy build: 25 `STAT` fields from `stats proxy` and 4 from `stats proxyfuncs`; the tool now returns matching populated maps (`observed`). Disabled 1.6.45 -> `disabled`; 1.5.22/1.4.39 -> `not_applicable`. Fixed proxy views only; no Lua execution. |
| Multi-cluster comparison | **PARTIAL** | Live comparison of two explicit snapshot clusters (1.4.39+1.6.45 vs 1.6.45+failover router): 5 findings; no discovery or live multi-cluster production run |
| Cache migration advisor | **PARTIAL** | Live current mcrouter config plus supplied snapshots: 6 structural changes, 2 capacity findings, cold-cache expected; no data movement or exact key simulation |
| MCP tools / stdio / Streamable HTTP / sessions | **SUPPORTED** | End-to-end binary tests; session/auth/limits |
| MCP resources | **SUPPORTED (bounded)** | Four stable read-only URIs (`capabilities`, `tools`, `operator-guide`, `targets`); 2048-byte URI and 64 KiB content limits; `targets` requires read permission and denials are audited |
| MCP prompts | **SUPPORTED (static)** | Six read-only investigation prompts; prompt arguments are ignored rather than interpolated; prompts execute no tools |
| MCP structured tool output | **PARTIAL** | `server_info` advertises `outputSchema` and returns matching `structuredContent` plus its legacy text; all other tools keep the existing text/JSON format and advertise no unvalidated output schema |
| MCP 2024-11-05 / 2025-06-18 interoperability | **SUPPORTED** | Legacy initialize handshake, tools, resources, prompts and structured content covered by repository e2e and an independent Python MCP SDK client |
| MCP 2026-07-28 compatibility | **PARTIAL** | Independent SDK in auto mode negotiated 2026-07-28; tools, resources, prompts and structured content worked. No extensions, tasks, elicitation, sampling or list-change claims |
| Auth, allowlists, budgets, deadlines, audit, redaction | **SUPPORTED** | Security/e2e regressions; no secrets or automatic remediation |
| Prometheus | **SUPPORTED / OPTIONAL** | `/metrics` only when targets are configured; not required |
| Binary protocol | **NOT APPLICABLE** | Deprecated upstream; not implemented |

## Expanded alpha integration campaign (2026-11-03)

Isolated Docker lab: the repository compose file (memcached 1.4.39 on 11214, 1.5.22 on 11215,
1.6.45 on 11216, 4 MB 1.6.45 on 11217, mcrouter 34.0.0 with a plain pool on 11218 and a failover
route on 11222). A separate official `memcached:1.6.45` container on 11223 was started with
`proxy_config=routelib` and a minimal server-owned Lua route file. The repository e2e suite ran
47/47 against each of 1.4.39, 1.5.22 and 1.6.45 with no skips.

| Area | Scenario | Result | Concrete evidence / remaining risk |
| --- | --- | --- | --- |
| Capacity planner | Healthy 1.4.39 after 1,200 hits | **PASS** | `status: healthy`, no findings |
| Capacity planner | 1.6.45 at 82.0% memory with 1,203 gets and 90% target | **PASS** | `status: actionable`; `memory_pressure`, `hit_ratio_below_target`, `hit_ratio_low` |
| Capacity planner | 1.5.22 with 83 gets | **PASS (incomplete)** | `status: watch`; `hit_ratio_insufficient_data` |
| Capacity planner | Three snapshots (19.8 s) | **PASS** | `history` present; hit-ratio change +5.1 pp, no forecast |
| Capacity planner | Invalid target 2.0; closed upstream 11224 | **PASS (rejected)** | `target_hit_ratio must be between 0.0 and 1.0`; connection error |
| Slab analyzer | 1.6.45 with 55 × 1 MB values | **PASS** | `actionable`; class 2 internal waste warning |
| Slab analyzer | 4 MB node with mixed sizes | **PASS** | `actionable`; class 29 evicted 61 items; classes 6/12 free-chunk rebalance opportunities |
| Slab analyzer | Malformed address; closed upstream | **PASS (rejected)** | allowlist/invalid address and connection errors |
| Timeline / history | Three 1.6.45 snapshots with changing workload | **PASS** | 2 intervals, 22 events, 4 anomalies; eviction rate 1.422/s vs 0 baseline, confidence low |
| Timeline / history | One snapshot; malformed snapshot | **PASS** | `insufficient_evidence`; malformed schema version rejected |
| Cluster comparison | cluster-a (1.4.39 + 1.6.45 + router) vs cluster-b (4 MB node + failover router) | **PASS** | 5 findings: +37.0 pp memory, +0.442 evictions/s, −1 reachable destination, RCA/history differences |
| Cluster comparison | One cluster; empty list | **PASS (rejected)** | `cluster comparison needs at least two clusters` |
| Migration advisor | Live plain router → proposed failover config with supplied snapshots | **PASS** | 6 structural changes, 2 capacity/availability findings, `cold-cache expected=true`; routing equivalence UNKNOWN |
| Migration advisor | Malformed proposed config; missing source; closed upstream | **PASS (rejected)** | invalid JSON, `provide addr or current_config`, connection error |
| Routing analysis | Live 11218 and 11222; proposed failover config | **PASS** | PoolRoute 3 destinations; FailoverRoute depth 2; impact pools +2/−1, destinations −1, failover feature |
| Routing analysis | Malformed proposed config; closed upstream | **PASS (rejected)** | invalid mcrouter config; connection error |
| TKO analysis | Healthy 11218/11222 | **PASS** | `healthy`; 0 down/suspect, missing `result_*` counters reported |
| TKO analysis | mc-a stopped, traffic attempted | **PASS (partial evidence)** | `actionable`: down=1, suspect=1; critical `hard_tko_without_failover` on 11218; `failover_active` inferred on 11222; 20/20 plain-router probes completed without transport errors (miss semantics not asserted), 35/40 failover probes completed and 5 timed out/errored |
| TKO analysis | mc-a restarted, observed after ~21 s | **PASS (state only)** | Both routers `healthy`, 3/3 and 2/2 up; exact transition/recovery durations not measured |
| TKO analysis | Non-router; closed upstream | **PASS (rejected)** | `is this an mcrouter?`; connection error |
| MCP resources/prompts/structured | Live lab and independent client | **PASS** | 4 resources, 6 prompts; `server_info` returned matching `structuredContent` and legacy text |
| Built-in proxy detection | Proxy-enabled 1.6.45 on 11223 | **PASS** | `status: observed`, `enabled: true`, `statistics_available: true`; no Lua executed |
| Built-in proxy stats | Raw `stats proxy` / `stats proxyfuncs` on 11223 | **PASS** | Raw server returned 25 and 4 `STAT` fields (26/5 lines including `END`); tool returned the same 25/4 populated fields |
| Built-in proxy disabled | Non-proxy 1.6.45 on 11216 | **PASS** | `status: disabled`, `enabled: false`, `detected: false`, empty stats; raw `stats proxy` is empty |
| Built-in proxy older | 1.5.22 / 1.4.39 | **PASS** | `not_applicable` (predates 1.6.23); no proxy view is requested |
| Built-in proxy safety/limits | Extra Lua-like argument; stalling upstream | **PASS** | Extra `lua`/`config` arguments ignored and not echoed; 500 ms deadline returned an error in 0.52 s; no Lua execution path |
| Independent MCP client | Python MCP SDK 2.3.0 over Streamable HTTP and stdio | **PASS** | Legacy mode negotiated 2025-11-25; auto mode negotiated 2026-07-28; 27 tools, resources, prompts, structured content; unknown tool/resource rejected; bad token 401 |
| Client session close | DELETE with session id | **PARTIAL** | Server returns 202; SDK logs `Session termination failed: 202` although the session ends. Transport was not changed |
| Peak memory | Current-tree test image, 8 sessions, 30 s, 256 MiB limit | **PASS (sampled)** | 47,388 successful calls, 0 errors, sampled peak 9.04 MiB, median 8.22 MiB, `OOMKilled=false`, `/healthz` 200; not a cgroup high-water measurement |
| Reverse proxy | Reference nginx in front of the HTTP server | **PASS (lab)** | MCP initialize/tools worked through the proxy; 4 KiB body → 413, 4 KiB header → 400, idle close at 2.0 s, second held connection → 503, rapid requests → 429 |
| Helm runtime | Chart on local kind v1.37.0 with in-cluster memcached 1.6.45 | **PASS (local)** | Pod Ready, non-root UID/GID 65532, read-only rootfs, fsGroup 65532, valid token works, wrong token 401, `targets` and `server_info` work; production ingress/NetworkPolicy not tested |

### Proxy blocker correction (2026-11-03)

The campaign's two proxy failures were fixed without widening the arbitrary stats surface:

- Added fixed `Client::stats_proxy` / `Client::stats_proxyfuncs` commands. They are not reachable
  through `get_stats`; `encode_stats` still rejects `proxy`, `proxyfuncs` and every other
  unlisted group before anything reaches the wire.
- Added `proxy_enabled` parsing with documented `yes`/`no` semantics. Missing or malformed values
  are `insufficient_evidence`, never inferred as enabled.
- Added explicit `disabled` and `statistics_unavailable` statuses, plus `enabled`,
  `statistics_available` and bounded `statistics_error` fields. Command failures are retained as
  evidence instead of becoming empty successful maps.
- Live retest: proxy-enabled 1.6.45 -> `observed` with all 25/4 fields; disabled 1.6.45 ->
  `disabled`; 1.5.22/1.4.39 -> `not_applicable`; closed upstream and malformed target rejected.
- Regression coverage: 10 proxy analyzer tests, fixed-command/error/oversize tests, deadline and
  cancelled-memory-budget tests, end-to-end enabled/disabled/unavailable/missing/malformed/hostile
  cases, allowlist and HTTP authorization checks.

The proxy build was not changed; only the adapter and its fixed read-only stats access were
corrected.

## Official sources used

Accessed 2026-11-03. Source revisions are default-branch tips at audit time, not vendored code.

- Memcached docs: <https://docs.memcached.org/>, meta protocol
  <https://docs.memcached.org/protocols/meta/>, built-in proxy
  <https://docs.memcached.org/features/proxy/> (proxy available from 1.6.23; requires a
  proxy-enabled build), proxy API/settings references.
- Memcached source: `memcached/memcached` at
  `2d51e364799bc9698bd4b11728ea978cea12da6e`.
- Memcached proxy libraries: `memcached/memcached-proxylibs` at
  `e3c024fb0d020fee4b57a8e5a4694e74c05d85c6`.
- mcrouter wiki: <https://github.com/facebook/mcrouter/wiki>, including the route-handle list
  (51 revisions, last edited 2021-02-25); source `facebook/mcrouter` at
  `9349015aedf19856a4c40b8650f3b5bb3d9d9c0b`.
- MCP specification 2026-07-28: <https://modelcontextprotocol.io/specification/2026-07-28>;
  specification repository at `a40e90cab4e50219d3274658c2b2f5c550c684c8`.
