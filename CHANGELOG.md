# Changelog

All notable changes. The project is pre-1.0 and versions are `0.1.0-alpha.N`.

## 0.1.0-alpha.9 (unreleased)

Branding
- The project is now **MemCacheRoute MCP Server**. README, package descriptions, OCI metadata, Helm
  chart description, workflow display names and release archive names use the new branding. The
  executable, Rust package names, `MEMCACHED_MCP_*` variables, MCP tool names, Helm chart name and
  image repository keep their existing identifiers for compatibility.

Security
- Session caps are enforced with an atomic reservation: concurrent `initialize` requests can no
  longer all pass the same check. The global and per-user caps are bounded even under a burst.
- `/metrics` GETs count against `MEMCACHED_MCP_HTTP_MAX_CONCURRENT`; previously only POSTs did, so
  a token with the `metrics` permission could start unbounded concurrent scrapes.
- Targets are validated at startup (`host:port`); link-local, unspecified and multicast addresses
  are refused, hostnames are resolved with a deadline, checked and connected to as resolved.
- Open sessions are capped per user (default 32) as well as globally.
- Untrusted replies have total byte budgets, not only line limits: `stats` 8 MiB, non-uniform
  metadump 16 MiB, uniform scan 64 MiB, values 16 MiB. Over-budget replies fail closed and the
  connection is retired; metadata reads on classic servers discard the value in chunks.
- A process-wide reservation budget (`MEMCACHED_MCP_MEMORY_BUDGET_MB`, default 96 MiB) is taken
  before value buffers, STAT maps, metadump scans, `/metrics` stats/config replies and the cached
  `/metrics` body. Reservations are RAII, so timeout, cancellation and panic release them;
  exhaustion fails the operation closed. This is a reservation limit, not an absolute process
  memory cap.
- Exactly 16 MiB values are now accepted: the get limit included the trailing CRLF but the limit
  did not.
- Container builder is pinned by Rust version and multi-arch digest; the final image gets
  `org.opencontainers.image.created`, reproducible-build settings and an executable-only copy.
  `.dockerignore` excludes repository metadata, reports, tests and deployment files from the build
  context.
- Helm chart: `values.schema.json` validates critical values; supports an immutable `image.digest`
  and `imagePullSecrets`; mounts the token Secret read-only with `defaultMode: 0440`/`fsGroup`;
  adds a startup probe, explicit probe timeouts, rolling-update strategy, termination grace,
  `enableServiceLinks: false`, revision history and an optional PDB/HPA. NetworkPolicy can
  isolate egress with explicit destination rules and configurable DNS selectors. Session affinity
  config and operational warnings are rendered.
- Removing or rotating a user closes that user's open sessions; expired tokens' sessions are
  closed on the reload tick. A revoked token cannot use an existing session.
- Hostnames are resolved to all usable IPv4/IPv6 addresses (bounded to 16); an unreachable first
  address no longer disables a healthy fallback. The allowlist parser now rejects URLs, paths,
  userinfo, malformed DNS labels and unbracketed IPv6 instead of starting with an unusable entry.
- Every command has a 60-second whole-operation deadline in addition to per-read timeouts, so a
  slow-dripping server cannot hold an HTTP request or permit indefinitely.
- Audit output is capped at 100 lines/second process-wide, fields are clipped, multi-address
  allowlist denials are aggregated, and a busy audit file lock makes later audit calls drop the
  line instead of blocking on it. Failed authentication keeps its separate 20/s cap.
- `Authorization` scheme matching is case-insensitive and accepts multiple OWS characters.
- `mcrouter_trace_key_route` rejects route-expression delimiters and keys whose generated probe
  exceeds memcached's 250-byte limit before connecting.
- WP-04 final stabilization: whole-call tool deadlines, POST body slow-drip deadlines, strict
  truncated-line/VALUE/mg/parser validation, mcrouter config/topology/route/JSON bounds, bounded
  asynchronous audit writing with per-identity fairness and drop/error counters, combined DNS and
  connect budgets, a DNS lookup concurrency cap, and family-interleaved resolver fallback.
- `analyze_cluster_topology`: explicit-router-only, read-only cluster topology and health model
  with opaque pool/destination/backend IDs, coverage, shared/unreachable backend detection and
  existing RCA evidence. No network scanning, persistence or remediation.
- `advise_cache_efficiency`: read-only, deterministic efficiency advice from one snapshot, with
  explicit evidence/confidence/missing data, and recommendations carrying rationale, expected
  benefit, risk, priority and validation steps. It does not claim that adding RAM resolves
  evictions without historical/capacity evidence.
- `advise_safe_remediation`: accepts existing RCA/efficiency/cluster/snapshot findings as untrusted
  data and returns human-approved, read-only remediation guidance with issue, priority, rationale,
  evidence, risks, validation and rollback considerations. No commands, scripts or changes.
- `analyze_snapshot_history`: deterministic anomaly detection over user-supplied snapshots with
  resets/restarts, irregular timestamp, partial-topology and missing-evidence handling. No
  collection, persistence, upstream connection or automatic remediation.

Added
- `GET /healthz` without token or Host check, for probes.
- `diagnose_node_rca` and `mcrouter_diagnose_rca`: read-only, deterministic RCA with stable
  `schema_version: "1.0"`, confidence/basis, evidence, alternative explanations, recommended
  checks, explicit missing evidence and mcrouter destination coverage. Both are bounded and reuse
  existing diagnostics, connection/memory budgets and deadlines.
- `capture_node_snapshot`, `capture_mcrouter_snapshot` and `compare_incident_snapshots`: stateless,
  bounded incident snapshots and deterministic diffs. Snapshots contain selected numeric metrics,
  slab summaries and RCA; mcrouter topology uses opaque IDs. Diffs detect counter resets, clock
  skew and interval problems, and emit rates only for valid intervals of at least 5 seconds. No
  files are written and no background collector is added.
- `mcrouter_diagnose_failover` reports `failover_scope` and `failover_confidence`.
- Security regression tests for token reload, revocation/rotation session cleanup, session caps
  (concurrent global and per-user), `/metrics` concurrency, malformed requests and secret leakage.
- Hostile-server tests for reply byte budgets, partial values, malformed stats/meta replies and
  connection retirement.
- Metrics resource regression tests: bounded 16/64/256-node fan-out, 1/8/16 concurrent users,
  cache/singleflight, overall deadline, upstream failure and process-wide fail-closed limits.
- Memory-budget regression tests: 1/8/16/64 concurrent 16 MiB reads, 64 concurrent MCP tool
  replies, stats-map reservations, timeout/truncation/cancellation/panic release, low-budget
  fail-closed and metrics-cache refresh without leaks. `memcached_mcp_memory_budget_bytes` and
  `..._available_bytes` expose reserved headroom.
- Container security documentation (image pinning, SBOM/provenance/scanning gates, secret and
  shutdown behavior) and a production runbook covering install, upgrade, rollback, token
  rotation, rollout restart, scaling caveats and incident checks.
- Reliability regressions for slow-drip stats/metadump/value/metadata reads, DNS multi-address
  fallback, strict allowlist parsing, audit flood/field bounds/nonblocking lock, case-insensitive
  bearer parsing and mcrouter route-key rejection.
- Load and chaos laboratory under `tests/load-lab/`, MCP benchmark, Grafana dashboard.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `docs/`.

Changed
- `compare_nodes` and `mcrouter_compare_destinations` read nodes 16 at a time; `compare_nodes`
  accepts up to 256 addresses (was 32). `mcrouter_compare_destinations` compares per pool and
  reports lost audit lines.
- Diagnosis treats busy evictions as critical from 80% memory; a full cache without evictions is
  only informational.
- The HTTP listener sets `TCP_NODELAY`: small replies were delayed by about 40 ms (measured
  `compare_nodes` p50 44 ms to 1.8 ms in the lab).
- The per-user request permit is held until the reply body ends, so it bounds the work and not
  just the headers.
- Tool connections draw from a process-wide `MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS` budget
  (default 64) and fail closed when it is exhausted.
- `/metrics` has a process-wide request cap (default 4), bounded fan-out (default 16), an overall
  deadline (default 8 s), a singleflight successful-body cache (default 5 s), and a 64 KiB stats /
  256 KiB config budget per target. It exports internal cache/scrape counters and freshness
  gauges; failed refreshes return 503, and a failed target is always `*_up 0`.
- Helm: default resource requests and a 256Mi memory limit (the 256-node load-lab stress case
  used ~136MiB); probes use `/healthz`; chart `version` and `appVersion` are `0.1.0-alpha.9`.
- CI: actions pinned by SHA, minimal permissions, licence check; memcached 1.4.39/1.5.22/1.6.45
  and the mcrouter image digest are pinned. Release: per-asset checksums, combined `SHA256SUMS`
  and build provenance.
- `docs/CONFIGURATION.md` and the operations/load-lab guide were added; compatibility and deployment notes
  were corrected.

Fixed
- Counter arithmetic in diagnostics saturates instead of overflowing on hostile values.
- Target resolution has a deadline and connects to the address it checked.
- A read, write, timeout, malformed-protocol or partial-response error retires the connection;
  optional `stats items`/`stats settings` calls and the metadata meta-to-classic fallback no
  longer reuse a connection whose protocol state is suspect.

## 0.1.0-alpha.8

alpha.8 included the read-only stats group allowlist (so `reset` was no longer reachable with the
`read` permission), the 30-day TTL cap, connection retirement after a failed read, runtime token
reload, graceful SIGTERM/SIGINT shutdown and eviction-rate-aware diagnosis.

## Earlier

See the GitHub releases. Highlights: per-user hashed tokens with expiry, Prometheus metrics for
memcached and mcrouter, HTTP session cap, runtime token reload, Helm chart, meta protocol
capability probing, uniform key sampling, mcrouter tools.
