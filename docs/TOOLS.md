# Tool reference and permissions matrix

Every tool takes the target as `addr` (`host:port`) unless noted. A target must be listed in
`MEMCACHED_MCP_ALLOWLIST` and must not resolve to a link-local, unspecified or multicast address
(see [CONFIGURATION.md](CONFIGURATION.md#target-policy)). Keys are validated on every request:
1-250 bytes, no spaces or control characters.

## Permissions

Over HTTP each user (token) holds a set of permissions from the token file; over stdio the
process owner holds all of them. A tool needs its permission **and** any server-wide switch.

| Tool | Permission | Server switch | Changes the server? | Notes |
| --- | --- | --- | --- | --- |
| `server_info` | `read` | - | no | `version` plus a `mn` capability probe |
| `get_stats` | `read` | - | no | optional `group`: only `items`, `slabs`, `sizes`, `settings`, `conns`, `extstore`. Anything else (including `reset`, `detail`, `sizes_enable`) is refused before it is sent |
| `get_key_metadata` | `read` | - | no | never returns the value. With meta commands it does not touch LRU or fetched state; on older servers (`source: classic`) the value is fetched internally, never returned |
| `diagnose_node` | `read` | - | no | rules over `stats`, `stats items`, `stats settings` |
| `diagnose_node_rca` | `read` | - | no | versioned, evidence-based RCA over one node snapshot; see [DIAGNOSTICS.md](DIAGNOSTICS.md#root-cause-analysis-rca) |
| `advise_cache_efficiency` | `read` | - | no | read-only efficiency advice from one snapshot with rationale, risk and validation steps; see [DIAGNOSTICS.md](DIAGNOSTICS.md#cache-efficiency-advisor) |
| `advise_safe_remediation` | `read` | - | no | converts existing findings/reports into human-approved guidance; no commands or changes; see [DIAGNOSTICS.md](DIAGNOSTICS.md#safe-remediation-advisor) |
| `analyze_snapshot_history` | `read` | - | no | deterministic anomaly detection over user-supplied snapshots; no collection or persistence; see [DIAGNOSTICS.md](DIAGNOSTICS.md#historical-anomaly-detection) |
| `capture_node_snapshot` | `read` | - | no | timestamped, bounded snapshot with selected metrics and RCA; no files written |
| `compare_nodes` | `read` | - | no | 1-256 addresses, read 16 at a time; needs 3 nodes for outlier detection |
| `mcrouter_get_stats` | `read` | - | no | target must be an mcrouter |
| `mcrouter_inspect_config` | `read` | - | no | reads the running config; shows pools and servers |
| `mcrouter_compare_destinations` | `read` | `MEMCACHED_MCP_DEST_MAP` | no | compares each pool on its own; unmapped or unreachable destinations are reported |
| `mcrouter_diagnose_failover` | `read` | - | no | reports `failover_scope` and a confidence level, see below |
| `mcrouter_diagnose_rca` | `read` | `MEMCACHED_MCP_DEST_MAP` optional | no | correlates router config/stats with reachable destination stats; reports partial coverage; see [DIAGNOSTICS.md](DIAGNOSTICS.md#root-cause-analysis-rca) |
| `analyze_cluster_topology` | `read` | `MEMCACHED_MCP_DEST_MAP` | no | explicit routers only; bounded topology/health model with coverage and opaque IDs; see [DIAGNOSTICS.md](DIAGNOSTICS.md#cluster-topology-and-health) |
| `capture_mcrouter_snapshot` | `read` | `MEMCACHED_MCP_DEST_MAP` optional | no | timestamped snapshot with opaque topology IDs and RCA; no raw config |
| `compare_incident_snapshots` | `read` | - | no | deterministic diff of two supplied snapshots; see [DIAGNOSTICS.md](DIAGNOSTICS.md#incident-snapshots-and-diffs) |
| `mcrouter_trace_key_route` | `read` | - | no | asks mcrouter where a key would go |
| `sample_keys` | `sample` (totals) / `key_names` (names) | `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1`, names also `MEMCACHED_MCP_ALLOW_KEY_NAMES=1` | no | walks the LRU crawler's metadump; `uniform: true` reads the whole dump (stops at 2 million items, 64 MiB or 60 s) |
| `set_key` | `write` | `MEMCACHED_MCP_ALLOW_WRITE=1` | **yes** | value at most 1 MiB, `ttl_seconds` 0..2592000 (30 days), key must match `MEMCACHED_MCP_WRITE_PREFIX` if set |
| `delete_key` | `write` | `MEMCACHED_MCP_ALLOW_WRITE=1` | **yes** | prefix rule as above |
| `touch_key` | `write` | `MEMCACHED_MCP_ALLOW_WRITE=1` | **yes** | `ttl_seconds` rule as above |
| `GET /metrics` | `metrics` | metrics targets configured | no | not a tool; same bearer token |

Write tools are not listed at all unless `MEMCACHED_MCP_ALLOW_WRITE=1`. There is no flush tool.
Tools that read return an error naming the missing permission, and the denial is audited.

`mcrouter_trace_key_route` embeds the key in mcrouter's `__mcrouter__.route(op,key)` expression.
Keys containing comma, parentheses, backslash, whitespace/control characters are rejected before
connecting, as is a key whose route probe would exceed memcached's 250-byte key limit. This prefers
a clear error over guessing mcrouter's escape syntax and reporting a misleading destination.

## Failover confidence (`mcrouter_diagnose_failover`)

The route tree says where a failover handle sits, not which operations it fails over (that
depends on its `failover_errors`). The report therefore carries a level:

| `failover_scope` | `failover_confidence` | Meaning |
| --- | --- | --- |
| `none` | `confirmed` | no failover handle anywhere in the route tree |
| `root` | `inferred` | the route itself is a failover handle, in front of every key; operations not checked |
| `nested` | `unknown` | a failover handle exists below other handles (selectors, hashing, ...); which keys or operations reach it is not determined |
| `no_route` | `unknown` | the config has no route to analyse |

## Diagnosis rules (`diagnose_node`)

Counters are cumulative since the server started, so rules use the uptime.

| Code | Severity | Condition |
| --- | --- | --- |
| `hit_ratio_low` | warning < 80%, critical < 50% | needs at least 1000 gets, otherwise `hit_ratio_insufficient_data` (info) |
| `evictions` | info below 0.01/s average; warning from there; critical at 1/s or more with memory at 80% or more | average over the uptime; without `uptime` the memory rule alone applies |
| `memory_near_limit` | info | memory at 90% or more, no evictions yet |
| `connection_limit_hit` | critical | `listen_disabled_num > 0` at any time since start |
| `connections_near_limit` | warning | 80% of `maxconns` in use |
| `eviction_skew` | warning | one slab class holds 80% or more of at least 100 evictions, with two or more populated classes |

`compare_nodes` flags `item_count_outlier` (more than 2x or less than 0.5x the median, with at
least 100 items on one side) and `hit_ratio_spread` (more than 20 points between nodes that each
served at least 1000 gets). These thresholds are starting points chosen from synthetic load, not
values validated on production traffic.

## Root-cause analysis

`diagnose_node_rca` and `mcrouter_diagnose_rca` enrich these rules with structured evidence,
alternative explanations and recommended checks. They return stable JSON with
`schema_version: "1.0"`; the field meanings, confidence semantics, coverage reporting and safety
limits are documented in [DIAGNOSTICS.md](DIAGNOSTICS.md#root-cause-analysis-rca). They are read-only and do not add a background
collector, historical storage or remediation action.

## Incident snapshots

`capture_node_snapshot` and `capture_mcrouter_snapshot` return bounded, timestamped snapshots
containing selected numeric metrics, slab summaries and the RCA report. mcrouter topology is
represented by opaque IDs; raw configuration, pool names and destination names are excluded.
`compare_incident_snapshots` compares two supplied snapshot objects, detects counter resets and
only emits rates for a valid interval of at least 5 seconds. It never writes a snapshot, starts a
monitor or changes a server. Rate rules, limits and the full schema are documented in
[DIAGNOSTICS.md](DIAGNOSTICS.md#incident-snapshots-and-diffs).

`analyze_cluster_topology` accepts only explicitly supplied, allowlisted mcrouter addresses. It
models routers, pools, destinations, mapped backends and links; probes only mapped/allowlisted
backends; and reports unmapped, denied, unreachable, shared and unknown elements. It never scans
the network or changes infrastructure. Schema and limits: [DIAGNOSTICS.md](DIAGNOSTICS.md#cluster-topology-and-health).

`advise_cache_efficiency` is a single-node, single-snapshot advisor. It reuses the existing
diagnostics/RCA calculations and returns findings, evidence, confidence, recommendations with
rationale/benefit/risk/priority/validation steps, missing evidence and limitations. It does not
claim that adding RAM fixes evictions without historical or capacity evidence. Schema:
[DIAGNOSTICS.md](DIAGNOSTICS.md#cache-efficiency-advisor).

`advise_safe_remediation` consumes existing RCA/efficiency/cluster/snapshot findings as untrusted
data and returns prose guidance with issue, priority, rationale, evidence, risks, validation,
rollback considerations and mandatory human approval. It accepts no commands or scripts and makes
no changes. Schema: [DIAGNOSTICS.md](DIAGNOSTICS.md#safe-remediation-advisor).

`analyze_snapshot_history` accepts user-captured incident snapshots in any order and reports
deterministic anomalies with evidence, confidence and uncertainty. It makes no upstream connection,
does not collect or persist snapshots, suppresses unreliable rates across resets/irregular
timestamps, and returns `insufficient_evidence` below three observations. Schema and method:
[DIAGNOSTICS.md](DIAGNOSTICS.md#historical-anomaly-detection).
