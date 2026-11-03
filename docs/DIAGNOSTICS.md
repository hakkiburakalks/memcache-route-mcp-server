# Diagnostics guide

The diagnostic tools are read-only and return stable `schema_version: "1.0"` JSON. They do
not start collectors, write snapshots, persist history, call an external AI service or change
Memcached/mcrouter. Every tool uses the existing allowlist, authentication, permissions,
connection budget, memory budget and whole-call deadline. Tool names and the permission
matrix are in [TOOLS.md](TOOLS.md).

## Contents

- [Root-cause analysis (RCA)](#root-cause-analysis-rca)
- [Incident snapshots and diffs](#incident-snapshots-and-diffs)
- [Cluster topology and health](#cluster-topology-and-health)
- [Cache efficiency advisor](#cache-efficiency-advisor)
- [Safe remediation advisor](#safe-remediation-advisor)
- [Historical anomaly detection](#historical-anomaly-detection)
- [Capacity planning (`plan_cache_capacity`)](#capacity-planning-plan_cache_capacity)
- [Slab and storage analysis (`analyze_slab_fragmentation`)](#slab-and-storage-analysis-analyze_slab_fragmentation)
- [Incident timeline (`analyze_incident_timeline`)](#incident-timeline-analyze_incident_timeline)
- [mcrouter routing intelligence (`analyze_mcrouter_routing`)](#mcrouter-routing-intelligence-analyze_mcrouter_routing)
- [mcrouter TKO analysis (`analyze_mcrouter_tko`)](#mcrouter-tko-analysis-analyze_mcrouter_tko)
- [Multi-cluster comparison (`compare_cache_clusters`)](#multi-cluster-comparison-compare_cache_clusters)
- [Cache migration advisor (`advise_cache_migration`)](#cache-migration-advisor-advise_cache_migration)
- [Memcached built-in proxy (`analyze_memcached_proxy`)](#memcached-built-in-proxy-analyze_memcached_proxy)

## Root-cause analysis (RCA)

The `diagnose_node_rca` and `mcrouter_diagnose_rca` tools add a deterministic, evidence-based
explanation layer over the existing diagnostics. They do not collect continuously, store history,
or change anything on Memcached or mcrouter.

### What the analysis uses

| Tool | Inputs | Connections |
| --- | --- | --- |
| `diagnose_node_rca` | One node's `stats`, `stats items`, `stats settings` | One |
| `mcrouter_diagnose_rca` | The running config, router `stats`, and each mapped/allowlisted destination's stats/items/settings | One to the router, plus one per probed destination (at most 16 in flight, 256 destinations per call) |

Both tools use the existing allowlist, authentication, permission (`read`), upstream connection
budget, memory budget and bounded JSON serializer. They never call a write command, never fail over,
and never change configuration.

> A finding is a hypothesis supported by the current snapshot. It is not proof of causation, and a
> single snapshot cannot show a trend or a counter reset. These limitations are included in every
> report.

### Stable JSON shape (schema_version `1.0`)

```json
{
  "schema_version": "1.0",
  "analysis": "memcached_node",
  "target": "cache:11211",
  "status": "actionable",
  "summary": "2 finding(s) at warning or critical severity. Primary hypothesis: The server reached its connection limit at least once since start.",
  "findings": [
    {
      "id": "connection_limit_hit",
      "suspected_cause": "The server reached its connection limit at least once since start. New connections were refused while the limit was held.",
      "severity": "critical",
      "confidence": "high",
      "confidence_basis": "`listen_disabled_num` is a cumulative counter, so a non-zero value is direct evidence that the condition occurred during this uptime.",
      "evidence": [
        {
          "metric": "listen_disabled_num",
          "kind": "counter",
          "value": "2",
          "unit": null,
          "interpretation": "Times the listener was disabled because the connection limit was reached."
        },
        {
          "metric": "curr_connections",
          "kind": "gauge",
          "value": "90",
          "unit": null,
          "interpretation": "Connections currently open."
        },
        {
          "metric": "maxconns",
          "kind": "configuration",
          "value": "100",
          "unit": null,
          "interpretation": "Configured maximum connections."
        }
      ],
      "alternative_explanations": [
        "A short connection burst reached the limit.",
        "Clients hold connections open longer than expected.",
        "The configured `maxconns` is too low for the workload."
      ],
      "recommended_checks": [
        "Compare `curr_connections` with `maxconns` over time.",
        "Inspect client connection pooling and idle timeouts."
      ]
    }
  ],
  "missing_evidence": [],
  "limitations": [
    "Single snapshot: cumulative counters are not differenced against a previous sample, so trends and counter resets cannot be confirmed.",
    "Findings are evidence-based hypotheses; correlation does not prove causation."
  ]
}
```

For `mcrouter_diagnose_rca`, `analysis` is `mcrouter` and `coverage` is also present:

```json
"coverage": {
  "configured_destinations": 3,
  "probed_destinations": 2,
  "reachable_destinations": 2,
  "unreachable_destinations": 0,
  "unmapped_destinations": 1,
  "denied_destinations": 0,
  "truncated_destinations": 0,
  "complete": false
}
```

### Field meanings

| Field | Meaning |
| --- | --- |
| `schema_version` | Stable JSON version; currently `1.0` |
| `analysis` | `memcached_node` or `mcrouter` |
| `target` | The allowlisted target address, clipped to 256 bytes |
| `status` | `healthy`, `actionable`, `partial`, or `insufficient_evidence` |
| `summary` | Short deterministic summary; names the top hypothesis when actionable |
| `findings` | At most 16 findings, sorted by severity then stable `id` |
| `findings[].id` | Stable rule code (for example `evictions`, `connection_limit_hit`) |
| `findings[].suspected_cause` | The hypothesis, explicitly worded as evidence-consistent |
| `findings[].severity` | Reuses existing `info`, `warning`, `critical` |
| `findings[].confidence` | `high`, `medium`, `low`, or `insufficient` |
| `findings[].confidence_basis` | Why the evidence is strong or incomplete; not a probability |
| `findings[].evidence[]` | Observed or derived values with `kind` = `counter`, `gauge`, `derived`, `configuration`, `data_quality`, or `coverage` |
| `findings[].alternative_explanations[]` | Other plausible explanations, including benign ones |
| `findings[].recommended_checks[]` | Read-only checks an operator can perform |
| `coverage` | mcrouter only: how much of the configured topology was actually observed |
| `missing_evidence[]` | Expected metrics or mappings that were absent or malformed |
| `limitations[]` | Explicit uncertainty and scope boundaries |

Counters are cumulative since `uptime`; gauges describe one collection instant. The RCA layer does
not treat a counter as a trend and does not compute a rate unless `uptime` is present. If uptime is
below 300 seconds, counter-based confidence is lowered and a `short_uptime` finding is added when
there is activity to analyze.

### Rule families

| Area | Source / finding IDs |
| --- | --- |
| Hit ratio | Existing `hit_ratio_low` and `hit_ratio_insufficient_data`, enriched with eviction/TTL correlation |
| Evictions and memory | Existing `evictions` and `memory_near_limit` |
| Connections | Existing `connection_limit_hit` and `connections_near_limit` |
| Slab imbalance | Existing `eviction_skew` |
| TTL/churn | New `ttl_or_expiry_pressure`, using `expired_unfetched / total_items` |
| Data quality | New `inconsistent_statistics`, `short_uptime`, `insufficient_evidence` |
| mcrouter backends | Existing `analyze_stats` / `diagnose_failover`, plus observed destination reachability |
| mcrouter routing | Existing `analyze_config` findings, aggregated without pool names |
| mcrouter cluster | Per-destination `diagnostics::analyze_node` and `compare_nodes`, aggregated |

### Safety properties

- Read-only: no tool calls any write command.
- One router connection and at most one observation per configured destination, bounded by the
  existing upstream budget and a 256-destination cap.
- One whole-call deadline (60 s); inner client command deadlines still apply.
- Output is serialized through the existing memory-budgeted `bounded_json`, with a 256 KiB limit.
- No values, keys, tokens, credentials, pool names or destination names are returned. Evidence is
  metric values and aggregate counts only.
- Missing, malformed, overflowed or inconsistent values are reported as missing/inconsistent; they
  are never converted into a confident cause.

## Incident snapshots and diffs

`capture_node_snapshot`, `capture_mcrouter_snapshot` and `compare_incident_snapshots` provide a
stateless incident workflow. The server never writes a snapshot to disk and never starts a
background collector. Store snapshots in your own system and pass them back for comparison.

All three tools are read-only and require the `read` permission. They reuse the existing client,
allowlist, connection budget, memory budget, deadline and bounded JSON serializer.

### Snapshot schema (`schema_version: "1.0"`)

```json
{
  "schema_version": "1.0",
  "kind": "memcached_node",
  "captured_at_unix_ms": 1790000000000,
  "target": "cache:11211",
  "metrics": {
    "counters": {
      "get_hits": "9000",
      "get_misses": "1000",
      "evictions": "0",
      "total_items": "10000"
    },
    "gauges": {
      "bytes": "50",
      "limit_maxbytes": "100",
      "curr_items": "1000",
      "curr_connections": "10",
      "uptime": "10000"
    },
    "settings": {"maxconns": "100"},
    "slabs": [
      {"class": 1, "items": 1000, "evicted": 0, "mem_requested": 64000, "reclaimed": 0}
    ]
  },
  "rca": {
    "schema_version": "1.0",
    "analysis": "memcached_node",
    "target": "cache:11211",
    "status": "healthy",
    "summary": "No evidence of resource exhaustion or configuration pressure in this snapshot.",
    "findings": [],
    "missing_evidence": [],
    "limitations": []
  },
  "missing_evidence": [],
  "limitations": [
    "Snapshot contains selected numeric metrics and RCA summaries only; keys and values are excluded."
  ]
}
```

`kind` is `memcached_node` or `mcrouter`. The snapshot schema deliberately contains only selected
numeric metrics:
- `metrics.counters` — cumulative counters (`get_hits`, `get_misses`, `evictions`, ...).
- `metrics.gauges` — instantaneous gauges (`bytes`, `curr_items`, `curr_connections`, `uptime`, ...).
- `metrics.settings` — selected numeric settings (`maxconns`, `maxbytes`, ...).
- `metrics.slabs` — per-class item/eviction/memory summaries from `stats items`.

No keys, key values, tokens, credentials or raw configuration are stored. `target` is the
allowlisted address.

For mcrouter, `topology` is present:

```json
"topology": {
  "pools": [{"id": "a1b2c3d4e5f60718", "servers": 3}],
  "destinations": [
    {"id": "0f1e2d3c4b5a6978", "reachable": true},
    {"id": "9988776655443322", "reachable": false},
    {"id": "1122334455667788", "reachable": null}
  ],
  "coverage": {
    "configured_destinations": 3,
    "probed_destinations": 2,
    "reachable_destinations": 1,
    "unreachable_destinations": 1,
    "unmapped_destinations": 1,
    "denied_destinations": 0,
    "truncated_destinations": 0,
    "complete": false
  }
}
```

`id` values are stable FNV-1a fingerprints of pool/destination names, not anonymization
guarantees. Pool and destination names, addresses and raw config are never included. `reachable:
null` means the destination was configured but not probed (unmapped, denied or capped).

### Diff schema (`schema_version: "1.0"`)

```json
{
  "schema_version": "1.0",
  "kind": "memcached_node",
  "status": "changed",
  "summary": "3 metric change(s), 0 counter reset(s), 0 topology change(s) and 1 RCA change(s); interval 10.000 s.",
  "before": {"target": "cache:11211", "captured_at_unix_ms": 1790000000000},
  "after": {"target": "cache:11211", "captured_at_unix_ms": 1790000010000},
  "interval_seconds": 10.0,
  "interval_valid": true,
  "rate_interval_valid": true,
  "changes": [
    {
      "id": "counter_change",
      "subject": "get_hits",
      "kind": "counter",
      "before": "9000",
      "after": "9500",
      "delta": "500",
      "rate_per_second": "50.000000",
      "severity": "info",
      "confidence": "high",
      "interpretation": "Counter increased between snapshots; the rate is only shown when the interval is valid and no reset was detected.",
      "limitations": []
    }
  ],
  "resets": [],
  "rca": {
    "before_status": "healthy",
    "after_status": "actionable",
    "changes": []
  },
  "missing_evidence": [],
  "limitations": [
    "Diff describes only two snapshots; it cannot establish a longer trend or prove causation."
  ]
}
```

`status` is `no_change`, `changed`, `partial` or `insufficient_evidence`.

Change fields:
| Field | Meaning |
| --- | --- |
| `id` | Stable change category (`counter_change`, `counter_reset`, `gauge_change`, `hit_ratio_change`, `memory_utilization_change`, `connection_utilization_change`, `eviction_rate`, `slab_change`, `topology_change`, `destination_coverage_change`) |
| `subject` | Metric or opaque slab/topology identifier |
| `kind` | `counter`, `gauge`, `derived` or `coverage` |
| `before` / `after` | Observed values |
| `delta` | Numeric difference; omitted for resets |
| `rate_per_second` | Only for counters with a valid interval, at least 5 s, and no reset |
| `severity` / `confidence` | Reuse the existing diagnostic severity and RCA confidence |
| `interpretation` | Why the change matters; not a causal claim |
| `limitations` | Per-change caveats |

`resets[]` records counter decreases and uptime decreases. The diff also compares:
- hit ratio and memory utilization (derived);
- connection utilization (derived);
- eviction rate (only with a valid interval);
- per-slab item/eviction/memory changes;
- mcrouter pool and destination membership/reachability changes using opaque IDs;
- RCA finding presence, severity and confidence changes.

### Rate and reset rules

- A rate is emitted only when both timestamps are present, `after > before`, the interval is at
  least **5 seconds**, and the relevant counter did not decrease.
- If uptime decreases, all counter rates are suppressed because a restart invalidates the series.
- A counter decrease is reported as a reset, not a negative rate.
- A non-increasing timestamp is treated as clock skew; interval and rates are invalid and the
  comparison is `partial`.
- Missing metrics are listed in `missing_evidence`; no rate is inferred from one snapshot.
- Gauges never get a rate.

### Limits

| Limit | Value |
| --- | --- |
| Snapshot JSON input size | 512 KiB |
| Counter/gauge/setting entries per map | 32 |
| Slab classes | 64 |
| mcrouter pools | 128 |
| mcrouter destinations | 512 |
| RCA findings | 32 |
| Diff changes | 64 |
| Diff resets / missing evidence / limitations | 32 / 64 / 64 |
| Capture/compare deadline | 60 s (capture; compare is pure and bounded) |

Snapshots are returned through the existing memory-budgeted `bounded_json`; compare input is
size-checked before deserialization and schema-version checked before analysis.

### Tool contracts

| Tool | Parameters | Output |
| --- | --- | --- |
| `capture_node_snapshot` | `addr` | `IncidentSnapshot` for one node |
| `capture_mcrouter_snapshot` | `addr` | `IncidentSnapshot` with sanitized topology |
| `compare_incident_snapshots` | `before`, `after` (snapshot objects) | `SnapshotDiff` |

No tool writes a file, contacts an external service, changes a server, or starts a monitor.

## Cluster topology and health

`analyze_cluster_topology` builds a deterministic, read-only view of explicitly configured
mcrouter instances and their destinations. It never scans the network, never discovers routers
automatically and never changes infrastructure.

### Inputs and discovery

- `routers`: one or more explicitly supplied, allowlisted mcrouter `host:port` addresses (maximum
  32; duplicates are removed).
- Each router is read once for its running config and `stats`.
- Destination names come only from those configs.
- `MEMCACHED_MCP_DEST_MAP` maps destination names to reachable addresses; those addresses must also
  be allowlisted.
- Only unique mapped, allowlisted backends are probed, at most 16 in flight and 128 per call.
- No host discovery, port scanning or connection to an address that is not both mapped and
  allowlisted.

The whole call is bounded by `MEMCACHED_MCP_MULTI_TOOL_TIMEOUT_MS` (default 120 s) and the
existing upstream connection and memory budgets. The output is bounded to 1 MiB.

### Schema (`schema_version: "1.0"`)

```json
{
  "schema_version": "1.0",
  "analysis": "cluster_topology",
  "observed_at_unix_ms": 1790000000000,
  "status": "healthy",
  "summary": "All configured routers and mapped backends were observed without warning-level topology or health findings.",
  "routers": [
    {"id": "a1b2c3d4e5f60718", "address": "router:5000", "reachable": true, "config_parsed": true, "stats_available": true, "pools": 1, "destinations": 2}
  ],
  "pools": [
    {"id": "1122334455667788", "router_ids": ["a1b2c3d4e5f60718"], "servers": 2, "destination_ids": ["..."], "empty": false}
  ],
  "destinations": [
    {"id": "9988776655443322", "router_ids": ["a1b2c3d4e5f60718"], "pool_ids": ["1122334455667788"], "mapped": true, "backend_id": "0f1e2d3c4b5a6978", "status": "reachable"}
  ],
  "backends": [
    {"id": "0f1e2d3c4b5a6978", "address": "127.0.0.1:11211", "reachable": true, "rca_status": "healthy", "rca_findings": [], "destination_count": 1, "router_count": 1}
  ],
  "links": [
    {"router_id": "a1b2c3d4e5f60718", "pool_id": "1122334455667788", "destination_id": "9988776655443322", "backend_id": "0f1e2d3c4b5a6978", "status": "reachable"}
  ],
  "findings": [],
  "coverage": {
    "routers_requested": 1,
    "routers_probed": 1,
    "routers_parsed": 1,
    "pools": 1,
    "destinations": 2,
    "destinations_mapped": 2,
    "destinations_unmapped": 0,
    "destinations_denied": 0,
    "destinations_reachable": 2,
    "destinations_unreachable": 0,
    "destinations_unknown": 0,
    "backends_probed": 2,
    "backends_reachable": 2,
    "backends_unreachable": 0,
    "truncated": false,
    "complete": true
  },
  "limitations": [
    "Topology is built only from explicitly requested, allowlisted mcrouter configs and mapped destinations; no network scan is performed."
  ]
}
```

#### Status values

- `healthy` — no warning/critical findings and complete coverage.
- `degraded` — at least one warning or critical cluster finding.
- `partial` — no warning-level finding, but coverage is incomplete.
- `insufficient_evidence` — no usable router/config/destination data.

#### Destination status

| Status | Meaning |
| --- | --- |
| `reachable` | Mapped, allowlisted backend answered the probe |
| `unreachable` | Mapped, allowlisted backend did not answer |
| `unmapped` | No `MEMCACHED_MCP_DEST_MAP` entry |
| `denied` | Mapped address is outside `MEMCACHED_MCP_ALLOWLIST` |
| `unknown` | Not probed because a cluster cap or missing topology data was reached |

#### Finding IDs

Existing rules are reused rather than duplicated:

- `pool_empty`, `pool_undefined`, `pool_unused`, `duplicate_server` — existing mcrouter config
  analysis;
- `all_destinations_down`, `destinations_down`, `destinations_suspect` — existing mcrouter stats;
- `down_without_failover`, `failover_active`, `failover_capacity`, `no_failover_configured` —
  existing failover diagnosis;
- `backend_rca_pressure` — aggregate of existing per-backend RCA status/findings.

New cluster correlations:

- `unreachable_backend`
- `unmapped_destination`
- `denied_destination`
- `unknown_destination`
- `shared_backend`
- `shared_destination`
- `incomplete_topology`

Every finding includes severity, confidence, evidence, affected opaque IDs, alternative
explanations and read-only checks.

### Sanitization

- Pool names, destination names and backend addresses are not exposed as raw configuration. Pool
  and destination IDs are deterministic FNV-1a fingerprints; backend addresses are included only
  because they are explicitly supplied through the destination map/allowlist.
- Router addresses are the explicit tool inputs.
- No keys, values, tokens, credentials or raw config are included.
- Fingerprints are not anonymization guarantees; low-entropy names can be guessed.
- No snapshot or topology is written to disk.

### Limits

| Limit | Value |
| --- | --- |
| Routers | 32 |
| Pools | 128 |
| Destinations | 512 |
| Probed backends | 128 |
| Links | 1,024 |
| Output | 1 MiB |
| Backend fan-out | 16 in flight |
| Whole-call deadline | `MEMCACHED_MCP_MULTI_TOOL_TIMEOUT_MS` (default 120 s) |

Unmapped, denied, truncated, missing and unreachable elements are reported in `coverage` and
`findings`; the tool never invents a healthy cluster view.

### Failure and safety behavior

- A router that cannot be read is represented as unreachable and makes coverage incomplete.
- A malformed or oversized config makes that router unparsable; no partial config is trusted.
- A destination is probed only after mapping and allowlist checks.
- No write, flush, failover, restart or configuration command is issued.

## Cache efficiency advisor

`advise_cache_efficiency` is a read-only advisor over one Memcached snapshot (`stats`, `stats items`,
`stats settings`). It reuses the existing diagnostics/RCA calculations and never changes the server.

### Inputs and behavior

- One allowlisted node, one connection.
- Uses the existing `MEMCACHED_MCP_TOOL_TIMEOUT_MS` deadline and memory/connection budgets.
- Returns bounded JSON (`schema_version: "1.0"`) through the existing bounded serializer.
- No write, flush, failover, restart, configuration change or automatic remediation.

### Schema

```json
{
  "schema_version": "1.0",
  "analysis": "cache_efficiency",
  "target": "cache:11211",
  "overall_assessment": "watch",
  "efficiency_findings": [
    {
      "id": "memory_near_limit",
      "assessment": "The cache is at or near its memory limit without evictions yet.",
      "severity": "info",
      "confidence": "high",
      "evidence": [],
      "alternative_explanations": []
    }
  ],
  "evidence": [
    {
      "metric": "hit_ratio",
      "kind": "derived",
      "value": "0.900",
      "unit": null,
      "interpretation": "Derived from cumulative get_hits / (get_hits + get_misses); not a trend."
    }
  ],
  "confidence": "high",
  "recommendations": [
    {
      "id": "watch_memory_headroom",
      "priority": "low",
      "rationale": "Memory is near the configured limit but no evictions were observed.",
      "expected_benefit": "Monitoring can catch a future capacity boundary without premature tuning.",
      "potential_risk": "Reducing the working set or changing limits can cause misses.",
      "suggested_validation_steps": [
        "Observe memory and eviction counters over a stable interval."
      ],
      "related_findings": ["memory_near_limit"]
    }
  ],
  "missing_evidence": [],
  "limitations": [
    "Single snapshot: cumulative counters are not differenced, so trends and counter resets cannot be confirmed."
  ]
}
```

#### `overall_assessment`

| Value | Meaning |
| --- | --- |
| `healthy` | Complete-enough evidence and no warning/critical efficiency finding |
| `watch` | Only informational/insufficient-data findings (for example memory near limit) |
| `actionable` | At least one warning/critical finding |
| `insufficient_evidence` | Core metrics are missing, malformed or too incomplete to support advice |

`confidence` is evidence quality (`high`, `medium`, `low`, `insufficient`), not a probability.

### Evidence

Top-level `evidence` includes only selected metrics and derived values:

- `get_hits`, `get_misses`, `gets`, `hit_ratio`
- `bytes`, `limit_maxbytes`, `memory_utilization_pct`
- `evictions`, `eviction_rate_per_second` (average since uptime only)
- `curr_items`, `total_items`, `expired_unfetched_ratio`
- `curr_connections`, `maxconns`, `connection_utilization_pct`
- `uptime`
- slab class/eviction summaries where `stats items` is available

Counters are cumulative; gauges are one instant; derived values are labelled. A single snapshot
never produces a forecast or a historical trend.

### Recommendation semantics

Each recommendation contains:

- `rationale`
- `expected_benefit`
- `potential_risk`
- `priority` (`high`, `medium`, `low`)
- `suggested_validation_steps`
- `related_findings`

The advisor deliberately does **not** claim that adding RAM will fix eviction pressure. That
recommendation would require historical/capacity evidence. Recommendations for eviction pressure
ask for multi-snapshot measurement, slab/item-size review and capacity modeling first.

### Missing/inconsistent evidence

- Missing or malformed core metrics produce `missing_evidence` and, when appropriate,
  `insufficient_evidence`.
- Short uptime or low get volume lowers confidence and defers tuning.
- Inconsistent counters produce a `revalidate_statistics` recommendation.
- Counter resets cannot be proven from one snapshot; short uptime and inconsistent values are
  reported explicitly.
- No key names or values are read or returned.

### Limits

- Findings: 16
- Evidence items: 24
- Recommendations: 12
- Output: 256 KiB
- One connection, one snapshot, existing tool deadline.

### Non-goals

- No automatic remediation or configuration mutation.
- No RAM-sizing promise, slab reconfiguration, eviction elimination claim or historical anomaly
  detection.
- No external AI/ML service, database, background collector or mandatory Prometheus dependency.

## Safe remediation advisor

`advise_safe_remediation` translates existing diagnostic findings into read-only operational
guidance. It never executes a command, restarts a server, changes configuration, fails over, flushes
or mutates a cache.

### Input

The tool accepts either:

```json
{"report": <existing RCA, efficiency, cluster or snapshot/compatible JSON report>}
```

or:

```json
{"findings": [<existing finding objects>]}
```

Do not provide both. Findings are treated as **untrusted data**. Free-form fields are not
interpreted as instructions, and there is no command/script field. Unknown fields are ignored.

Accepted report shapes:

- RCA: `{"findings":[...]}`
- Cache efficiency: `{"efficiency_findings":[...]}`
- Cluster topology: `{"findings":[...]}`
- Snapshot: `{"rca":{"findings":[...]}}`
- Compatible wrapper: `{"report":...}` or `{"reports":[...]}`

Limits: 512 KiB input, 64 findings, 32 recommendations, 256 KiB output. Malformed roots and
oversized inputs are rejected. Malformed individual findings become low-confidence unknown
findings or explicit `missing_evidence`.

### Output (`schema_version: "1.0"`)

```json
{
  "schema_version": "1.0",
  "analysis": "safe_remediation",
  "overall_priority": "high",
  "summary": "2 recommendation(s); 2 source finding(s); overall priority high.",
  "recommendations": [
    {
      "issue": "evictions",
      "priority": "high",
      "recommended_action": "Measure the working set and per-slab eviction distribution over a second observation before changing memory or slab limits.",
      "rationale": "Eviction pressure can be caused by capacity, item-size distribution or workload churn; one cumulative snapshot cannot distinguish them.",
      "supporting_evidence": [
        "reported severity: warning",
        "reported confidence: high",
        "evictions=20000"
      ],
      "confidence": "high",
      "potential_risks": [
        "Changing memory or slab limits without capacity modeling may waste resources or disrupt the cache."
      ],
      "validation_steps": [
        "Collect a second snapshot over a stable interval and compare eviction deltas."
      ],
      "rollback_considerations": "No change is performed by this tool. If a human applies a configuration or infrastructure change, use normal change control with a documented rollback and a verified backup/restore plan.",
      "requires_human_approval": true
    }
  ],
  "source_findings": 2,
  "missing_evidence": [],
  "limitations": [
    "This tool is advisory only. It does not restart, flush, fail over, change configuration or mutate a cache."
  ]
}
```

### Supported issue mapping

| Issue family | Guidance |
| --- | --- |
| `evictions`, `memory_pressure` | Measure working set/slab distribution; capacity modeling before memory/slab changes |
| `memory_near_limit`, `memory_utilization` | Monitor headroom; do not change limits from one snapshot |
| `hit_ratio_low` | Review workload/TTL/key distribution and eviction evidence |
| `hit_ratio_insufficient_data`, `insufficient_evidence` | Collect complete stats over a representative window |
| `eviction_skew` | Inspect slab/item-size distribution; validate any layout change |
| `connection_limit_hit`, `connections_near_limit` | Review pooling/idle timeouts/maxconns capacity |
| `ttl_or_expiry_pressure` | Review TTL vs read cadence |
| `short_uptime` | Wait for a stable window |
| `inconsistent_statistics` | Re-read and validate data path before acting |
| backend unavailable/down | Check backend/network health and failover/capacity externally |
| failover anomalies | Review failover scope, errors and remaining capacity |
| routing/pool anomalies | Review running config through normal change control |
| incomplete/unmapped/denied topology | Complete mapping/allowlist/coverage; do not guess |
| shared backend/destination | Review failure domains and capacity ownership |
| unknown issue type | Low-confidence human review; no action authorized |

### Safety properties

- Read-only; no connection is made by this tool.
- No shell/code execution and no command fields.
- Input text is data, never instruction.
- All recommendations require human approval.
- No claim that adding RAM fixes evictions without historical/capacity evidence.
- No credentials, key values or tokens are required or emitted.
- Prometheus, databases, collectors and external AI services are optional or unused.

## Historical anomaly detection

`analyze_snapshot_history` analyzes a user-supplied list of incident snapshots. It does not collect
snapshots, persist history, query a database or connect to Memcached/mcrouter.

### Input

```json
{"snapshots": [<snapshot>, <snapshot>, <snapshot>]}
```

Each snapshot must be a valid `IncidentSnapshot` with `schema_version: "1.0"`. Snapshots may be
supplied in any order; they are sorted by `captured_at_unix_ms` for deterministic analysis.
All snapshots must describe the same target and snapshot kind.

Limits:

| Limit | Value |
| --- | --- |
| Snapshots | 64 |
| Total input | 2 MiB |
| Time span | 31 days |
| Output | 256 KiB |
| Anomalies | 32 |

### Output (`schema_version: "1.0"`)

```json
{
  "schema_version": "1.0",
  "analysis": "snapshot_history",
  "analysis_window": {
    "kind": "memcached_node",
    "target": "cache:11211",
    "snapshots": 3,
    "start_unix_ms": 1000000,
    "end_unix_ms": 1120000,
    "duration_seconds": 120.0,
    "valid_intervals": 2,
    "irregular_intervals": false
  },
  "overall_assessment": "anomalous",
  "anomalies": [
    {
      "id": "eviction_rate_increase",
      "metric": "evictions",
      "kind": "derived",
      "direction": "increase",
      "magnitude": "2.000/s vs baseline 1.000/s",
      "what_changed": "The latest valid eviction rate is materially above the prior median.",
      "severity": "critical",
      "confidence": "medium",
      "evidence": [],
      "uncertainty": [
        "One interval can be a burst; a capacity conclusion requires a longer history and slab/workload context."
      ]
    }
  ],
  "supporting_evidence": [],
  "confidence": "medium",
  "missing_evidence": [],
  "limitations": [
    "Analysis uses only the supplied snapshots; it does not collect data or persist history."
  ]
}
```

`overall_assessment` is `healthy`, `watch`, `anomalous` or `insufficient_evidence`.

### Method

- **Endpoint changes** for hit ratio, memory utilization, connection utilization and item count.
- **Per-interval counter deltas** for eviction rates; only intervals with increasing timestamps and
  at least 5 seconds are used.
- **Medians** of earlier valid observations as a simple baseline; no machine learning.
- **Counter resets** are detected when cumulative counters decrease; affected rates are suppressed.
- **Node restarts** are detected from decreasing uptime.
- **Persistent RCA findings** are counted across snapshots; a finding repeated in at least half of
  the observations is reported.
- **Backend availability changes** use only explicit reachability in snapshot topology; incomplete
  coverage is reported as missing evidence.
- Non-monotonic input timestamps are sorted for analysis but mark the window irregular and reduce
  rate confidence. Duplicate or sub-5-second intervals are irregular.
- Fewer than three snapshots produce `insufficient_evidence`; no trend is inferred.

### Anomaly identifiers

- `hit_ratio_deterioration`
- `persistent_low_hit_ratio`
- `eviction_rate_increase`
- `memory_pressure_increase`
- `connection_saturation`
- `item_count_change`
- `backend_availability_drop`
- `counter_reset`
- `node_restart`
- `persistent_rca_finding`
- `insufficient_observations`

### Safety

- Read-only; no upstream connection.
- No snapshot collection, file write or server-side persistence.
- No automatic remediation or commands.
- No secrets, keys, values or raw config are read or emitted.
- Raw pool/destination names are not present in snapshots; topology evidence is aggregate.
- Prometheus, databases, collectors and external AI services are not required.

## Capacity planning (`plan_cache_capacity`)

Uses one live `stats`/`settings` snapshot and optional incident snapshots. The report returns memory
utilization/headroom, item and average-item-size facts, hit ratio and gets, eviction rate since
uptime, connection utilization, and observed first/last snapshot deltas. It explicitly does not
predict time-to-exhaustion, future traffic, allocator fragmentation or a RAM upgrade outcome.
`target_hit_ratio` is an optional workload comparison input (0.0–1.0).

Recommendations are read-only and ask for more measurements or review of workload/slab evidence.
The output is schema-versioned `1.0`, bounded to 256 KiB, with no automatic remediation.

## Slab and storage analysis (`analyze_slab_fragmentation`)

Reads `stats`, `stats items`, `stats slabs` and `stats settings`. Per-class output includes chunk
size, pages/chunks, used/free chunks, requested bytes, evictions, OOM events, internal chunk waste
and page utilization. Segmented-LRU settings are reported; per-segment HOT/WARM/COLD/TEMP population
is not guessed because stable stats do not expose it. Extstore fields are reported when present.

The analyzer distinguishes slab/chunk waste from allocator fragmentation, flags free-capacity versus
pressure, and never rebalances slabs or changes automove settings.

## Incident timeline (`analyze_incident_timeline`)

Accepts up to 64 snapshots in any order and builds sorted adjacent intervals using the existing
snapshot diff engine, then includes the historical anomaly analyzer's findings. Each interval reports
changes, counter resets, topology/RCA deltas, missing evidence and limitations. A single snapshot
produces no interval rather than an invented event.

## mcrouter routing intelligence (`analyze_mcrouter_routing`)

Inventories known route handles, pools, destinations, maximum depth/fan-out and structural features
(failover, prefix/operation selectors, shadows, rate limits, migration, warm-up, inline pools, hash
names, SSL/protocol markers). It flags shadow traffic, synchronous fan-out, migration windows, large
fan-out and unsupported/custom handles as UNKNOWN. `proposed_config` is treated as untrusted data
and compared structurally (pools, destinations, handle counts, features).

Offline consistent-hash/routing simulation is **UNSUPPORTED**. The tool never executes a config or
claims behavioral equivalence; use `mcrouter_trace_key_route` against a live router for actual trace
validation.

## Memcached built-in proxy (`analyze_memcached_proxy`)

The built-in proxy exists only in proxy-enabled builds starting at Memcached 1.6.23. The adapter reads
`stats`, `stats settings`, `stats proxy` and `stats proxyfuncs` and reports bounded raw proxy fields
with explicit version/support status. The two proxy views use fixed internal commands and are not
reachable through `get_stats`, so clients cannot supply arbitrary statistics subcommands. It never
compiles or evaluates Lua, never treats proxy configuration as executable code, and reports dynamic
routing behavior as UNKNOWN. Proxy counter semantics vary by build and route library, so values are
not converted into causal claims.

`status` is one of:

| Status | Meaning |
| --- | --- |
| `observed` | `proxy_enabled=yes` and usable `stats proxy`/`proxyfuncs` fields were read |
| `disabled` | the server explicitly returned `proxy_enabled=no` |
| `not_applicable` | version is older than 1.6.23 |
| `statistics_unavailable` | proxy is enabled but the statistics views failed or returned no fields |
| `insufficient_evidence` | version is unparseable, or `proxy_enabled` is missing/malformed and no proxy statistics were returned |

The report keeps `enabled` (`true`/`false`/`null`), `detected`, `statistics_available` and a bounded
`statistics_error`. Command failures are reported as unavailable evidence, never as an empty
successful map. `settings` contains only proxy-related keys, and `stats`/`functions` are capped at
128 fields of 256 characters each.

## mcrouter TKO analysis (`analyze_mcrouter_tko`)

Combines the live config and supported mcrouter stats into soft/hard TKO evidence: total/down/suspect
destinations, `result_*` TKO/connect/timeout counters, cumulative failover/shadow request counters,
proxy queue depth, config reload failures and config fields such as `failures_until_tko` and probe
delays when present. Down destinations are hard-TKO evidence; suspect destinations are soft/probe
evidence. Exact transition times and recovery duration are not available from a snapshot, so they are
reported as missing evidence rather than inferred.

## Multi-cluster comparison (`compare_cache_clusters`)

Compares two or more explicitly supplied clusters built from captured snapshots. It aggregates
Memcached capacity/utilization, weighted hit ratio, eviction rate, connection utilization, mcrouter
destination reachability/coverage, RCA statuses, historical anomaly counts and observed metric
coverage. The first cluster is the baseline; differences are observations, not causal claims or
capacity-transfer predictions. No discovery, upstream connection or automatic cluster selection is
performed.

## Cache migration advisor (`advise_cache_migration`)

Composes structural mcrouter config impact, optional current/target cluster snapshots and optional
version labels into read-only migration advice. It covers backend/pool membership changes, failover
changes, capacity/availability differences, version downgrade/proxy-availability risks, cold-cache and
warm-up implications, rollback considerations and mandatory human approval. Offline key-movement
simulation is unsupported; live route traces are required before cutover.

## Feature/version matrix

See [COMPATIBILITY.md](../COMPATIBILITY.md#feature-and-version-coverage-matrix) for the maintained
SUPPORTED / PARTIAL / MISSING / NOT APPLICABLE / NOT VERIFIED matrix and the official source
revisions used for this audit.
