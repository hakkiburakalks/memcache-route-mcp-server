//! Bounded, read-only incident snapshots and deterministic snapshot diffs.
//!
//! A snapshot contains selected numeric statistics, the existing RCA report and, for mcrouter, an
//! opaque topology fingerprint. It never contains keys, values, tokens or raw configuration.
//! Comparison is deliberately conservative: cumulative counters are not differenced across a
//! reset, and rates are omitted without two valid timestamps and a long enough interval.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::rca::{AnalysisStatus, Confidence, Coverage, EvidenceKind, RcaFinding, RcaReport};
use crate::{Severity, Stats};

pub const SNAPSHOT_SCHEMA_VERSION: &str = "1.0";
pub const MAX_SNAPSHOT_JSON_BYTES: usize = 512 * 1024;
pub const MAX_SNAPSHOT_METRICS: usize = 32;
pub const MAX_SNAPSHOT_SLABS: usize = 64;
pub const MAX_SNAPSHOT_POOLS: usize = 128;
pub const MAX_SNAPSHOT_DESTINATIONS: usize = 512;
pub const MAX_SNAPSHOT_RCA_FINDINGS: usize = 32;
pub const MAX_DIFF_CHANGES: usize = 64;
pub const MAX_DIFF_RESETS: usize = 32;
pub const MAX_DIFF_MISSING: usize = 64;
pub const MIN_RATE_INTERVAL_MS: u64 = 5_000;

const MAX_KEY_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 512;

const COUNTER_KEYS: &[&str] = &[
    "get_hits",
    "get_misses",
    "cmd_get",
    "cmd_set",
    "total_items",
    "evictions",
    "reclaimed",
    "expired_unfetched",
    "evicted_unfetched",
    "listen_disabled_num",
];

const GAUGE_KEYS: &[&str] = &[
    "bytes",
    "limit_maxbytes",
    "curr_items",
    "curr_connections",
    "uptime",
    "num_servers",
    "num_servers_down",
    "num_suspect_servers",
    "threads",
];

const SETTING_KEYS: &[&str] = &["maxconns", "maxbytes", "item_size_max", "chunk_size"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    #[default]
    MemcachedNode,
    Mcrouter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlabSnapshot {
    pub class: u32,
    #[serde(default)]
    pub items: Option<u64>,
    #[serde(default)]
    pub evicted: Option<u64>,
    #[serde(default)]
    pub mem_requested: Option<u64>,
    #[serde(default)]
    pub reclaimed: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PoolSnapshot {
    pub id: String,
    pub servers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DestinationSnapshot {
    pub id: String,
    /// None means the destination was configured but not probed (unmapped, denied or truncated).
    #[serde(default)]
    pub reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TopologySnapshot {
    #[serde(default)]
    pub pools: Vec<PoolSnapshot>,
    #[serde(default)]
    pub destinations: Vec<DestinationSnapshot>,
    #[serde(default)]
    pub coverage: Option<Coverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SnapshotMetrics {
    #[serde(default)]
    pub counters: BTreeMap<String, String>,
    #[serde(default)]
    pub gauges: BTreeMap<String, String>,
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub slabs: Vec<SlabSnapshot>,
}

impl SnapshotMetrics {
    pub fn from_stats(stats: &Stats, items: &Stats, settings: &Stats) -> Self {
        let mut counters = BTreeMap::new();
        for key in COUNTER_KEYS {
            if let Some(value) = stats.get(*key).filter(|v| v.parse::<u64>().is_ok()) {
                counters.insert((*key).to_owned(), value.clone());
            }
        }
        let mut gauges = BTreeMap::new();
        for key in GAUGE_KEYS {
            if let Some(value) = stats.get(*key).filter(|v| v.parse::<u64>().is_ok()) {
                gauges.insert((*key).to_owned(), value.clone());
            }
        }
        let mut numeric_settings = BTreeMap::new();
        for key in SETTING_KEYS {
            if let Some(value) = settings.get(*key).filter(|v| v.parse::<u64>().is_ok()) {
                numeric_settings.insert((*key).to_owned(), value.clone());
            }
        }

        let mut by_class: BTreeMap<u32, SlabSnapshot> = BTreeMap::new();
        for (key, value) in items {
            let Some(rest) = key.strip_prefix("items:") else {
                continue;
            };
            let Some((class, field)) = rest.split_once(':') else {
                continue;
            };
            let Ok(class) = class.parse::<u32>() else {
                continue;
            };
            let Ok(value) = value.parse::<u64>() else {
                continue;
            };
            let entry = by_class.entry(class).or_default();
            entry.class = class;
            match field {
                "number" => entry.items = Some(value),
                "evicted" => entry.evicted = Some(value),
                "mem_requested" => entry.mem_requested = Some(value),
                "reclaimed" => entry.reclaimed = Some(value),
                _ => {}
            }
        }
        let mut slabs: Vec<SlabSnapshot> = by_class.into_values().collect();
        slabs.sort_by_key(|s| s.class);
        slabs.truncate(MAX_SNAPSHOT_SLABS);

        Self {
            counters,
            gauges,
            settings: numeric_settings,
            slabs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentSnapshot {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub kind: SnapshotKind,
    #[serde(default)]
    pub captured_at_unix_ms: u64,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub metrics: SnapshotMetrics,
    #[serde(default)]
    pub topology: Option<TopologySnapshot>,
    #[serde(default)]
    pub rca: Option<RcaReport>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

impl IncidentSnapshot {
    pub fn node(
        target: &str,
        captured_at_unix_ms: u64,
        stats: &Stats,
        items: &Stats,
        settings: &Stats,
        rca: RcaReport,
    ) -> Self {
        let mut missing = rca.missing_evidence.clone();
        missing.sort();
        missing.dedup();
        let mut limitations = rca.limitations.clone();
        limitations.extend([
            "Snapshot contains selected numeric metrics and RCA summaries only; keys and values are excluded.".to_owned(),
            "The timestamp is from the MCP host clock; cross-host clock skew is possible.".to_owned(),
        ]);
        dedup_limits(&mut limitations);
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
            kind: SnapshotKind::MemcachedNode,
            captured_at_unix_ms,
            target: clip(target, 256),
            metrics: SnapshotMetrics::from_stats(stats, items, settings),
            topology: None,
            rca: Some(rca),
            missing_evidence: missing,
            limitations,
        }
    }

    pub fn mcrouter(
        target: &str,
        captured_at_unix_ms: u64,
        stats: &Stats,
        topology: TopologySnapshot,
        rca: RcaReport,
    ) -> Self {
        let mut missing = rca.missing_evidence.clone();
        missing.sort();
        missing.dedup();
        let mut limitations = rca.limitations.clone();
        limitations.extend([
            "Snapshot contains selected numeric metrics and RCA summaries only; raw config, pool names and destination names are excluded.".to_owned(),
            "Topology identifiers are opaque fingerprints, not anonymization guarantees.".to_owned(),
            "The timestamp is from the MCP host clock; cross-host clock skew is possible.".to_owned(),
        ]);
        dedup_limits(&mut limitations);
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
            kind: SnapshotKind::Mcrouter,
            captured_at_unix_ms,
            target: clip(target, 256),
            metrics: SnapshotMetrics::from_stats(stats, &Stats::new(), &Stats::new()),
            topology: Some(topology),
            rca: Some(rca),
            missing_evidence: missing,
            limitations,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported snapshot schema_version '{}'; expected '{SNAPSHOT_SCHEMA_VERSION}'",
                self.schema_version
            ));
        }
        if self.target.is_empty() {
            return Err("snapshot target must not be empty".to_owned());
        }
        validate_map(&self.metrics.counters, "counters")?;
        validate_map(&self.metrics.gauges, "gauges")?;
        validate_map(&self.metrics.settings, "settings")?;
        if self.metrics.slabs.len() > MAX_SNAPSHOT_SLABS {
            return Err(format!(
                "snapshot has {} slab entries; the limit is {MAX_SNAPSHOT_SLABS}",
                self.metrics.slabs.len()
            ));
        }
        if let Some(topology) = &self.topology {
            if topology.pools.len() > MAX_SNAPSHOT_POOLS {
                return Err(format!(
                    "snapshot has {} pools; the limit is {MAX_SNAPSHOT_POOLS}",
                    topology.pools.len()
                ));
            }
            if topology.destinations.len() > MAX_SNAPSHOT_DESTINATIONS {
                return Err(format!(
                    "snapshot has {} destinations; the limit is {MAX_SNAPSHOT_DESTINATIONS}",
                    topology.destinations.len()
                ));
            }
            for pool in &topology.pools {
                if pool.id.len() > MAX_KEY_BYTES {
                    return Err("snapshot pool id is too long".to_owned());
                }
            }
            for dest in &topology.destinations {
                if dest.id.len() > MAX_KEY_BYTES {
                    return Err("snapshot destination id is too long".to_owned());
                }
            }
        }
        if let Some(rca) = &self.rca {
            if rca.findings.len() > MAX_SNAPSHOT_RCA_FINDINGS {
                return Err(format!(
                    "snapshot has {} RCA findings; the limit is {MAX_SNAPSHOT_RCA_FINDINGS}",
                    rca.findings.len()
                ));
            }
            for finding in &rca.findings {
                if finding.id.len() > MAX_KEY_BYTES
                    || finding.suspected_cause.len() > MAX_TEXT_BYTES
                    || finding.evidence.len() > 16
                    || finding.alternative_explanations.len() > 16
                    || finding.recommended_checks.len() > 16
                {
                    return Err("snapshot RCA finding exceeds its bounds".to_owned());
                }
            }
        }
        if self.missing_evidence.len() > MAX_DIFF_MISSING
            || self.limitations.len() > MAX_DIFF_MISSING
        {
            return Err("snapshot metadata list is too long".to_owned());
        }
        for value in self.missing_evidence.iter().chain(self.limitations.iter()) {
            if value.len() > MAX_TEXT_BYTES {
                return Err("snapshot metadata entry is too long".to_owned());
            }
        }
        Ok(())
    }
}

/// Parses a supplied snapshot with an exact serialized-size check before deserializing.
pub fn parse_snapshot(value: serde_json::Value) -> Result<IncidentSnapshot, String> {
    let encoded =
        serde_json::to_vec(&value).map_err(|e| format!("cannot measure snapshot: {e}"))?;
    if encoded.len() > MAX_SNAPSHOT_JSON_BYTES {
        return Err(format!(
            "snapshot is {} bytes; the limit is {MAX_SNAPSHOT_JSON_BYTES}",
            encoded.len()
        ));
    }
    let snapshot: IncidentSnapshot =
        serde_json::from_value(value).map_err(|e| format!("invalid snapshot JSON: {e}"))?;
    snapshot.validate()?;
    Ok(snapshot)
}

fn validate_map(map: &BTreeMap<String, String>, label: &str) -> Result<(), String> {
    if map.len() > MAX_SNAPSHOT_METRICS {
        return Err(format!(
            "snapshot has {} {label}; the limit is {MAX_SNAPSHOT_METRICS}",
            map.len()
        ));
    }
    for (key, value) in map {
        if key.len() > MAX_KEY_BYTES || value.len() > MAX_VALUE_BYTES {
            return Err(format!("snapshot {label} entry '{key}' is too long"));
        }
    }
    Ok(())
}

fn dedup_limits(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn clip(value: &str, max: usize) -> String {
    let mut value = value.to_owned();
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    NoChange,
    Changed,
    Partial,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotRef {
    pub target: String,
    pub captured_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffChange {
    pub id: String,
    pub subject: String,
    pub kind: EvidenceKind,
    pub before: Option<String>,
    pub after: Option<String>,
    pub delta: Option<String>,
    pub rate_per_second: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub interpretation: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CounterReset {
    pub metric: String,
    pub before: String,
    pub after: String,
    pub interpretation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct PoolChange {
    pub id: String,
    pub before_servers: usize,
    pub after_servers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct DestinationChange {
    pub id: String,
    pub before_reachable: Option<bool>,
    pub after_reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct TopologyDiff {
    pub pools_added: Vec<String>,
    pub pools_removed: Vec<String>,
    pub pool_changes: Vec<PoolChange>,
    pub destinations_added: Vec<String>,
    pub destinations_removed: Vec<String>,
    pub destination_availability: Vec<DestinationChange>,
}

impl TopologyDiff {
    pub fn is_empty(&self) -> bool {
        self.pools_added.is_empty()
            && self.pools_removed.is_empty()
            && self.pool_changes.is_empty()
            && self.destinations_added.is_empty()
            && self.destinations_removed.is_empty()
            && self.destination_availability.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RcaChange {
    pub id: String,
    pub before_severity: Option<Severity>,
    pub after_severity: Option<Severity>,
    pub before_confidence: Option<Confidence>,
    pub after_confidence: Option<Confidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct RcaDiff {
    pub before_status: Option<AnalysisStatus>,
    pub after_status: Option<AnalysisStatus>,
    pub changes: Vec<RcaChange>,
}

impl RcaDiff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SnapshotDiff {
    pub schema_version: String,
    pub kind: SnapshotKind,
    pub status: DiffStatus,
    pub summary: String,
    pub before: SnapshotRef,
    pub after: SnapshotRef,
    pub interval_seconds: Option<f64>,
    pub interval_valid: bool,
    pub rate_interval_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_reason: Option<String>,
    pub changes: Vec<DiffChange>,
    pub resets: Vec<CounterReset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology: Option<TopologyDiff>,
    pub rca: RcaDiff,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

fn metric_u64(map: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    map.get(key)?.parse().ok()
}

#[allow(clippy::too_many_arguments)]
fn change(
    id: &str,
    subject: impl Into<String>,
    kind: EvidenceKind,
    before: Option<String>,
    after: Option<String>,
    delta: Option<String>,
    rate: Option<String>,
    severity: Severity,
    confidence: Confidence,
    interpretation: impl Into<String>,
) -> DiffChange {
    DiffChange {
        id: id.to_owned(),
        subject: clip(&subject.into(), MAX_KEY_BYTES),
        kind,
        before: before.map(|v| clip(&v, MAX_VALUE_BYTES)),
        after: after.map(|v| clip(&v, MAX_VALUE_BYTES)),
        delta: delta.map(|v| clip(&v, MAX_VALUE_BYTES)),
        rate_per_second: rate.map(|v| clip(&v, MAX_VALUE_BYTES)),
        severity,
        confidence,
        interpretation: clip(&interpretation.into(), MAX_TEXT_BYTES),
        limitations: Vec::new(),
    }
}

fn push_change(changes: &mut Vec<DiffChange>, c: DiffChange) {
    if changes.len() < MAX_DIFF_CHANGES {
        changes.push(c);
    }
}

fn counter_severity(key: &str, delta: u64) -> Severity {
    if delta == 0 {
        return Severity::Info;
    }
    match key {
        "listen_disabled_num" => Severity::Critical,
        "evictions" | "expired_unfetched" | "evicted_unfetched" | "reclaimed" => Severity::Warning,
        _ => Severity::Info,
    }
}

fn hit_ratio_from(map: &BTreeMap<String, String>) -> Option<(f64, u64)> {
    let hits = metric_u64(map, "get_hits")?;
    let misses = metric_u64(map, "get_misses")?;
    let total = hits.saturating_add(misses);
    (total > 0).then(|| (hits as f64 / total as f64, total))
}

fn memory_pct_from(gauges: &BTreeMap<String, String>) -> Option<f64> {
    let used = metric_u64(gauges, "bytes")?;
    let limit = metric_u64(gauges, "limit_maxbytes")?;
    (limit > 0).then(|| used as f64 / limit as f64 * 100.0)
}

fn connection_pct_from(
    gauges: &BTreeMap<String, String>,
    settings: &BTreeMap<String, String>,
) -> Option<f64> {
    let cur = metric_u64(gauges, "curr_connections")?;
    let max = metric_u64(settings, "maxconns")?;
    (max > 0).then(|| cur as f64 / max as f64 * 100.0)
}

fn compare_topology(before: &IncidentSnapshot, after: &IncidentSnapshot) -> Option<TopologyDiff> {
    let bt = before.topology.as_ref()?;
    let at = after.topology.as_ref()?;
    let mut diff = TopologyDiff::default();
    let bp: BTreeMap<&str, usize> = bt
        .pools
        .iter()
        .map(|p| (p.id.as_str(), p.servers))
        .collect();
    let ap: BTreeMap<&str, usize> = at
        .pools
        .iter()
        .map(|p| (p.id.as_str(), p.servers))
        .collect();
    for id in bp.keys().filter(|id| !ap.contains_key(**id)) {
        diff.pools_removed.push((*id).to_owned());
    }
    for id in ap.keys().filter(|id| !bp.contains_key(**id)) {
        diff.pools_added.push((*id).to_owned());
    }
    for (id, before_servers) in &bp {
        if let Some(after_servers) = ap.get(id) {
            if before_servers != after_servers {
                diff.pool_changes.push(PoolChange {
                    id: (*id).to_owned(),
                    before_servers: *before_servers,
                    after_servers: *after_servers,
                });
            }
        }
    }
    let bd: BTreeMap<&str, Option<bool>> = bt
        .destinations
        .iter()
        .map(|d| (d.id.as_str(), d.reachable))
        .collect();
    let ad: BTreeMap<&str, Option<bool>> = at
        .destinations
        .iter()
        .map(|d| (d.id.as_str(), d.reachable))
        .collect();
    for id in bd.keys().filter(|id| !ad.contains_key(**id)) {
        diff.destinations_removed.push((*id).to_owned());
    }
    for id in ad.keys().filter(|id| !bd.contains_key(**id)) {
        diff.destinations_added.push((*id).to_owned());
    }
    for (id, before_reachable) in &bd {
        if let Some(after_reachable) = ad.get(id) {
            if before_reachable != after_reachable {
                diff.destination_availability.push(DestinationChange {
                    id: (*id).to_owned(),
                    before_reachable: *before_reachable,
                    after_reachable: *after_reachable,
                });
            }
        }
    }
    Some(diff)
}

fn compare_rca(before: &Option<RcaReport>, after: &Option<RcaReport>) -> RcaDiff {
    let mut diff = RcaDiff {
        before_status: before.as_ref().map(|r| r.status),
        after_status: after.as_ref().map(|r| r.status),
        changes: Vec::new(),
    };
    let bm: BTreeMap<&str, &RcaFinding> = before
        .as_ref()
        .map(|r| r.findings.iter().map(|f| (f.id.as_str(), f)).collect())
        .unwrap_or_default();
    let am: BTreeMap<&str, &RcaFinding> = after
        .as_ref()
        .map(|r| r.findings.iter().map(|f| (f.id.as_str(), f)).collect())
        .unwrap_or_default();
    let ids: BTreeSet<&str> = bm.keys().chain(am.keys()).copied().collect();
    for id in ids {
        let b = bm.get(id).copied();
        let a = am.get(id).copied();
        let changed = match (b, a) {
            (Some(b), Some(a)) => b.severity != a.severity || b.confidence != a.confidence,
            _ => true,
        };
        if changed {
            diff.changes.push(RcaChange {
                id: id.to_owned(),
                before_severity: b.map(|f| f.severity),
                after_severity: a.map(|f| f.severity),
                before_confidence: b.map(|f| f.confidence),
                after_confidence: a.map(|f| f.confidence),
            });
        }
    }
    diff
}

fn topology_coverage_incomplete(snapshot: &IncidentSnapshot) -> bool {
    snapshot.topology.as_ref().is_some_and(|t| {
        t.coverage
            .as_ref()
            .is_none_or(|coverage| !coverage.complete)
    })
}

/// Compares two snapshots. Returns an error for incompatible or invalid snapshots; all other
/// uncertainty is reported as `partial`/`insufficient_evidence` plus limitations.
pub fn compare_snapshots(
    before: &IncidentSnapshot,
    after: &IncidentSnapshot,
) -> Result<SnapshotDiff, String> {
    before.validate()?;
    after.validate()?;
    if before.kind != after.kind {
        return Err("snapshots have different kinds and cannot be compared".to_owned());
    }

    let before_ms = before.captured_at_unix_ms;
    let after_ms = after.captured_at_unix_ms;
    let (interval_seconds, interval_valid, rate_interval_valid, interval_reason) = if before_ms == 0
        || after_ms == 0
    {
        (
            None,
            false,
            false,
            Some("one or both snapshots have no usable timestamp".to_owned()),
        )
    } else if after_ms <= before_ms {
        (
            None,
            false,
            false,
            Some(
                "clock skew or non-increasing timestamps; rates and interval are invalid"
                    .to_owned(),
            ),
        )
    } else {
        let ms = after_ms - before_ms;
        let seconds = ms as f64 / 1000.0;
        (
                Some(seconds),
                true,
                ms >= MIN_RATE_INTERVAL_MS,
                (ms < MIN_RATE_INTERVAL_MS).then(|| {
                    format!(
                        "interval is {seconds:.3} s, shorter than the {MIN_RATE_INTERVAL_MS} ms rate floor; rates are omitted"
                    )
                }),
            )
    };
    let target_changed = before.target != after.target;

    let mut changes = Vec::new();
    let mut resets = Vec::new();
    let mut missing = BTreeSet::new();
    for key in before
        .missing_evidence
        .iter()
        .chain(after.missing_evidence.iter())
    {
        missing.insert(key.clone());
    }

    let before_uptime = metric_u64(&before.metrics.gauges, "uptime");
    let after_uptime = metric_u64(&after.metrics.gauges, "uptime");
    let uptime_reset = matches!((before_uptime, after_uptime), (Some(b), Some(a)) if a < b);
    if let (Some(b), Some(a)) = (before_uptime, after_uptime) {
        if a < b {
            resets.push(CounterReset {
                metric: "uptime".to_owned(),
                before: b.to_string(),
                after: a.to_string(),
                interpretation:
                    "Uptime decreased: the node restarted or a different instance answered. Rates are suppressed."
                        .to_owned(),
            });
        }
    }

    let counter_keys: BTreeSet<&str> = before
        .metrics
        .counters
        .keys()
        .chain(after.metrics.counters.keys())
        .map(String::as_str)
        .collect();
    for key in counter_keys {
        let b = metric_u64(&before.metrics.counters, key);
        let a = metric_u64(&after.metrics.counters, key);
        let (Some(b), Some(a)) = (b, a) else {
            missing.insert(format!("counter {key}"));
            continue;
        };
        if a < b {
            if resets.len() < MAX_DIFF_RESETS {
                resets.push(CounterReset {
                    metric: key.to_owned(),
                    before: b.to_string(),
                    after: a.to_string(),
                    interpretation:
                        "Counter decreased: a reset or different instance is more likely than a negative event."
                            .to_owned(),
                });
            }
            push_change(
                &mut changes,
                change(
                    "counter_reset",
                    key,
                    EvidenceKind::Counter,
                    Some(b.to_string()),
                    Some(a.to_string()),
                    None,
                    None,
                    Severity::Warning,
                    Confidence::High,
                    "Counter decreased between snapshots; the delta is not reported as a rate.",
                ),
            );
            continue;
        }
        if a == b {
            continue;
        }
        let delta = a - b;
        let rate = if rate_interval_valid && !uptime_reset {
            interval_seconds.map(|s| format!("{:.6}", delta as f64 / s))
        } else {
            None
        };
        let confidence = if rate.is_some() {
            Confidence::High
        } else if interval_valid && !uptime_reset {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        push_change(
            &mut changes,
            change(
                "counter_change",
                key,
                EvidenceKind::Counter,
                Some(b.to_string()),
                Some(a.to_string()),
                Some(delta.to_string()),
                rate,
                counter_severity(key, delta),
                confidence,
                "Counter increased between snapshots; the rate is only shown when the interval is valid and no reset was detected.",
            ),
        );
    }

    let gauge_keys: BTreeSet<&str> = before
        .metrics
        .gauges
        .keys()
        .chain(after.metrics.gauges.keys())
        .map(String::as_str)
        .collect();
    for key in gauge_keys {
        let b = metric_u64(&before.metrics.gauges, key);
        let a = metric_u64(&after.metrics.gauges, key);
        let (Some(b), Some(a)) = (b, a) else {
            missing.insert(format!("gauge {key}"));
            continue;
        };
        if key == "uptime" {
            continue;
        }
        if b == a {
            continue;
        }
        let delta = a as i128 - b as i128;
        let severity = match key {
            "num_servers_down" | "num_suspect_servers" if a > b => Severity::Warning,
            "limit_maxbytes" => Severity::Warning,
            _ => Severity::Info,
        };
        push_change(
            &mut changes,
            change(
                "gauge_change",
                key,
                EvidenceKind::Gauge,
                Some(b.to_string()),
                Some(a.to_string()),
                Some(delta.to_string()),
                None,
                severity,
                Confidence::High,
                "Gauge changed between snapshots; it is an instantaneous value, not a rate.",
            ),
        );
    }

    if let (Some(b), Some(a)) = (
        hit_ratio_from(&before.metrics.counters),
        hit_ratio_from(&after.metrics.counters),
    ) {
        let delta = a.0 - b.0;
        if delta.abs() >= 0.005 {
            push_change(
                &mut changes,
                change(
                    "hit_ratio_change",
                    "hit_ratio",
                    EvidenceKind::Derived,
                    Some(format!("{:.3}", b.0)),
                    Some(format!("{:.3}", a.0)),
                    Some(format!("{delta:+.3}")),
                    None,
                    if a.0 < 0.5 {
                        Severity::Critical
                    } else if a.0 < 0.8 {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    if b.1 >= 1_000 && a.1 >= 1_000 {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    },
                    "Hit ratio is derived from the two snapshots, not from a historical series.",
                ),
            );
        }
    }

    if let (Some(b), Some(a)) = (
        memory_pct_from(&before.metrics.gauges),
        memory_pct_from(&after.metrics.gauges),
    ) {
        let delta = a - b;
        if delta.abs() >= 1.0 {
            push_change(
                &mut changes,
                change(
                    "memory_utilization_change",
                    "memory_utilization_pct",
                    EvidenceKind::Derived,
                    Some(format!("{b:.1}")),
                    Some(format!("{a:.1}")),
                    Some(format!("{delta:+.1}")),
                    None,
                    if a >= 95.0 {
                        Severity::Critical
                    } else if a >= 90.0 {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    Confidence::High,
                    "Derived from bytes / limit_maxbytes at each snapshot.",
                ),
            );
        }
    }

    if let (Some(b), Some(a)) = (
        connection_pct_from(&before.metrics.gauges, &before.metrics.settings),
        connection_pct_from(&after.metrics.gauges, &after.metrics.settings),
    ) {
        let delta = a - b;
        if delta.abs() >= 1.0 {
            push_change(
                &mut changes,
                change(
                    "connection_utilization_change",
                    "connection_utilization_pct",
                    EvidenceKind::Derived,
                    Some(format!("{b:.1}")),
                    Some(format!("{a:.1}")),
                    Some(format!("{delta:+.1}")),
                    None,
                    if a >= 80.0 {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    Confidence::High,
                    "Derived from curr_connections / maxconns at each snapshot.",
                ),
            );
        }
    }

    if let Some(rate) = (rate_interval_valid && !uptime_reset)
        .then_some(())
        .and_then(|_| {
            let b = metric_u64(&before.metrics.counters, "evictions")?;
            let a = metric_u64(&after.metrics.counters, "evictions")?;
            let delta = a.checked_sub(b)?;
            let seconds = interval_seconds?;
            Some((delta, delta as f64 / seconds))
        })
    {
        if rate.0 > 0 {
            push_change(
                &mut changes,
                change(
                    "eviction_rate",
                    "evictions",
                    EvidenceKind::Derived,
                    None,
                    None,
                    Some(rate.0.to_string()),
                    Some(format!("{:.6}", rate.1)),
                    if rate.1 >= 1.0 {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    },
                    Confidence::Medium,
                    "Eviction rate is derived only from a valid interval and an unreset counter.",
                ),
            );
        }
    }

    compare_slabs(
        &before.metrics.slabs,
        &after.metrics.slabs,
        rate_interval_valid && !uptime_reset,
        interval_seconds,
        &mut changes,
        &mut resets,
        &mut missing,
    );

    let topology = if before.kind == SnapshotKind::Mcrouter {
        match (&before.topology, &after.topology) {
            (Some(_), Some(_)) => compare_topology(before, after),
            _ => {
                missing.insert("topology snapshot".to_owned());
                None
            }
        }
    } else {
        None
    };
    if let Some(ref t) = topology {
        let n = t.pools_added.len()
            + t.pools_removed.len()
            + t.pool_changes.len()
            + t.destinations_added.len()
            + t.destinations_removed.len()
            + t.destination_availability.len();
        if n > 0 {
            push_change(
                &mut changes,
                change(
                    "topology_change",
                    "mcrouter_topology",
                    EvidenceKind::Coverage,
                    Some(format!(
                        "{} pools / {} destinations",
                        before.topology.as_ref().map_or(0, |t| t.pools.len()),
                        before.topology.as_ref().map_or(0, |t| t.destinations.len())
                    )),
                    Some(format!(
                        "{} pools / {} destinations",
                        after.topology.as_ref().map_or(0, |t| t.pools.len()),
                        after.topology.as_ref().map_or(0, |t| t.destinations.len())
                    )),
                    Some(n.to_string()),
                    None,
                    Severity::Warning,
                    Confidence::High,
                    "Opaque topology membership or reachability changed between snapshots.",
                ),
            );
        }
        let coverage_changed = before.topology.as_ref().and_then(|t| t.coverage.as_ref())
            != after.topology.as_ref().and_then(|t| t.coverage.as_ref());
        if coverage_changed || topology_coverage_incomplete(after) {
            push_change(
                &mut changes,
                change(
                    "destination_coverage_change",
                    "destination_coverage",
                    EvidenceKind::Coverage,
                    before
                        .topology
                        .as_ref()
                        .and_then(|t| t.coverage.as_ref())
                        .map(|c| format!("{}/{}", c.probed_destinations, c.configured_destinations)),
                    after
                        .topology
                        .as_ref()
                        .and_then(|t| t.coverage.as_ref())
                        .map(|c| format!("{}/{}", c.probed_destinations, c.configured_destinations)),
                    None,
                    None,
                    if topology_coverage_incomplete(after) {
                        Severity::Warning
                    } else {
                        Severity::Info
                    },
                    Confidence::High,
                    "Destination coverage changed or remains incomplete; cluster-wide conclusions are limited.",
                ),
            );
        }
    }

    let rca = compare_rca(&before.rca, &after.rca);
    if before.rca.is_none() || after.rca.is_none() {
        missing.insert("RCA report".to_owned());
    }

    let mut limitations = vec![
        "Diff describes only two snapshots; it cannot establish a longer trend or prove causation."
            .to_owned(),
        "Counters are cumulative since uptime; rates are omitted on reset, missing timestamps, clock skew, or intervals shorter than 5 s."
            .to_owned(),
        "Topology identifiers are opaque fingerprints; raw pool and destination names are not included."
            .to_owned(),
    ];
    if target_changed {
        limitations.push(
            "The two snapshots name different targets; this may be a node replacement rather than a continuous series."
                .to_owned(),
        );
    }
    if let Some(reason) = &interval_reason {
        limitations.push(reason.clone());
    }
    if uptime_reset {
        limitations.push(
            "Uptime decreased, so all counter rates are suppressed even where individual counters increased."
                .to_owned(),
        );
    }
    if topology_coverage_incomplete(before) || topology_coverage_incomplete(after) {
        limitations.push(
            "At least one mcrouter snapshot has incomplete destination coverage; topology changes may be under-reported."
                .to_owned(),
        );
    }
    for l in before.limitations.iter().chain(after.limitations.iter()) {
        if limitations.len() < MAX_DIFF_MISSING && !limitations.contains(l) {
            limitations.push(l.clone());
        }
    }
    dedup_limits(&mut limitations);
    limitations.truncate(MAX_DIFF_MISSING);
    let missing: Vec<String> = missing.into_iter().take(MAX_DIFF_MISSING).collect();

    let has_changes = !changes.is_empty()
        || !resets.is_empty()
        || topology.as_ref().is_some_and(|t| !t.is_empty())
        || !rca.is_empty();
    let no_comparable = before.metrics.counters.is_empty()
        && before.metrics.gauges.is_empty()
        && before.topology.is_none()
        && after.metrics.counters.is_empty()
        && after.metrics.gauges.is_empty()
        && after.topology.is_none()
        && before.rca.is_none()
        && after.rca.is_none();
    let partial = !interval_valid
        || target_changed
        || !missing.is_empty()
        || topology_coverage_incomplete(before)
        || topology_coverage_incomplete(after)
        || before
            .rca
            .as_ref()
            .is_some_and(|r| r.status == AnalysisStatus::Partial)
        || after
            .rca
            .as_ref()
            .is_some_and(|r| r.status == AnalysisStatus::Partial);
    let status = if has_changes {
        DiffStatus::Changed
    } else if no_comparable {
        DiffStatus::InsufficientEvidence
    } else if partial {
        DiffStatus::Partial
    } else {
        DiffStatus::NoChange
    };

    let topology_count = topology.as_ref().map_or(0, |t| {
        t.pools_added.len()
            + t.pools_removed.len()
            + t.pool_changes.len()
            + t.destinations_added.len()
            + t.destinations_removed.len()
            + t.destination_availability.len()
    });
    let summary = match status {
        DiffStatus::NoChange => {
            "No material changes detected between the two snapshots.".to_owned()
        }
        DiffStatus::Changed => format!(
            "{} metric change(s), {} counter reset(s), {} topology change(s) and {} RCA change(s); interval {}.",
            changes.len(),
            resets.len(),
            topology_count,
            rca.changes.len(),
            interval_seconds.map_or_else(
                || "invalid".to_owned(),
                |s| format!("{s:.3} s")
            )
        ),
        DiffStatus::Partial => format!(
            "{} change(s) observed, but the comparison is partial: {}.",
            changes.len(),
            interval_reason
                .as_deref()
                .or_else(|| missing.first().map(String::as_str))
                .unwrap_or("some evidence is missing or incomplete")
        ),
        DiffStatus::InsufficientEvidence => {
            "Insufficient comparable metrics or RCA evidence in the supplied snapshots.".to_owned()
        }
    };

    Ok(SnapshotDiff {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
        kind: before.kind,
        status,
        summary,
        before: SnapshotRef {
            target: before.target.clone(),
            captured_at_unix_ms: before_ms,
        },
        after: SnapshotRef {
            target: after.target.clone(),
            captured_at_unix_ms: after_ms,
        },
        interval_seconds,
        interval_valid,
        rate_interval_valid,
        interval_reason,
        changes,
        resets,
        topology,
        rca,
        missing_evidence: missing,
        limitations,
    })
}

fn compare_slabs(
    before: &[SlabSnapshot],
    after: &[SlabSnapshot],
    rate_valid: bool,
    interval_seconds: Option<f64>,
    changes: &mut Vec<DiffChange>,
    resets: &mut Vec<CounterReset>,
    missing: &mut BTreeSet<String>,
) {
    let bm: BTreeMap<u32, &SlabSnapshot> = before.iter().map(|s| (s.class, s)).collect();
    let am: BTreeMap<u32, &SlabSnapshot> = after.iter().map(|s| (s.class, s)).collect();
    let classes: BTreeSet<u32> = bm.keys().chain(am.keys()).copied().collect();
    for class in classes {
        let before_slab = bm.get(&class);
        let after_slab = am.get(&class);
        if before_slab.is_none() || after_slab.is_none() {
            let (id, before_items, after_items) = if let Some(s) = before_slab {
                ("slab_class_removed", s.items.map(|v| v.to_string()), None)
            } else {
                (
                    "slab_class_added",
                    None,
                    after_slab.and_then(|s| s.items).map(|v| v.to_string()),
                )
            };
            push_change(
                changes,
                change(
                    id,
                    format!("slab:{class}"),
                    EvidenceKind::Gauge,
                    before_items,
                    after_items,
                    None,
                    None,
                    Severity::Info,
                    Confidence::High,
                    "Slab class membership changed between snapshots; this is reported as a change, not as missing data.",
                ),
            );
            continue;
        }
        let (b, a) = (before_slab.unwrap(), after_slab.unwrap());
        for (field, bv, av, kind, severity) in [
            (
                "items",
                b.items,
                a.items,
                EvidenceKind::Gauge,
                Severity::Info,
            ),
            (
                "evicted",
                b.evicted,
                a.evicted,
                EvidenceKind::Counter,
                Severity::Warning,
            ),
            (
                "mem_requested",
                b.mem_requested,
                a.mem_requested,
                EvidenceKind::Gauge,
                Severity::Info,
            ),
            (
                "reclaimed",
                b.reclaimed,
                a.reclaimed,
                EvidenceKind::Counter,
                Severity::Warning,
            ),
        ] {
            let (bv, av) = match (bv, av) {
                (Some(b), Some(a)) => (b, a),
                (None, None) => continue,
                _ => {
                    missing.insert(format!("slab {class} {field}"));
                    continue;
                }
            };
            if bv == av {
                continue;
            }
            if av < bv {
                if resets.len() < MAX_DIFF_RESETS {
                    resets.push(CounterReset {
                        metric: format!("slab {class} {field}"),
                        before: bv.to_string(),
                        after: av.to_string(),
                        interpretation:
                            "Slab counter decreased; a reset or different instance is likely."
                                .to_owned(),
                    });
                }
                continue;
            }
            let delta = av - bv;
            let rate = if rate_valid && kind == EvidenceKind::Counter {
                interval_seconds.map(|s| format!("{:.6}", delta as f64 / s))
            } else {
                None
            };
            push_change(
                changes,
                change(
                    "slab_change",
                    format!("slab:{class}:{field}"),
                    kind,
                    Some(bv.to_string()),
                    Some(av.to_string()),
                    Some(delta.to_string()),
                    rate,
                    severity,
                    Confidence::Medium,
                    "Per-slab value changed between snapshots; class membership is not compared across a slab reconfiguration.",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rca::{analyze_node, Coverage};
    use crate::Stats;

    fn st(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn healthy_stats() -> (Stats, Stats, Stats) {
        (
            st(&[
                ("get_hits", "9000"),
                ("get_misses", "1000"),
                ("bytes", "50"),
                ("limit_maxbytes", "100"),
                ("curr_items", "1000"),
                ("total_items", "10000"),
                ("curr_connections", "10"),
                ("evictions", "0"),
                ("uptime", "10000"),
            ]),
            st(&[("items:1:number", "1000"), ("items:1:evicted", "0")]),
            st(&[("maxconns", "100")]),
        )
    }

    fn node_snapshot(at: u64) -> IncidentSnapshot {
        let (stats, items, settings) = healthy_stats();
        let rca = analyze_node("cache:11211", &stats, &items, &settings);
        IncidentSnapshot::node("cache:11211", at, &stats, &items, &settings, rca)
    }

    #[test]
    fn snapshot_round_trips_and_validates() {
        let snapshot = node_snapshot(1_000_000);
        let json = serde_json::to_value(&snapshot).unwrap();
        let parsed = parse_snapshot(json).unwrap();
        assert_eq!(snapshot, parsed);
        assert_eq!(parsed.schema_version, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(parsed.kind, SnapshotKind::MemcachedNode);
    }

    #[test]
    fn rejects_unknown_schema_and_oversized_input() {
        let mut snapshot = node_snapshot(1_000_000);
        snapshot.schema_version = "9.9".to_owned();
        assert!(snapshot.validate().is_err());
        let mut json = serde_json::to_value(node_snapshot(1_000_000)).unwrap();
        json["metrics"]["counters"]["x"] =
            serde_json::Value::String("y".repeat(MAX_VALUE_BYTES + 1));
        assert!(parse_snapshot(json).is_err());
    }

    #[test]
    fn no_change_is_deterministic() {
        let a = node_snapshot(1_000_000);
        let b = node_snapshot(1_005_000);
        let d1 = compare_snapshots(&a, &b).unwrap();
        let d2 = compare_snapshots(&a, &b).unwrap();
        assert_eq!(d1, d2);
        assert!(
            d1.missing_evidence.is_empty(),
            "missing={:?} changes={:?}",
            d1.missing_evidence,
            d1.changes
        );
        assert_eq!(d1.status, DiffStatus::NoChange);
        assert!(d1.interval_valid);
        assert!(d1.rate_interval_valid);
    }

    #[test]
    fn detects_counter_changes_and_rates() {
        let before = node_snapshot(1_000_000);
        let (mut stats, items, settings) = healthy_stats();
        stats.insert("get_hits".into(), "10000".into());
        stats.insert("evictions".into(), "10".into());
        let rca = analyze_node("cache:11211", &stats, &items, &settings);
        let after =
            IncidentSnapshot::node("cache:11211", 1_010_000, &stats, &items, &settings, rca);
        let d = compare_snapshots(&before, &after).unwrap();
        let hit = d.changes.iter().find(|c| c.subject == "get_hits").unwrap();
        assert_eq!(hit.delta.as_deref(), Some("1000"));
        assert_eq!(hit.rate_per_second.as_deref(), Some("100.000000"));
        assert!(d.changes.iter().any(|c| c.id == "eviction_rate"));
    }

    #[test]
    fn counter_reset_suppresses_rate_and_is_explicit() {
        let before = node_snapshot(1_000_000);
        let (mut stats, items, settings) = healthy_stats();
        stats.insert("get_hits".into(), "100".into());
        stats.insert("get_misses".into(), "20".into());
        let rca = analyze_node("cache:11211", &stats, &items, &settings);
        let after =
            IncidentSnapshot::node("cache:11211", 1_010_000, &stats, &items, &settings, rca);
        let d = compare_snapshots(&before, &after).unwrap();
        assert!(d.resets.iter().any(|r| r.metric == "get_hits"));
        let reset = d
            .changes
            .iter()
            .find(|c| c.id == "counter_reset" && c.subject == "get_hits")
            .unwrap();
        assert!(reset.rate_per_second.is_none());
    }

    #[test]
    fn clock_skew_suppresses_rates() {
        let before = node_snapshot(1_000_000);
        let after = node_snapshot(900_000);
        let d = compare_snapshots(&before, &after).unwrap();
        assert!(!d.interval_valid);
        assert!(!d.rate_interval_valid);
        assert!(d.changes.iter().all(|c| c.rate_per_second.is_none()));
        assert_eq!(d.status, DiffStatus::Partial);
    }

    #[test]
    fn short_interval_suppresses_rates_but_not_changes() {
        let before = node_snapshot(1_000_000);
        let (mut stats, items, settings) = healthy_stats();
        stats.insert("get_hits".into(), "9001".into());
        let rca = analyze_node("cache:11211", &stats, &items, &settings);
        let after =
            IncidentSnapshot::node("cache:11211", 1_001_000, &stats, &items, &settings, rca);
        let d = compare_snapshots(&before, &after).unwrap();
        assert!(d.interval_valid);
        assert!(!d.rate_interval_valid);
        assert!(d.changes.iter().all(|c| c.rate_per_second.is_none()));
        assert!(d.changes.iter().any(|c| c.subject == "get_hits"));
    }

    #[test]
    fn missing_metrics_are_explicit() {
        let mut before = node_snapshot(1_000_000);
        before.metrics.gauges.remove("bytes");
        let after = node_snapshot(1_010_000);
        let d = compare_snapshots(&before, &after).unwrap();
        assert!(d.missing_evidence.iter().any(|m| m.contains("bytes")));
    }

    #[test]
    fn topology_additions_removals_and_availability() {
        let coverage = Coverage {
            configured_destinations: 2,
            probed_destinations: 2,
            reachable_destinations: 1,
            unreachable_destinations: 1,
            unmapped_destinations: 0,
            denied_destinations: 0,
            truncated_destinations: 0,
            complete: true,
        };
        let before = IncidentSnapshot::mcrouter(
            "router:5000",
            1_000_000,
            &st(&[("num_servers", "2")]),
            TopologySnapshot {
                pools: vec![PoolSnapshot {
                    id: "pool-a".into(),
                    servers: 2,
                }],
                destinations: vec![
                    DestinationSnapshot {
                        id: "dest-a".into(),
                        reachable: Some(true),
                    },
                    DestinationSnapshot {
                        id: "dest-b".into(),
                        reachable: Some(false),
                    },
                ],
                coverage: Some(coverage.clone()),
            },
            analyze_node(
                "router:5000",
                &st(&[("get_hits", "1"), ("get_misses", "1")]),
                &Stats::new(),
                &Stats::new(),
            ),
        );
        let after = IncidentSnapshot::mcrouter(
            "router:5000",
            1_010_000,
            &st(&[("num_servers", "2")]),
            TopologySnapshot {
                pools: vec![PoolSnapshot {
                    id: "pool-a".into(),
                    servers: 3,
                }],
                destinations: vec![
                    DestinationSnapshot {
                        id: "dest-a".into(),
                        reachable: Some(true),
                    },
                    DestinationSnapshot {
                        id: "dest-c".into(),
                        reachable: Some(true),
                    },
                ],
                coverage: Some(Coverage {
                    configured_destinations: 3,
                    probed_destinations: 3,
                    ..coverage
                }),
            },
            analyze_node(
                "router:5000",
                &st(&[("get_hits", "1"), ("get_misses", "1")]),
                &Stats::new(),
                &Stats::new(),
            ),
        );
        let d = compare_snapshots(&before, &after).unwrap();
        let t = d.topology.as_ref().unwrap();
        assert!(t.pools_added.is_empty());
        assert!(!t.pool_changes.is_empty());
        assert_eq!(t.destinations_added, ["dest-c"]);
        assert_eq!(t.destinations_removed, ["dest-b"]);
        assert!(d.changes.iter().any(|c| c.id == "topology_change"));
    }

    #[test]
    fn rca_severity_changes_are_compared() {
        let before = node_snapshot(1_000_000);
        let (mut stats, items, settings) = healthy_stats();
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "20000".into());
        let rca = analyze_node("cache:11211", &stats, &items, &settings);
        let after =
            IncidentSnapshot::node("cache:11211", 1_010_000, &stats, &items, &settings, rca);
        let d = compare_snapshots(&before, &after).unwrap();
        assert!(d.rca.changes.iter().any(|c| c.id == "evictions"));
        assert!(d.status == DiffStatus::Changed);
    }

    #[test]
    fn deterministic_ordering_is_stable() {
        let before = node_snapshot(1_000_000);
        let (mut stats, items, settings) = healthy_stats();
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "20000".into());
        let rca = analyze_node("cache:11211", &stats, &items, &settings);
        let after =
            IncidentSnapshot::node("cache:11211", 1_010_000, &stats, &items, &settings, rca);
        let a = compare_snapshots(&before, &after).unwrap();
        let b = compare_snapshots(&before, &after).unwrap();
        assert_eq!(a, b);
    }
}
