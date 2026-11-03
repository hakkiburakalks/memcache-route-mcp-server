//! Read-only comparison of explicitly supplied Memcached/mcrouter cluster snapshots.
//!
//! No discovery, collection or cross-cluster connection is performed. Snapshot data is bounded and
//! aggregated by target; comparisons report observed differences and missing coverage, not causal
//! or capacity-transfer claims.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::snapshot::{IncidentSnapshot, SnapshotKind};
use crate::Severity;

pub const CLUSTER_COMPARE_SCHEMA_VERSION: &str = "1.0";
pub const MAX_COMPARE_CLUSTERS: usize = 8;
pub const MAX_CLUSTER_SNAPSHOTS: usize = 64;
const MAX_CLUSTER_FINDINGS: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterInput {
    pub name: String,
    pub snapshots: Vec<IncidentSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterMemory {
    pub nodes: usize,
    pub used_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
    pub utilization_pct: Option<f64>,
    pub headroom_pct: Option<f64>,
    pub items: Option<u64>,
    pub average_item_bytes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterWorkload {
    pub gets: Option<u64>,
    pub hit_ratio: Option<f64>,
    pub evictions: Option<u64>,
    pub eviction_rate_per_second: Option<f64>,
    pub expired_unfetched: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterConnections {
    pub curr_connections: Option<u64>,
    pub max_connections: Option<u64>,
    pub utilization_pct: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterAvailability {
    pub routers: usize,
    pub pools: usize,
    pub destinations: usize,
    pub reachable: usize,
    pub unreachable: usize,
    pub unknown: usize,
    pub coverage_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterSummary {
    pub name: String,
    pub snapshots: usize,
    pub memcached_nodes: usize,
    pub mcrouter_snapshots: usize,
    pub memory: ClusterMemory,
    pub workload: ClusterWorkload,
    pub connections: ClusterConnections,
    pub availability: ClusterAvailability,
    pub rca_statuses: BTreeMap<String, usize>,
    pub rca_finding_counts: BTreeMap<String, usize>,
    pub history_anomalies: BTreeMap<String, usize>,
    pub observed_metrics: Vec<String>,
    pub missing_metrics: Vec<String>,
    pub missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterFinding {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterComparison {
    pub baseline: String,
    pub compared: String,
    pub memory_utilization_delta_pct: Option<f64>,
    pub hit_ratio_delta_pct: Option<f64>,
    pub eviction_rate_delta_per_second: Option<f64>,
    pub connection_utilization_delta_pct: Option<f64>,
    pub reachable_destination_delta: Option<i64>,
    pub missing_metric_delta: Vec<String>,
    pub rca_status_changes: Vec<String>,
    pub history_anomaly_delta: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterCompareReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub clusters: Vec<ClusterSummary>,
    pub comparisons: Vec<ClusterComparison>,
    pub findings: Vec<ClusterFinding>,
    pub limitations: Vec<String>,
}

fn sum(values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    let mut total = 0u64;
    let mut seen = false;
    for v in values.flatten() {
        total = total.saturating_add(v);
        seen = true;
    }
    seen.then_some(total)
}

fn sum_f64(values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    let mut total = 0.0f64;
    let mut seen = false;
    for v in values.flatten() {
        total += v;
        seen = true;
    }
    seen.then_some(total)
}

fn pct(value: u64, limit: u64) -> Option<f64> {
    (limit > 0).then(|| value as f64 * 100.0 / limit as f64)
}

fn latest_per_target(snapshots: &[IncidentSnapshot]) -> Vec<&IncidentSnapshot> {
    let mut latest: BTreeMap<(SnapshotKind, &str), &IncidentSnapshot> = BTreeMap::new();
    for s in snapshots {
        let key = (s.kind, s.target.as_str());
        let replace = latest
            .get(&key)
            .is_none_or(|old| s.captured_at_unix_ms >= old.captured_at_unix_ms);
        if replace {
            latest.insert(key, s);
        }
    }
    latest.into_values().collect()
}

fn metric(snapshot: &IncidentSnapshot, key: &str) -> Option<u64> {
    snapshot
        .metrics
        .counters
        .get(key)
        .or_else(|| snapshot.metrics.gauges.get(key))?
        .parse()
        .ok()
}

fn metric_keys(snapshots: &[IncidentSnapshot]) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for s in snapshots {
        keys.extend(s.metrics.counters.keys().cloned());
        keys.extend(s.metrics.gauges.keys().cloned());
    }
    keys
}

fn summarize(name: &str, snapshots: &[IncidentSnapshot]) -> ClusterSummary {
    let latest = latest_per_target(snapshots);
    let nodes: Vec<_> = latest
        .iter()
        .copied()
        .filter(|s| s.kind == SnapshotKind::MemcachedNode)
        .collect();
    let routers: Vec<_> = latest
        .iter()
        .copied()
        .filter(|s| s.kind == SnapshotKind::Mcrouter)
        .collect();
    let used = sum(nodes.iter().map(|s| metric(s, "bytes")));
    let limit = sum(nodes.iter().map(|s| metric(s, "limit_maxbytes")));
    let items = sum(nodes.iter().map(|s| metric(s, "curr_items")));
    let hits = sum(nodes.iter().map(|s| metric(s, "get_hits")));
    let misses = sum(nodes.iter().map(|s| metric(s, "get_misses")));
    let gets = hits.zip(misses).map(|(h, m)| h.saturating_add(m));
    let hit_ratio = hits
        .zip(gets)
        .and_then(|(h, g)| (g > 0).then(|| h as f64 / g as f64));
    let evictions = sum(nodes.iter().map(|s| metric(s, "evictions")));
    let eviction_rate = sum_f64(nodes.iter().map(|s| {
        let uptime = metric(s, "uptime")?;
        let ev = metric(s, "evictions")?;
        (uptime > 0).then(|| ev as f64 / uptime as f64)
    }));
    let curr_connections = sum(nodes.iter().map(|s| metric(s, "curr_connections")));
    let max_connections = sum(nodes.iter().map(|s| {
        metric(s, "maxconns").or_else(|| s.metrics.settings.get("maxconns")?.parse().ok())
    }));
    let mut reachable = 0usize;
    let mut unreachable = 0usize;
    let mut unknown = 0usize;
    let mut pools = 0usize;
    let mut destinations = 0usize;
    let mut coverage_complete = true;
    for s in &routers {
        if let Some(t) = &s.topology {
            pools += t.pools.len();
            destinations += t.destinations.len();
            for d in &t.destinations {
                match d.reachable {
                    Some(true) => reachable += 1,
                    Some(false) => unreachable += 1,
                    None => unknown += 1,
                }
            }
            coverage_complete &= t.coverage.as_ref().is_some_and(|c| c.complete);
        } else {
            coverage_complete = false;
        }
    }
    let mut rca_statuses = BTreeMap::new();
    let mut rca_findings = BTreeMap::new();
    for s in latest.iter() {
        if let Some(rca) = &s.rca {
            *rca_statuses
                .entry(format!("{:?}", rca.status).to_ascii_lowercase())
                .or_insert(0) += 1;
            for f in &rca.findings {
                *rca_findings.entry(f.id.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut history_anomalies = BTreeMap::new();
    let mut missing_evidence = Vec::new();
    let mut targets: BTreeMap<(SnapshotKind, String), Vec<IncidentSnapshot>> = BTreeMap::new();
    for s in snapshots {
        targets
            .entry((s.kind, s.target.clone()))
            .or_default()
            .push(s.clone());
    }
    for ((kind, target), series) in targets {
        if series.len() < 2 {
            continue;
        }
        if let Ok(report) = crate::history::analyze_history(&series) {
            for a in report.anomalies {
                *history_anomalies.entry(a.id).or_insert(0) += 1;
            }
        } else {
            missing_evidence.push(format!("history unavailable for {kind:?} {target}"));
        }
    }
    let observed_metrics: Vec<String> = metric_keys(snapshots).into_iter().take(128).collect();
    let required = [
        "bytes",
        "limit_maxbytes",
        "curr_items",
        "get_hits",
        "get_misses",
        "evictions",
        "curr_connections",
        "uptime",
    ];
    let missing_metrics: Vec<String> = required
        .iter()
        .filter(|k| !observed_metrics.iter().any(|m| m == *k))
        .map(|k| (*k).to_owned())
        .collect();
    if nodes.is_empty() {
        missing_evidence.push("no memcached_node snapshots".to_owned());
    }
    if used.is_none() || limit.is_none() {
        missing_evidence.push("memory used/limit".to_owned());
    }
    if gets.is_none() {
        missing_evidence.push("get_hits/get_misses".to_owned());
    }
    if routers.is_empty() {
        missing_evidence.push("no mcrouter snapshots; backend availability unavailable".to_owned());
    }
    ClusterSummary {
        name: name.to_owned(),
        snapshots: snapshots.len(),
        memcached_nodes: nodes.len(),
        mcrouter_snapshots: routers.len(),
        memory: ClusterMemory {
            nodes: nodes.len(),
            used_bytes: used,
            limit_bytes: limit,
            utilization_pct: used.zip(limit).and_then(|(u, l)| pct(u, l)),
            headroom_pct: used
                .zip(limit)
                .and_then(|(u, l)| pct(u, l))
                .map(|u| (100.0 - u).max(0.0)),
            items,
            average_item_bytes: used
                .zip(items)
                .and_then(|(b, i)| (i > 0).then(|| b as f64 / i as f64)),
        },
        workload: ClusterWorkload {
            gets,
            hit_ratio,
            evictions,
            eviction_rate_per_second: eviction_rate,
            expired_unfetched: sum(nodes.iter().map(|s| metric(s, "expired_unfetched"))),
        },
        connections: ClusterConnections {
            curr_connections,
            max_connections,
            utilization_pct: curr_connections
                .zip(max_connections)
                .and_then(|(c, m)| pct(c, m)),
        },
        availability: ClusterAvailability {
            routers: routers.len(),
            pools,
            destinations,
            reachable,
            unreachable,
            unknown,
            coverage_complete,
        },
        rca_statuses,
        rca_finding_counts: rca_findings,
        history_anomalies,
        observed_metrics,
        missing_metrics,
        missing_evidence,
    }
}

fn finding(
    code: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
) -> ClusterFinding {
    ClusterFinding {
        code,
        severity,
        confidence,
        message,
    }
}

/// Compare two or more explicitly supplied clusters. The first cluster is the baseline.
pub fn compare_clusters(clusters: &[ClusterInput]) -> Result<ClusterCompareReport, String> {
    if clusters.len() < 2 {
        return Err("cluster comparison needs at least two clusters".to_owned());
    }
    if clusters.len() > MAX_COMPARE_CLUSTERS {
        return Err(format!(
            "cluster comparison takes at most {MAX_COMPARE_CLUSTERS} clusters"
        ));
    }
    for c in clusters {
        if c.name.trim().is_empty() {
            return Err("cluster names must not be empty".to_owned());
        }
        if c.snapshots.len() > MAX_CLUSTER_SNAPSHOTS {
            return Err(format!(
                "cluster '{}' has more than {MAX_CLUSTER_SNAPSHOTS} snapshots",
                c.name
            ));
        }
        for s in &c.snapshots {
            s.validate()?;
        }
    }
    let mut summaries = Vec::new();
    for c in clusters {
        if c.snapshots.is_empty() {
            return Err(format!("cluster '{}' has no snapshots", c.name));
        }
        summaries.push(summarize(&c.name, &c.snapshots));
    }
    let baseline = &summaries[0];
    let mut comparisons = Vec::new();
    let mut findings = Vec::new();
    if baseline.availability.unreachable > 0
        || baseline.availability.unknown > 0
        || !baseline.availability.coverage_complete
    {
        findings.push(finding(
            "partial_cluster_coverage",
            Severity::Warning,
            "high",
            format!(
                "Baseline cluster '{}' reports {} unreachable, {} unknown and complete={} destination coverage.",
                baseline.name,
                baseline.availability.unreachable,
                baseline.availability.unknown,
                baseline.availability.coverage_complete
            ),
        ));
    }
    for other in summaries.iter().skip(1) {
        let memory = baseline
            .memory
            .utilization_pct
            .zip(other.memory.utilization_pct)
            .map(|(a, b)| b - a);
        let hit_ratio = baseline
            .workload
            .hit_ratio
            .zip(other.workload.hit_ratio)
            .map(|(a, b)| (b - a) * 100.0);
        let eviction_rate = baseline
            .workload
            .eviction_rate_per_second
            .zip(other.workload.eviction_rate_per_second)
            .map(|(a, b)| b - a);
        let connections = baseline
            .connections
            .utilization_pct
            .zip(other.connections.utilization_pct)
            .map(|(a, b)| b - a);
        let reachable =
            (other.availability.reachable as i64) - (baseline.availability.reachable as i64);
        let missing_delta: Vec<String> = other
            .missing_metrics
            .iter()
            .filter(|m| !baseline.missing_metrics.contains(m))
            .cloned()
            .collect();
        let mut rca_changes = Vec::new();
        let mut statuses: BTreeSet<&str> = BTreeSet::new();
        statuses.extend(baseline.rca_statuses.keys().map(String::as_str));
        statuses.extend(other.rca_statuses.keys().map(String::as_str));
        for status in statuses {
            let a = baseline.rca_statuses.get(status).copied().unwrap_or(0);
            let b = other.rca_statuses.get(status).copied().unwrap_or(0);
            if a != b {
                rca_changes.push(format!("{status}: {a} -> {b}"));
            }
        }
        if memory.is_some_and(|d| d.abs() >= 10.0) {
            findings.push(finding(
                "memory_utilization_difference",
                Severity::Warning,
                "medium",
                format!(
                    "Cluster '{}' memory utilization differs from '{}' by {:.1} percentage points.",
                    other.name,
                    baseline.name,
                    memory.unwrap_or(0.0)
                ),
            ));
        }
        if hit_ratio.is_some_and(|d| d <= -5.0) {
            findings.push(finding(
                "hit_ratio_difference",
                Severity::Warning,
                "medium",
                format!(
                    "Cluster '{}' hit ratio is {:.1} percentage points below '{}'.",
                    other.name,
                    hit_ratio.unwrap_or(0.0).abs(),
                    baseline.name
                ),
            ));
        }
        if eviction_rate.is_some_and(|d| d > 0.0) {
            findings.push(finding(
                "eviction_pressure_difference",
                Severity::Warning,
                "medium",
                format!(
                    "Cluster '{}' observed eviction rate is {:.3}/s above '{}'.",
                    other.name,
                    eviction_rate.unwrap_or(0.0),
                    baseline.name
                ),
            ));
        }
        if other.memory.utilization_pct.is_some_and(|u| u >= 90.0) {
            findings.push(finding(
                "target_memory_pressure",
                Severity::Warning,
                "high",
                format!(
                    "Cluster '{}' has observed memory utilization of {:.1}%.",
                    other.name,
                    other.memory.utilization_pct.unwrap_or(0.0)
                ),
            ));
        }
        if connections.is_some_and(|d| d.abs() >= 10.0) {
            findings.push(finding(
                "connection_utilization_difference",
                Severity::Warning,
                "medium",
                format!(
                    "Cluster '{}' connection utilization differs by {:.1} percentage points.",
                    other.name,
                    connections.unwrap_or(0.0)
                ),
            ));
        }
        if reachable < 0 {
            findings.push(finding(
                "backend_availability_difference",
                Severity::Warning,
                "high",
                format!(
                    "Cluster '{}' has {} fewer reachable destinations than '{}'.",
                    other.name,
                    reachable.abs(),
                    baseline.name
                ),
            ));
        }
        if other.availability.unreachable > 0
            || other.availability.unknown > 0
            || !other.availability.coverage_complete
        {
            findings.push(finding(
                "partial_cluster_coverage",
                Severity::Warning,
                "high",
                format!(
                    "Cluster '{}' reports {} unreachable, {} unknown and complete={} destination coverage.",
                    other.name,
                    other.availability.unreachable,
                    other.availability.unknown,
                    other.availability.coverage_complete
                ),
            ));
        }
        if !missing_delta.is_empty() {
            findings.push(finding(
                "metric_coverage_difference",
                Severity::Info,
                "high",
                format!(
                    "Cluster '{}' is missing metric(s) not missing in '{}': {}.",
                    other.name,
                    baseline.name,
                    missing_delta.join(", ")
                ),
            ));
        }
        if !rca_changes.is_empty() {
            findings.push(finding(
                "rca_status_difference",
                Severity::Info,
                "medium",
                format!(
                    "RCA status counts differ for '{}': {}.",
                    other.name,
                    rca_changes.join("; ")
                ),
            ));
        }
        let baseline_anomalies: i64 = baseline.history_anomalies.values().map(|v| *v as i64).sum();
        let other_anomalies: i64 = other.history_anomalies.values().map(|v| *v as i64).sum();
        if baseline_anomalies != other_anomalies {
            findings.push(finding(
                "history_anomaly_difference",
                Severity::Info,
                "low",
                format!("Historical anomaly counts differ: '{}' {baseline_anomalies}, '{}' {other_anomalies}.", baseline.name, other.name),
            ));
        }
        comparisons.push(ClusterComparison {
            baseline: baseline.name.clone(),
            compared: other.name.clone(),
            memory_utilization_delta_pct: memory,
            hit_ratio_delta_pct: hit_ratio,
            eviction_rate_delta_per_second: eviction_rate,
            connection_utilization_delta_pct: connections,
            reachable_destination_delta: Some(reachable),
            missing_metric_delta: missing_delta,
            rca_status_changes: rca_changes,
            history_anomaly_delta: Some(other_anomalies - baseline_anomalies),
        });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings.truncate(MAX_CLUSTER_FINDINGS);
    let status = if findings.iter().any(|f| f.severity >= Severity::Warning) {
        "review"
    } else if summaries.iter().any(|s| s.memory.utilization_pct.is_none()) {
        "partial"
    } else {
        "comparable"
    };
    let summary = format!(
        "{} cluster(s); baseline '{}'; {} comparison(s); {} finding(s). Differences are observed, not causal; missing coverage is explicit.",
        summaries.len(),
        baseline.name,
        comparisons.len(),
        findings.len()
    );
    Ok(ClusterCompareReport {
        schema_version: CLUSTER_COMPARE_SCHEMA_VERSION,
        analysis: "cluster_comparison",
        status,
        summary,
        clusters: summaries,
        comparisons,
        findings,
        limitations: vec![
            "Compares only supplied snapshots; no cluster discovery or collection is performed.".to_owned(),
            "Metric availability can differ by version/configuration; missing metrics are not inferred.".to_owned(),
            "Differences in utilization or hit ratio are observations, not migration or capacity predictions.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{DestinationSnapshot, SnapshotKind, SnapshotMetrics, TopologySnapshot};
    use std::collections::BTreeMap;

    fn node(target: &str, bytes: u64, hits: u64, misses: u64, evictions: u64) -> IncidentSnapshot {
        let mut counters = BTreeMap::new();
        counters.insert("get_hits".into(), hits.to_string());
        counters.insert("get_misses".into(), misses.to_string());
        counters.insert("evictions".into(), evictions.to_string());
        let mut gauges = BTreeMap::new();
        gauges.insert("bytes".into(), bytes.to_string());
        gauges.insert("limit_maxbytes".into(), "1000".into());
        gauges.insert("curr_connections".into(), "10".into());
        gauges.insert("uptime".into(), "1000".into());
        IncidentSnapshot {
            schema_version: "1.0".into(),
            kind: SnapshotKind::MemcachedNode,
            captured_at_unix_ms: 1000,
            target: target.into(),
            metrics: SnapshotMetrics {
                counters,
                gauges,
                ..Default::default()
            },
            topology: None,
            rca: None,
            missing_evidence: vec![],
            limitations: vec![],
        }
    }

    fn cluster(name: &str, bytes: u64, hits: u64, misses: u64, evictions: u64) -> ClusterInput {
        ClusterInput {
            name: name.into(),
            snapshots: vec![node("cache:11211", bytes, hits, misses, evictions)],
        }
    }

    #[test]
    fn compares_capacity_and_workload() {
        let r = compare_clusters(&[
            cluster("a", 500, 900, 100, 0),
            cluster("b", 900, 500, 500, 100),
        ])
        .unwrap();
        assert_eq!(r.clusters.len(), 2);
        assert_eq!(r.comparisons.len(), 1);
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "memory_utilization_difference"));
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "eviction_pressure_difference"));
    }

    #[test]
    fn reports_backend_coverage() {
        let mut router = node("router:5000", 0, 0, 0, 0);
        router.kind = SnapshotKind::Mcrouter;
        router.topology = Some(TopologySnapshot {
            pools: vec![],
            destinations: vec![
                DestinationSnapshot {
                    id: "a".into(),
                    reachable: Some(true),
                },
                DestinationSnapshot {
                    id: "b".into(),
                    reachable: Some(false),
                },
            ],
            coverage: None,
        });
        let r = compare_clusters(&[
            ClusterInput {
                name: "a".into(),
                snapshots: vec![router],
            },
            ClusterInput {
                name: "b".into(),
                snapshots: vec![node("cache:11211", 100, 1, 1, 0)],
            },
        ])
        .unwrap();
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "partial_cluster_coverage"));
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "backend_availability_difference"));
    }

    #[test]
    fn rejects_single_cluster() {
        assert!(compare_clusters(&[cluster("a", 1, 1, 1, 0)]).is_err());
    }
}
