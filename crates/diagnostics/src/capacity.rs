//! Deterministic, read-only cache capacity and workload analysis.
//!
//! The report is deliberately conservative: cumulative counters are not treated as trends, no
//! time-to-exhaustion is invented, and allocator fragmentation is not inferred from aggregate
//! counters. Optional incident snapshots provide observed deltas only.

use serde::Serialize;

use crate::snapshot::IncidentSnapshot;
use crate::{Severity, Stats};

pub const CAPACITY_SCHEMA_VERSION: &str = "1.0";
pub const MAX_CAPACITY_FINDINGS: usize = 16;
pub const MAX_CAPACITY_RECOMMENDATIONS: usize = 12;
const MIN_GETS_FOR_RATIO: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityStatus {
    Healthy,
    Watch,
    Actionable,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityFacts {
    pub used_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
    pub utilization_pct: Option<f64>,
    pub headroom_bytes: Option<u64>,
    pub headroom_pct: Option<f64>,
    pub curr_items: Option<u64>,
    pub average_item_bytes: Option<f64>,
    pub total_items: Option<u64>,
    pub uptime_seconds: Option<u64>,
    pub get_hits: Option<u64>,
    pub get_misses: Option<u64>,
    pub gets: Option<u64>,
    pub hit_ratio: Option<f64>,
    pub evictions: Option<u64>,
    pub eviction_rate_per_second: Option<f64>,
    pub expired_unfetched: Option<u64>,
    pub curr_connections: Option<u64>,
    pub max_connections: Option<u64>,
    pub connection_utilization_pct: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityHistory {
    pub snapshots: usize,
    pub span_seconds: Option<f64>,
    pub memory_utilization_change_pct: Option<f64>,
    pub eviction_rate_change_per_second: Option<f64>,
    pub hit_ratio_change_pct: Option<f64>,
    pub item_count_change: Option<i64>,
    pub confidence: &'static str,
    pub basis: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityFinding {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityRecommendation {
    pub code: &'static str,
    pub priority: &'static str,
    pub rationale: String,
    pub validation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub target: String,
    pub status: CapacityStatus,
    pub summary: String,
    pub facts: CapacityFacts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<CapacityHistory>,
    pub findings: Vec<CapacityFinding>,
    pub recommendations: Vec<CapacityRecommendation>,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

fn num(stats: &Stats, key: &str) -> Option<u64> {
    stats.get(key)?.parse().ok()
}

fn pct(value: u64, limit: u64) -> Option<f64> {
    (limit > 0).then(|| value as f64 * 100.0 / limit as f64)
}

fn rate(value: u64, uptime: Option<u64>) -> Option<f64> {
    uptime.filter(|u| *u > 0).map(|u| value as f64 / u as f64)
}

fn failure(
    severity: Severity,
    code: &'static str,
    confidence: &'static str,
    message: String,
) -> CapacityFinding {
    CapacityFinding {
        code,
        severity,
        confidence,
        message,
    }
}

fn recommendation(
    code: &'static str,
    priority: &'static str,
    rationale: &str,
    validation: &str,
) -> CapacityRecommendation {
    CapacityRecommendation {
        code,
        priority,
        rationale: rationale.to_owned(),
        validation: validation.to_owned(),
    }
}

fn snapshot_metric(snapshot: &IncidentSnapshot, key: &str) -> Option<u64> {
    snapshot
        .metrics
        .counters
        .get(key)
        .or_else(|| snapshot.metrics.gauges.get(key))?
        .parse()
        .ok()
}

fn snapshot_hit_ratio(snapshot: &IncidentSnapshot) -> Option<f64> {
    let hits = snapshot_metric(snapshot, "get_hits")?;
    let misses = snapshot_metric(snapshot, "get_misses")?;
    let total = hits.saturating_add(misses);
    (total > 0).then(|| hits as f64 / total as f64)
}

fn snapshot_memory_pct(snapshot: &IncidentSnapshot) -> Option<f64> {
    let used = snapshot_metric(snapshot, "bytes")?;
    let limit = snapshot
        .metrics
        .gauges
        .get("limit_maxbytes")
        .or_else(|| snapshot.metrics.settings.get("maxbytes"))?
        .parse()
        .ok()?;
    pct(used, limit)
}

fn snapshot_eviction_rate(snapshot: &IncidentSnapshot) -> Option<f64> {
    let evictions = snapshot_metric(snapshot, "evictions")?;
    let uptime = snapshot_metric(snapshot, "uptime")?;
    rate(evictions, Some(uptime))
}

fn history(snapshots: &[IncidentSnapshot], target: &str) -> Option<CapacityHistory> {
    let mut ordered: Vec<&IncidentSnapshot> = snapshots
        .iter()
        .filter(|s| s.target == target && s.captured_at_unix_ms > 0)
        .collect();
    ordered.sort_by_key(|s| s.captured_at_unix_ms);
    ordered.dedup_by_key(|s| s.captured_at_unix_ms);
    if ordered.len() < 2 {
        return None;
    }
    let first = ordered.first()?;
    let last = ordered.last()?;
    let span_seconds = (last.captured_at_unix_ms > first.captured_at_unix_ms)
        .then(|| (last.captured_at_unix_ms - first.captured_at_unix_ms) as f64 / 1000.0);
    let memory = match (snapshot_memory_pct(first), snapshot_memory_pct(last)) {
        (Some(a), Some(b)) => Some(b - a),
        _ => None,
    };
    let eviction = match (snapshot_eviction_rate(first), snapshot_eviction_rate(last)) {
        (Some(a), Some(b)) => Some(b - a),
        _ => None,
    };
    let hit_ratio = match (snapshot_hit_ratio(first), snapshot_hit_ratio(last)) {
        (Some(a), Some(b)) => Some((b - a) * 100.0),
        _ => None,
    };
    let items = match (
        snapshot_metric(first, "curr_items"),
        snapshot_metric(last, "curr_items"),
    ) {
        (Some(a), Some(b)) => Some(b as i64 - a as i64),
        _ => None,
    };
    let confidence = if span_seconds.is_some() {
        "medium"
    } else {
        "low"
    };
    Some(CapacityHistory {
        snapshots: ordered.len(),
        span_seconds,
        memory_utilization_change_pct: memory,
        eviction_rate_change_per_second: eviction,
        hit_ratio_change_pct: hit_ratio,
        item_count_change: items,
        confidence,
        basis: "first and last usable snapshots only; no regression or forecast",
    })
}

/// Analyze one live node plus optional incident snapshots. The caller is responsible for collecting
/// read-only `stats`/`settings`; this function performs no I/O.
pub fn plan_capacity(
    target: &str,
    stats: &Stats,
    settings: &Stats,
    snapshots: &[IncidentSnapshot],
    target_hit_ratio: Option<f64>,
) -> CapacityReport {
    let used = num(stats, "bytes");
    let limit = num(stats, "limit_maxbytes").or_else(|| num(settings, "maxbytes"));
    let utilization = used.zip(limit).and_then(|(u, l)| pct(u, l));
    let headroom = used.zip(limit).map(|(u, l)| l.saturating_sub(u));
    let curr_items = num(stats, "curr_items");
    let average_item = used
        .zip(curr_items)
        .and_then(|(b, i)| (i > 0).then(|| b as f64 / i as f64));
    let uptime = num(stats, "uptime");
    let hits = num(stats, "get_hits");
    let misses = num(stats, "get_misses");
    let gets = hits.zip(misses).map(|(h, m)| h.saturating_add(m));
    let hit_ratio = hits
        .zip(gets)
        .and_then(|(h, g)| (g > 0).then(|| h as f64 / g as f64));
    let evictions = num(stats, "evictions");
    let eviction_rate = evictions.and_then(|e| rate(e, uptime));
    let curr_connections = num(stats, "curr_connections");
    let max_connections = num(settings, "maxconns").or_else(|| num(stats, "maxconns"));
    let connection_pct = curr_connections
        .zip(max_connections)
        .and_then(|(c, m)| pct(c, m));

    let facts = CapacityFacts {
        used_bytes: used,
        limit_bytes: limit,
        utilization_pct: utilization,
        headroom_bytes: headroom,
        headroom_pct: utilization.map(|u| (100.0 - u).max(0.0)),
        curr_items,
        average_item_bytes: average_item,
        total_items: num(stats, "total_items"),
        uptime_seconds: uptime,
        get_hits: hits,
        get_misses: misses,
        gets,
        hit_ratio,
        evictions,
        eviction_rate_per_second: eviction_rate,
        expired_unfetched: num(stats, "expired_unfetched"),
        curr_connections,
        max_connections,
        connection_utilization_pct: connection_pct,
    };

    let mut findings = Vec::new();
    let mut missing = Vec::new();
    if used.is_none() || limit.is_none() {
        missing.push("bytes and/or limit_maxbytes".to_owned());
    }
    if uptime.is_none() {
        missing.push("uptime".to_owned());
    }
    if gets.is_none() {
        missing.push("get_hits/get_misses".to_owned());
    }
    if max_connections.is_none() {
        missing.push("maxconns".to_owned());
    }

    if let Some(u) = utilization {
        if u >= 95.0 {
            findings.push(failure(
                Severity::Critical,
                "memory_pressure",
                "high",
                format!(
                    "Memory utilization is {u:.1}% ({} of {} bytes); there is little headroom.",
                    used.unwrap_or(0),
                    limit.unwrap_or(0)
                ),
            ));
        } else if u >= 80.0 {
            findings.push(failure(
                Severity::Warning,
                "memory_pressure",
                "high",
                format!("Memory utilization is {u:.1}%; plan headroom before adding workload."),
            ));
        }
    }
    if let Some(e) = evictions.filter(|e| *e > 0) {
        let severity = if eviction_rate.is_some_and(|r| r >= 1.0) {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let rate_text = eviction_rate
            .map(|r| format!(" (about {r:.3}/s average)"))
            .unwrap_or_default();
        findings.push(failure(
            severity,
            "evictions_observed",
            "high",
            format!(
                "{e} evictions have occurred since start{rate_text}; capacity is below the working set or item sizes are changing."
            ),
        ));
    }
    if let Some(c) = connection_pct {
        if c >= 80.0 {
            findings.push(failure(
                Severity::Warning,
                "connection_pressure",
                "high",
                format!("Connection utilization is {c:.1}%; review pooling and maxconns."),
            ));
        }
    }
    if let Some(ratio) = hit_ratio {
        if let Some(target_ratio) = target_hit_ratio.filter(|r| (0.0..=1.0).contains(r)) {
            if gets.is_some_and(|g| g >= MIN_GETS_FOR_RATIO) && ratio < target_ratio {
                findings.push(failure(
                    Severity::Warning,
                    "hit_ratio_below_target",
                    "high",
                    format!(
                        "Hit ratio {:.1}% is below the supplied target {:.1}%; this is a workload signal, not proof that adding RAM will fix it.",
                        ratio * 100.0,
                        target_ratio * 100.0
                    ),
                ));
            }
        }
        if gets.is_some_and(|g| g >= MIN_GETS_FOR_RATIO) && ratio < 0.80 {
            findings.push(failure(
                Severity::Warning,
                "hit_ratio_low",
                "medium",
                format!("Hit ratio is {:.1}% over {} gets; review key/TTL/workload evidence before sizing.", ratio * 100.0, gets.unwrap_or(0)),
            ));
        } else if gets.is_some_and(|g| g < MIN_GETS_FOR_RATIO) {
            findings.push(failure(
                Severity::Info,
                "hit_ratio_insufficient_data",
                "insufficient",
                format!(
                    "Only {} gets since start; the hit ratio is not yet representative.",
                    gets.unwrap_or(0)
                ),
            ));
        }
    }
    if let Some(h) = history(snapshots, target) {
        if let Some(change) = h.memory_utilization_change_pct {
            if change >= 10.0 {
                findings.push(failure(
                    Severity::Warning,
                    "memory_utilization_rising",
                    "medium",
                    format!("Memory utilization rose {change:.1} percentage points between the first and last usable snapshot; continue observing."),
                ));
            }
        }
        if let Some(change) = h.eviction_rate_change_per_second {
            if change > 0.0 {
                findings.push(failure(
                    Severity::Warning,
                    "eviction_rate_rising",
                    "medium",
                    format!("The observed eviction rate rose {change:.3}/s between snapshots; this is an observed delta, not a forecast."),
                ));
            }
        }
        if let Some(change) = h.hit_ratio_change_pct {
            if change <= -5.0 {
                findings.push(failure(
                    Severity::Warning,
                    "hit_ratio_declining",
                    "medium",
                    format!(
                        "Hit ratio fell {:.1} percentage points between snapshots.",
                        change.abs()
                    ),
                ));
            }
        }
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings.truncate(MAX_CAPACITY_FINDINGS);

    let mut recommendations = Vec::new();
    if utilization.is_some_and(|u| u >= 80.0) || evictions.is_some_and(|e| e > 0) {
        recommendations.push(recommendation(
            "measure_working_set",
            "high",
            "Collect multiple snapshots over a stable window and review item-size and slab distributions before changing memory.",
            "Compare memory, eviction and item-count deltas with the incident timeline or slab analyzer.",
        ));
    }
    if hit_ratio.is_some_and(|r| r < 0.80) {
        recommendations.push(recommendation(
            "review_workload_evidence",
            "medium",
            "A low hit ratio can come from TTLs, key churn, routing, or capacity; a single cumulative snapshot cannot distinguish them.",
            "Inspect TTL/churn counters and routing traces, then repeat after a workload change.",
        ));
    }
    if connection_pct.is_some_and(|c| c >= 80.0) {
        recommendations.push(recommendation(
            "review_connection_headroom",
            "medium",
            "Connection pressure can increase latency independently of memory capacity.",
            "Check client pooling, idle timeouts and maxconns before raising limits.",
        ));
    }
    recommendations.push(recommendation(
        "collect_more_evidence",
        "low",
        "Capacity advice is stronger with at least three timestamped snapshots and known workload context.",
        "Capture snapshots during normal and peak traffic and compare them with analyze_snapshot_history.",
    ));
    recommendations.truncate(MAX_CAPACITY_RECOMMENDATIONS);

    let status = if used.is_none() || limit.is_none() {
        CapacityStatus::InsufficientEvidence
    } else if findings.iter().any(|f| f.severity >= Severity::Warning) {
        CapacityStatus::Actionable
    } else if findings.is_empty() {
        CapacityStatus::Healthy
    } else {
        CapacityStatus::Watch
    };
    let summary = match status {
        CapacityStatus::InsufficientEvidence => {
            "Core memory counters are missing; capacity conclusions are not reliable.".to_owned()
        }
        CapacityStatus::Actionable => {
            format!(
            "{} finding(s) at warning or critical severity; treat projections as evidence-limited.",
            findings.iter().filter(|f| f.severity >= Severity::Warning).count()
        )
        }
        CapacityStatus::Watch => {
            "Only informational findings; continue collecting evidence.".to_owned()
        }
        CapacityStatus::Healthy => {
            "No memory, eviction, connection or workload finding in this snapshot.".to_owned()
        }
    };

    CapacityReport {
        schema_version: CAPACITY_SCHEMA_VERSION,
        analysis: "cache_capacity",
        target: target.to_owned(),
        status,
        summary,
        facts,
        history: history(snapshots, target),
        findings,
        recommendations,
        missing_evidence: missing,
        limitations: vec![
            "Single snapshot: cumulative counters are not a trend; no time-to-exhaustion or future traffic is predicted.".to_owned(),
            "Allocator fragmentation is not inferred from aggregate counters; use the slab analyzer for class-level evidence.".to_owned(),
            "The memory budget in the MCP server is a reservation limit, not an upstream RSS measurement.".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{IncidentSnapshot, SnapshotKind, SnapshotMetrics};
    use std::collections::BTreeMap;

    fn stats(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn snap(at: u64, bytes: u64, evictions: u64, hits: u64, misses: u64) -> IncidentSnapshot {
        let mut counters = BTreeMap::new();
        counters.insert("get_hits".into(), hits.to_string());
        counters.insert("get_misses".into(), misses.to_string());
        counters.insert("evictions".into(), evictions.to_string());
        let mut gauges = BTreeMap::new();
        gauges.insert("bytes".into(), bytes.to_string());
        gauges.insert("limit_maxbytes".into(), "1000".into());
        gauges.insert("uptime".into(), "1000".into());
        IncidentSnapshot {
            schema_version: "1.0".into(),
            kind: SnapshotKind::MemcachedNode,
            captured_at_unix_ms: at,
            target: "cache:11211".into(),
            metrics: SnapshotMetrics {
                counters,
                gauges,
                ..Default::default()
            },
            topology: None,
            rca: None,
            missing_evidence: Vec::new(),
            limitations: Vec::new(),
        }
    }

    #[test]
    fn healthy_capacity_has_no_warning() {
        let report = plan_capacity(
            "cache:11211",
            &stats(&[
                ("bytes", "500"),
                ("limit_maxbytes", "1000"),
                ("curr_items", "50"),
                ("get_hits", "900"),
                ("get_misses", "100"),
                ("evictions", "0"),
                ("uptime", "1000"),
            ]),
            &stats(&[("maxconns", "100")]),
            &[],
            None,
        );
        assert_eq!(report.status, CapacityStatus::Healthy);
        assert_eq!(report.facts.utilization_pct, Some(50.0));
        assert!(report.findings.is_empty());
    }

    #[test]
    fn pressure_and_history_are_explicit() {
        let report = plan_capacity(
            "cache:11211",
            &stats(&[
                ("bytes", "900"),
                ("limit_maxbytes", "1000"),
                ("curr_items", "10"),
                ("get_hits", "5000"),
                ("get_misses", "5000"),
                ("evictions", "100"),
                ("uptime", "1000"),
            ]),
            &stats(&[("maxconns", "10")]),
            &[snap(1000, 500, 0, 100, 900), snap(2000, 900, 100, 500, 900)],
            Some(0.9),
        );
        assert_eq!(report.status, CapacityStatus::Actionable);
        assert!(report.findings.iter().any(|f| f.code == "memory_pressure"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "evictions_observed"));
        assert!(report.history.is_some());
    }

    #[test]
    fn missing_core_counters_are_insufficient() {
        let report = plan_capacity("cache:11211", &Stats::new(), &Stats::new(), &[], None);
        assert_eq!(report.status, CapacityStatus::InsufficientEvidence);
        assert!(!report.missing_evidence.is_empty());
    }
}
