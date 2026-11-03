//! Deterministic anomaly detection over a user-supplied snapshot history.
//!
//! No collection, persistence or upstream access happens here. The analysis uses simple robust
//! comparisons (endpoint changes, per-interval counter deltas and medians) and suppresses rates
//! when timestamps, resets or missing evidence make them unreliable.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Serialize;

use crate::rca::{Confidence, Evidence, EvidenceKind};
use crate::snapshot::{IncidentSnapshot, SnapshotKind};
use crate::Severity;

pub const HISTORY_SCHEMA_VERSION: &str = "1.0";
pub const MAX_HISTORY_SNAPSHOTS: usize = 64;
pub const MIN_TREND_SNAPSHOTS: usize = 3;
pub const MAX_HISTORY_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HISTORY_SPAN: Duration = Duration::from_secs(31 * 24 * 60 * 60);
pub const MAX_HISTORY_ANOMALIES: usize = 32;
const MIN_RATE_INTERVAL_MS: u64 = 5_000;
const MIN_GETS_FOR_RATIO: u64 = 1_000;
const MAX_TEXT_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallAssessment {
    Healthy,
    Watch,
    Anomalous,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AnalysisWindow {
    pub kind: SnapshotKind,
    pub target: String,
    pub snapshots: usize,
    pub start_unix_ms: u64,
    pub end_unix_ms: u64,
    pub duration_seconds: Option<f64>,
    pub valid_intervals: usize,
    pub irregular_intervals: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryAnomaly {
    pub id: String,
    pub metric: String,
    pub kind: EvidenceKind,
    pub direction: String,
    pub magnitude: Option<String>,
    pub what_changed: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub uncertainty: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryReport {
    pub schema_version: String,
    pub analysis: String,
    pub analysis_window: AnalysisWindow,
    pub overall_assessment: OverallAssessment,
    pub anomalies: Vec<HistoryAnomaly>,
    pub supporting_evidence: Vec<Evidence>,
    pub confidence: Confidence,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

fn metric(snapshot: &IncidentSnapshot, key: &str) -> Option<u64> {
    snapshot.metrics.counters.get(key)?.parse().ok()
}

fn gauge(snapshot: &IncidentSnapshot, key: &str) -> Option<u64> {
    snapshot.metrics.gauges.get(key)?.parse().ok()
}

fn setting(snapshot: &IncidentSnapshot, key: &str) -> Option<u64> {
    snapshot.metrics.settings.get(key)?.parse().ok()
}

fn hit_ratio(snapshot: &IncidentSnapshot) -> Option<(f64, u64)> {
    let hits = metric(snapshot, "get_hits")?;
    let misses = metric(snapshot, "get_misses")?;
    let total = hits.saturating_add(misses);
    (total > 0).then(|| (hits as f64 / total as f64, total))
}

fn memory_pct(snapshot: &IncidentSnapshot) -> Option<f64> {
    let used = gauge(snapshot, "bytes")?;
    let limit = gauge(snapshot, "limit_maxbytes")?;
    (limit > 0).then(|| used as f64 / limit as f64 * 100.0)
}

fn connection_pct(snapshot: &IncidentSnapshot) -> Option<f64> {
    let cur = gauge(snapshot, "curr_connections")?;
    let max = setting(snapshot, "maxconns")?;
    (max > 0).then(|| cur as f64 / max as f64 * 100.0)
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

fn ev(
    metric_name: &str,
    kind: EvidenceKind,
    value: impl ToString,
    interpretation: &str,
) -> Evidence {
    Evidence::new(
        metric_name,
        kind,
        Some(value.to_string()),
        None,
        clip(interpretation, MAX_TEXT_BYTES),
    )
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mid = sorted.len() / 2;
    Some(if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    })
}

#[allow(clippy::too_many_arguments)]
fn anomaly(
    id: &str,
    metric: &str,
    kind: EvidenceKind,
    direction: &str,
    magnitude: Option<String>,
    severity: Severity,
    confidence: Confidence,
    what_changed: String,
) -> HistoryAnomaly {
    HistoryAnomaly {
        id: id.to_owned(),
        metric: metric.to_owned(),
        kind,
        direction: direction.to_owned(),
        magnitude: magnitude.map(|m| clip(&m, 128)),
        what_changed: clip(&what_changed, MAX_TEXT_BYTES),
        severity,
        confidence,
        evidence: Vec::new(),
        uncertainty: Vec::new(),
    }
}

fn push_unique(anomalies: &mut Vec<HistoryAnomaly>, candidate: HistoryAnomaly) {
    if anomalies.len() >= MAX_HISTORY_ANOMALIES {
        return;
    }
    if !anomalies
        .iter()
        .any(|a| a.id == candidate.id && a.metric == candidate.metric)
    {
        anomalies.push(candidate);
    }
}

pub fn analyze_history(snapshots: &[IncidentSnapshot]) -> Result<HistoryReport, String> {
    if snapshots.is_empty() {
        return Err("snapshot history is empty".to_owned());
    }
    if snapshots.len() > MAX_HISTORY_SNAPSHOTS {
        return Err(format!(
            "snapshot history has {} entries; the limit is {MAX_HISTORY_SNAPSHOTS}",
            snapshots.len()
        ));
    }
    let kind = snapshots[0].kind;
    let target = snapshots[0].target.clone();
    for snapshot in snapshots {
        snapshot.validate()?;
        if snapshot.kind != kind {
            return Err("snapshot history mixes different snapshot kinds".to_owned());
        }
        if snapshot.target != target {
            return Err("snapshot history mixes different targets".to_owned());
        }
    }

    let input_monotonic = snapshots
        .windows(2)
        .all(|pair| pair[0].captured_at_unix_ms <= pair[1].captured_at_unix_ms);
    let mut ordered: Vec<&IncidentSnapshot> = snapshots.iter().collect();
    ordered.sort_by_key(|s| s.captured_at_unix_ms);
    let start = ordered[0].captured_at_unix_ms;
    let end = ordered[ordered.len() - 1].captured_at_unix_ms;
    if end > start {
        let span_ms = end - start;
        if span_ms > MAX_HISTORY_SPAN.as_millis() as u64 {
            return Err(format!(
                "snapshot history spans {span_ms} ms; the limit is {} ms",
                MAX_HISTORY_SPAN.as_millis()
            ));
        }
    }

    let mut intervals = Vec::new();
    let mut valid_intervals = 0usize;
    let mut irregular = !input_monotonic;
    for pair in ordered.windows(2) {
        let before = pair[0].captured_at_unix_ms;
        let after = pair[1].captured_at_unix_ms;
        if before == 0 || after == 0 || after <= before {
            irregular = true;
            intervals.push(0);
            continue;
        }
        let dt = after - before;
        if dt < MIN_RATE_INTERVAL_MS {
            irregular = true;
        }
        intervals.push(dt);
        valid_intervals += 1;
    }
    let duration_seconds = (end > start).then(|| (end - start) as f64 / 1000.0);
    let window = AnalysisWindow {
        kind,
        target: clip(&target, 256),
        snapshots: ordered.len(),
        start_unix_ms: start,
        end_unix_ms: end,
        duration_seconds,
        valid_intervals,
        irregular_intervals: irregular,
    };

    let mut missing: BTreeSet<String> = BTreeSet::new();
    for snapshot in &ordered {
        missing.extend(snapshot.missing_evidence.iter().cloned());
    }
    let expected = [
        ("counter", "get_hits"),
        ("counter", "get_misses"),
        ("counter", "evictions"),
        ("gauge", "bytes"),
        ("gauge", "limit_maxbytes"),
        ("gauge", "curr_items"),
        ("gauge", "curr_connections"),
        ("gauge", "uptime"),
    ];
    for (kind_name, key) in expected {
        if ordered.iter().any(|s| {
            if kind_name == "counter" {
                metric(s, key).is_none()
            } else {
                gauge(s, key).is_none()
            }
        }) {
            missing.insert(key.to_owned());
        }
    }
    if ordered.iter().any(|s| setting(s, "maxconns").is_none()) {
        missing.insert("settings.maxconns".to_owned());
    }
    if kind == SnapshotKind::Mcrouter && ordered.iter().any(|s| s.topology.is_none()) {
        missing.insert("topology".to_owned());
    }

    let mut anomalies = Vec::new();
    let mut supporting = Vec::new();
    let core_complete = ["get_hits", "get_misses", "evictions"].iter().all(|key| {
        metric(ordered[0], key).is_some() || metric(ordered[ordered.len() - 1], key).is_some()
    }) && (gauge(ordered[0], "uptime").is_some()
        || gauge(ordered[ordered.len() - 1], "uptime").is_some());
    if ordered.len() < MIN_TREND_SNAPSHOTS {
        let mut a = anomaly(
            "insufficient_observations",
            "snapshots",
            EvidenceKind::Coverage,
            "insufficient",
            Some(format!("{}/{}", ordered.len(), MIN_TREND_SNAPSHOTS)),
            Severity::Info,
            Confidence::Insufficient,
            "Fewer than the minimum observations are available for a trend judgment.".to_owned(),
        );
        a.uncertainty.push(
            "A single or two-snapshot history can show a change but cannot establish a trend."
                .to_owned(),
        );
        anomalies.push(a);
        return Ok(finish_report(
            window,
            OverallAssessment::InsufficientEvidence,
            anomalies,
            supporting,
            Confidence::Insufficient,
            missing,
            vec![
                "At least three snapshots are required for trend analysis.".to_owned(),
                "No collection is performed by this tool.".to_owned(),
            ],
        ));
    }

    let first = ordered[0];
    let last = ordered[ordered.len() - 1];

    // Counter resets and uptime resets are explicit and suppress rate interpretation.
    let mut reset_metrics = BTreeSet::new();
    for pair in ordered.windows(2) {
        for key in ["get_hits", "get_misses", "evictions", "total_items"] {
            if let (Some(before), Some(after)) = (metric(pair[0], key), metric(pair[1], key)) {
                if after < before {
                    reset_metrics.insert(key.to_owned());
                }
            }
        }
    }
    if let (Some(before), Some(after)) = (gauge(first, "uptime"), gauge(last, "uptime")) {
        if after < before {
            let mut a = anomaly(
                "node_restart",
                "uptime",
                EvidenceKind::Gauge,
                "reset",
                Some(format!("{before} -> {after} s")),
                Severity::Warning,
                Confidence::High,
                "Uptime decreased between observations, indicating a restart or a different instance."
                    .to_owned(),
            );
            a.evidence.push(ev(
                "uptime",
                EvidenceKind::Gauge,
                format!("{before} -> {after}"),
                "Seconds since start at the first and last observations.",
            ));
            a.uncertainty.push(
                "A restart means cumulative counters are not a continuous series; rates are suppressed."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
    }
    if !reset_metrics.is_empty() {
        let mut a = anomaly(
            "counter_reset",
            "counters",
            EvidenceKind::Counter,
            "reset",
            None,
            Severity::Warning,
            Confidence::High,
            format!(
                "One or more cumulative counters decreased: {}.",
                reset_metrics.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        );
        for key in &reset_metrics {
            if let (Some(before), Some(after)) = (metric(first, key), metric(last, key)) {
                a.evidence.push(ev(
                    key,
                    EvidenceKind::Counter,
                    format!("{before} -> {after}"),
                    "First and last cumulative values; a decrease indicates reset or instance change.",
                ));
            }
        }
        a.uncertainty.push(
            "The exact reset point cannot be known without per-observation continuity; rates for affected counters are omitted."
                .to_owned(),
        );
        push_unique(&mut anomalies, a);
    }

    // Hit-ratio deterioration.
    let ratio_reset = reset_metrics.contains("get_hits") || reset_metrics.contains("get_misses");
    let ratios: Vec<(f64, u64)> = ordered.iter().filter_map(|s| hit_ratio(s)).collect();
    if ratios.len() >= 2 && !ratio_reset {
        let (first_ratio, first_gets) = ratios[0];
        let (last_ratio, last_gets) = ratios[ratios.len() - 1];
        let drop = first_ratio - last_ratio;
        if first_gets >= MIN_GETS_FOR_RATIO && last_gets >= MIN_GETS_FOR_RATIO && drop >= 0.05 {
            let severity = if last_ratio < 0.5 {
                Severity::Critical
            } else if last_ratio < 0.8 {
                Severity::Warning
            } else {
                Severity::Info
            };
            let mut a = anomaly(
                "hit_ratio_deterioration",
                "hit_ratio",
                EvidenceKind::Derived,
                "decrease",
                Some(format!("{drop:+.3} ({first_ratio:.3} -> {last_ratio:.3})")),
                severity,
                if ratios.len() >= 3 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                "The derived hit ratio fell between the first and last observations.".to_owned(),
            );
            a.evidence.push(ev(
                "hit_ratio",
                EvidenceKind::Derived,
                format!("{first_ratio:.3} -> {last_ratio:.3}"),
                "Derived from cumulative get_hits / (get_hits + get_misses) at each endpoint.",
            ));
            a.uncertainty.push(
                "Workload changes, TTL and evictions can all change the ratio; this is not proof of capacity pressure."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
        if ratios.iter().all(|(r, _)| *r < 0.8) && ratios.len() >= 3 {
            let mut a = anomaly(
                "persistent_low_hit_ratio",
                "hit_ratio",
                EvidenceKind::Derived,
                "persistent",
                None,
                Severity::Warning,
                Confidence::Medium,
                "The hit ratio was below 80% in every observed snapshot.".to_owned(),
            );
            a.evidence.push(ev(
                "snapshots_below_80_pct",
                EvidenceKind::Derived,
                ratios.len(),
                "Number of observations with a hit ratio below 0.8.",
            ));
            a.uncertainty.push(
                "A persistent workload/ TTL pattern can be intentional; compare with application intent."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
    }
    if let Some((ratio, gets)) = hit_ratio(last) {
        supporting.push(ev(
            "hit_ratio_latest",
            EvidenceKind::Derived,
            format!("{ratio:.3}"),
            "Latest cumulative hit ratio; not a trend by itself.",
        ));
        if gets < MIN_GETS_FOR_RATIO {
            missing.insert("enough_get_traffic_for_hit_ratio".to_owned());
        }
    }

    // Eviction rate increase from valid consecutive deltas.
    let mut eviction_rates = Vec::new();
    for (index, pair) in ordered.windows(2).enumerate() {
        let dt = intervals[index];
        if dt < MIN_RATE_INTERVAL_MS {
            continue;
        }
        if let (Some(before), Some(after)) =
            (metric(pair[0], "evictions"), metric(pair[1], "evictions"))
        {
            if after >= before {
                eviction_rates.push((after - before) as f64 / (dt as f64 / 1000.0));
            }
        }
    }
    if let Some(latest_rate) = eviction_rates.last().copied() {
        supporting.push(ev(
            "eviction_rate_latest",
            EvidenceKind::Derived,
            format!("{latest_rate:.6}"),
            "Evictions per second over the latest valid interval; cumulative counter delta, not a historical model.",
        ));
        let baseline =
            median(&eviction_rates[..eviction_rates.len().saturating_sub(1)]).unwrap_or(0.0);
        if latest_rate >= 0.1 && latest_rate > (baseline * 1.5).max(baseline + 0.05) {
            let severity = if latest_rate >= 1.0 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let mut a = anomaly(
                "eviction_rate_increase",
                "evictions",
                EvidenceKind::Derived,
                "increase",
                Some(format!("{latest_rate:.3}/s vs baseline {baseline:.3}/s")),
                severity,
                if eviction_rates.len() >= 3 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                },
                "The latest valid eviction rate is materially above the prior median.".to_owned(),
            );
            a.evidence.push(ev(
                "eviction_rate_latest",
                EvidenceKind::Derived,
                format!("{latest_rate:.6}"),
                "Evictions per second over the latest valid interval.",
            ));
            a.evidence.push(ev(
                "eviction_rate_baseline",
                EvidenceKind::Derived,
                format!("{baseline:.6}"),
                "Median of earlier valid interval rates.",
            ));
            a.uncertainty.push(
                "One interval can be a burst; a capacity conclusion requires a longer history and slab/workload context."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
    } else if metric(last, "evictions").unwrap_or(0) > 0 {
        missing.insert("valid_eviction_rate_intervals".to_owned());
    }

    // Memory pressure change.
    let memory: Vec<f64> = ordered.iter().filter_map(|s| memory_pct(s)).collect();
    if let (Some(first_pct), Some(last_pct)) = (memory.first().copied(), memory.last().copied()) {
        supporting.push(ev(
            "memory_utilization_latest",
            EvidenceKind::Derived,
            format!("{last_pct:.1}"),
            "Latest derived memory utilization; a gauge, not a forecast.",
        ));
        let delta = last_pct - first_pct;
        if last_pct >= 90.0 && (first_pct < 90.0 || delta >= 5.0) {
            let severity = if last_pct >= 95.0 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let mut a = anomaly(
                "memory_pressure_increase",
                "memory_utilization_pct",
                EvidenceKind::Derived,
                "increase",
                Some(format!("{delta:+.1} pp ({first_pct:.1} -> {last_pct:.1})")),
                severity,
                Confidence::High,
                "Memory utilization rose into or remained in the high-pressure range.".to_owned(),
            );
            a.evidence.push(ev(
                "memory_utilization_pct",
                EvidenceKind::Derived,
                format!("{first_pct:.1} -> {last_pct:.1}"),
                "First and last derived memory utilization.",
            ));
            a.uncertainty.push(
                "A full cache can be normal; eviction and workload evidence are needed to infer harm."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
    }

    // Connection saturation trend.
    let connections: Vec<f64> = ordered.iter().filter_map(|s| connection_pct(s)).collect();
    if let (Some(first_pct), Some(last_pct)) =
        (connections.first().copied(), connections.last().copied())
    {
        supporting.push(ev(
            "connection_utilization_latest",
            EvidenceKind::Derived,
            format!("{last_pct:.1}"),
            "Latest derived connection utilization; a gauge, not a forecast.",
        ));
        let delta = last_pct - first_pct;
        if last_pct >= 80.0 && (first_pct < 80.0 || delta >= 10.0) {
            let mut a = anomaly(
                "connection_saturation",
                "connection_utilization_pct",
                EvidenceKind::Derived,
                "increase",
                Some(format!("{delta:+.1} pp ({first_pct:.1} -> {last_pct:.1})")),
                Severity::Warning,
                Confidence::High,
                "Connection utilization rose into or remained in the saturation range.".to_owned(),
            );
            a.evidence.push(ev(
                "connection_utilization_pct",
                EvidenceKind::Derived,
                format!("{first_pct:.1} -> {last_pct:.1}"),
                "First and last derived connection utilization.",
            ));
            a.uncertainty.push(
                "A brief traffic peak can produce the same shape; inspect client pooling and maxconns."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
    }

    // Item-count change versus the median of earlier observations.
    let items: Vec<u64> = ordered
        .iter()
        .filter_map(|s| gauge(s, "curr_items"))
        .collect();
    if items.len() >= 3 {
        if let Some(baseline) = median(
            &items[..items.len() - 1]
                .iter()
                .map(|v| *v as f64)
                .collect::<Vec<_>>(),
        ) {
            let latest = items[items.len() - 1] as f64;
            if baseline >= 100.0 {
                let ratio = (latest - baseline) / baseline;
                if ratio.abs() >= 0.25 {
                    let mut a = anomaly(
                        "item_count_change",
                        "curr_items",
                        EvidenceKind::Gauge,
                        if ratio > 0.0 { "increase" } else { "decrease" },
                        Some(format!(
                            "{:+.1}% vs prior median {baseline:.0}",
                            ratio * 100.0
                        )),
                        Severity::Info,
                        Confidence::Medium,
                        "The latest item count differs materially from the prior median."
                            .to_owned(),
                    );
                    a.evidence.push(ev(
                        "curr_items_latest",
                        EvidenceKind::Gauge,
                        format!("{latest:.0}"),
                        "Latest curr_items gauge.",
                    ));
                    a.uncertainty.push(
                        "Item count naturally varies with workload/expiry; this is not by itself a fault."
                            .to_owned(),
                    );
                    push_unique(&mut anomalies, a);
                }
            }
        }
    }

    // Backend availability from mcrouter topology.
    if kind == SnapshotKind::Mcrouter {
        let reachable: Vec<usize> = ordered
            .iter()
            .filter_map(|s| s.topology.as_ref())
            .map(|t| {
                t.destinations
                    .iter()
                    .filter(|d| d.reachable == Some(true))
                    .count()
            })
            .collect();
        if let (Some(first_reachable), Some(last_reachable)) =
            (reachable.first().copied(), reachable.last().copied())
        {
            if last_reachable < first_reachable {
                let mut a = anomaly(
                    "backend_availability_drop",
                    "reachable_destinations",
                    EvidenceKind::Coverage,
                    "decrease",
                    Some(format!("{first_reachable} -> {last_reachable}")),
                    Severity::Warning,
                    Confidence::Medium,
                    "The number of observed reachable destinations decreased.".to_owned(),
                );
                a.evidence.push(ev(
                    "reachable_destinations",
                    EvidenceKind::Coverage,
                    format!("{first_reachable} -> {last_reachable}"),
                    "First and last counts of destinations with explicit reachability.",
                ));
                a.uncertainty.push(
                    "Coverage may be partial; an absent destination is not necessarily down."
                        .to_owned(),
                );
                push_unique(&mut anomalies, a);
            }
        }
        if ordered.iter().any(|s| {
            s.topology
                .as_ref()
                .and_then(|t| t.coverage.as_ref())
                .is_some_and(|c| !c.complete)
        }) {
            missing.insert("complete_topology_coverage".to_owned());
        }
    }

    // Persistent RCA findings across observations.
    let mut rca_counts: BTreeMap<String, (usize, Severity)> = BTreeMap::new();
    for snapshot in &ordered {
        if let Some(rca) = &snapshot.rca {
            for finding in &rca.findings {
                let entry = rca_counts
                    .entry(clip(&finding.id, 128))
                    .or_insert((0, finding.severity));
                entry.0 += 1;
                entry.1 = entry.1.max(finding.severity);
            }
        }
    }
    for (id, (count, severity)) in rca_counts {
        if count >= 2 && count * 2 >= ordered.len() {
            let mut a = anomaly(
                "persistent_rca_finding",
                &id,
                EvidenceKind::DataQuality,
                "persistent",
                Some(format!("{count}/{} snapshots", ordered.len())),
                severity,
                if count == ordered.len() {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                format!("The existing RCA finding '{id}' appears repeatedly across the history."),
            );
            a.evidence.push(ev(
                "finding_occurrences",
                EvidenceKind::Derived,
                count,
                "Number of snapshots where the existing RCA finding was present.",
            ));
            a.uncertainty.push(
                "Repetition strengthens the hypothesis but does not prove the cause; review the RCA evidence."
                    .to_owned(),
            );
            push_unique(&mut anomalies, a);
        }
    }

    // Overall confidence and assessment.
    let confidence = if !core_complete {
        Confidence::Low
    } else if irregular || !missing.is_empty() {
        Confidence::Medium
    } else if ordered.len() >= 5 {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let assessment = if confidence == Confidence::Insufficient {
        OverallAssessment::InsufficientEvidence
    } else if anomalies.iter().any(|a| a.severity >= Severity::Warning) {
        OverallAssessment::Anomalous
    } else if anomalies.is_empty() && missing.is_empty() && !irregular {
        OverallAssessment::Healthy
    } else {
        OverallAssessment::Watch
    };

    if let Some((ratio, _)) = hit_ratio(first) {
        supporting.push(ev(
            "hit_ratio_first",
            EvidenceKind::Derived,
            format!("{ratio:.3}"),
            "Earliest cumulative hit ratio.",
        ));
    }
    if let (Some(first_pct), Some(last_pct)) = (memory_pct(first), memory_pct(last)) {
        supporting.push(ev(
            "memory_utilization_span",
            EvidenceKind::Derived,
            format!("{first_pct:.1} -> {last_pct:.1}"),
            "First and last memory utilization; one gauge per observation.",
        ));
    }
    if let (Some(first_count), Some(last_count)) =
        (gauge(first, "curr_items"), gauge(last, "curr_items"))
    {
        supporting.push(ev(
            "item_count_span",
            EvidenceKind::Gauge,
            format!("{first_count} -> {last_count}"),
            "First and last item counts.",
        ));
    }

    let mut limitations = vec![
        "Analysis uses only the supplied snapshots; it does not collect data or persist history."
            .to_owned(),
        "Anomaly detection uses simple endpoint changes, per-interval counter deltas and medians, not machine learning."
            .to_owned(),
        "A trend is suppressed when timestamps are missing/non-increasing or fewer than three observations are available."
            .to_owned(),
        "Correlation in a snapshot history does not prove causation or justify automatic remediation."
            .to_owned(),
    ];
    if irregular {
        limitations.push(
            "Sampling intervals are irregular or below 5 seconds in at least one segment; rates use only valid intervals."
                .to_owned(),
        );
    }
    if !reset_metrics.is_empty() {
        limitations.push(
            "Cumulative counters reset during the history; affected rates are not treated as a continuous series."
                .to_owned(),
        );
    }
    if !missing.is_empty() {
        limitations.push(
            "Some metrics or topology coverage are missing; confidence and anomaly coverage are reduced."
                .to_owned(),
        );
    }
    limitations.sort();
    limitations.dedup();

    Ok(finish_report(
        window,
        assessment,
        anomalies,
        supporting,
        confidence,
        missing,
        limitations,
    ))
}

fn finish_report(
    window: AnalysisWindow,
    assessment: OverallAssessment,
    mut anomalies: Vec<HistoryAnomaly>,
    supporting: Vec<Evidence>,
    confidence: Confidence,
    missing: BTreeSet<String>,
    limitations: Vec<String>,
) -> HistoryReport {
    anomalies.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.metric.cmp(&b.metric))
    });
    anomalies.truncate(MAX_HISTORY_ANOMALIES);
    HistoryReport {
        schema_version: HISTORY_SCHEMA_VERSION.to_owned(),
        analysis: "snapshot_history".to_owned(),
        analysis_window: window,
        overall_assessment: assessment,
        anomalies,
        supporting_evidence: supporting,
        confidence,
        missing_evidence: missing.into_iter().collect(),
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rca::{Coverage, RcaReport};
    use crate::snapshot::{DestinationSnapshot, IncidentSnapshot, SnapshotKind, TopologySnapshot};
    use crate::Stats;

    fn st(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn snap(
        at: u64,
        hits: &str,
        misses: &str,
        bytes: &str,
        evictions: &str,
        uptime: &str,
    ) -> IncidentSnapshot {
        let stats = st(&[
            ("get_hits", hits),
            ("get_misses", misses),
            ("bytes", bytes),
            ("limit_maxbytes", "100"),
            ("curr_items", "1000"),
            ("total_items", "10000"),
            ("curr_connections", "10"),
            ("evictions", evictions),
            ("uptime", uptime),
        ]);
        let items = st(&[("items:1:number", "1000"), ("items:1:evicted", "0")]);
        let settings = st(&[("maxconns", "100")]);
        let mut s = IncidentSnapshot::node(
            "cache:11211",
            at,
            &stats,
            &items,
            &settings,
            RcaReport::new("memcached_node", "cache:11211"),
        );
        s.kind = SnapshotKind::MemcachedNode;
        s
    }

    #[test]
    fn healthy_stable_history() {
        let history = vec![
            snap(1_000_000, "9000", "1000", "50", "0", "10000"),
            snap(1_060_000, "9000", "1000", "50", "0", "10060"),
            snap(1_120_000, "9000", "1000", "50", "0", "10120"),
            snap(1_180_000, "9000", "1000", "50", "0", "10180"),
            snap(1_240_000, "9000", "1000", "50", "0", "10240"),
        ];
        let r = analyze_history(&history).unwrap();
        assert_eq!(r.overall_assessment, OverallAssessment::Healthy);
        assert!(r.anomalies.is_empty());
        assert_eq!(
            r.confidence,
            Confidence::High,
            "missing evidence: {:?}",
            r.missing_evidence
        );
    }

    #[test]
    fn rising_eviction_rate() {
        let history = vec![
            snap(1_000_000, "9000", "1000", "95", "0", "10000"),
            snap(1_060_000, "9000", "1000", "95", "60", "10060"),
            snap(1_120_000, "9000", "1000", "95", "180", "10120"),
        ];
        let r = analyze_history(&history).unwrap();
        assert!(r.anomalies.iter().any(|a| a.id == "eviction_rate_increase"));
        assert_eq!(r.overall_assessment, OverallAssessment::Anomalous);
    }

    #[test]
    fn falling_hit_ratio() {
        let history = vec![
            snap(1_000_000, "9000", "1000", "50", "0", "10000"),
            snap(1_060_000, "9500", "3000", "50", "0", "10060"),
            snap(1_120_000, "9800", "6000", "50", "0", "10120"),
        ];
        let r = analyze_history(&history).unwrap();
        assert!(r
            .anomalies
            .iter()
            .any(|a| a.id == "hit_ratio_deterioration"));
    }

    #[test]
    fn memory_pressure_and_connection_saturation() {
        let mut history = Vec::new();
        for (i, (bytes, conn)) in [("50", "10"), ("80", "60"), ("95", "90")]
            .iter()
            .enumerate()
        {
            let mut s = snap(
                1_000_000 + i as u64 * 60_000,
                "9000",
                "1000",
                bytes,
                "0",
                &(10000 + i as u64 * 60).to_string(),
            );
            s.metrics
                .gauges
                .insert("curr_connections".into(), (*conn).into());
            history.push(s);
        }
        let r = analyze_history(&history).unwrap();
        assert!(r
            .anomalies
            .iter()
            .any(|a| a.id == "memory_pressure_increase"));
        assert!(r.anomalies.iter().any(|a| a.id == "connection_saturation"));
    }

    #[test]
    fn counter_reset_and_node_restart() {
        let history = vec![
            snap(1_000_000, "9000", "1000", "50", "100", "10000"),
            snap(1_060_000, "100", "20", "50", "5", "10"),
            snap(1_120_000, "200", "40", "50", "10", "70"),
        ];
        let r = analyze_history(&history).unwrap();
        assert!(r.anomalies.iter().any(|a| a.id == "counter_reset"));
        assert!(r.anomalies.iter().any(|a| a.id == "node_restart"));
    }

    #[test]
    fn insufficient_observations_and_bad_timestamps() {
        let one = vec![snap(1_000_000, "9000", "1000", "50", "0", "10000")];
        let r = analyze_history(&one).unwrap();
        assert_eq!(
            r.overall_assessment,
            OverallAssessment::InsufficientEvidence
        );
        assert!(r
            .anomalies
            .iter()
            .any(|a| a.id == "insufficient_observations"));
        let skewed = vec![
            snap(1_000_000, "9000", "1000", "50", "0", "10000"),
            snap(900_000, "9000", "1000", "50", "0", "10000"),
            snap(800_000, "9000", "1000", "50", "0", "10000"),
        ];
        let r = analyze_history(&skewed).unwrap();
        assert!(r.analysis_window.irregular_intervals);
        assert!(r.limitations.iter().any(|l| l.contains("irregular")));
    }

    #[test]
    fn partial_mcrouter_topology() {
        let mut first = snap(1_000_000, "9000", "1000", "50", "0", "10000");
        first.kind = SnapshotKind::Mcrouter;
        first.topology = Some(TopologySnapshot {
            pools: vec![],
            destinations: vec![
                DestinationSnapshot {
                    id: "a".into(),
                    reachable: Some(true),
                },
                DestinationSnapshot {
                    id: "b".into(),
                    reachable: Some(true),
                },
            ],
            coverage: Some(Coverage {
                configured_destinations: 2,
                probed_destinations: 2,
                reachable_destinations: 2,
                unreachable_destinations: 0,
                unmapped_destinations: 0,
                denied_destinations: 0,
                truncated_destinations: 0,
                complete: true,
            }),
        });
        let mut last = snap(1_120_000, "9000", "1000", "50", "0", "10120");
        last.kind = SnapshotKind::Mcrouter;
        last.topology = Some(TopologySnapshot {
            pools: vec![],
            destinations: vec![DestinationSnapshot {
                id: "a".into(),
                reachable: Some(true),
            }],
            coverage: Some(Coverage {
                configured_destinations: 2,
                probed_destinations: 1,
                reachable_destinations: 1,
                unreachable_destinations: 0,
                unmapped_destinations: 1,
                denied_destinations: 0,
                truncated_destinations: 0,
                complete: false,
            }),
        });
        let mut middle = snap(1_060_000, "9000", "1000", "50", "0", "10060");
        middle.kind = SnapshotKind::Mcrouter;
        let history = vec![first, middle, last];
        let r = analyze_history(&history).unwrap();
        assert!(r
            .anomalies
            .iter()
            .any(|a| a.id == "backend_availability_drop"));
        assert!(r
            .missing_evidence
            .iter()
            .any(|m| m == "complete_topology_coverage"));
    }

    #[test]
    fn missing_metrics_and_hostile_input_are_bounded() {
        let mut s = snap(1_000_000, "9000", "1000", "50", "0", "10000");
        s.metrics.counters.clear();
        s.metrics.gauges.clear();
        let history = vec![s.clone(), s.clone(), s];
        let r = analyze_history(&history).unwrap();
        assert_eq!(r.overall_assessment, OverallAssessment::Watch);
        assert!(!r.missing_evidence.is_empty());
        let encoded = serde_json::to_string(&r).unwrap();
        assert!(encoded.len() < 256 * 1024);
    }

    #[test]
    fn deterministic_output() {
        let history = vec![
            snap(1_000_000, "9000", "1000", "50", "0", "10000"),
            snap(1_060_000, "9000", "1000", "95", "60", "10060"),
            snap(1_120_000, "9000", "1000", "95", "180", "10120"),
        ];
        let a = analyze_history(&history).unwrap();
        let b = analyze_history(&history).unwrap();
        assert_eq!(a, b);
    }
}
