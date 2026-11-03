//! Chronological incident view built from existing snapshots, diffs and history analysis.
//!
//! This is a composition of tested analyses: it does not collect data, persist snapshots, or
//! introduce another anomaly detector.

use serde::Serialize;

use crate::history::{self, HistoryAnomaly, OverallAssessment};
use crate::snapshot::{
    compare_snapshots, DiffChange, DiffStatus, IncidentSnapshot, RcaDiff, SnapshotKind,
    SnapshotRef, TopologyDiff,
};

pub const TIMELINE_SCHEMA_VERSION: &str = "1.0";
pub const MAX_TIMELINE_INTERVALS: usize = 64;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimelineInterval {
    pub before: SnapshotRef,
    pub after: SnapshotRef,
    pub interval_seconds: Option<f64>,
    pub status: DiffStatus,
    pub changes: Vec<DiffChange>,
    pub resets: Vec<crate::snapshot::CounterReset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology: Option<TopologyDiff>,
    pub rca: RcaDiff,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimelineReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub kind: SnapshotKind,
    pub target: String,
    pub snapshots: usize,
    pub start_unix_ms: u64,
    pub end_unix_ms: u64,
    pub intervals: Vec<TimelineInterval>,
    pub event_count: usize,
    pub overall_assessment: OverallAssessment,
    pub anomalies: Vec<HistoryAnomaly>,
    pub summary: String,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

fn event_count(i: &TimelineInterval) -> usize {
    i.changes.len()
        + i.resets.len()
        + i.rca.changes.len()
        + i.topology.as_ref().map_or(0, |t| {
            t.pools_added.len()
                + t.pools_removed.len()
                + t.pool_changes.len()
                + t.destinations_added.len()
                + t.destinations_removed.len()
                + t.destination_availability.len()
        })
}

/// Build a deterministic timeline from snapshots supplied by the caller. Snapshots are sorted by
/// timestamp and deduplicated by `(target, timestamp)`.
pub fn analyze_timeline(snapshots: &[IncidentSnapshot]) -> Result<TimelineReport, String> {
    if snapshots.is_empty() {
        return Err("incident timeline needs at least one snapshot".to_owned());
    }
    if snapshots.len() > MAX_TIMELINE_INTERVALS {
        return Err(format!(
            "incident timeline takes at most {MAX_TIMELINE_INTERVALS} snapshots, got {}",
            snapshots.len()
        ));
    }
    let kind = snapshots[0].kind;
    let target = snapshots[0].target.clone();
    for s in snapshots {
        if s.kind != kind {
            return Err("timeline snapshots have different kinds".to_owned());
        }
        if s.target != target {
            return Err("timeline snapshots have different targets".to_owned());
        }
        s.validate()?;
    }
    let mut ordered: Vec<&IncidentSnapshot> = snapshots.iter().collect();
    ordered.sort_by_key(|s| (s.captured_at_unix_ms, s.target.as_str()));
    ordered.dedup_by_key(|s| s.captured_at_unix_ms);
    if ordered.is_empty() {
        return Err("incident timeline has no usable snapshots".to_owned());
    }
    let mut intervals = Vec::new();
    for pair in ordered.windows(2) {
        let diff = compare_snapshots(pair[0], pair[1])?;
        intervals.push(TimelineInterval {
            before: diff.before,
            after: diff.after,
            interval_seconds: diff.interval_seconds,
            status: diff.status,
            changes: diff.changes,
            resets: diff.resets,
            topology: diff.topology,
            rca: diff.rca,
            missing_evidence: diff.missing_evidence,
            limitations: diff.limitations,
        });
    }
    intervals.truncate(MAX_TIMELINE_INTERVALS);
    let history = history::analyze_history(snapshots)?;
    let events: usize = intervals.iter().map(event_count).sum();
    let start = ordered.first().map_or(0, |s| s.captured_at_unix_ms);
    let end = ordered.last().map_or(0, |s| s.captured_at_unix_ms);
    let summary = if intervals.is_empty() {
        "Only one distinct snapshot: no interval or timeline event can be derived.".to_owned()
    } else {
        format!(
            "{} interval(s), {} change/reset/topology/RCA event(s), {} historical anomaly finding(s).",
            intervals.len(),
            events,
            history.anomalies.len()
        )
    };
    Ok(TimelineReport {
        schema_version: TIMELINE_SCHEMA_VERSION,
        analysis: "incident_timeline",
        kind,
        target,
        snapshots: ordered.len(),
        start_unix_ms: start,
        end_unix_ms: end,
        intervals,
        event_count: events,
        overall_assessment: history.overall_assessment,
        anomalies: history.anomalies,
        summary,
        missing_evidence: history.missing_evidence,
        limitations: vec![
            "Timeline events are derived only from supplied snapshots; no collection or persistence occurs.".to_owned(),
            "A diff between two observations cannot prove causation or establish a longer trend.".to_owned(),
            "Unsupported or missing metrics are reported as missing evidence, not inferred.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{SnapshotKind, SnapshotMetrics};
    use std::collections::BTreeMap;

    fn snap(at: u64, hits: u64, misses: u64, bytes: u64) -> IncidentSnapshot {
        let mut counters = BTreeMap::new();
        counters.insert("get_hits".into(), hits.to_string());
        counters.insert("get_misses".into(), misses.to_string());
        counters.insert("evictions".into(), "0".into());
        let mut gauges = BTreeMap::new();
        gauges.insert("bytes".into(), bytes.to_string());
        gauges.insert("limit_maxbytes".into(), "1000".into());
        gauges.insert("uptime".into(), (at / 1000).to_string());
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
    fn builds_intervals_and_handles_single_snapshot() {
        let one = analyze_timeline(&[snap(1_000, 100, 900, 100)]).unwrap();
        assert!(one.intervals.is_empty());
        assert_eq!(one.event_count, 0);
        let two =
            analyze_timeline(&[snap(1_000, 100, 900, 100), snap(11_000, 1000, 1000, 800)]).unwrap();
        assert_eq!(two.intervals.len(), 1);
        assert!(two.event_count > 0);
    }

    #[test]
    fn rejects_mixed_targets() {
        let mut other = snap(1_000, 1, 1, 1);
        other.target = "other:11211".into();
        assert!(analyze_timeline(&[snap(1_000, 1, 1, 1), other]).is_err());
    }
}
