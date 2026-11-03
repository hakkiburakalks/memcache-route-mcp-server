//! Read-only cache-efficiency advice over one `stats`/`stats items`/`stats settings` snapshot.
//!
//! This module is intentionally an advisor, not a tuning engine. It reuses the existing RCA
//! findings and metric calculations, reports uncertainty explicitly, and never claims that adding
//! RAM or changing slab/connection limits will fix a problem without historical or capacity
//! evidence.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::rca::{analyze_node as analyze_node_rca, Confidence, Evidence, EvidenceKind, RcaReport};
use crate::{hit_ratio, per_slab, Severity, Stats};

pub const EFFICIENCY_SCHEMA_VERSION: &str = "1.0";
const MIN_STABLE_UPTIME_SECS: u64 = 300;
const MIN_GETS_FOR_RATIO: u64 = 1_000;
const MAX_FINDINGS: usize = 16;
const MAX_RECOMMENDATIONS: usize = 12;
const MAX_EVIDENCE: usize = 24;
const MAX_TEXT_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallAssessment {
    Healthy,
    Watch,
    Actionable,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EfficiencyFinding {
    pub id: String,
    pub assessment: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub alternative_explanations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Recommendation {
    pub id: String,
    pub priority: Priority,
    pub rationale: String,
    pub expected_benefit: String,
    pub potential_risk: String,
    pub suggested_validation_steps: Vec<String>,
    pub related_findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EfficiencyReport {
    pub schema_version: String,
    pub analysis: String,
    pub target: String,
    pub overall_assessment: OverallAssessment,
    pub efficiency_findings: Vec<EfficiencyFinding>,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
    pub recommendations: Vec<Recommendation>,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

fn metric(stats: &Stats, key: &str) -> Option<u64> {
    stats.get(key)?.parse().ok()
}

fn gets(stats: &Stats) -> u64 {
    metric(stats, "get_hits")
        .unwrap_or(0)
        .saturating_add(metric(stats, "get_misses").unwrap_or(0))
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
    unit: Option<&'static str>,
    interpretation: &str,
) -> Evidence {
    Evidence::new(
        metric_name,
        kind,
        Some(value.to_string()),
        unit,
        clip(interpretation, MAX_TEXT_BYTES),
    )
}

fn memory_pct(stats: &Stats) -> Option<f64> {
    let used = metric(stats, "bytes")?;
    let limit = metric(stats, "limit_maxbytes")?;
    (limit > 0).then(|| used as f64 / limit as f64 * 100.0)
}

fn connection_pct(stats: &Stats, settings: &Stats) -> Option<f64> {
    let cur = metric(stats, "curr_connections")?;
    let max = metric(settings, "maxconns")?;
    (max > 0).then(|| cur as f64 / max as f64 * 100.0)
}

fn expired_ratio(stats: &Stats) -> Option<f64> {
    let total = metric(stats, "total_items")?;
    let expired = metric(stats, "expired_unfetched")?;
    (total > 0).then(|| expired as f64 / total as f64)
}

fn overall_confidence(stats: &Stats, settings: &Stats) -> Confidence {
    let core = [
        "get_hits",
        "get_misses",
        "bytes",
        "limit_maxbytes",
        "evictions",
        "uptime",
    ]
    .iter()
    .all(|key| metric(stats, key).is_some());
    if !core {
        return Confidence::Insufficient;
    }
    if metric(stats, "uptime").is_none_or(|u| u < MIN_STABLE_UPTIME_SECS)
        || gets(stats) < MIN_GETS_FOR_RATIO
        || metric(settings, "maxconns").is_none()
    {
        return Confidence::Low;
    }
    if metric(stats, "total_items").is_none() || metric(stats, "curr_items").is_none() {
        return Confidence::Medium;
    }
    Confidence::High
}

fn finding_from_rca(f: &crate::rca::RcaFinding) -> EfficiencyFinding {
    EfficiencyFinding {
        id: clip(&f.id, 128),
        assessment: clip(&f.suspected_cause, MAX_TEXT_BYTES),
        severity: f.severity,
        confidence: f.confidence,
        evidence: f.evidence.iter().take(8).cloned().collect(),
        alternative_explanations: f.alternative_explanations.iter().take(6).cloned().collect(),
    }
}

fn recommendation(
    id: &str,
    priority: Priority,
    rationale: &str,
    benefit: &str,
    risk: &str,
    checks: &[&str],
    related: &[&str],
) -> Recommendation {
    Recommendation {
        id: id.to_owned(),
        priority,
        rationale: clip(rationale, MAX_TEXT_BYTES),
        expected_benefit: clip(benefit, MAX_TEXT_BYTES),
        potential_risk: clip(risk, MAX_TEXT_BYTES),
        suggested_validation_steps: checks.iter().map(|s| clip(s, MAX_TEXT_BYTES)).collect(),
        related_findings: related.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn recommendations_for(report: &RcaReport, stats: &Stats) -> Vec<Recommendation> {
    let ids: BTreeSet<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    let evictions = metric(stats, "evictions").unwrap_or(0);
    let mut out = Vec::new();

    if ids.contains("hit_ratio_low") {
        if evictions > 0 {
            out.push(recommendation(
                "investigate_eviction_pressure",
                Priority::High,
                "The hit ratio is low while the eviction counter is non-zero. The available evidence is consistent with capacity or slab pressure, but a single snapshot cannot prove it.",
                "A capacity/slab investigation may identify avoidable misses and improve the effective hit ratio.",
                "Adding RAM or changing slab limits without a working-set/capacity model can waste resources or disrupt other workloads; this advisor does not make that change.",
                &[
                    "Collect a second snapshot over a stable interval and compare eviction and hit-ratio deltas.",
                    "Inspect `stats items` and `stats slabs` for the classes holding the working set.",
                    "Model the application working set and item-size distribution before any capacity change.",
                    "Confirm with the application owner whether misses are expected for the access pattern.",
                ],
                &["hit_ratio_low", "evictions"],
            ));
        } else {
            out.push(recommendation(
                "review_workload_and_ttl",
                Priority::Medium,
                "The hit ratio is low without eviction evidence. Workload/key distribution, expiry or data-not-populated is at least as likely as memory pressure.",
                "Reviewing key distribution and TTL can reveal avoidable misses without changing capacity.",
                "Changing TTLs or key strategy can alter correctness, freshness and write amplification; test with the application owner.",
                &[
                    "Inspect a second snapshot to separate a cold/warm-up period from a persistent pattern.",
                    "Check `stats items` for expired/reclaimed counts and the application TTL policy.",
                    "Compare the key namespace and read cadence with the observed misses.",
                    "Do not add RAM solely from this snapshot; there is no eviction evidence.",
                ],
                &["hit_ratio_low"],
            ));
        }
    }

    if ids.contains("evictions") {
        out.push(recommendation(
            "measure_eviction_pressure",
            Priority::Medium,
            "The cumulative eviction counter is non-zero. The average since uptime is useful context, not proof of a current trend.",
            "A measured, multi-snapshot eviction analysis can distinguish a one-off burst from sustained capacity pressure.",
            "Adding RAM without historical/capacity modeling may not address slab skew or workload churn; reconfiguration can cause disruption.",
            &[
                "Collect two snapshots at a known interval and compare eviction deltas.",
                "Inspect per-slab eviction and item-size distributions.",
                "Check whether the cache is intentionally full and churn is expected.",
                "Model capacity before recommending a memory limit or slab change.",
            ],
            &["evictions"],
        ));
    }

    if ids.contains("memory_near_limit") {
        out.push(recommendation(
            "watch_memory_headroom",
            Priority::Low,
            "Memory is near the configured limit but no evictions were observed. A full cache can be normal; this is a watch item, not a proven problem.",
            "Monitoring headroom and eviction onset can catch a future capacity boundary without premature tuning.",
            "Reducing the working set or changing limits can cause misses; no change is justified by this snapshot alone.",
            &[
                "Observe memory and eviction counters over a stable interval.",
                "Compare the configured limit with the application working set.",
                "Revisit only if evictions or sustained pressure appear.",
            ],
            &["memory_near_limit"],
        ));
    }

    if ids.contains("eviction_skew") {
        out.push(recommendation(
            "review_slab_layout",
            Priority::Medium,
            "Evictions are concentrated in one slab class. The current item-size distribution may not fit the slab layout, but the config may also be intentional.",
            "Reviewing item sizes and slab-class allocation may improve hit ratio for the dominant size class.",
            "Changing slab or chunk settings is a server configuration change and can disrupt existing items/restart the service; this advisor does not perform it.",
            &[
                "Inspect `stats slabs` and the dominant item sizes.",
                "Check whether the skew persists across multiple observations.",
                "Validate a proposed slab change in a non-production environment.",
            ],
            &["eviction_skew"],
        ));
    }

    if ids.contains("connection_limit_hit") || ids.contains("connections_near_limit") {
        out.push(recommendation(
            "review_connection_pressure",
            Priority::High,
            "Connection counters show the listener limit was reached or is closely approached. This can cause refused or delayed client work independent of cache hit ratio.",
            "Reviewing connection pooling, idle timeouts and maxconns can prevent avoidable client failures.",
            "Raising maxconns or changing pooling can increase memory/fd pressure and affect other services; validate capacity first.",
            &[
                "Compare curr_connections and maxconns over multiple samples.",
                "Inspect client pooling, idle timeouts and connection churn.",
                "Check whether the event correlates with deployment or traffic bursts.",
            ],
            &["connection_limit_hit", "connections_near_limit"],
        ));
    }

    if ids.contains("ttl_or_expiry_pressure") {
        out.push(recommendation(
            "review_ttl_policy",
            Priority::Medium,
            "A large share of items expired before being fetched. TTL or the write/read interval is a plausible contributor to misses.",
            "Aligning TTL with the application's read cadence can reduce avoidable expiry misses.",
            "Longer TTLs can increase memory pressure, stale data and write amplification; correctness requirements must be checked.",
            &[
                "Review the application TTL policy and read cadence.",
                "Compare expired-unfetched counts over two snapshots.",
                "Check whether write-only or deliberately short-lived data explains the ratio.",
            ],
            &["ttl_or_expiry_pressure"],
        ));
    }

    if ids.contains("short_uptime") {
        out.push(recommendation(
            "wait_for_stable_window",
            Priority::Low,
            "The uptime is shorter than the stable-window threshold. Cumulative counters and rates are not yet representative.",
            "Waiting for a stable observation window avoids tuning on startup transients.",
            "Changing configuration during warm-up can be based on noise and can disrupt the cache before it stabilizes.",
            &[
                "Wait for at least 300 seconds of uptime.",
                "Collect a second snapshot and compare deltas.",
                "Check restart/deployment events before interpreting counters.",
            ],
            &["short_uptime"],
        ));
    }

    if ids.contains("inconsistent_statistics") {
        out.push(recommendation(
            "revalidate_statistics",
            Priority::High,
            "The statistics fail internal consistency checks. Optimization advice based on them would be unreliable.",
            "Re-reading the statistics can restore a trustworthy baseline.",
            "Acting on inconsistent values can misdiagnose the cache or mask a proxy/data-path problem.",
            &[
                "Re-read stats and verify the same values are returned consistently.",
                "Check whether a restart, proxy or custom server mixed responses.",
                "Compare with a peer node before making any decision.",
            ],
            &["inconsistent_statistics"],
        ));
    }

    if ids.contains("insufficient_evidence") || ids.contains("hit_ratio_insufficient_data") {
        out.push(recommendation(
            "collect_complete_statistics",
            Priority::Medium,
            "Some expected metrics are missing or the request sample is too small for a reliable efficiency judgment.",
            "Collecting complete statistics over a representative window enables a useful assessment.",
            "Tuning from partial data can produce false confidence or an unrelated change.",
            &[
                "Confirm the missing keys with `get_stats`.",
                "Wait for a representative request volume.",
                "Compare a second snapshot after the warm-up period.",
            ],
            &["insufficient_evidence", "hit_ratio_insufficient_data"],
        ));
    }

    let mut deduped: Vec<Recommendation> = Vec::new();
    for candidate in out {
        if !deduped.iter().any(|r| r.id == candidate.id) {
            deduped.push(candidate);
        }
    }
    deduped.truncate(MAX_RECOMMENDATIONS);
    deduped
}

/// Builds the efficiency report. Pure and deterministic.
pub fn advise_node(
    target: &str,
    stats: &Stats,
    items: &Stats,
    settings: &Stats,
) -> EfficiencyReport {
    let rca = analyze_node_rca(target, stats, items, settings);
    let mut evidence = Vec::new();
    let mut missing: BTreeSet<String> = rca.missing_evidence.iter().cloned().collect();

    let mut push = |e: Evidence| {
        if evidence.len() < MAX_EVIDENCE {
            evidence.push(e);
        }
    };

    if let Some(hits) = metric(stats, "get_hits") {
        push(ev(
            "get_hits",
            EvidenceKind::Counter,
            hits,
            None,
            "Cumulative hits since uptime.",
        ));
    } else {
        missing.insert("get_hits".to_owned());
    }
    if let Some(misses) = metric(stats, "get_misses") {
        push(ev(
            "get_misses",
            EvidenceKind::Counter,
            misses,
            None,
            "Cumulative misses since uptime.",
        ));
    } else {
        missing.insert("get_misses".to_owned());
    }
    let total_gets = gets(stats);
    if total_gets > 0 {
        push(ev(
            "gets",
            EvidenceKind::Derived,
            total_gets,
            None,
            "Derived as get_hits + get_misses; cumulative.",
        ));
    }
    if let Some(ratio) = hit_ratio(stats) {
        push(ev(
            "hit_ratio",
            EvidenceKind::Derived,
            format!("{ratio:.3}"),
            None,
            "Derived from cumulative get_hits / (get_hits + get_misses); not a trend.",
        ));
    }
    if let Some(pct) = memory_pct(stats) {
        push(ev(
            "memory_utilization_pct",
            EvidenceKind::Derived,
            format!("{pct:.1}"),
            None,
            "Derived from bytes / limit_maxbytes at one instant.",
        ));
    }
    if let Some(used) = metric(stats, "bytes") {
        push(ev(
            "bytes",
            EvidenceKind::Gauge,
            used,
            Some("bytes"),
            "Item data currently stored; excludes slab overhead.",
        ));
    }
    if let Some(limit) = metric(stats, "limit_maxbytes") {
        push(ev(
            "limit_maxbytes",
            EvidenceKind::Gauge,
            limit,
            Some("bytes"),
            "Configured memory limit.",
        ));
    }
    if let Some(evictions) = metric(stats, "evictions") {
        push(ev(
            "evictions",
            EvidenceKind::Counter,
            evictions,
            None,
            "Items evicted before expiry since uptime; cumulative.",
        ));
        if let (Some(uptime), true) = (metric(stats, "uptime"), evictions > 0) {
            if uptime > 0 {
                push(ev(
                    "eviction_rate_per_second",
                    EvidenceKind::Derived,
                    format!("{:.6}", evictions as f64 / uptime as f64),
                    Some("items/s"),
                    "Average since uptime, not an instantaneous or historical trend.",
                ));
            }
        }
    }
    if let Some(items_count) = metric(stats, "curr_items") {
        push(ev(
            "curr_items",
            EvidenceKind::Gauge,
            items_count,
            None,
            "Items currently stored.",
        ));
    }
    if let Some(total_items) = metric(stats, "total_items") {
        push(ev(
            "total_items",
            EvidenceKind::Counter,
            total_items,
            None,
            "Items stored since uptime; cumulative.",
        ));
    }
    if let Some(expired) = expired_ratio(stats) {
        push(ev(
            "expired_unfetched_ratio",
            EvidenceKind::Derived,
            format!("{expired:.3}"),
            None,
            "Derived from expired_unfetched / total_items; not a trend.",
        ));
    }
    if let Some(cur) = metric(stats, "curr_connections") {
        push(ev(
            "curr_connections",
            EvidenceKind::Gauge,
            cur,
            None,
            "Connections currently open.",
        ));
    }
    if let Some(max) = metric(settings, "maxconns") {
        push(ev(
            "maxconns",
            EvidenceKind::Configuration,
            max,
            None,
            "Configured maximum connections.",
        ));
    }
    if let Some(pct) = connection_pct(stats, settings) {
        push(ev(
            "connection_utilization_pct",
            EvidenceKind::Derived,
            format!("{pct:.1}"),
            None,
            "Derived from curr_connections / maxconns at one instant.",
        ));
    }
    if let Some(uptime) = metric(stats, "uptime") {
        push(ev(
            "uptime",
            EvidenceKind::Gauge,
            uptime,
            Some("s"),
            "Seconds since the last server start.",
        ));
    }
    let slabs = per_slab(items, "evicted");
    let total_slab_evictions: u64 = slabs.iter().fold(0, |a, (_, n)| a.saturating_add(*n));
    if !slabs.is_empty() {
        push(ev(
            "slab_classes_with_evictions",
            EvidenceKind::Derived,
            slabs.iter().filter(|(_, n)| *n > 0).count(),
            None,
            "Slab classes with a non-zero cumulative eviction counter.",
        ));
    }
    if total_slab_evictions > 0 {
        if let Some((slab, count)) = slabs.iter().max_by_key(|(_, n)| *n) {
            push(ev(
                "top_evicting_slab",
                EvidenceKind::Derived,
                format!("{slab}:{count}"),
                None,
                "Slab class with the largest cumulative eviction count.",
            ));
        }
    }
    let maxconns_missing = metric(settings, "maxconns").is_none();
    if maxconns_missing {
        missing.insert("settings.maxconns".to_owned());
    }

    let confidence = overall_confidence(stats, settings);
    let findings: Vec<EfficiencyFinding> = rca
        .findings
        .iter()
        .take(MAX_FINDINGS)
        .map(finding_from_rca)
        .collect();
    let recommendations = recommendations_for(&rca, stats);
    let overall_assessment = if findings.iter().any(|f| f.severity >= Severity::Warning) {
        OverallAssessment::Actionable
    } else if confidence == Confidence::Insufficient {
        OverallAssessment::InsufficientEvidence
    } else if findings.iter().any(|f| {
        matches!(
            f.id.as_str(),
            "memory_near_limit" | "short_uptime" | "hit_ratio_insufficient_data"
        )
    }) {
        OverallAssessment::Watch
    } else {
        OverallAssessment::Healthy
    };

    let mut limitations = vec![
        "Single snapshot: cumulative counters are not differenced, so trends and counter resets cannot be confirmed.".to_owned(),
        "Efficiency findings are hypotheses pending a second observation, capacity modeling or application context.".to_owned(),
        "A non-zero eviction counter does not by itself justify adding RAM; slab layout, workload churn and TTL must also be considered.".to_owned(),
        "Gauges describe one collection instant; the advisor does not forecast memory exhaustion.".to_owned(),
    ];
    if metric(stats, "uptime").is_none_or(|u| u < MIN_STABLE_UPTIME_SECS) {
        limitations.push(
            "Uptime is short or unknown; cumulative counters and any average rate may reflect startup or a burst."
                .to_owned(),
        );
    }
    if !missing.is_empty() {
        limitations.push(
            "Some expected statistics are missing or malformed; evidence confidence is reduced."
                .to_owned(),
        );
    }
    if rca.status == crate::rca::AnalysisStatus::Actionable && findings.is_empty() {
        limitations.push(
            "The underlying RCA marked this snapshot actionable without a detailed finding; review the raw diagnostics."
                .to_owned(),
        );
    }
    limitations.sort();
    limitations.dedup();

    EfficiencyReport {
        schema_version: EFFICIENCY_SCHEMA_VERSION.to_owned(),
        analysis: "cache_efficiency".to_owned(),
        target: clip(target, 256),
        overall_assessment,
        efficiency_findings: findings,
        evidence,
        confidence,
        recommendations,
        missing_evidence: missing.into_iter().collect(),
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rca::Confidence;

    fn st(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn healthy() -> (Stats, Stats, Stats) {
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

    #[test]
    fn healthy_cache_with_sufficient_evidence() {
        let (stats, items, settings) = healthy();
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.schema_version, EFFICIENCY_SCHEMA_VERSION);
        assert_eq!(report.overall_assessment, OverallAssessment::Healthy);
        assert_eq!(report.confidence, Confidence::High);
        assert!(report.efficiency_findings.is_empty());
        assert!(report.recommendations.is_empty());
    }

    #[test]
    fn low_hit_ratio_without_evictions_is_not_memory_advice() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), "300".into());
        stats.insert("get_misses".into(), "700".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.overall_assessment, OverallAssessment::Actionable);
        assert!(report
            .efficiency_findings
            .iter()
            .any(|f| f.id == "hit_ratio_low"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "review_workload_and_ttl"));
        assert!(!report
            .recommendations
            .iter()
            .any(|r| r.id == "investigate_eviction_pressure"));
        assert!(report
            .recommendations
            .iter()
            .all(|r| !r.expected_benefit.to_lowercase().contains("add ram")));
    }

    #[test]
    fn low_hit_ratio_with_evictions_avoids_ram_promise() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), "300".into());
        stats.insert("get_misses".into(), "700".into());
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "20000".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        let rec = report
            .recommendations
            .iter()
            .find(|r| r.id == "investigate_eviction_pressure")
            .unwrap();
        assert!(rec.rationale.contains("single snapshot"));
        assert!(rec.potential_risk.contains("Adding RAM"));
        assert!(!rec.expected_benefit.contains("Adding RAM"));
    }

    #[test]
    fn contradictory_memory_and_hit_evidence_is_not_treated_as_proof() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), "300".into());
        stats.insert("get_misses".into(), "700".into());
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "0".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.overall_assessment, OverallAssessment::Actionable);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "review_workload_and_ttl"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "watch_memory_headroom"));
        assert!(!report
            .recommendations
            .iter()
            .any(|r| r.id == "investigate_eviction_pressure"));
        assert!(report
            .limitations
            .iter()
            .any(|l| l.contains("does not by itself justify adding RAM")));
    }

    #[test]
    fn high_memory_without_eviction_is_watch_only() {
        let (mut stats, items, settings) = healthy();
        stats.insert("bytes".into(), "95".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.overall_assessment, OverallAssessment::Watch);
        assert!(report
            .efficiency_findings
            .iter()
            .any(|f| f.id == "memory_near_limit"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "watch_memory_headroom"));
    }

    #[test]
    fn slab_imbalance_recommends_layout_review() {
        let (stats, mut items, settings) = healthy();
        items.insert("items:1:number".into(), "10".into());
        items.insert("items:2:number".into(), "10".into());
        items.insert("items:3:number".into(), "10".into());
        items.insert("items:1:evicted".into(), "900".into());
        items.insert("items:2:evicted".into(), "50".into());
        items.insert("items:3:evicted".into(), "50".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert!(report
            .efficiency_findings
            .iter()
            .any(|f| f.id == "eviction_skew"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "review_slab_layout"));
    }

    #[test]
    fn short_uptime_and_low_sample_defer_tuning() {
        let (mut stats, items, settings) = healthy();
        stats.insert("uptime".into(), "10".into());
        stats.insert("get_hits".into(), "10".into());
        stats.insert("get_misses".into(), "50".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.confidence, Confidence::Low);
        assert!(report
            .efficiency_findings
            .iter()
            .any(|f| f.id == "short_uptime"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "wait_for_stable_window"));
    }

    #[test]
    fn missing_and_malformed_statistics_are_insufficient() {
        let report = advise_node("cache:11211", &Stats::new(), &Stats::new(), &Stats::new());
        assert_eq!(
            report.overall_assessment,
            OverallAssessment::InsufficientEvidence
        );
        assert_eq!(report.confidence, Confidence::Insufficient);
        assert!(!report.missing_evidence.is_empty());
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "collect_complete_statistics"));
    }

    #[test]
    fn inconsistent_counters_are_revalidated_not_optimized() {
        let (mut stats, items, settings) = healthy();
        stats.insert("curr_items".into(), "20000".into());
        stats.insert("total_items".into(), "10000".into());
        stats.insert("bytes".into(), "150".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert!(report
            .efficiency_findings
            .iter()
            .any(|f| f.id == "inconsistent_statistics"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.id == "revalidate_statistics"));
    }

    #[test]
    fn hostile_values_do_not_panic_and_output_is_bounded() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), u64::MAX.to_string());
        stats.insert("get_misses".into(), u64::MAX.to_string());
        stats.insert("evictions".into(), "not-a-number".into());
        stats.insert("bytes".into(), "999999999999999999999".into());
        let report = advise_node("cache:11211", &stats, &items, &settings);
        assert!(report.evidence.len() <= MAX_EVIDENCE);
        assert!(report.efficiency_findings.len() <= MAX_FINDINGS);
        assert!(report.recommendations.len() <= MAX_RECOMMENDATIONS);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(encoded.len() < 256 * 1024);
    }

    #[test]
    fn output_is_deterministic() {
        let (mut stats, items, settings) = healthy();
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "20000".into());
        let a = advise_node("cache:11211", &stats, &items, &settings);
        let b = advise_node("cache:11211", &stats, &items, &settings);
        assert_eq!(a, b);
    }
}
