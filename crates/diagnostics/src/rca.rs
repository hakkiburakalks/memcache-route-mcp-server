//! Deterministic, evidence-based root-cause analysis (RCA).
//!
//! This module deliberately does not collect anything. It enriches the existing
//! [`crate::analyze_node`] rules with structured evidence, alternatives and checks, and adds
//! data-quality findings for snapshots that cannot support a conclusion. The result is derived
//! only from one `stats` / `stats items` / `stats settings` snapshot, so it never claims a trend
//! or a proven causal relationship.

use serde::{Deserialize, Serialize};

use crate::{analyze_node as base_analyze_node, hit_ratio, num, per_slab, Severity, Stats};

/// Version of the stable JSON shape emitted by the MCP tools.
pub const RCA_SCHEMA_VERSION: &str = "1.0";

/// Below this uptime, cumulative counters are treated as not yet representative.
pub const MIN_STABLE_UPTIME_SECS: u64 = 300;

const MAX_FINDINGS: usize = 16;
const MAX_EVIDENCE: usize = 12;
const MAX_ALTERNATIVES: usize = 6;
const MAX_CHECKS: usize = 8;
const MAX_TEXT_BYTES: usize = 512;
const MAX_VALUE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The snapshot does not contain enough data to support a conclusion.
    Insufficient,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Healthy,
    Actionable,
    Partial,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Counter,
    Gauge,
    Derived,
    Configuration,
    DataQuality,
    Coverage,
}

/// One observable or derived value supporting a finding. Values are strings to preserve the
/// exact upstream representation and avoid precision or overflow surprises in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub metric: String,
    pub kind: EvidenceKind,
    pub value: Option<String>,
    pub unit: Option<String>,
    pub interpretation: String,
}

impl Evidence {
    pub fn new(
        metric: impl Into<String>,
        kind: EvidenceKind,
        value: Option<String>,
        unit: Option<&'static str>,
        interpretation: impl Into<String>,
    ) -> Self {
        Self {
            metric: clip(metric.into(), MAX_VALUE_BYTES),
            kind,
            value: value.map(|v| clip(v, MAX_VALUE_BYTES)),
            unit: unit.map(str::to_owned),
            interpretation: clip(interpretation.into(), MAX_TEXT_BYTES),
        }
    }

    pub fn stat(
        stats: &Stats,
        key: &str,
        kind: EvidenceKind,
        unit: Option<&'static str>,
        interpretation: &str,
    ) -> Self {
        Self::new(key, kind, stats.get(key).cloned(), unit, interpretation)
    }

    pub fn derived(metric: &str, value: impl Into<String>, interpretation: &str) -> Self {
        Self::new(
            metric,
            EvidenceKind::Derived,
            Some(value.into()),
            None,
            interpretation,
        )
    }
}

/// A diagnosed hypothesis. All fields are stable JSON names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RcaFinding {
    pub id: String,
    pub suspected_cause: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub confidence_basis: String,
    pub evidence: Vec<Evidence>,
    pub alternative_explanations: Vec<String>,
    pub recommended_checks: Vec<String>,
}

impl RcaFinding {
    pub fn new(
        id: &'static str,
        suspected_cause: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        confidence_basis: impl Into<String>,
    ) -> Self {
        Self {
            id: id.to_owned(),
            suspected_cause: clip(suspected_cause.into(), MAX_TEXT_BYTES),
            severity,
            confidence,
            confidence_basis: clip(confidence_basis.into(), MAX_TEXT_BYTES),
            evidence: Vec::new(),
            alternative_explanations: Vec::new(),
            recommended_checks: Vec::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        if self.evidence.len() < MAX_EVIDENCE {
            self.evidence.push(evidence);
        }
        self
    }

    pub fn with_alternatives<I, S>(mut self, alternatives: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for a in alternatives {
            if self.alternative_explanations.len() >= MAX_ALTERNATIVES {
                break;
            }
            self.alternative_explanations
                .push(clip(a.into(), MAX_TEXT_BYTES));
        }
        self
    }

    pub fn with_checks<I, S>(mut self, checks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for c in checks {
            if self.recommended_checks.len() >= MAX_CHECKS {
                break;
            }
            self.recommended_checks.push(clip(c.into(), MAX_TEXT_BYTES));
        }
        self
    }
}

/// How much of the expected topology was actually observed. Present only for mcrouter analyses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub configured_destinations: usize,
    pub probed_destinations: usize,
    pub reachable_destinations: usize,
    pub unreachable_destinations: usize,
    pub unmapped_destinations: usize,
    pub denied_destinations: usize,
    pub truncated_destinations: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RcaReport {
    pub schema_version: String,
    pub analysis: String,
    pub target: String,
    pub status: AnalysisStatus,
    pub summary: String,
    pub findings: Vec<RcaFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

impl RcaReport {
    pub fn new(analysis: &'static str, target: impl Into<String>) -> Self {
        Self {
            schema_version: RCA_SCHEMA_VERSION.to_owned(),
            analysis: analysis.to_owned(),
            target: clip(target.into(), 256),
            status: AnalysisStatus::Healthy,
            summary: String::new(),
            findings: Vec::new(),
            coverage: None,
            missing_evidence: Vec::new(),
            limitations: Vec::new(),
        }
    }

    /// Deterministic order: severity first, then the stable finding id.
    pub fn sort_findings(&mut self) {
        self.findings
            .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        self.findings.truncate(MAX_FINDINGS);
    }

    pub fn has_actionable_finding(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= Severity::Warning)
    }
}

fn clip(mut value: String, max: usize) -> String {
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

fn metric(stats: &Stats, key: &str) -> Option<u64> {
    num(stats, key)
}

fn gets(stats: &Stats) -> u64 {
    metric(stats, "get_hits")
        .unwrap_or(0)
        .saturating_add(metric(stats, "get_misses").unwrap_or(0))
}

fn memory_pct(stats: &Stats) -> Option<f64> {
    let used = metric(stats, "bytes")?;
    let limit = metric(stats, "limit_maxbytes")?;
    (limit > 0).then(|| used as f64 / limit as f64 * 100.0)
}

fn expired_ratio(stats: &Stats) -> Option<f64> {
    let total = metric(stats, "total_items")?;
    let expired = metric(stats, "expired_unfetched")?;
    (total >= 1_000).then(|| expired as f64 / total as f64)
}

fn counter_confidence(uptime: Option<u64>, memory: Option<f64>) -> (Confidence, String) {
    match (uptime, memory) {
        (Some(u), Some(_)) if u >= MIN_STABLE_UPTIME_SECS => (
            Confidence::High,
            format!(
                "Uptime is {u} s (at least {MIN_STABLE_UPTIME_SECS} s) and both counter and gauge evidence are present."
            ),
        ),
        (Some(u), Some(_)) => (
            Confidence::Medium,
            format!(
                "Uptime is only {u} s, below the {MIN_STABLE_UPTIME_SECS} s stability window; the cumulative rate may reflect a burst or startup."
            ),
        ),
        (Some(u), None) => (
            Confidence::Medium,
            format!(
                "The counter and uptime are present ({u} s), but memory gauges are missing, so the cause cannot be tied to capacity."
            ),
        ),
        _ => (
            Confidence::Low,
            "Uptime or memory gauges are missing; cumulative counters cannot be placed in a representative window.".to_owned(),
        ),
    }
}

fn enrich_base_finding(
    f: crate::Finding,
    stats: &Stats,
    items: &Stats,
    settings: &Stats,
) -> RcaFinding {
    let uptime = metric(stats, "uptime");
    let memory = memory_pct(stats);
    let evictions = metric(stats, "evictions");
    let ratio = hit_ratio(stats);

    match f.code {
        "hit_ratio_low" => {
            let ev = evictions.unwrap_or(0);
            let expired = expired_ratio(stats);
            let (cause, confidence, basis) = if ev > 0 {
                let (c, b) = counter_confidence(uptime, memory);
                (
                    "Requests are missing after items are evicted. The available evidence is consistent with a working set larger than the configured memory, or with one slab class exhausted.",
                    c,
                    b,
                )
            } else if expired.is_some_and(|r| r >= 0.5) {
                (
                    "Requests are missing without evictions, while many stored items expired before being fetched. TTL or the access pattern is the more likely explanation.",
                    Confidence::Medium,
                    "The hit-ratio counter is large enough to judge, and the expired-unfetched fraction is high; there is no eviction evidence.".to_owned(),
                )
            } else if evictions.is_none() {
                (
                    "Requests are missing, but this snapshot does not include an eviction counter. Memory pressure cannot be excluded from this evidence alone.",
                    Confidence::Low,
                    "The hit-ratio counter is large enough to judge, but the eviction counter is missing or malformed.".to_owned(),
                )
            } else {
                (
                    "Requests are missing without eviction pressure. The available evidence points to the workload, key distribution, TTL, or data not being populated rather than memory exhaustion.",
                    Confidence::Medium,
                    "At least 1000 gets were observed and evictions are zero; a single snapshot cannot distinguish workload changes from TTL effects.".to_owned(),
                )
            };
            let mut r = RcaFinding::new(f.code, cause, f.severity, confidence, basis)
                .with_evidence(Evidence::stat(stats, "get_hits", EvidenceKind::Counter, None, "Cache hits since start."))
                .with_evidence(Evidence::stat(stats, "get_misses", EvidenceKind::Counter, None, "Cache misses since start."))
                .with_evidence(Evidence::stat(stats, "evictions", EvidenceKind::Counter, None, "Items evicted before expiry since start."))
                .with_alternatives([
                    "The application changed its key distribution or access pattern.",
                    "Entries expire before the next read (TTL too short).",
                    "The cache is intentionally cold or was recently restarted.",
                    "A proxy or client is sending requests for keys that were never stored.",
                ])
                .with_checks([
                    "Compare the key namespace and TTL policy with the observed misses.",
                    "Inspect `stats items` for expired and reclaimed item counts.",
                    "Check whether the miss rate changes with cache warm-up or deployment events.",
                ]);
            if let Some(ratio_value) = ratio {
                r = r.with_evidence(Evidence::derived(
                    "hit_ratio",
                    format!("{ratio_value:.3}"),
                    "Derived from get_hits / (get_hits + get_misses); not a trend.",
                ));
            }
            if let Some(m) = memory {
                r = r.with_evidence(Evidence::derived(
                    "memory_utilization_pct",
                    format!("{m:.1}"),
                    "Derived from bytes / limit_maxbytes.",
                ));
            }
            r
        }
        "hit_ratio_insufficient_data" => RcaFinding::new(
            f.code,
            "There is not enough get traffic to attribute the hit ratio to a cause.",
            f.severity,
            Confidence::Insufficient,
            format!(
                "Only {} gets were observed; the existing rule requires at least 1000 before judging the ratio.",
                gets(stats)
            ),
        )
        .with_evidence(Evidence::stat(stats, "get_hits", EvidenceKind::Counter, None, "Cache hits since start."))
        .with_evidence(Evidence::stat(stats, "get_misses", EvidenceKind::Counter, None, "Cache misses since start."))
        .with_alternatives([
            "The instance is new or has served very little traffic.",
            "The counters were reset by a restart.",
            "The server is idle or not receiving the expected workload.",
        ])
        .with_checks([
            "Wait for a representative traffic window before judging the hit ratio.",
            "Compare with a peer node that has served similar traffic.",
        ]),
        "evictions" => {
            let (confidence, basis) = counter_confidence(uptime, memory);
            let rate = uptime.map(|u| {
                evictions.unwrap_or(0) as f64 / u.max(1) as f64
            });
            let mut r = RcaFinding::new(
                f.code,
                "Items are being evicted before expiry. The available evidence is consistent with the working set or slab-class demand exceeding the configured memory.",
                f.severity,
                confidence,
                basis,
            )
            .with_evidence(Evidence::stat(stats, "evictions", EvidenceKind::Counter, None, "Items evicted before expiry since start."))
            .with_evidence(Evidence::stat(stats, "uptime", EvidenceKind::Gauge, Some("s"), "Seconds since the last server start."))
            .with_evidence(Evidence::stat(stats, "curr_items", EvidenceKind::Gauge, None, "Items currently stored."))
            .with_evidence(Evidence::stat(stats, "total_items", EvidenceKind::Counter, None, "Items stored since start."))
            .with_alternatives([
                "A full cache with high churn is intentional.",
                "A short traffic burst filled the cache faster than the baseline rate suggests.",
                "One or two slab classes absorb most item sizes and run out first.",
                "The server restarted recently, so the cumulative rate is not steady state.",
            ])
            .with_checks([
                "Compare `bytes` and `limit_maxbytes` with the expected working set.",
                "Inspect `stats items` and `stats slabs` to find which classes are evicting.",
                "Check whether evictions persist after the current burst or deployment event.",
            ]);
            if let Some(m) = memory {
                r = r.with_evidence(Evidence::derived(
                    "memory_utilization_pct",
                    format!("{m:.1}"),
                    "Derived from bytes / limit_maxbytes.",
                ));
            }
            if let Some(rate) = rate {
                r = r.with_evidence(Evidence::derived(
                    "eviction_rate_per_second",
                    format!("{rate:.3}"),
                    "Average since start; this is a cumulative rate, not an instantaneous trend.",
                ));
            }
            r
        }
        "memory_near_limit" => {
            let confidence = if memory.is_some() {
                Confidence::High
            } else {
                Confidence::Low
            };
            let mut r = RcaFinding::new(
                f.code,
                "The cache is at or near its memory limit without evictions yet. A full cache is normal, but there is little headroom for additional data or slab growth.",
                f.severity,
                confidence,
                if memory.is_some() {
                    "Both the `bytes` gauge and the `limit_maxbytes` configuration value are present in the same snapshot."
                } else {
                    "One of the memory gauges is missing; the condition cannot be quantified from this snapshot."
                },
            )
            .with_evidence(Evidence::stat(stats, "bytes", EvidenceKind::Gauge, Some("bytes"), "Item data currently stored; excludes slab overhead."))
            .with_evidence(Evidence::stat(stats, "limit_maxbytes", EvidenceKind::Gauge, Some("bytes"), "Configured memory limit."))
            .with_alternatives([
                "A deliberately full cache is healthy.",
                "Slab and item overhead means the reported percentage is not a hard capacity boundary.",
                "A temporary data set may be released by TTL before eviction starts.",
            ])
            .with_checks([
                "Watch `evictions` and `evicted_unfetched` over a representative window.",
                "Compare the configured limit with the application's expected working set.",
            ]);
            if let Some(m) = memory {
                r = r.with_evidence(Evidence::derived(
                    "memory_utilization_pct",
                    format!("{m:.1}"),
                    "Derived from bytes / limit_maxbytes; a gauge at collection time, not a forecast.",
                ));
            }
            r
        }
        "connection_limit_hit" => {
            let confidence = if metric(stats, "listen_disabled_num").is_some() {
                Confidence::High
            } else {
                Confidence::Low
            };
            RcaFinding::new(
                f.code,
                "The server reached its connection limit at least once since start. New connections were refused while the limit was held.",
                f.severity,
                confidence,
                "`listen_disabled_num` is a cumulative counter, so a non-zero value is direct evidence that the condition occurred during this uptime.",
            )
            .with_evidence(Evidence::stat(stats, "listen_disabled_num", EvidenceKind::Counter, None, "Times the listener was disabled because the connection limit was reached."))
            .with_evidence(Evidence::stat(stats, "curr_connections", EvidenceKind::Gauge, None, "Connections currently open."))
            .with_evidence(Evidence::stat(settings, "maxconns", EvidenceKind::Configuration, None, "Configured maximum connections."))
            .with_alternatives([
                "A short connection burst reached the limit.",
                "Clients hold connections open longer than expected.",
                "The configured `maxconns` is too low for the workload.",
                "A restart makes an old counter look current.",
            ])
            .with_checks([
                "Compare `curr_connections` with `maxconns` over time.",
                "Inspect client connection pooling and idle timeouts.",
                "Check whether the event correlates with a deployment or traffic spike.",
            ])
        }
        "connections_near_limit" => {
            let confidence = if metric(settings, "maxconns").is_some() {
                Confidence::High
            } else {
                Confidence::Medium
            };
            let mut r = RcaFinding::new(
                f.code,
                "Connections are approaching the configured maximum. A further burst can reach the listener limit.",
                f.severity,
                confidence,
                "The current connection gauge and the configured maximum were present in the same snapshot.",
            )
            .with_evidence(Evidence::stat(stats, "curr_connections", EvidenceKind::Gauge, None, "Connections currently open."))
            .with_evidence(Evidence::stat(settings, "maxconns", EvidenceKind::Configuration, None, "Configured maximum connections."))
            .with_alternatives([
                "A normal traffic peak.",
                "Slow clients or missing connection pooling.",
                "The limit is intentionally sized for a lower concurrency.",
            ])
            .with_checks([
                "Check connection count at peak traffic.",
                "Review client keep-alive and pooling behavior.",
            ]);
            if let (Some(cur), Some(max)) = (metric(stats, "curr_connections"), metric(settings, "maxconns")) {
                if max > 0 {
                    r = r.with_evidence(Evidence::derived(
                        "connection_utilization_pct",
                        format!("{:.1}", cur as f64 / max as f64 * 100.0),
                        "Derived from curr_connections / maxconns; a gauge at collection time.",
                    ));
                }
            }
            r
        }
        "eviction_skew" => {
            let evicted = per_slab(items, "evicted");
            let total: u64 = evicted.iter().fold(0, |a, (_, n)| a.saturating_add(*n));
            let top = evicted.iter().max_by_key(|(_, n)| *n);
            let mut r = RcaFinding::new(
                f.code,
                "Evictions are concentrated in one slab class. The available evidence is consistent with an item-size distribution that does not fit the current slab layout or with one class being under-provisioned.",
                f.severity,
                Confidence::Medium,
                "Slab eviction counters are cumulative and are compared within this snapshot; exact slab memory pressure would require `stats slabs` and item-size history.",
            )
            .with_evidence(Evidence::derived(
                "evictions_in_skewed_classes",
                total.to_string(),
                "Sum of per-slab eviction counters in `stats items`.",
            ))
            .with_alternatives([
                "Traffic is naturally concentrated in one item size.",
                "The slab layout was not tuned for the current value sizes.",
                "A recent deployment changed the value-size distribution.",
            ])
            .with_checks([
                "Inspect `stats slabs` for class allocation and free chunks.",
                "Compare item sizes with the slab class boundaries.",
                "Check whether the skew persists across multiple samples.",
            ]);
            if let Some((slab, n)) = top {
                r = r.with_evidence(Evidence::new(
                    "top_evicting_slab",
                    EvidenceKind::Derived,
                    Some(format!("{slab}:{n}")),
                    None,
                    "Slab class with the largest eviction counter, followed by its count.",
                ));
            }
            r
        }
        _ => RcaFinding::new(
            f.code,
            format!("A diagnostic rule fired: {}", f.message),
            f.severity,
            Confidence::Medium,
            "The existing diagnostic rule fired on this snapshot, but this RCA layer has no additional enrichment for it.",
        )
        .with_checks(["Review the underlying diagnostic rule and the relevant stats group."]),
    }
}

fn inconsistency_finding(stats: &Stats, settings: &Stats) -> Option<RcaFinding> {
    let mut issues: Vec<(&'static str, String)> = Vec::new();
    let curr = metric(stats, "curr_items");
    let total = metric(stats, "total_items");
    let bytes = metric(stats, "bytes");
    let limit = metric(stats, "limit_maxbytes");
    let curr_conn = metric(stats, "curr_connections");
    let max_conn = metric(settings, "maxconns");
    let hits = metric(stats, "get_hits");
    let misses = metric(stats, "get_misses");
    let cmd_get = metric(stats, "cmd_get");
    let evictions = metric(stats, "evictions");

    if let (Some(c), Some(t)) = (curr, total) {
        if c > t {
            issues.push((
                "curr_items_gt_total_items",
                format!("curr_items={c} total_items={t}"),
            ));
        }
    }
    if let (Some(b), Some(l)) = (bytes, limit) {
        if b > l {
            issues.push((
                "bytes_gt_limit_maxbytes",
                format!("bytes={b} limit_maxbytes={l}"),
            ));
        }
        if l == 0 && b > 0 {
            issues.push((
                "zero_memory_limit_with_data",
                format!("bytes={b} limit_maxbytes=0"),
            ));
        }
    }
    if let (Some(c), Some(m)) = (curr_conn, max_conn) {
        if c > m {
            issues.push((
                "connections_gt_maxconns",
                format!("curr_connections={c} maxconns={m}"),
            ));
        }
    }
    if let (Some(h), Some(ms), Some(g)) = (hits, misses, cmd_get) {
        if h.saturating_add(ms) < g {
            issues.push((
                "hits_plus_misses_lt_cmd_get",
                format!("get_hits={h} get_misses={ms} cmd_get={g}"),
            ));
        }
    }
    if evictions.unwrap_or(0) > 0 && total == Some(0) {
        issues.push((
            "evictions_without_items",
            "evictions>0 total_items=0".to_owned(),
        ));
    }

    if issues.is_empty() {
        return None;
    }
    let mut r = RcaFinding::new(
        "inconsistent_statistics",
        "The statistics are internally inconsistent with a single healthy snapshot.",
        Severity::Warning,
        Confidence::High,
        "Arithmetic invariants that should hold in one complete `stats` response failed.",
    )
    .with_alternatives([
        "The server restarted or counters reset between the commands used to build the snapshot.",
        "A proxy or custom server merged responses from different instances.",
        "A non-standard memcached implementation reports overlapping or aliased fields.",
        "The values are malformed or truncated.",
    ])
    .with_checks([
        "Re-read `stats` once and verify the same values are returned consistently.",
        "Compare `uptime` and `version` with a known restart event.",
        "Check whether a proxy or sidecar is in the data path.",
    ]);
    for (metric, value) in issues {
        r = r.with_evidence(Evidence::new(
            metric,
            EvidenceKind::DataQuality,
            Some(value),
            None,
            "Two or more reported values cannot all describe the same healthy snapshot.",
        ));
    }
    Some(r)
}

fn ttl_finding(stats: &Stats) -> Option<RcaFinding> {
    let ratio = expired_ratio(stats)?;
    if ratio < 0.5 {
        return None;
    }
    let hit = hit_ratio(stats);
    let evictions = metric(stats, "evictions").unwrap_or(0);
    let severity = if hit.is_some_and(|h| h < 0.8) || evictions > 0 {
        Severity::Warning
    } else {
        Severity::Info
    };
    let uptime = metric(stats, "uptime");
    let confidence = if uptime.is_some_and(|u| u >= MIN_STABLE_UPTIME_SECS) {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let mut r = RcaFinding::new(
        "ttl_or_expiry_pressure",
        "A large share of stored items expired before being fetched. TTL or the interval between writes and reads is consistent with expiry-driven misses.",
        severity,
        confidence,
        if uptime.is_some_and(|u| u >= MIN_STABLE_UPTIME_SECS) {
            "The expired-unfetched counter is large relative to total_items over a stable uptime window; the counter is cumulative, not a trend."
        } else {
            "The expired-unfetched counter is large relative to total_items, but uptime is short or missing, so the rate may not be steady state."
        },
    )
    .with_evidence(Evidence::stat(stats, "expired_unfetched", EvidenceKind::Counter, None, "Items that expired before being fetched since start."))
    .with_evidence(Evidence::stat(stats, "total_items", EvidenceKind::Counter, None, "Items stored since start."))
    .with_evidence(Evidence::derived(
        "expired_unfetched_ratio",
        format!("{ratio:.3}"),
        "Derived from expired_unfetched / total_items; not a trend.",
    ))
    .with_alternatives([
        "The data is intentionally write-only or read very rarely.",
        "TTLs are shorter than the application's read interval.",
        "A restart or counter reset makes the ratio unrepresentative.",
        "A clock change on the server affected expiry.",
    ])
    .with_checks([
        "Review the application's TTL policy and read cadence.",
        "Inspect `stats items` for expired and reclaimed counts.",
        "Compare the ratio after a fixed observation window.",
    ]);
    if let Some(h) = hit {
        r = r.with_evidence(Evidence::derived(
            "hit_ratio",
            format!("{h:.3}"),
            "Derived from get_hits / (get_hits + get_misses); evidence for the impact, not proof of the cause.",
        ));
    }
    Some(r)
}

fn short_uptime_finding(stats: &Stats) -> Option<RcaFinding> {
    let uptime = metric(stats, "uptime")?;
    if uptime >= MIN_STABLE_UPTIME_SECS {
        return None;
    }
    let activity = metric(stats, "get_hits")
        .unwrap_or(0)
        .saturating_add(metric(stats, "get_misses").unwrap_or(0))
        .saturating_add(metric(stats, "total_items").unwrap_or(0))
        .saturating_add(metric(stats, "evictions").unwrap_or(0))
        .saturating_add(metric(stats, "cmd_get").unwrap_or(0));
    if activity == 0 {
        return None;
    }
    Some(
        RcaFinding::new(
            "short_uptime",
            "The server restarted or started recently. Cumulative counters have not yet reached a steady-state window.",
            Severity::Info,
            Confidence::High,
            format!(
                "`uptime` is {uptime} s, below the {MIN_STABLE_UPTIME_SECS} s window used by this RCA layer; counters reset at server start."
            ),
        )
        .with_evidence(Evidence::stat(stats, "uptime", EvidenceKind::Gauge, Some("s"), "Seconds since the last server start."))
        .with_evidence(Evidence::derived(
            "observed_counter_activity",
            activity.to_string(),
            "Sum of selected cumulative counters; used only to distinguish an idle fresh server from an active short-lived one.",
        ))
        .with_alternatives([
            "A planned restart or deployment.",
            "A new instance that has just joined the pool.",
            "A crash/restart that also reset counters.",
        ])
        .with_checks([
            "Wait for at least one stable observation window before comparing rates.",
            "Check restart events and compare with a peer instance.",
        ]),
    )
}

fn missing_metrics(stats: &Stats, settings: &Stats) -> Vec<String> {
    let mut missing = Vec::new();
    for key in [
        "get_hits",
        "get_misses",
        "bytes",
        "limit_maxbytes",
        "curr_items",
        "curr_connections",
        "evictions",
        "uptime",
        "total_items",
    ] {
        if metric(stats, key).is_none() {
            missing.push(key.to_owned());
        }
    }
    if metric(settings, "maxconns").is_none() {
        missing.push("settings.maxconns".to_owned());
    }
    missing.sort();
    missing
}

fn core_missing(stats: &Stats, _settings: &Stats) -> bool {
    // `stats settings` is optional on older servers. Its absence reduces connection-related
    // confidence and is listed in missing_evidence, but it does not make the whole snapshot
    // unusable for hit-ratio, memory, eviction or uptime analysis.
    metric(stats, "get_hits").is_none()
        || metric(stats, "get_misses").is_none()
        || metric(stats, "bytes").is_none()
        || metric(stats, "limit_maxbytes").is_none()
        || metric(stats, "evictions").is_none()
        || metric(stats, "uptime").is_none()
}

fn insufficient_finding(missing: &[String]) -> RcaFinding {
    let mut r = RcaFinding::new(
        "insufficient_evidence",
        "There is not enough of the expected statistics to support a root-cause conclusion.",
        Severity::Info,
        Confidence::Insufficient,
        format!(
            "At least one core metric family is missing from the snapshot ({}).",
            missing.join(", ")
        ),
    )
    .with_alternatives([
        "The server is an older or restricted implementation that omits some `stats` keys.",
        "The stats response was partial or the connection ended early.",
        "A proxy filters or rewrites statistics.",
    ])
    .with_checks([
        "Run `get_stats` and confirm the missing keys are absent at the server.",
        "Check the server version and whether a proxy is in the path.",
        "Compare with a peer node that reports the complete set.",
    ]);
    for key in missing.iter().take(MAX_EVIDENCE) {
        r = r.with_evidence(Evidence::new(
            key,
            EvidenceKind::DataQuality,
            None,
            None,
            "Expected metric is missing or not parseable as an unsigned integer.",
        ));
    }
    r
}

fn summary_for(status: AnalysisStatus, findings: &[RcaFinding]) -> String {
    match status {
        AnalysisStatus::Healthy => {
            "No evidence of resource exhaustion or configuration pressure in this snapshot."
                .to_owned()
        }
        AnalysisStatus::Actionable => findings.first().map_or_else(
            || {
                "Actionable findings were reported, but no primary hypothesis is available."
                    .to_owned()
            },
            |f| {
                format!(
                    "{} finding(s) at warning or critical severity. Primary hypothesis: {}",
                    findings.len(),
                    f.suspected_cause
                )
            },
        ),
        AnalysisStatus::Partial => {
            "The available evidence is incomplete; conclusions are limited to the observed subset."
                .to_owned()
        }
        AnalysisStatus::InsufficientEvidence => {
            "Insufficient statistics to support a root-cause conclusion.".to_owned()
        }
    }
}

/// Analyzes one memcached node from a single snapshot. The function is pure and deterministic.
pub fn analyze_node(target: &str, stats: &Stats, items: &Stats, settings: &Stats) -> RcaReport {
    let mut report = RcaReport::new("memcached_node", target);
    let mut findings: Vec<RcaFinding> = base_analyze_node(stats, items, settings)
        .into_iter()
        .map(|f| enrich_base_finding(f, stats, items, settings))
        .collect();

    if let Some(f) = inconsistency_finding(stats, settings) {
        findings.push(f);
    }
    if let Some(f) = ttl_finding(stats) {
        findings.push(f);
    }
    if let Some(f) = short_uptime_finding(stats) {
        findings.push(f);
    }

    let missing = missing_metrics(stats, settings);
    let core_missing = core_missing(stats, settings);
    if core_missing && !findings.iter().any(|f| f.severity >= Severity::Warning) {
        findings.push(insufficient_finding(&missing));
    }

    report.findings = findings;
    report.sort_findings();
    report.missing_evidence = missing;
    report.limitations = vec![
        "Single snapshot: cumulative counters are not differenced against a previous sample, so trends and counter resets cannot be confirmed.".to_owned(),
        "Findings are evidence-based hypotheses; correlation does not prove causation.".to_owned(),
        "Gauge values describe one collection instant, not a high-water mark.".to_owned(),
    ];
    if metric(stats, "uptime").is_none_or(|u| u < MIN_STABLE_UPTIME_SECS) {
        report.limitations.push(
            "Uptime is short or unknown; counter-based rates may not represent steady state."
                .to_owned(),
        );
    }
    if !report.missing_evidence.is_empty() {
        report.limitations.push(
            "Some expected metrics are missing or malformed; confidence is reduced and missing evidence is listed."
                .to_owned(),
        );
    }

    report.status = if report.has_actionable_finding() {
        AnalysisStatus::Actionable
    } else if core_missing || stats.is_empty() {
        AnalysisStatus::InsufficientEvidence
    } else {
        AnalysisStatus::Healthy
    };
    report.summary = summary_for(report.status, &report.findings);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn finding<'a>(report: &'a RcaReport, id: &str) -> &'a RcaFinding {
        report
            .findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("missing finding {id}: {:?}", report.findings))
    }

    #[test]
    fn healthy_node_has_no_false_positive() {
        let (stats, items, settings) = healthy();
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.schema_version, RCA_SCHEMA_VERSION);
        assert_eq!(report.analysis, "memcached_node");
        assert_eq!(report.status, AnalysisStatus::Healthy);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn high_eviction_pressure_is_actionable_and_evidence_based() {
        let (mut stats, items, settings) = healthy();
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "20000".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        assert_eq!(report.status, AnalysisStatus::Actionable);
        let f = finding(&report, "evictions");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::High);
        assert!(f.evidence.iter().any(|e| e.metric == "evictions"));
        assert!(f
            .evidence
            .iter()
            .any(|e| e.metric == "memory_utilization_pct"));
        assert!(!f.alternative_explanations.is_empty());
        assert!(!f.recommended_checks.is_empty());
    }

    #[test]
    fn memory_near_limit_is_reported_without_eviction_certainty() {
        let (mut stats, items, settings) = healthy();
        stats.insert("bytes".into(), "95".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "memory_near_limit");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn low_hit_ratio_without_evictions_points_away_from_memory_pressure() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), "300".into());
        stats.insert("get_misses".into(), "700".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "hit_ratio_low");
        assert!(
            f.suspected_cause.contains("without eviction pressure"),
            "{}",
            f.suspected_cause
        );
        assert!(!report.findings.iter().any(|f| f.id == "evictions"));
    }

    #[test]
    fn low_hit_ratio_without_eviction_metric_does_not_exclude_memory_pressure() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), "300".into());
        stats.insert("get_misses".into(), "700".into());
        stats.remove("evictions");
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "hit_ratio_low");
        assert_eq!(f.confidence, Confidence::Low);
        assert!(f.suspected_cause.contains("cannot be excluded"));
        assert!(report.missing_evidence.contains(&"evictions".to_owned()));
    }

    #[test]
    fn slab_imbalance_is_correlated_with_item_size_distribution() {
        let (stats, mut items, settings) = healthy();
        items.insert("items:1:number".into(), "10".into());
        items.insert("items:2:number".into(), "10".into());
        items.insert("items:3:number".into(), "10".into());
        items.insert("items:1:evicted".into(), "900".into());
        items.insert("items:2:evicted".into(), "50".into());
        items.insert("items:3:evicted".into(), "50".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "eviction_skew");
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(f.suspected_cause.contains("slab"));
    }

    #[test]
    fn connection_saturation_is_enriched() {
        let (mut stats, items, settings) = healthy();
        stats.insert("listen_disabled_num".into(), "2".into());
        stats.insert("curr_connections".into(), "90".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "connection_limit_hit");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Confidence::High);
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "connections_near_limit"));
    }

    #[test]
    fn missing_core_stats_are_explicit() {
        let report = analyze_node("cache:11211", &Stats::new(), &Stats::new(), &Stats::new());
        assert_eq!(report.status, AnalysisStatus::InsufficientEvidence);
        let f = finding(&report, "insufficient_evidence");
        assert_eq!(f.confidence, Confidence::Insufficient);
        assert!(report.missing_evidence.contains(&"get_hits".to_owned()));
    }

    #[test]
    fn inconsistent_statistics_are_flagged() {
        let (mut stats, items, settings) = healthy();
        stats.insert("curr_items".into(), "20000".into());
        stats.insert("total_items".into(), "10000".into());
        stats.insert("bytes".into(), "150".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "inconsistent_statistics");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f
            .evidence
            .iter()
            .any(|e| e.metric == "curr_items_gt_total_items"));
    }

    #[test]
    fn short_uptime_reduces_counter_certainty() {
        let (mut stats, items, settings) = healthy();
        stats.insert("uptime".into(), "10".into());
        stats.insert("evictions".into(), "5000".into());
        stats.insert("bytes".into(), "95".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "evictions");
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(finding(&report, "short_uptime").confidence == Confidence::High);
    }

    #[test]
    fn ttl_expiry_pressure_is_a_hypothesis_not_a_certainty() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), "700".into());
        stats.insert("get_misses".into(), "300".into());
        stats.insert("total_items".into(), "1000".into());
        stats.insert("expired_unfetched".into(), "700".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let f = finding(&report, "ttl_or_expiry_pressure");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.confidence <= Confidence::Medium);
        assert!(!f.alternative_explanations.is_empty());
    }

    #[test]
    fn hostile_numbers_do_not_panic_or_overflow() {
        let (mut stats, items, settings) = healthy();
        stats.insert("get_hits".into(), u64::MAX.to_string());
        stats.insert("get_misses".into(), u64::MAX.to_string());
        stats.insert("bytes".into(), "not-a-number".into());
        stats.insert("expired_unfetched".into(), "999999999999999999999".into());
        let report = analyze_node("cache:11211", &stats, &items, &settings);
        let _ = report.summary;
        assert!(report.missing_evidence.contains(&"bytes".to_owned()));
    }

    #[test]
    fn deterministic_ordering_and_ids() {
        let (mut stats, items, settings) = healthy();
        stats.insert("bytes".into(), "95".into());
        stats.insert("evictions".into(), "5000".into());
        stats.insert("listen_disabled_num".into(), "1".into());
        let a = analyze_node("cache:11211", &stats, &items, &settings);
        let b = analyze_node("cache:11211", &stats, &items, &settings);
        assert_eq!(a, b);
        let ids: Vec<_> = a.findings.iter().map(|f| f.id.clone()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        // The first finding is critical; the exact tie-breaker is id, so compare the ids after
        // removing severity ordering by checking the report is identical on repeat.
        assert_eq!(a.findings, b.findings);
        assert!(sorted.contains(&"evictions".to_owned()));
    }
}
