//! Read-only migration advice composed from structural routing impact and optional cluster
//! comparison. It never moves data, changes configuration or claims exact key movement.

use serde::Serialize;

use diagnostics::clusters::ClusterCompareReport;
use diagnostics::Severity;

use crate::routing::{compare_routing, RoutingImpact};

pub const MIGRATION_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MigrationRisk {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VersionCompatibility {
    pub current: Option<String>,
    pub target: Option<String>,
    pub target_parsed: bool,
    pub downgrade: bool,
    pub built_in_proxy_available: Option<bool>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WarmupGuidance {
    pub cold_cache_expected: bool,
    pub warmup_configured: bool,
    pub implications: Vec<String>,
    pub validation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MigrationReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub routing: RoutingImpact,
    pub compatibility: VersionCompatibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_comparison: Option<ClusterCompareReport>,
    pub warmup: WarmupGuidance,
    pub risks: Vec<MigrationRisk>,
    pub rollback: Vec<String>,
    pub requires_human_approval: bool,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

fn parse_version(raw: &str) -> Option<Version> {
    let mut parts = raw.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split('-')
        .next()?
        .parse()
        .ok()?;
    Some(Version(major, minor, patch))
}

fn risk(
    code: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
) -> MigrationRisk {
    MigrationRisk {
        code,
        severity,
        confidence,
        message,
    }
}

/// Analyze a current/proposed mcrouter configuration and optional current/target cluster snapshots.
/// `current_config` and `proposed_config` are JSON data and are never executed.
#[allow(clippy::too_many_arguments)]
pub fn advise(
    current_config: &str,
    proposed_config: &str,
    current_version: Option<&str>,
    target_version: Option<&str>,
    capacity_comparison: Option<ClusterCompareReport>,
) -> Result<MigrationReport, String> {
    let routing = compare_routing(current_config, proposed_config)?;
    let mut risks = Vec::new();
    let changed = routing.status == "review";
    if !routing.pools_added.is_empty() || !routing.pools_removed.is_empty() {
        risks.push(risk(
            "pool_topology_change",
            Severity::Warning,
            "high",
            format!(
                "Pool topology changes: {} added, {} removed. Key placement changes are not simulated.",
                routing.pools_added.len(),
                routing.pools_removed.len()
            ),
        ));
    }
    if !routing.destinations_added.is_empty() || !routing.destinations_removed.is_empty() {
        risks.push(risk(
            "backend_membership_change",
            Severity::Warning,
            "high",
            format!(
                "Backend membership changes: {} added, {} removed. The cache starts cold for affected keys.",
                routing.destinations_added.len(),
                routing.destinations_removed.len()
            ),
        ));
    }
    if routing.feature_changes.iter().any(|f| f == "failover") {
        risks.push(risk(
            "failover_semantics_change",
            Severity::Warning,
            "medium",
            "Failover presence changed. Verify failover_errors, confidence/scope and behavior with live traces.".to_owned(),
        ));
    }
    if changed {
        risks.push(risk(
            "routing_equivalence_unknown",
            Severity::Warning,
            "unknown",
            "Structural comparison cannot establish routing equivalence. Offline hash simulation is unsupported; use live mcrouter route traces before cutover.".to_owned(),
        ));
    }
    let current_v = current_version.and_then(parse_version);
    let target_v = target_version.and_then(parse_version);
    let mut notes = Vec::new();
    let mut compatibility = VersionCompatibility {
        current: current_version.map(str::to_owned),
        target: target_version.map(str::to_owned),
        target_parsed: target_v.is_some(),
        downgrade: false,
        built_in_proxy_available: target_v.map(|v| v >= Version(1, 6, 23)),
        notes: Vec::new(),
    };
    if current_version.is_some() && current_v.is_none() {
        notes.push("current version could not be parsed".to_owned());
    }
    if target_version.is_some() && target_v.is_none() {
        notes.push("target version could not be parsed".to_owned());
    }
    if let (Some(a), Some(b)) = (current_v, target_v) {
        compatibility.downgrade = b < a;
        if b < a {
            risks.push(risk(
                "version_downgrade",
                Severity::Warning,
                "high",
                format!("Target version {b:?} is older than current {a:?}; review feature compatibility before migration."),
            ));
        }
        if b < Version(1, 6, 23) {
            notes.push("target predates the Memcached built-in proxy (1.6.23)".to_owned());
        }
    }
    compatibility.notes = notes;
    let mut missing = Vec::new();
    if current_version.is_none() || target_version.is_none() {
        missing.push("current/target server version".to_owned());
    }
    let capacity_changed = capacity_comparison.as_ref().is_some_and(|c| {
        c.findings.iter().any(|f| {
            matches!(
                f.code,
                "memory_utilization_difference"
                    | "hit_ratio_difference"
                    | "eviction_pressure_difference"
                    | "backend_availability_difference"
                    | "partial_cluster_coverage"
            )
        })
    });
    if let Some(c) = &capacity_comparison {
        for f in &c.findings {
            if f.severity >= Severity::Warning {
                risks.push(risk(
                    "capacity_or_availability_difference",
                    f.severity,
                    f.confidence,
                    f.message.clone(),
                ));
            }
        }
        if c.clusters
            .iter()
            .any(|s| s.memory.utilization_pct.is_some_and(|u| u >= 90.0))
        {
            risks.push(risk(
                "target_capacity_pressure",
                Severity::Warning,
                "high",
                "At least one compared cluster already has high observed memory utilization; migration may not have headroom.".to_owned(),
            ));
        }
    } else {
        missing.push("current/target cluster snapshots for capacity comparison".to_owned());
    }
    let cold = changed || capacity_changed;
    let warmup_configured =
        routing.proposed.features.warm_up || routing.proposed.features.migration;
    let warmup = WarmupGuidance {
        cold_cache_expected: cold,
        warmup_configured,
        implications: if cold {
            vec![
                "Keys whose placement changes can start cold; expect misses and backend load during warmup.".to_owned(),
                "No exact key-movement estimate is produced without a validated routing simulator.".to_owned(),
            ]
        } else {
            vec!["No structural placement change was detected; behavioral equivalence is still not claimed.".to_owned()]
        },
        validation: vec![
            "Canary a small traffic slice and compare live route traces, hit ratio, latency and backend load.".to_owned(),
            "Pre-warm or use a warm-up route where supported; never assume the target is already warm.".to_owned(),
        ],
    };
    let mut rollback = vec![
        "Retain the previous mcrouter configuration and a verified rollback procedure.".to_owned(),
        "Validate that the old config still passes allowlist/auth/deadline and route-trace checks.".to_owned(),
        "Do not move or delete old cache data until the new route has been observed through a full rollback window.".to_owned(),
    ];
    if capacity_comparison.is_some() {
        rollback.push(
            "Keep the current capacity baseline snapshots for post-rollback comparison.".to_owned(),
        );
    }
    risks.sort_by_key(|r| std::cmp::Reverse(r.severity));
    let status = if risks.iter().any(|r| r.severity >= Severity::Warning) {
        "review"
    } else {
        "advisory"
    };
    let summary = if changed || capacity_changed {
        format!(
            "Migration review required: {} structural routing change(s), {} capacity/availability finding(s), cold-cache expected={cold}. Routing equivalence and exact key movement are UNKNOWN.",
            routing.pools_added.len()
                + routing.pools_removed.len()
                + routing.destinations_added.len()
                + routing.destinations_removed.len()
                + routing.handle_changes.len(),
            capacity_comparison.as_ref().map_or(0, |c| c.findings.len())
        )
    } else {
        "No structural or observed capacity difference was detected; migration still requires live route-trace validation and human approval.".to_owned()
    };
    Ok(MigrationReport {
        schema_version: MIGRATION_SCHEMA_VERSION,
        analysis: "cache_migration_advisor",
        status,
        summary,
        routing,
        compatibility,
        capacity_comparison,
        warmup,
        risks,
        rollback,
        requires_human_approval: true,
        missing_evidence: missing,
        limitations: vec![
            "Read-only advice: no config, data, routing, failover or infrastructure change is performed.".to_owned(),
            "Structural routing comparison is not a hash/route simulator; exact key movement is not claimed.".to_owned(),
            "Capacity comparisons use supplied snapshots only; missing metrics are not inferred.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: &str =
        r#"{"pools":{"a":{"servers":["a:1"]},"b":{"servers":["b:1"]}},"route":"PoolRoute|a"}"#;
    const PROPOSED: &str = r#"{"pools":{"a":{"servers":["a:1"]},"c":{"servers":["c:1"]}},"route":{"type":"FailoverRoute","children":["PoolRoute|a","PoolRoute|c"]}}"#;

    #[test]
    fn flags_topology_and_failover_change() {
        let r = advise(CURRENT, PROPOSED, Some("1.6.45"), Some("1.6.45"), None).unwrap();
        assert_eq!(r.status, "review");
        assert!(r
            .risks
            .iter()
            .any(|x| x.code == "backend_membership_change"));
        assert!(r
            .risks
            .iter()
            .any(|x| x.code == "failover_semantics_change"));
        assert!(r.warmup.cold_cache_expected);
        assert!(r.requires_human_approval);
    }

    #[test]
    fn version_and_rollback_are_explicit() {
        let r = advise(CURRENT, CURRENT, Some("1.6.45"), Some("1.5.22"), None).unwrap();
        assert!(r.compatibility.downgrade);
        assert_eq!(r.compatibility.built_in_proxy_available, Some(false));
        assert!(!r.rollback.is_empty());
    }
}
