//! Root-cause analysis for an mcrouter snapshot.
//!
//! This module is pure: the MCP layer collects one router config/stats snapshot and, when the
//! destination map allows it, one observation per reachable destination. The analysis reuses the
//! existing `analyze_config`, `analyze_stats`, `diagnose_failover` and `diagnostics::analyze_node`
//! rules instead of defining a second diagnostic engine.

use std::collections::BTreeMap;

use diagnostics::rca::{
    AnalysisStatus, Confidence, Coverage, Evidence, EvidenceKind, RcaFinding, RcaReport,
};
use diagnostics::{analyze_node, compare_nodes, NodeSummary, Severity, Stats};

use crate::{analyze_config, diagnose_failover, ConfigSummary, FailoverScope};

/// One configured destination that was actually probed. Names are intentionally not stored;
/// output only reports aggregate counts so a large or sensitive topology is not echoed back.
#[derive(Debug, Clone)]
pub struct DestinationObservation {
    /// Opaque, stable identity used by snapshots; RCA output does not expose it.
    pub id: String,
    pub reachable: bool,
    pub stats: Option<Stats>,
    pub items: Stats,
    pub settings: Stats,
}

pub struct McrouterRcaInput<'a> {
    pub target: &'a str,
    pub config: &'a ConfigSummary,
    pub router_stats: &'a Stats,
    pub destinations: &'a [DestinationObservation],
    pub coverage: Coverage,
}

fn metric(stats: &Stats, key: &str) -> Option<u64> {
    stats.get(key)?.parse().ok()
}

fn scope_name(scope: FailoverScope) -> String {
    match scope {
        FailoverScope::None => "none",
        FailoverScope::Root => "root",
        FailoverScope::Nested => "nested",
        FailoverScope::NoRoute => "no_route",
    }
    .to_owned()
}

fn scope_confidence(scope: FailoverScope) -> (Confidence, String) {
    match scope {
        FailoverScope::None => (
            Confidence::High,
            "No failover handle appears anywhere in the parsed route tree.".to_owned(),
        ),
        FailoverScope::Root => (
            Confidence::Medium,
            "The route itself is a failover handle, but its failover_errors and covered operations are not checked; the scope is inferred from the config shape.".to_owned(),
        ),
        FailoverScope::Nested => (
            Confidence::Low,
            "A failover handle is nested below other route handles; which keys and operations reach it is unknown.".to_owned(),
        ),
        FailoverScope::NoRoute => (
            Confidence::Low,
            "The config has no route to analyse; route coverage is unknown.".to_owned(),
        ),
    }
}

fn config_finding(config: &ConfigSummary) -> Option<RcaFinding> {
    let findings = analyze_config(config);
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut severity = Severity::Info;
    for f in &findings {
        *counts.entry(f.code).or_default() += 1;
        severity = severity.max(f.severity);
    }
    let no_route = config.failover_scope == FailoverScope::NoRoute;
    if counts.is_empty() && !no_route {
        return None;
    }

    let mut r = RcaFinding::new(
        "routing_configuration",
        "The parsed route configuration has unresolved, empty, unused or duplicate pool references, or no route at all. The available evidence points to a routing/configuration problem rather than a data-path resource problem.",
        if no_route { Severity::Warning } else { severity },
        if no_route {
            Confidence::Medium
        } else {
            Confidence::High
        },
        if no_route {
            "No route section was present in the parsed config; inline or dynamically generated routes cannot be inspected from this snapshot.".to_owned()
        } else {
            "The finding is derived from the running config; inline pool definitions are not listed and may explain an undefined reference.".to_owned()
        },
    )
    .with_alternatives([
        "The route uses inline pool definitions that this analyzer does not enumerate.",
        "The config is intentionally staged or a pool is temporarily unused.",
        "A deployment is in progress and the running config is between versions.",
        "The mcrouter config format is newer or differs from the assumptions in this analyzer.",
    ])
    .with_checks([
        "Inspect `__mcrouter__.preprocessed_config` and verify every referenced pool.",
        "Check whether an undefined pool is defined inline.",
        "Compare the running config with the intended deployment config.",
    ]);
    for (code, n) in counts {
        r = r.with_evidence(Evidence::new(
            code,
            EvidenceKind::Configuration,
            Some(n.to_string()),
            None,
            "Number of parsed-config findings with this code.",
        ));
    }
    if no_route {
        r = r.with_evidence(Evidence::new(
            "route_present",
            EvidenceKind::Configuration,
            Some("false".to_owned()),
            None,
            "The parsed config did not contain a route or routes section.",
        ));
    }
    Some(r)
}

fn backend_health(input: &McrouterRcaInput<'_>, findings: &mut Vec<RcaFinding>) {
    let router = input.router_stats;
    let total = metric(router, "num_servers");
    let down = metric(router, "num_servers_down");
    let suspect = metric(router, "num_suspect_servers");
    let observed = input.destinations.len();
    let reachable = input.destinations.iter().filter(|d| d.reachable).count();
    let unreachable = observed.saturating_sub(reachable);
    let all_router_down = total.is_some_and(|t| t > 0 && down.unwrap_or(0) >= t);
    let all_probed_down = observed > 0 && reachable == 0;
    let any_down = down.unwrap_or(0) > 0;
    if !any_down && unreachable == 0 && suspect.unwrap_or(0) == 0 {
        return;
    }

    let severity = if all_router_down || all_probed_down {
        Severity::Critical
    } else {
        Severity::Warning
    };
    let confidence = if input.coverage.complete && observed > 0 && total.is_some() {
        Confidence::High
    } else if observed > 0 || total.is_some() {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let mut r = RcaFinding::new(
        "backend_unavailable",
        if all_router_down || all_probed_down {
            "All declared or observed backend destinations are unavailable. The available evidence is consistent with a total backend outage, a network partition, or a health-check failure."
        } else {
            "One or more backend destinations are unavailable or suspect. Requests hashed to them may fail or look like misses when no failover is configured."
        },
        severity,
        confidence,
        if input.coverage.complete {
            "The router stats report and all configured destinations were probed; the observed failure is not a sampling gap."
        } else {
            "The router stats report is available, but destination coverage is partial; the count may understate the outage."
        },
    )
    .with_evidence(Evidence::stat(router, "num_servers", EvidenceKind::Gauge, None, "Destinations known to mcrouter."))
    .with_evidence(Evidence::stat(router, "num_servers_down", EvidenceKind::Gauge, None, "Destinations currently marked down."))
    .with_evidence(Evidence::stat(router, "num_suspect_servers", EvidenceKind::Gauge, None, "Destinations marked suspect after recent failures."))
    .with_evidence(Evidence::derived(
        "probed_destinations",
        observed.to_string(),
        "Destinations this RCA call attempted to observe.",
    ))
    .with_evidence(Evidence::derived(
        "reachable_destinations",
        reachable.to_string(),
        "Destinations that answered the probe.",
    ))
    .with_evidence(Evidence::derived(
        "unreachable_destinations",
        unreachable.to_string(),
        "Destinations that did not answer the probe.",
    ))
    .with_alternatives([
        "A network partition or firewall change isolated one or more backends.",
        "A backend process restarted or was removed from the pool.",
        "mcrouter's health-check thresholds are too aggressive or too slow for the current latency.",
        "The destination map or allowlist points at the wrong address.",
    ])
    .with_checks([
        "Check backend process and network health outside this read-only analysis.",
        "Compare `num_servers_down` with the destination probes and mcrouter logs.",
        "Inspect failover configuration and whether it covers the affected operations.",
        "Verify `MEMCACHED_MCP_DEST_MAP` and allowlist entries for the affected destinations.",
    ]);
    if let Some(s) = suspect {
        if s > 0 {
            r = r.with_evidence(Evidence::derived(
                "suspect_destinations",
                s.to_string(),
                "Destinations with recent failures that may not be marked down yet.",
            ));
        }
    }
    findings.push(r);
}

fn failover_findings(input: &McrouterRcaInput<'_>, findings: &mut Vec<RcaFinding>) {
    for f in diagnose_failover(input.config, input.router_stats) {
        let (cause, confidence, basis) = match f.code {
            "down_without_failover" => (
                "Backends are down and the route has no failover handle. Writes to their keys fail and reads can look like misses, so the cache silently loses hit ratio.",
                if input.coverage.complete {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                if input.coverage.complete {
                    "The route tree has no failover handle and the router/destination evidence is complete for the observed topology."
                } else {
                    "The route tree has no failover handle, but destination coverage is partial; the impact may be understated."
                }
                .to_owned(),
            ),
            "failover_active" => (
                "A failover handle is active while one or more destinations are down. Traffic for affected keys should use the fallback, but the exact operations and error classes are not proven by the config.",
                scope_confidence(input.config.failover_scope).0,
                scope_confidence(input.config.failover_scope).1,
            ),
            "failover_capacity" => (
                "Half or more destinations are down while failover is active. The remaining destinations may be carrying the full load and can become the next bottleneck.",
                Confidence::Medium,
                "The capacity warning is inferred from the down/total ratio; it is not a measured throughput limit.".to_owned(),
            ),
            "no_failover_configured" => (
                "No failover handle is configured. Losing a destination will fail writes for its keys and turn reads into misses until the destination recovers.",
                Confidence::High,
                "The absence of a failover handle is confirmed by the parsed route tree; operational impact still depends on the workload.".to_owned(),
            ),
            _ => (
                "The existing failover diagnostic rule fired; the available evidence supports a failover-related hypothesis.",
                Confidence::Medium,
                "The diagnosis reuses the existing failover rules and does not add historical evidence.".to_owned(),
            ),
        };
        let mut r = RcaFinding::new(f.code, cause, f.severity, confidence, basis)
            .with_evidence(Evidence::stat(
                input.router_stats,
                "num_servers",
                EvidenceKind::Gauge,
                None,
                "Destinations known to mcrouter.",
            ))
            .with_evidence(Evidence::stat(
                input.router_stats,
                "num_servers_down",
                EvidenceKind::Gauge,
                None,
                "Destinations currently marked down.",
            ))
            .with_evidence(Evidence::derived(
                "failover_scope",
                scope_name(input.config.failover_scope),
                "Where the failover handle sits in the parsed route tree.",
            ))
            .with_alternatives([
                "The route intentionally trades availability for strict consistency.",
                "A nested failover handle covers only some operations or error classes.",
                "The destination is expected to recover before failover triggers.",
            ])
            .with_checks([
                "Inspect the route's `failover_errors` and operation policies.",
                "Verify whether reads and writes both fail over.",
                "Compare the current route config with the intended availability policy.",
            ]);
        if f.code == "failover_active" {
            r = r.with_evidence(Evidence::new(
                "failover_confidence",
                EvidenceKind::Configuration,
                Some(input.config.failover_scope.confidence().to_owned()),
                None,
                "Existing failover confidence: confirmed, inferred or unknown based on route-tree placement.",
            ));
        }
        findings.push(r);
    }
}

fn destination_pressure(input: &McrouterRcaInput<'_>, findings: &mut Vec<RcaFinding>) {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut reachable = 0usize;
    for obs in input.destinations.iter().filter(|d| d.reachable) {
        let Some(stats) = &obs.stats else {
            continue;
        };
        reachable += 1;
        for f in analyze_node(stats, &obs.items, &obs.settings) {
            if f.severity >= Severity::Warning {
                *counts.entry(f.code).or_default() += 1;
            }
        }
    }
    if counts.is_empty() || reachable == 0 {
        return;
    }
    let mut r = RcaFinding::new(
        "destination_pressure",
        "One or more reachable destinations show warning-level or critical resource pressure (evictions, low hit ratio, connection pressure, or slab imbalance). Uneven routing or under-provisioned backends are plausible explanations.",
        Severity::Warning,
        if input.coverage.complete {
            Confidence::High
        } else {
            Confidence::Medium
        },
        if input.coverage.complete {
            "All configured destinations were probed and the existing per-node rules fired on the observed snapshot."
        } else {
            "Only part of the destination set was probed; this count is a lower bound."
        },
    )
    .with_evidence(Evidence::derived(
        "reachable_destinations_analyzed",
        reachable.to_string(),
        "Destinations with a complete stats/items/settings snapshot.",
    ))
    .with_alternatives([
        "Different pools intentionally serve different data and load.",
        "Hashing or key distribution sends disproportionate traffic to one destination.",
        "One backend has a smaller memory or connection budget.",
        "Normal churn on a deliberately full cache.",
    ])
    .with_checks([
        "Compare memory, eviction and hit-ratio counters per destination.",
        "Check pool sizes and mcrouter hashing/key distribution.",
        "Inspect whether the pressure is confined to one pool or shared across pools.",
    ]);
    for (code, n) in counts {
        r = r.with_evidence(Evidence::new(
            code,
            EvidenceKind::Derived,
            Some(n.to_string()),
            None,
            "Number of reachable destinations where this existing diagnostic code fired.",
        ));
    }
    findings.push(r);
}

fn cluster_imbalance(input: &McrouterRcaInput<'_>, findings: &mut Vec<RcaFinding>) {
    let stats: Vec<&Stats> = input
        .destinations
        .iter()
        .filter(|d| d.reachable)
        .filter_map(|d| d.stats.as_ref())
        .collect();
    if stats.len() < 3 {
        return;
    }
    // The comparison only needs labels for its messages, which are not copied into the RCA
    // output. A stable placeholder keeps the analysis deterministic.
    let nodes: Vec<NodeSummary<'_>> = stats
        .iter()
        .map(|s| NodeSummary {
            name: "observed_destination",
            stats: s,
        })
        .collect();
    let findings_from_compare = compare_nodes(&nodes);
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in findings_from_compare {
        if matches!(f.code, "item_count_outlier" | "hit_ratio_spread") {
            *counts.entry(f.code).or_default() += 1;
        }
    }
    if counts.is_empty() {
        return;
    }
    let mut r = RcaFinding::new(
        "cluster_imbalance",
        "Reachable destinations differ materially in item count or hit ratio. The available evidence is consistent with uneven key distribution, different pool data, or an imbalance introduced by a restart or resharding.",
        Severity::Warning,
        Confidence::Medium,
        "The comparison uses current per-destination gauges and counters; it cannot distinguish intentional per-pool data differences from a fault.",
    )
    .with_evidence(Evidence::derived(
        "reachable_destinations_compared",
        stats.len().to_string(),
        "Destinations included in the peer comparison.",
    ))
    .with_alternatives([
        "Pools intentionally hold different data sets.",
        "A recent resharding or deploy changed the key distribution.",
        "A destination restarted and lost its local data.",
        "The comparison includes destinations from different pools.",
    ])
    .with_checks([
        "Compare destinations within the same pool separately.",
        "Check hit ratio and item count after a warm-up window.",
        "Review recent restarts, resharding and routing changes.",
    ]);
    for (code, n) in counts {
        r = r.with_evidence(Evidence::new(
            code,
            EvidenceKind::Derived,
            Some(n.to_string()),
            None,
            "Number of peer-comparison findings with this code.",
        ));
    }
    findings.push(r);
}

fn coverage_finding(input: &McrouterRcaInput<'_>, findings: &mut Vec<RcaFinding>) {
    let c = &input.coverage;
    if c.complete
        && c.unmapped_destinations == 0
        && c.denied_destinations == 0
        && c.truncated_destinations == 0
    {
        return;
    }
    let has_unavailable = findings.iter().any(|f| f.severity >= Severity::Warning);
    let mut r = RcaFinding::new(
        "partial_destination_coverage",
        "The RCA call could not observe every configured destination. Cluster-wide conclusions are limited to the observed subset and may understate an outage or imbalance.",
        if has_unavailable { Severity::Warning } else { Severity::Info },
        Confidence::High,
        "Coverage is derived from the parsed config, destination map, allowlist and the destination cap; the counts are direct.",
    )
    .with_evidence(Evidence::new(
        "configured_destinations",
        EvidenceKind::Coverage,
        Some(c.configured_destinations.to_string()),
        None,
        "Destinations named in the parsed config after deduplication.",
    ))
    .with_evidence(Evidence::new(
        "probed_destinations",
        EvidenceKind::Coverage,
        Some(c.probed_destinations.to_string()),
        None,
        "Destinations this RCA call attempted to probe.",
    ))
    .with_evidence(Evidence::new(
        "unmapped_destinations",
        EvidenceKind::Coverage,
        Some(c.unmapped_destinations.to_string()),
        None,
        "Destinations with no MEMCACHED_MCP_DEST_MAP entry.",
    ))
    .with_evidence(Evidence::new(
        "denied_destinations",
        EvidenceKind::Coverage,
        Some(c.denied_destinations.to_string()),
        None,
        "Destinations mapped to addresses outside the allowlist.",
    ))
    .with_evidence(Evidence::new(
        "truncated_destinations",
        EvidenceKind::Coverage,
        Some(c.truncated_destinations.to_string()),
        None,
        "Destinations skipped because of the per-call destination cap.",
    ))
    .with_alternatives([
        "The destination map is not configured for all pools.",
        "The backend addresses are not in MEMCACHED_MCP_ALLOWLIST.",
        "The topology exceeds the per-call analysis cap.",
        "The config contains destinations that are intentionally not probeable.",
    ])
    .with_checks([
        "Populate `MEMCACHED_MCP_DEST_MAP` for every destination name.",
        "Add the mapped backend addresses to the allowlist.",
        "Reduce the topology or split the analysis if it exceeds the cap.",
    ]);
    if c.unreachable_destinations > 0 {
        r = r.with_evidence(Evidence::new(
            "unreachable_destinations",
            EvidenceKind::Coverage,
            Some(c.unreachable_destinations.to_string()),
            None,
            "Destinations that were probed but did not answer.",
        ));
    }
    findings.push(r);
}

fn missing_evidence(input: &McrouterRcaInput<'_>) -> Vec<String> {
    let mut missing = Vec::new();
    for key in ["num_servers", "num_servers_down"] {
        if metric(input.router_stats, key).is_none() {
            missing.push(key.to_owned());
        }
    }
    if input.destinations.is_empty() && input.coverage.configured_destinations > 0 {
        missing.push("destination statistics".to_owned());
    }
    if input.coverage.unmapped_destinations > 0 {
        missing.push("destination address mapping".to_owned());
    }
    if input.coverage.denied_destinations > 0 {
        missing.push("destination allowlist coverage".to_owned());
    }
    if input.coverage.truncated_destinations > 0 {
        missing.push("complete destination set (cap reached)".to_owned());
    }
    missing.sort();
    missing
}

fn insufficient_finding(missing: &[String]) -> RcaFinding {
    let mut r = RcaFinding::new(
        "insufficient_evidence",
        "There is not enough router or destination evidence to support a root-cause conclusion.",
        Severity::Info,
        Confidence::Insufficient,
        format!(
            "The snapshot is missing required evidence: {}.",
            if missing.is_empty() {
                "no destination was observed".to_owned()
            } else {
                missing.join(", ")
            }
        ),
    )
    .with_alternatives([
        "The target is not an mcrouter or does not expose the expected keys.",
        "The destination map is empty or no destination is allowlisted.",
        "The stats response was partial.",
    ])
    .with_checks([
        "Run `mcrouter_get_stats` and `mcrouter_inspect_config` separately.",
        "Verify `MEMCACHED_MCP_DEST_MAP` and allowlist entries.",
    ]);
    for key in missing.iter().take(8) {
        r = r.with_evidence(Evidence::new(
            key,
            EvidenceKind::DataQuality,
            None,
            None,
            "Expected RCA evidence is unavailable or not parseable.",
        ));
    }
    r
}

fn summary_for(status: AnalysisStatus, findings: &[RcaFinding], coverage: &Coverage) -> String {
    match status {
        AnalysisStatus::Healthy => "No evidence of backend, routing or resource pressure in the observed snapshot.".to_owned(),
        AnalysisStatus::Actionable => findings.first().map_or_else(
            || "Actionable findings were reported, but no primary hypothesis is available.".to_owned(),
            |f| {
                format!(
                    "{} finding(s) at warning or critical severity. Primary hypothesis: {}",
                    findings.len(),
                    f.suspected_cause
                )
            },
        ),
        AnalysisStatus::Partial => format!(
            "Partial evidence: observed {} of {} configured destinations; conclusions are limited to that subset.",
            coverage.probed_destinations, coverage.configured_destinations
        ),
        AnalysisStatus::InsufficientEvidence => {
            "Insufficient router/destination evidence to support a root-cause conclusion.".to_owned()
        }
    }
}

/// Analyzes one mcrouter snapshot. Pure and deterministic.
pub fn analyze_mcrouter(input: &McrouterRcaInput<'_>) -> RcaReport {
    let mut report = RcaReport::new("mcrouter", input.target);
    report.coverage = Some(input.coverage.clone());
    let mut findings = Vec::new();

    if let Some(f) = config_finding(input.config) {
        findings.push(f);
    }
    backend_health(input, &mut findings);
    failover_findings(input, &mut findings);
    destination_pressure(input, &mut findings);
    cluster_imbalance(input, &mut findings);
    coverage_finding(input, &mut findings);

    let missing = missing_evidence(input);
    let no_observations = input.destinations.is_empty();
    if no_observations && input.coverage.configured_destinations > 0 {
        findings.push(insufficient_finding(&missing));
    }

    report.findings = findings;
    report.sort_findings();
    report.missing_evidence = missing;
    report.limitations = vec![
        "Single snapshot: no historical series is available, so trends, counter resets and transient spikes cannot be confirmed.".to_owned(),
        "Findings are evidence-based hypotheses; correlation does not prove causation.".to_owned(),
        "Only the parsed running config and probed destinations are visible; inline pools and key-level routing are not analyzed.".to_owned(),
        "Failover coverage is inferred from route-tree placement; failover_errors and covered operations are not checked.".to_owned(),
    ];
    if !input.coverage.complete {
        report.limitations.push(format!(
            "Destination coverage is incomplete (probed {} of {}; unmapped {}, denied {}, truncated {}).",
            input.coverage.probed_destinations,
            input.coverage.configured_destinations,
            input.coverage.unmapped_destinations,
            input.coverage.denied_destinations,
            input.coverage.truncated_destinations
        ));
    }

    report.status = if report.has_actionable_finding() {
        AnalysisStatus::Actionable
    } else if !input.coverage.complete || no_observations {
        AnalysisStatus::Partial
    } else if input.router_stats.is_empty() {
        AnalysisStatus::InsufficientEvidence
    } else {
        AnalysisStatus::Healthy
    };
    report.summary = summary_for(report.status, &report.findings, &input.coverage);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pool;
    use diagnostics::rca::RCA_SCHEMA_VERSION;

    fn st(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn config(pools: Vec<Pool>, _route: &str, has_failover: bool) -> ConfigSummary {
        let referenced = pools.iter().map(|p| p.name.clone()).collect();
        ConfigSummary {
            pools,
            referenced_pools: referenced,
            has_failover,
            failover_scope: if has_failover {
                FailoverScope::Root
            } else {
                FailoverScope::None
            },
        }
    }

    fn healthy_observation() -> DestinationObservation {
        DestinationObservation {
            id: "healthy".into(),
            reachable: true,
            stats: Some(st(&[
                ("get_hits", "9000"),
                ("get_misses", "1000"),
                ("bytes", "50"),
                ("limit_maxbytes", "100"),
                ("curr_items", "1000"),
                ("curr_connections", "10"),
                ("evictions", "0"),
                ("uptime", "10000"),
            ])),
            items: Stats::new(),
            settings: st(&[("maxconns", "100")]),
        }
    }

    fn coverage(configured: usize, probed: usize, reachable: usize) -> Coverage {
        Coverage {
            configured_destinations: configured,
            probed_destinations: probed,
            reachable_destinations: reachable,
            unreachable_destinations: probed.saturating_sub(reachable),
            unmapped_destinations: 0,
            denied_destinations: 0,
            truncated_destinations: 0,
            complete: probed == configured,
        }
    }

    fn base_input<'a>(
        cfg: &'a ConfigSummary,
        stats: &'a Stats,
        destinations: &'a [DestinationObservation],
        coverage: Coverage,
    ) -> McrouterRcaInput<'a> {
        McrouterRcaInput {
            target: "router:5000",
            config: cfg,
            router_stats: stats,
            destinations,
            coverage,
        }
    }

    #[test]
    fn healthy_topology_has_no_false_positive() {
        let cfg = config(
            vec![Pool {
                name: "main".into(),
                servers: vec!["a:11211".into(), "b:11211".into(), "c:11211".into()],
            }],
            "PoolRoute|main",
            false,
        );
        let stats = st(&[
            ("num_servers", "3"),
            ("num_servers_down", "0"),
            ("num_suspect_servers", "0"),
        ]);
        let destinations = vec![
            healthy_observation(),
            healthy_observation(),
            healthy_observation(),
        ];
        let report = analyze_mcrouter(&base_input(&cfg, &stats, &destinations, coverage(3, 3, 3)));
        assert_eq!(report.schema_version, RCA_SCHEMA_VERSION);
        assert_eq!(report.status, AnalysisStatus::Healthy);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.severity >= Severity::Warning));
    }

    #[test]
    fn partial_backend_availability_is_actionable_and_correlated() {
        let cfg = config(
            vec![Pool {
                name: "main".into(),
                servers: vec!["a:11211".into(), "b:11211".into(), "c:11211".into()],
            }],
            "PoolRoute|main",
            false,
        );
        let stats = st(&[
            ("num_servers", "3"),
            ("num_servers_down", "1"),
            ("num_suspect_servers", "0"),
        ]);
        let destinations = vec![
            healthy_observation(),
            healthy_observation(),
            DestinationObservation {
                id: "unreachable".into(),
                reachable: false,
                stats: None,
                items: Stats::new(),
                settings: Stats::new(),
            },
        ];
        let report = analyze_mcrouter(&base_input(&cfg, &stats, &destinations, coverage(3, 3, 2)));
        assert_eq!(report.status, AnalysisStatus::Actionable);
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "backend_unavailable"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "down_without_failover"));
        assert!(report
            .findings
            .iter()
            .all(|f| !f.alternative_explanations.is_empty()));
    }

    #[test]
    fn root_failover_is_inferred_not_confirmed() {
        let cfg = config(
            vec![Pool {
                name: "main".into(),
                servers: vec!["a:11211".into(), "b:11211".into()],
            }],
            "FailoverRoute|main",
            true,
        );
        let stats = st(&[("num_servers", "2"), ("num_servers_down", "1")]);
        let destinations = vec![
            healthy_observation(),
            DestinationObservation {
                id: "unreachable".into(),
                reachable: false,
                stats: None,
                items: Stats::new(),
                settings: Stats::new(),
            },
        ];
        let report = analyze_mcrouter(&base_input(&cfg, &stats, &destinations, coverage(2, 2, 1)));
        let f = report
            .findings
            .iter()
            .find(|f| f.id == "failover_active")
            .unwrap();
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(f.confidence_basis.contains("inferred"));
    }

    #[test]
    fn incomplete_destination_coverage_is_explicit() {
        let cfg = config(
            vec![Pool {
                name: "main".into(),
                servers: vec!["a:11211".into(), "b:11211".into()],
            }],
            "PoolRoute|main",
            false,
        );
        let stats = st(&[("num_servers", "2"), ("num_servers_down", "0")]);
        let destinations = vec![healthy_observation()];
        let mut c = coverage(2, 1, 1);
        c.unmapped_destinations = 1;
        c.complete = false;
        let report = analyze_mcrouter(&base_input(&cfg, &stats, &destinations, c));
        assert_eq!(report.status, AnalysisStatus::Partial);
        assert!(report.coverage.as_ref().is_some_and(|c| !c.complete));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "partial_destination_coverage"));
    }

    #[test]
    fn destination_pressure_is_aggregated_without_names() {
        let cfg = config(
            vec![Pool {
                name: "main".into(),
                servers: vec!["a:11211".into(), "b:11211".into()],
            }],
            "PoolRoute|main",
            false,
        );
        let stats = st(&[("num_servers", "2"), ("num_servers_down", "0")]);
        let pressured = DestinationObservation {
            id: "pressured".into(),
            reachable: true,
            stats: Some(st(&[
                ("get_hits", "9000"),
                ("get_misses", "1000"),
                ("bytes", "95"),
                ("limit_maxbytes", "100"),
                ("curr_items", "1000"),
                ("curr_connections", "10"),
                ("evictions", "5000"),
                ("uptime", "10000"),
            ])),
            items: Stats::new(),
            settings: st(&[("maxconns", "100")]),
        };
        let report = analyze_mcrouter(&base_input(
            &cfg,
            &stats,
            &[pressured.clone(), pressured],
            coverage(2, 2, 2),
        ));
        let f = report
            .findings
            .iter()
            .find(|f| f.id == "destination_pressure")
            .unwrap();
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.evidence.iter().any(|e| e.metric == "evictions"));
        assert!(!format!("{f:?}").contains("a:11211"));
    }

    #[test]
    fn deterministic_output() {
        let cfg = config(
            vec![Pool {
                name: "main".into(),
                servers: vec!["a:11211".into(), "b:11211".into(), "c:11211".into()],
            }],
            "PoolRoute|main",
            false,
        );
        let stats = st(&[
            ("num_servers", "3"),
            ("num_servers_down", "1"),
            ("num_suspect_servers", "1"),
        ]);
        let destinations = vec![
            healthy_observation(),
            healthy_observation(),
            healthy_observation(),
        ];
        let input = base_input(&cfg, &stats, &destinations, coverage(3, 3, 3));
        assert_eq!(analyze_mcrouter(&input), analyze_mcrouter(&input));
    }
}
