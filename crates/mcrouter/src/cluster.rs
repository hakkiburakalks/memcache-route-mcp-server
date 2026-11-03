//! Deterministic cluster topology and health model.
//!
//! Discovery is limited to the [`RouterObservation`]s supplied by the MCP layer. Those observations
//! come only from explicitly requested, allowlisted mcrouter instances. Destinations are taken
//! from their configs and mapped through `MEMCACHED_MCP_DEST_MAP`; no network scanning is done.
//!
//! The analysis reuses the existing mcrouter config/stats/failover rules and the existing
//! per-node RCA. It never contains raw pool names, destination names, keys, values or config.

use std::collections::{BTreeMap, BTreeSet};

use diagnostics::rca::{AnalysisStatus, Confidence, Evidence, EvidenceKind, RcaReport};
use diagnostics::{Severity, Stats};
use serde::Serialize;

use crate::snapshot::opaque_id;
use crate::{
    analyze_config, analyze_stats, destinations, diagnose_failover, ConfigSummary, FailoverScope,
};

pub const CLUSTER_SCHEMA_VERSION: &str = "1.0";
pub const MAX_CLUSTER_ROUTERS: usize = 32;
pub const MAX_CLUSTER_POOLS: usize = 128;
pub const MAX_CLUSTER_DESTINATIONS: usize = 512;
pub const MAX_CLUSTER_BACKENDS: usize = 128;
pub const MAX_CLUSTER_LINKS: usize = 1_024;
const MAX_AFFECTED_IDS: usize = 24;
const MAX_BACKEND_RCA_FINDINGS: usize = 4;
const MAX_TEXT_BYTES: usize = 512;

/// One router snapshot, or an observation that it could not be read/parsed.
#[derive(Debug, Clone)]
pub struct RouterObservation {
    pub address: String,
    pub config: Option<ConfigSummary>,
    pub stats: Option<Stats>,
}

/// One reachable or unreachable backend snapshot. RCA is computed by the MCP layer using the
/// existing `diagnostics::rca::analyze_node` function.
#[derive(Debug, Clone)]
pub struct BackendObservation {
    pub address: String,
    pub reachable: bool,
    pub rca: Option<RcaReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationStatus {
    Reachable,
    Unreachable,
    Unmapped,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterStatus {
    Healthy,
    Degraded,
    Partial,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouterNode {
    pub id: String,
    pub address: String,
    pub reachable: bool,
    pub config_parsed: bool,
    pub stats_available: bool,
    pub pools: usize,
    pub destinations: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PoolNode {
    pub id: String,
    pub router_ids: Vec<String>,
    pub servers: usize,
    pub destination_ids: Vec<String>,
    pub empty: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DestinationNode {
    pub id: String,
    pub router_ids: Vec<String>,
    pub pool_ids: Vec<String>,
    pub mapped: bool,
    pub backend_id: Option<String>,
    pub status: DestinationStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BackendRcaFinding {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub suspected_cause: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BackendNode {
    pub id: String,
    pub address: String,
    pub reachable: bool,
    pub rca_status: Option<AnalysisStatus>,
    pub rca_findings: Vec<BackendRcaFinding>,
    pub destination_count: usize,
    pub router_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClusterLink {
    pub router_id: String,
    pub pool_id: String,
    pub destination_id: String,
    pub backend_id: Option<String>,
    pub status: DestinationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ClusterCoverage {
    pub routers_requested: usize,
    pub routers_probed: usize,
    pub routers_parsed: usize,
    pub pools: usize,
    pub destinations: usize,
    pub destinations_mapped: usize,
    pub destinations_unmapped: usize,
    pub destinations_denied: usize,
    pub destinations_reachable: usize,
    pub destinations_unreachable: usize,
    pub destinations_unknown: usize,
    pub backends_probed: usize,
    pub backends_reachable: usize,
    pub backends_unreachable: usize,
    pub truncated: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterFinding {
    pub id: String,
    pub suspected_cause: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub affected_ids: Vec<String>,
    pub alternative_explanations: Vec<String>,
    pub recommended_checks: Vec<String>,
}

impl ClusterFinding {
    fn with_evidence(mut self, evidence: Evidence) -> Self {
        if self.evidence.len() < 8 {
            self.evidence.push(evidence);
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClusterTopology {
    pub schema_version: String,
    pub analysis: String,
    pub observed_at_unix_ms: u64,
    pub status: ClusterStatus,
    pub summary: String,
    pub routers: Vec<RouterNode>,
    pub pools: Vec<PoolNode>,
    pub destinations: Vec<DestinationNode>,
    pub backends: Vec<BackendNode>,
    pub links: Vec<ClusterLink>,
    pub findings: Vec<ClusterFinding>,
    pub coverage: ClusterCoverage,
    pub limitations: Vec<String>,
}

#[derive(Default)]
struct DestinationAgg {
    router_ids: BTreeSet<String>,
    pool_ids: BTreeSet<String>,
    mapped: bool,
    allowed: bool,
    backend_address: Option<String>,
}

#[derive(Default)]
struct PoolAgg {
    router_ids: BTreeSet<String>,
    servers: usize,
    destinations: BTreeSet<String>,
}

struct FindingAgg {
    severity: Severity,
    confidence: Confidence,
    count: usize,
    affected: BTreeSet<String>,
}

impl FindingAgg {
    fn new(severity: Severity, confidence: Confidence) -> Self {
        Self {
            severity,
            confidence,
            count: 0,
            affected: BTreeSet::new(),
        }
    }

    fn add(&mut self, severity: Severity, affected: Option<&str>) {
        self.severity = self.severity.max(severity);
        self.count += 1;
        if let Some(id) = affected {
            self.affected.insert(id.to_owned());
        }
    }
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

fn evidence(
    metric: &str,
    kind: EvidenceKind,
    value: impl ToString,
    interpretation: &str,
) -> Evidence {
    Evidence::new(metric, kind, Some(value.to_string()), None, interpretation)
}

fn finding(id: &str, severity: Severity, confidence: Confidence, cause: &str) -> ClusterFinding {
    ClusterFinding {
        id: id.to_owned(),
        suspected_cause: clip(cause, MAX_TEXT_BYTES),
        severity,
        confidence,
        evidence: Vec::new(),
        affected_ids: Vec::new(),
        alternative_explanations: Vec::new(),
        recommended_checks: Vec::new(),
    }
}

/// Unique resolved backend addresses that the MCP layer should probe. Only mapped, allowlisted
/// destinations are returned. The boolean is true when the cap truncated the set.
pub fn backend_targets(
    routers: &[RouterObservation],
    dest_map: &BTreeMap<String, String>,
    allowlist: &std::collections::HashSet<String>,
) -> (Vec<String>, bool) {
    let mut targets = BTreeSet::new();
    let mut truncated = false;
    for router in routers {
        let Some(config) = &router.config else {
            continue;
        };
        for name in destinations(config) {
            let Some(real) = dest_map.get(&name) else {
                continue;
            };
            if !allowlist.contains(real) {
                continue;
            }
            if targets.contains(real) {
                continue;
            }
            if targets.len() >= MAX_CLUSTER_BACKENDS {
                truncated = true;
                break;
            }
            targets.insert(real.clone());
        }
        if truncated {
            break;
        }
    }
    (targets.into_iter().collect(), truncated)
}

/// Builds the cluster model from already-collected observations. Pure and deterministic.
pub fn analyze_cluster(
    routers: &[RouterObservation],
    dest_map: &BTreeMap<String, String>,
    allowlist: &std::collections::HashSet<String>,
    backends: &[BackendObservation],
    observed_at_unix_ms: u64,
) -> ClusterTopology {
    analyze_cluster_with_truncation(
        routers,
        dest_map,
        allowlist,
        backends,
        observed_at_unix_ms,
        false,
    )
}

/// Like [`analyze_cluster`], with an explicit indication that the MCP caller stopped collecting
/// backend targets at the cap.
pub fn analyze_cluster_with_truncation(
    routers: &[RouterObservation],
    dest_map: &BTreeMap<String, String>,
    allowlist: &std::collections::HashSet<String>,
    backends: &[BackendObservation],
    observed_at_unix_ms: u64,
    backend_targets_truncated: bool,
) -> ClusterTopology {
    let mut router_nodes = Vec::new();
    let mut pool_aggs: BTreeMap<String, PoolAgg> = BTreeMap::new();
    let mut dest_aggs: BTreeMap<String, DestinationAgg> = BTreeMap::new();
    let mut raw_links: Vec<(String, String, String)> = Vec::new();
    let mut backend_usage: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut config_findings: BTreeMap<&'static str, FindingAgg> = BTreeMap::new();
    let mut stats_findings: BTreeMap<&'static str, FindingAgg> = BTreeMap::new();
    let mut failover_findings: BTreeMap<&'static str, FindingAgg> = BTreeMap::new();
    let mut truncated = backend_targets_truncated;

    for router in routers {
        let router_id = opaque_id(&router.address);
        let parsed = router.config.is_some();
        let stats_available = router.stats.is_some();
        let mut pool_count = 0usize;
        let mut destination_count = 0usize;
        if let Some(config) = &router.config {
            for pool in &config.pools {
                pool_count += 1;
                let pool_id = opaque_id(&pool.name);
                if pool_aggs.len() < MAX_CLUSTER_POOLS {
                    let entry = pool_aggs.entry(pool_id.clone()).or_default();
                    entry.router_ids.insert(router_id.clone());
                    entry.servers = entry.servers.max(pool.servers.len());
                    for name in &pool.servers {
                        let dest_id = opaque_id(name);
                        entry.destinations.insert(dest_id.clone());
                        destination_count += 1;
                        if dest_aggs.len() < MAX_CLUSTER_DESTINATIONS
                            || dest_aggs.contains_key(&dest_id)
                        {
                            let dest = dest_aggs.entry(dest_id.clone()).or_default();
                            dest.router_ids.insert(router_id.clone());
                            dest.pool_ids.insert(pool_id.clone());
                            if let Some(real) = dest_map.get(name) {
                                dest.mapped = true;
                                dest.allowed = allowlist.contains(real);
                                dest.backend_address = Some(real.clone());
                                backend_usage
                                    .entry(real.clone())
                                    .or_default()
                                    .insert(dest_id.clone());
                            }
                            raw_links.push((router_id.clone(), pool_id.clone(), dest_id));
                        } else {
                            truncated = true;
                        }
                    }
                } else {
                    truncated = true;
                }
            }
            for f in analyze_config(config) {
                let agg = config_findings
                    .entry(f.code)
                    .or_insert_with(|| FindingAgg::new(f.severity, Confidence::High));
                agg.add(f.severity, Some(&router_id));
            }
            if config.failover_scope == FailoverScope::NoRoute {
                let agg = config_findings
                    .entry("route_missing")
                    .or_insert_with(|| FindingAgg::new(Severity::Warning, Confidence::Medium));
                agg.add(Severity::Warning, Some(&router_id));
            }
        }
        if let Some(stats) = &router.stats {
            for f in analyze_stats(stats) {
                let agg = stats_findings
                    .entry(f.code)
                    .or_insert_with(|| FindingAgg::new(f.severity, Confidence::High));
                agg.add(f.severity, Some(&router_id));
            }
            if let Some(config) = &router.config {
                for f in diagnose_failover(config, stats) {
                    let (confidence, _) = failover_confidence(config.failover_scope);
                    let agg = failover_findings
                        .entry(f.code)
                        .or_insert_with(|| FindingAgg::new(f.severity, confidence));
                    agg.add(f.severity, Some(&router_id));
                }
            }
        }
        router_nodes.push(RouterNode {
            id: router_id,
            address: clip(&router.address, 256),
            reachable: parsed && stats_available,
            config_parsed: parsed,
            stats_available,
            pools: pool_count,
            destinations: destination_count,
        });
    }
    router_nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let backend_map: BTreeMap<String, &BackendObservation> =
        backends.iter().map(|b| (b.address.clone(), b)).collect();

    let mut destination_nodes = Vec::new();
    for (id, dest) in dest_aggs {
        let (status, backend_id) = if !dest.mapped {
            (DestinationStatus::Unmapped, None)
        } else if !dest.allowed {
            (
                DestinationStatus::Denied,
                dest.backend_address.as_ref().map(|a| opaque_id(a)),
            )
        } else {
            let backend = dest
                .backend_address
                .as_ref()
                .and_then(|address| backend_map.get(address).copied());
            let status = match backend {
                Some(backend) if backend.reachable => DestinationStatus::Reachable,
                Some(_) => DestinationStatus::Unreachable,
                None => DestinationStatus::Unknown,
            };
            (status, dest.backend_address.as_ref().map(|a| opaque_id(a)))
        };
        destination_nodes.push(DestinationNode {
            id,
            router_ids: dest.router_ids.into_iter().collect(),
            pool_ids: dest.pool_ids.into_iter().collect(),
            mapped: dest.mapped,
            backend_id,
            status,
        });
    }
    destination_nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let mut pools = Vec::new();
    for (id, pool) in pool_aggs {
        let mut destination_ids: Vec<String> = pool.destinations.into_iter().collect();
        destination_ids.sort();
        pools.push(PoolNode {
            id,
            router_ids: pool.router_ids.into_iter().collect(),
            servers: pool.servers,
            empty: destination_ids.is_empty(),
            destination_ids,
        });
    }
    pools.sort_by(|a, b| a.id.cmp(&b.id));

    let mut backend_nodes = Vec::new();
    for backend in backends {
        let id = opaque_id(&backend.address);
        let usage = backend_usage.get(&backend.address);
        let destination_count = usage.map_or(0, BTreeSet::len);
        let router_count = usage.map_or(0, |ids| {
            let mut routers = BTreeSet::new();
            for id in ids {
                if let Some(dest) = destination_nodes.iter().find(|d| &d.id == id) {
                    routers.extend(dest.router_ids.iter().cloned());
                }
            }
            routers.len()
        });
        let (rca_status, rca_findings) = backend.rca.as_ref().map_or((None, Vec::new()), |rca| {
            let mut findings: Vec<BackendRcaFinding> = rca
                .findings
                .iter()
                .take(MAX_BACKEND_RCA_FINDINGS)
                .map(|f| BackendRcaFinding {
                    id: clip(&f.id, 128),
                    severity: f.severity,
                    confidence: f.confidence,
                    suspected_cause: clip(&f.suspected_cause, MAX_TEXT_BYTES),
                })
                .collect();
            findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
            (Some(rca.status), findings)
        });
        backend_nodes.push(BackendNode {
            id,
            address: clip(&backend.address, 256),
            reachable: backend.reachable,
            rca_status,
            rca_findings,
            destination_count,
            router_count,
        });
    }
    backend_nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let status_for = |destination_id: &str| {
        destination_nodes
            .iter()
            .find(|d| d.id == destination_id)
            .map_or(DestinationStatus::Unknown, |d| d.status)
    };
    let mut links = Vec::new();
    for (router_id, pool_id, dest_id) in raw_links {
        if links.len() >= MAX_CLUSTER_LINKS {
            truncated = true;
            break;
        }
        let backend_id = destination_nodes
            .iter()
            .find(|d| d.id == dest_id)
            .and_then(|d| d.backend_id.clone());
        links.push(ClusterLink {
            router_id,
            pool_id,
            destination_id: dest_id.clone(),
            backend_id,
            status: status_for(&dest_id),
        });
    }
    links.sort_by(|a, b| {
        a.router_id
            .cmp(&b.router_id)
            .then_with(|| a.pool_id.cmp(&b.pool_id))
            .then_with(|| a.destination_id.cmp(&b.destination_id))
    });

    let mut findings: BTreeMap<String, ClusterFinding> = BTreeMap::new();
    add_aggregated_findings(
        &mut findings,
        config_findings,
        "mcrouter configuration rule fired",
        "Review the parsed running config and verify pool references, empty pools and duplicate servers.",
    );
    add_aggregated_findings(
        &mut findings,
        stats_findings,
        "mcrouter destination-health rule fired",
        "Check mcrouter destination health and backend availability.",
    );
    add_aggregated_findings(
        &mut findings,
        failover_findings,
        "mcrouter failover rule fired",
        "Review failover scope, operation coverage and remaining backend capacity.",
    );

    let unreachable_ids: Vec<String> = backend_nodes
        .iter()
        .filter(|b| !b.reachable)
        .map(|b| b.id.clone())
        .collect();
    if !unreachable_ids.is_empty() {
        let all = backend_nodes.iter().filter(|b| b.reachable).count() == 0;
        let f = finding(
            "unreachable_backend",
            if all { Severity::Critical } else { Severity::Warning },
            Confidence::High,
            "One or more mapped, allowlisted backends did not answer the probe. Requests to destinations that use them may fail or look like misses.",
        )
        .with_evidence(evidence(
            "unreachable_backends",
            EvidenceKind::Coverage,
            unreachable_ids.len(),
            "Mapped allowlisted backends that did not answer.",
        ));
        findings.insert(
            "unreachable_backend".to_owned(),
            with_affected(f, unreachable_ids),
        );
    }

    let unmapped: Vec<String> = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Unmapped)
        .map(|d| d.id.clone())
        .collect();
    if !unmapped.is_empty() {
        let f = finding(
            "unmapped_destination",
            Severity::Warning,
            Confidence::High,
            "Some configured destinations have no MEMCACHED_MCP_DEST_MAP entry, so their backend health and shared-backend relationships are unknown.",
        )
        .with_evidence(evidence(
            "unmapped_destinations",
            EvidenceKind::Coverage,
            unmapped.len(),
            "Destinations excluded from backend probing by missing mapping.",
        ));
        findings.insert(
            "unmapped_destination".to_owned(),
            with_affected(f, unmapped),
        );
    }

    let denied: Vec<String> = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Denied)
        .map(|d| d.id.clone())
        .collect();
    if !denied.is_empty() {
        let f = finding(
            "denied_destination",
            Severity::Warning,
            Confidence::High,
            "Some mapped destination addresses are outside MEMCACHED_MCP_ALLOWLIST and were not probed.",
        )
        .with_evidence(evidence(
            "denied_destinations",
            EvidenceKind::Coverage,
            denied.len(),
            "Destinations excluded by the allowlist.",
        ));
        findings.insert("denied_destination".to_owned(), with_affected(f, denied));
    }

    let unknown: Vec<String> = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Unknown)
        .map(|d| d.id.clone())
        .collect();
    if !unknown.is_empty() {
        let f = finding(
            "unknown_destination",
            Severity::Warning,
            Confidence::Medium,
            "Some mapped destinations were not probed because the backend or destination cap was reached. Their health is unknown.",
        )
        .with_evidence(evidence(
            "unknown_destinations",
            EvidenceKind::Coverage,
            unknown.len(),
            "Destinations with no backend observation.",
        ));
        findings.insert("unknown_destination".to_owned(), with_affected(f, unknown));
    }

    let shared_backends: Vec<String> = backend_usage
        .iter()
        .filter(|(_, dests)| dests.len() > 1)
        .map(|(address, _)| opaque_id(address))
        .collect();
    if !shared_backends.is_empty() {
        let f = finding(
            "shared_backend",
            Severity::Info,
            Confidence::High,
            "Multiple destinations map to the same backend. A backend failure can affect more than one pool or router, and capacity is shared rather than independent.",
        )
        .with_evidence(evidence(
            "shared_backends",
            EvidenceKind::Derived,
            shared_backends.len(),
            "Backend fingerprints used by more than one destination.",
        ));
        findings.insert(
            "shared_backend".to_owned(),
            with_affected(f, shared_backends),
        );
    }

    let shared_destinations: Vec<String> = destination_nodes
        .iter()
        .filter(|d| d.router_ids.len() > 1 || d.pool_ids.len() > 1)
        .map(|d| d.id.clone())
        .collect();
    if !shared_destinations.is_empty() {
        let f = finding(
            "shared_destination",
            Severity::Info,
            Confidence::High,
            "The same destination name appears in more than one router or pool. Its backend health affects multiple topology locations.",
        )
        .with_evidence(evidence(
            "shared_destinations",
            EvidenceKind::Derived,
            shared_destinations.len(),
            "Destination fingerprints referenced by multiple routers or pools.",
        ));
        findings.insert(
            "shared_destination".to_owned(),
            with_affected(f, shared_destinations),
        );
    }

    let pressured: Vec<String> = backend_nodes
        .iter()
        .filter(|b| {
            b.rca_status
                .is_some_and(|s| s == AnalysisStatus::Actionable || s == AnalysisStatus::Partial)
        })
        .map(|b| b.id.clone())
        .collect();
    if !pressured.is_empty() {
        let severity = backend_nodes
            .iter()
            .filter(|b| b.rca_status.is_some())
            .flat_map(|b| b.rca_findings.iter().map(|f| f.severity))
            .max()
            .unwrap_or(Severity::Warning);
        let f = finding(
            "backend_rca_pressure",
            severity,
            Confidence::Medium,
            "Existing per-backend RCA found actionable or partial evidence on one or more reachable backends. This is a correlated health hypothesis, not proof of a cluster-wide cause.",
        )
        .with_evidence(evidence(
            "backends_with_rca_pressure",
            EvidenceKind::Derived,
            pressured.len(),
            "Reachable backends whose existing RCA status is actionable or partial.",
        ));
        findings.insert(
            "backend_rca_pressure".to_owned(),
            with_affected(f, pressured),
        );
    }

    let routers_failed = router_nodes.iter().filter(|r| !r.reachable).count();
    let coverage_incomplete = !destination_nodes.is_empty()
        && (destination_nodes
            .iter()
            .any(|d| d.status != DestinationStatus::Reachable)
            || truncated
            || routers_failed > 0);
    if coverage_incomplete {
        let mut f = finding(
            "incomplete_topology",
            Severity::Warning,
            Confidence::High,
            "Topology coverage is incomplete because routers, destinations or backend probes were unavailable. Cluster-wide conclusions are limited to the observed subset.",
        );
        f = f.with_evidence(evidence(
            "unreachable_routers",
            EvidenceKind::Coverage,
            routers_failed,
            "Requested routers that could not be read and parsed.",
        ));
        if truncated {
            f = f.with_evidence(evidence(
                "topology_truncated",
                EvidenceKind::Coverage,
                1,
                "At least one cluster cap (pools, destinations, backends or links) was reached.",
            ));
        }
        findings.insert("incomplete_topology".to_owned(), f);
    }

    let mut findings: Vec<ClusterFinding> = findings.into_values().collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    findings.truncate(32);

    let routers_probed = router_nodes.len();
    let routers_parsed = router_nodes.iter().filter(|r| r.config_parsed).count();
    let mapped = destination_nodes.iter().filter(|d| d.mapped).count();
    let unmapped_count = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Unmapped)
        .count();
    let denied_count = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Denied)
        .count();
    let reachable = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Reachable)
        .count();
    let unreachable = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Unreachable)
        .count();
    let unknown_count = destination_nodes
        .iter()
        .filter(|d| d.status == DestinationStatus::Unknown)
        .count();
    let coverage = ClusterCoverage {
        routers_requested: routers.len(),
        routers_probed,
        routers_parsed,
        pools: pools.len(),
        destinations: destination_nodes.len(),
        destinations_mapped: mapped,
        destinations_unmapped: unmapped_count,
        destinations_denied: denied_count,
        destinations_reachable: reachable,
        destinations_unreachable: unreachable,
        destinations_unknown: unknown_count,
        backends_probed: backend_nodes.len(),
        backends_reachable: backend_nodes.iter().filter(|b| b.reachable).count(),
        backends_unreachable: backend_nodes.iter().filter(|b| !b.reachable).count(),
        truncated,
        complete: routers_parsed == routers_probed
            && unmapped_count == 0
            && denied_count == 0
            && unknown_count == 0
            && !truncated
            && !destination_nodes.is_empty(),
    };

    let status = if router_nodes.is_empty() || destination_nodes.is_empty() {
        ClusterStatus::InsufficientEvidence
    } else if findings.iter().any(|f| f.severity >= Severity::Warning) {
        ClusterStatus::Degraded
    } else if !coverage.complete {
        ClusterStatus::Partial
    } else {
        ClusterStatus::Healthy
    };
    let summary = match status {
        ClusterStatus::Healthy => {
            "All configured routers and mapped backends were observed without warning-level topology or health findings."
                .to_owned()
        }
        ClusterStatus::Degraded => format!(
            "{} router(s), {} destination(s), {} backend(s); {} warning/critical finding(s).",
            coverage.routers_probed,
            coverage.destinations,
            coverage.backends_probed,
            findings
                .iter()
                .filter(|f| f.severity >= Severity::Warning)
                .count()
        ),
        ClusterStatus::Partial => format!(
            "Observed {} of {} routers and {} of {} destinations; coverage is incomplete.",
            coverage.routers_probed,
            coverage.routers_requested,
            coverage.destinations_reachable + coverage.destinations_unreachable,
            coverage.destinations
        ),
        ClusterStatus::InsufficientEvidence => {
            "No usable router/config/destination evidence was collected.".to_owned()
        }
    };

    ClusterTopology {
        schema_version: CLUSTER_SCHEMA_VERSION.to_owned(),
        analysis: "cluster_topology".to_owned(),
        observed_at_unix_ms,
        status,
        summary,
        routers: router_nodes,
        pools,
        destinations: destination_nodes,
        backends: backend_nodes,
        links,
        findings,
        coverage,
        limitations: vec![
            "Topology is built only from explicitly requested, allowlisted mcrouter configs and mapped destinations; no network scan is performed.".to_owned(),
            "Pool, destination and backend names are replaced by opaque fingerprints; they are not an anonymization guarantee.".to_owned(),
            "A single observation cannot establish trends or prove causation.".to_owned(),
            "Unmapped, denied, truncated or unreachable elements make the cluster view partial; see coverage.".to_owned(),
            "Backend health is the existing per-node RCA over one snapshot, not a historical or cross-node causal proof.".to_owned(),
        ],
    }
}

fn with_affected(mut f: ClusterFinding, ids: Vec<String>) -> ClusterFinding {
    f.affected_ids = ids.into_iter().take(MAX_AFFECTED_IDS).collect();
    f.alternative_explanations = vec![
        "The condition may be intentional or expected for this topology.".to_owned(),
        "A transient network, deployment or resolver condition may have affected the observation."
            .to_owned(),
    ];
    f.recommended_checks = vec![
        "Verify the relevant config, mapping and allowlist entries.".to_owned(),
        "Compare with a second observation from the same routers.".to_owned(),
    ];
    f
}

fn add_aggregated_findings(
    out: &mut BTreeMap<String, ClusterFinding>,
    aggregated: BTreeMap<&'static str, FindingAgg>,
    cause: &str,
    check: &str,
) {
    for (code, agg) in aggregated {
        let mut f = finding(code, agg.severity, agg.confidence, cause);
        f.evidence.push(evidence(
            "occurrences",
            EvidenceKind::Derived,
            agg.count,
            "Number of router observations where this existing diagnostic rule fired.",
        ));
        f.affected_ids = agg.affected.into_iter().take(MAX_AFFECTED_IDS).collect();
        f.alternative_explanations = vec![
            "The config may use inline definitions that the parser cannot enumerate.".to_owned(),
            "The condition may be intentional or a staging/config-generation artifact.".to_owned(),
        ];
        f.recommended_checks = vec![check.to_owned()];
        out.insert(code.to_owned(), f);
    }
}

fn failover_confidence(scope: FailoverScope) -> (Confidence, &'static str) {
    match scope {
        FailoverScope::None => (Confidence::High, "confirmed"),
        FailoverScope::Root => (Confidence::Medium, "inferred"),
        FailoverScope::Nested | FailoverScope::NoRoute => (Confidence::Low, "unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FailoverScope, Pool};
    use diagnostics::rca::analyze_node;

    fn st(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn config(pools: Vec<Pool>, has_failover: bool) -> ConfigSummary {
        ConfigSummary {
            referenced_pools: pools.iter().map(|p| p.name.clone()).collect(),
            pools,
            has_failover,
            failover_scope: if has_failover {
                FailoverScope::Root
            } else {
                FailoverScope::None
            },
        }
    }

    fn healthy_backend(addr: &str) -> BackendObservation {
        let stats = st(&[
            ("get_hits", "9000"),
            ("get_misses", "1000"),
            ("bytes", "50"),
            ("limit_maxbytes", "100"),
            ("curr_items", "1000"),
            ("curr_connections", "10"),
            ("evictions", "0"),
            ("uptime", "10000"),
        ]);
        BackendObservation {
            address: addr.into(),
            reachable: true,
            rca: Some(analyze_node(addr, &stats, &Stats::new(), &Stats::new())),
        }
    }

    fn allowlist(addrs: &[&str]) -> std::collections::HashSet<String> {
        addrs.iter().map(|a| (*a).to_owned()).collect()
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn single_router_deterministic_topology() {
        let router = RouterObservation {
            address: "router:5000".into(),
            config: Some(config(
                vec![Pool {
                    name: "main".into(),
                    servers: vec!["mc-a:11211".into(), "mc-b:11211".into()],
                }],
                false,
            )),
            stats: Some(st(&[("num_servers", "2"), ("num_servers_down", "0")])),
        };
        let dest_map = map(&[
            ("mc-a:11211", "127.0.0.1:11211"),
            ("mc-b:11211", "127.0.0.1:11212"),
        ]);
        let allow = allowlist(&["127.0.0.1:11211", "127.0.0.1:11212"]);
        let backends = vec![
            healthy_backend("127.0.0.1:11211"),
            healthy_backend("127.0.0.1:11212"),
        ];
        let first = analyze_cluster(
            std::slice::from_ref(&router),
            &dest_map,
            &allow,
            &backends,
            1,
        );
        let second = analyze_cluster(&[router], &dest_map, &allow, &backends, 1);
        assert_eq!(first, second);
        assert_eq!(first.schema_version, CLUSTER_SCHEMA_VERSION);
        assert_eq!(first.analysis, "cluster_topology");
        assert_eq!(first.coverage.destinations_reachable, 2);
        assert!(first.coverage.complete);
        assert!(!first.pools.is_empty());
        assert!(!first.links.is_empty());
    }

    #[test]
    fn multiple_pools_shared_destination_and_backend() {
        let cfg = config(
            vec![
                Pool {
                    name: "a".into(),
                    servers: vec!["mc-a:11211".into(), "mc-b:11211".into()],
                },
                Pool {
                    name: "b".into(),
                    servers: vec!["mc-a:11211".into(), "mc-c:11211".into()],
                },
            ],
            true,
        );
        let router = RouterObservation {
            address: "router:5000".into(),
            config: Some(cfg),
            stats: Some(st(&[("num_servers", "3"), ("num_servers_down", "1")])),
        };
        let dest_map = map(&[
            ("mc-a:11211", "127.0.0.1:1"),
            ("mc-b:11211", "127.0.0.1:2"),
            ("mc-c:11211", "127.0.0.1:1"),
        ]);
        let allow = allowlist(&["127.0.0.1:1", "127.0.0.1:2"]);
        let backends = vec![
            healthy_backend("127.0.0.1:1"),
            BackendObservation {
                address: "127.0.0.1:2".into(),
                reachable: false,
                rca: None,
            },
        ];
        let report = analyze_cluster(&[router], &dest_map, &allow, &backends, 1);
        assert!(report.findings.iter().any(|f| f.id == "shared_backend"));
        assert!(report.findings.iter().any(|f| f.id == "shared_destination"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "unreachable_backend"));
        assert_eq!(report.coverage.backends_unreachable, 1);
    }

    #[test]
    fn empty_pool_duplicate_destination_and_unmapped_are_explicit() {
        let mut cfg = config(
            vec![
                Pool {
                    name: "empty".into(),
                    servers: vec![],
                },
                Pool {
                    name: "dup".into(),
                    servers: vec!["mc-a:11211".into(), "mc-a:11211".into()],
                },
                Pool {
                    name: "unmapped".into(),
                    servers: vec!["mc-z:11211".into()],
                },
            ],
            false,
        );
        cfg.referenced_pools = vec!["dup".into(), "unmapped".into()];
        let router = RouterObservation {
            address: "router:5000".into(),
            config: Some(cfg),
            stats: Some(st(&[("num_servers", "2")])),
        };
        let dest_map = map(&[("mc-a:11211", "127.0.0.1:1")]);
        let allow = allowlist(&["127.0.0.1:1"]);
        let backend = healthy_backend("127.0.0.1:1");
        let report = analyze_cluster(&[router], &dest_map, &allow, &[backend], 1);
        assert!(report.pools.iter().any(|p| p.empty));
        assert!(report.findings.iter().any(|f| f.id == "pool_empty"));
        assert!(report.findings.iter().any(|f| f.id == "pool_unused"));
        assert!(report.findings.iter().any(|f| f.id == "duplicate_server"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "unmapped_destination"));
        assert!(!report.coverage.complete);
    }

    #[test]
    fn missing_and_denied_destinations_are_unknown_or_denied() {
        let cfg = config(
            vec![Pool {
                name: "p".into(),
                servers: vec!["mc-a:11211".into(), "mc-b:11211".into()],
            }],
            false,
        );
        let router = RouterObservation {
            address: "router:5000".into(),
            config: Some(cfg),
            stats: Some(st(&[("num_servers", "2")])),
        };
        let dest_map = map(&[("mc-a:11211", "127.0.0.1:1"), ("mc-b:11211", "127.0.0.1:2")]);
        let allow = allowlist(&["127.0.0.1:1"]);
        let report = analyze_cluster(
            &[router],
            &dest_map,
            &allow,
            &[healthy_backend("127.0.0.1:1")],
            1,
        );
        assert!(report
            .destinations
            .iter()
            .any(|d| d.status == DestinationStatus::Denied));
        assert!(report.findings.iter().any(|f| f.id == "denied_destination"));
        assert!(!report.coverage.complete);
    }

    #[test]
    fn unreachable_router_is_partial_not_healthy() {
        let router = RouterObservation {
            address: "router:5000".into(),
            config: None,
            stats: None,
        };
        let report = analyze_cluster(&[router], &BTreeMap::new(), &allowlist(&[]), &[], 1);
        assert_eq!(report.status, ClusterStatus::InsufficientEvidence);
        assert_eq!(report.coverage.routers_parsed, 0);
        assert!(
            report.findings.is_empty()
                || report
                    .findings
                    .iter()
                    .any(|f| f.severity >= Severity::Warning)
        );
    }

    #[test]
    fn oversized_destination_set_is_bounded_and_partial() {
        let servers: Vec<String> = (0..MAX_CLUSTER_DESTINATIONS + 10)
            .map(|i| format!("mc-{i}:11211"))
            .collect();
        let router = RouterObservation {
            address: "router:5000".into(),
            config: Some(config(
                vec![Pool {
                    name: "p".into(),
                    servers,
                }],
                false,
            )),
            stats: Some(st(&[("num_servers", "10")])),
        };
        let allow = allowlist(&[]);
        let report = analyze_cluster(&[router], &BTreeMap::new(), &allow, &[], 1);
        assert!(report.coverage.truncated);
        assert!(report.destinations.len() <= MAX_CLUSTER_DESTINATIONS);
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "incomplete_topology"));
    }
}
