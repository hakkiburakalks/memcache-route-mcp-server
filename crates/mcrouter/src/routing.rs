//! Safe, offline analysis of mcrouter route configuration.
//!
//! This module inventories explicitly known route handles and flags structural risks. It does not
//! execute a route, run Lua, or claim that two configs behave identically. A validated offline hash
//! simulator is intentionally not provided; use `mcrouter_trace_key_route` against a live router to
//! compare actual traces.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use diagnostics::Severity;

pub const ROUTING_SCHEMA_VERSION: &str = "1.0";

const KNOWN_HANDLES: &[&str] = &[
    "AllAsyncRoute",
    "AllFastestRoute",
    "AllInitialRoute",
    "AllMajorityRoute",
    "AllSyncRoute",
    "BigValueRoute",
    "DevNullRoute",
    "ErrorRoute",
    "FailoverRoute",
    "FailoverWithExptimeRoute",
    "HashRoute",
    "HostIdRoute",
    "LatencyInjectionRoute",
    "LatestRoute",
    "LoadBalancerRoute",
    "MigrateRoute",
    "MissFailoverRoute",
    "ModifyExptimeRoute",
    "NullRoute",
    "OperationSelectorRoute",
    "PoolRoute",
    "PrefixSelectorRoute",
    "RandomRoute",
    "WarmUpRoute",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutingFeatures {
    pub failover: bool,
    pub prefix_selector: bool,
    pub operation_selector: bool,
    pub shadowing: bool,
    pub rate_limiting: bool,
    pub migration: bool,
    pub warm_up: bool,
    pub inline_pools: usize,
    pub hash_functions: Vec<String>,
    pub ssl_or_protocol_markers: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RouteHandleCount {
    pub handle: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutingFinding {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SimulationStatus {
    pub status: &'static str,
    pub supported_handles: Vec<String>,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutingReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub source: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub route_present: bool,
    pub handles: Vec<RouteHandleCount>,
    pub handle_total: usize,
    pub max_depth: usize,
    pub max_fanout: usize,
    pub pools: usize,
    pub destinations: usize,
    pub features: RoutingFeatures,
    pub findings: Vec<RoutingFinding>,
    pub unsupported_handles: Vec<String>,
    pub simulation: SimulationStatus,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoutingImpact {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub current: RoutingReport,
    pub proposed: RoutingReport,
    pub pools_added: Vec<String>,
    pub pools_removed: Vec<String>,
    pub destinations_added: Vec<String>,
    pub destinations_removed: Vec<String>,
    pub handle_changes: Vec<HandleDelta>,
    pub feature_changes: Vec<String>,
    pub simulation: SimulationStatus,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HandleDelta {
    pub handle: String,
    pub before: usize,
    pub after: usize,
}

fn known(name: &str) -> bool {
    KNOWN_HANDLES.contains(&name)
}

fn handle_name(raw: &str) -> Option<&str> {
    let base = raw.split('|').next().unwrap_or(raw).trim();
    if base.is_empty() {
        None
    } else if known(base) || base.ends_with("Route") {
        Some(base)
    } else {
        None
    }
}

fn add_handle(
    handles: &mut BTreeMap<String, usize>,
    unsupported: &mut BTreeSet<String>,
    features: &mut RoutingFeatures,
    raw: &str,
) {
    let Some(name) = handle_name(raw) else {
        return;
    };
    *handles.entry(name.to_owned()).or_default() += 1;
    if !known(name) {
        unsupported.insert(name.to_owned());
    }
    features.failover |= name.contains("Failover");
    features.prefix_selector |= name == "PrefixSelectorRoute";
    features.operation_selector |= name == "OperationSelectorRoute";
    features.migration |= name == "MigrateRoute";
    features.warm_up |= name == "WarmUpRoute";
}

fn add_hash(features: &mut RoutingFeatures, value: &Value) {
    match value {
        Value::String(s) if !s.is_empty() && features.hash_functions.len() < 16 => {
            features.hash_functions.push(s.clone());
        }
        Value::Object(o) => {
            if let Some(t) = o.get("type").and_then(Value::as_str) {
                if features.hash_functions.len() < 16 {
                    features.hash_functions.push(t.to_owned());
                }
            }
        }
        _ => {}
    }
}

fn walk(
    value: &Value,
    depth: usize,
    handles: &mut BTreeMap<String, usize>,
    unsupported: &mut BTreeSet<String>,
    features: &mut RoutingFeatures,
    max_depth: &mut usize,
    max_fanout: &mut usize,
) {
    *max_depth = (*max_depth).max(depth);
    match value {
        Value::String(s) => add_handle(handles, unsupported, features, s),
        Value::Array(a) => {
            *max_fanout = (*max_fanout).max(a.len());
            for v in a {
                walk(
                    v,
                    depth + 1,
                    handles,
                    unsupported,
                    features,
                    max_depth,
                    max_fanout,
                );
            }
        }
        Value::Object(o) => {
            if let Some(t) = o.get("type").and_then(Value::as_str) {
                add_handle(handles, unsupported, features, t);
            }
            if o.get("shadows")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
            {
                features.shadowing = true;
            }
            if o.contains_key("rates") {
                features.rate_limiting = true;
            }
            if o.contains_key("slow_warmup") {
                features.warm_up = true;
            }
            if let Some(Value::Object(pool)) = o.get("pool") {
                if pool.contains_key("servers") {
                    features.inline_pools += 1;
                }
            }
            if let Some(hash) = o.get("hash_func").or_else(|| o.get("hash")) {
                add_hash(features, hash);
            }
            if o.get("ssl").and_then(Value::as_bool) == Some(true)
                || o.contains_key("protocol")
                || o.contains_key("tls")
            {
                features.ssl_or_protocol_markers += 1;
            }
            for (k, v) in o {
                if k == "type" {
                    continue;
                }
                walk(
                    v,
                    depth + 1,
                    handles,
                    unsupported,
                    features,
                    max_depth,
                    max_fanout,
                );
            }
        }
        _ => {}
    }
}

fn finding(
    code: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
) -> RoutingFinding {
    RoutingFinding {
        code,
        severity,
        confidence,
        message,
    }
}

/// Analyze one config document. `source` is `live_config` or `proposed_config`.
pub fn analyze_routing(json: &str, source: &'static str) -> Result<RoutingReport, String> {
    let cfg = crate::parse_config(json)?;
    let root: Value =
        serde_json::from_str(json).map_err(|e| format!("invalid mcrouter config: {e}"))?;
    let route = root.get("route").or_else(|| root.get("routes"));
    let mut handles = BTreeMap::new();
    let mut unsupported = BTreeSet::new();
    let mut features = RoutingFeatures {
        failover: false,
        prefix_selector: false,
        operation_selector: false,
        shadowing: false,
        rate_limiting: false,
        migration: false,
        warm_up: false,
        inline_pools: 0,
        hash_functions: Vec::new(),
        ssl_or_protocol_markers: 0,
    };
    let mut max_depth = 0;
    let mut max_fanout = 0;
    if let Some(route) = route {
        walk(
            route,
            0,
            &mut handles,
            &mut unsupported,
            &mut features,
            &mut max_depth,
            &mut max_fanout,
        );
    }
    let mut findings = Vec::new();
    if route.is_none() {
        findings.push(finding(
            "route_missing",
            Severity::Warning,
            "high",
            "Config has no `route`/`routes` tree; routing behavior is unknown.".to_owned(),
        ));
    }
    if features.shadowing {
        findings.push(finding(
            "shadow_traffic_enabled",
            Severity::Warning,
            "high",
            "PoolRoute shadows duplicate requests to additional targets; shadow writes can increase backend load and must be verified against the intended traffic policy.".to_owned(),
        ));
    }
    if handles.contains_key("AllSyncRoute") {
        findings.push(finding(
            "synchronous_fanout",
            Severity::Warning,
            "medium",
            "AllSyncRoute waits for all children and returns the worst reply; one slow backend can increase latency for every affected request.".to_owned(),
        ));
    }
    if features.migration {
        findings.push(finding(
            "migration_window",
            Severity::Warning,
            "medium",
            "MigrateRoute behavior depends on start_time and interval; verify the current phase against a live route trace before treating the migration as complete.".to_owned(),
        ));
    }
    if !unsupported.is_empty() {
        findings.push(finding(
            "unsupported_route_handle",
            Severity::Warning,
            "unknown",
            format!(
                "The route tree contains handle(s) not modelled by this analyzer: {}; their behavior is UNKNOWN.",
                unsupported.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    if max_fanout > 32 {
        findings.push(finding(
            "large_fanout",
            Severity::Warning,
            "medium",
            format!("A route node has {max_fanout} children; fan-out cost and failure amplification should be reviewed."),
        ));
    }
    if features.inline_pools > 0 {
        findings.push(finding(
            "inline_pools_present",
            Severity::Info,
            "high",
            format!("{} inline pool definition(s) are present; the pool summary does not count them, so topology coverage is partial.", features.inline_pools),
        ));
    }
    if features.rate_limiting {
        findings.push(finding(
            "rate_limiting_configured",
            Severity::Info,
            "high",
            "Pool rate limiting is configured; limits may reject traffic before it reaches a backend.".to_owned(),
        ));
    }
    if features.failover {
        findings.push(finding(
            "failover_configured",
            Severity::Info,
            "high",
            "A failover handle is present; its coverage still depends on failover_errors and runtime TKO state.".to_owned(),
        ));
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let status = if route.is_none() {
        "insufficient_evidence"
    } else if findings.iter().any(|f| f.severity >= Severity::Warning) {
        "review"
    } else {
        "healthy"
    };
    let handle_total: usize = handles.values().sum();
    let mut handle_list: Vec<_> = handles
        .into_iter()
        .map(|(handle, count)| RouteHandleCount { handle, count })
        .collect();
    handle_list.sort_by(|a, b| a.handle.cmp(&b.handle));
    let summary = if route.is_none() {
        "No route tree was found; routing behavior is unknown.".to_owned()
    } else {
        format!(
            "{handle_total} known route handle(s), {} pool(s), {} destination(s), max depth {max_depth}, max fan-out {max_fanout}; {} finding(s).",
            cfg.pools.len(),
            cfg.pools.iter().map(|p| p.servers.len()).sum::<usize>(),
            findings.len()
        )
    };
    Ok(RoutingReport {
        schema_version: ROUTING_SCHEMA_VERSION,
        analysis: "mcrouter_routing",
        source,
        status,
        summary,
        route_present: route.is_some(),
        handles: handle_list,
        handle_total,
        max_depth,
        max_fanout,
        pools: cfg.pools.len(),
        destinations: cfg.pools.iter().map(|p| p.servers.len()).sum(),
        features,
        findings,
        unsupported_handles: unsupported.into_iter().collect(),
        simulation: SimulationStatus {
            status: "unsupported",
            supported_handles: vec![],
            reason: "No validated offline consistent-hash/route simulator is included. Use mcrouter_trace_key_route against a live router to compare actual routing; configuration comparison alone does not establish behavioral equivalence.",
        },
        limitations: vec![
            "Route handles are recognized structurally; nested or custom handlers may be reported as unsupported/UNKNOWN.".to_owned(),
            "Pool counts exclude inline pools; the report flags that partial coverage explicitly.".to_owned(),
            "No config is executed, changed or deployed.".to_owned(),
        ],
    })
}

/// Compare two configs structurally. This is a configuration-impact report, not a routing simulation.
pub fn compare_routing(current_json: &str, proposed_json: &str) -> Result<RoutingImpact, String> {
    let current = analyze_routing(current_json, "live_config")?;
    let proposed = analyze_routing(proposed_json, "proposed_config")?;
    let current_cfg = crate::parse_config(current_json)?;
    let proposed_cfg = crate::parse_config(proposed_json)?;
    let current_pool_names: BTreeSet<_> =
        current_cfg.pools.iter().map(|p| p.name.clone()).collect();
    let proposed_pool_names: BTreeSet<_> =
        proposed_cfg.pools.iter().map(|p| p.name.clone()).collect();
    let current_dests: BTreeSet<_> = crate::destinations(&current_cfg).into_iter().collect();
    let proposed_dests: BTreeSet<_> = crate::destinations(&proposed_cfg).into_iter().collect();
    let mut handle_changes = Vec::new();
    let names: BTreeSet<_> = current
        .handles
        .iter()
        .chain(proposed.handles.iter())
        .map(|h| h.handle.clone())
        .collect();
    for name in names {
        let before = current
            .handles
            .iter()
            .find(|h| h.handle == name)
            .map_or(0, |h| h.count);
        let after = proposed
            .handles
            .iter()
            .find(|h| h.handle == name)
            .map_or(0, |h| h.count);
        if before != after {
            handle_changes.push(HandleDelta {
                handle: name,
                before,
                after,
            });
        }
    }
    let mut feature_changes = Vec::new();
    let f = &current.features;
    let p = &proposed.features;
    if f.failover != p.failover {
        feature_changes.push("failover".to_owned());
    }
    if f.shadowing != p.shadowing {
        feature_changes.push("shadowing".to_owned());
    }
    if f.rate_limiting != p.rate_limiting {
        feature_changes.push("rate_limiting".to_owned());
    }
    if f.migration != p.migration {
        feature_changes.push("migration".to_owned());
    }
    if f.warm_up != p.warm_up {
        feature_changes.push("warm_up".to_owned());
    }
    if f.inline_pools != p.inline_pools {
        feature_changes.push("inline_pools".to_owned());
    }
    let added_pools: Vec<_> = proposed_pool_names
        .difference(&current_pool_names)
        .cloned()
        .collect();
    let removed_pools: Vec<_> = current_pool_names
        .difference(&proposed_pool_names)
        .cloned()
        .collect();
    let added_dests: Vec<_> = proposed_dests.difference(&current_dests).cloned().collect();
    let removed_dests: Vec<_> = current_dests.difference(&proposed_dests).cloned().collect();
    let changed = !added_pools.is_empty()
        || !removed_pools.is_empty()
        || !added_dests.is_empty()
        || !removed_dests.is_empty()
        || !handle_changes.is_empty()
        || !feature_changes.is_empty();
    let summary = if changed {
        format!(
            "Structural change: pools +{}/-{}, destinations +{}/-{}, {} handle change(s), features {:?}. Routing equivalence is UNKNOWN; validate with live traces.",
            added_pools.len(),
            removed_pools.len(),
            added_dests.len(),
            removed_dests.len(),
            handle_changes.len(),
            feature_changes
        )
    } else {
        "No structural pool, destination, handle-count or feature difference was detected; behavioral equivalence is still not claimed.".to_owned()
    };
    Ok(RoutingImpact {
        schema_version: ROUTING_SCHEMA_VERSION,
        analysis: "mcrouter_config_impact",
        status: if changed { "review" } else { "unchanged" },
        summary,
        current,
        proposed,
        pools_added: added_pools,
        pools_removed: removed_pools,
        destinations_added: added_dests,
        destinations_removed: removed_dests,
        handle_changes,
        feature_changes,
        simulation: SimulationStatus {
            status: "unsupported",
            supported_handles: vec![],
            reason: "Structural comparison only; no offline hash/route simulation is validated. Compare live mcrouter route traces before a migration.",
        },
        limitations: vec![
            "Added/removed pools and destinations are not a key-distribution simulation.".to_owned(),
            "Inline pools and custom route handles may make coverage partial/UNKNOWN.".to_owned(),
            "No change is applied to a router or backend.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{
      "pools": {"a": {"servers": ["a:11211"]}, "b": {"servers": ["b:11211"]}},
      "route": {"type": "FailoverRoute", "children": ["PoolRoute|a", "PoolRoute|b"]}
    }"#;

    #[test]
    fn inventories_handles_and_failover() {
        let r = analyze_routing(BASE, "live_config").unwrap();
        assert!(r.route_present);
        assert!(r.features.failover);
        assert!(r.handles.iter().any(|h| h.handle == "FailoverRoute"));
        assert!(r.handles.iter().any(|h| h.handle == "PoolRoute"));
        assert_eq!(r.status, "healthy");
    }

    #[test]
    fn flags_shadowing_and_unknown_handles() {
        let cfg = r#"{
          "pools": {"a": {"servers": ["a:11211"]}},
          "route": {"type": "PoolRoute", "pool": "a",
                    "shadows": [{"target": "PoolRoute|a"}]}
        }"#;
        let r = analyze_routing(cfg, "live_config").unwrap();
        assert!(r.features.shadowing);
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "shadow_traffic_enabled"));
        let unknown = r#"{"route": {"type": "CustomRoute"}}"#;
        let r = analyze_routing(unknown, "live_config").unwrap();
        assert!(r.unsupported_handles.contains(&"CustomRoute".to_owned()));
        assert_eq!(r.simulation.status, "unsupported");
    }

    #[test]
    fn comparison_reports_pool_and_destination_changes() {
        let proposed = r#"{
          "pools": {"a": {"servers": ["a:11211"]}, "c": {"servers": ["c:11211"]}},
          "route": "PoolRoute|a"
        }"#;
        let impact = compare_routing(BASE, proposed).unwrap();
        assert!(impact.pools_added.iter().any(|p| p == "c"));
        assert!(impact.pools_removed.iter().any(|p| p == "b"));
        assert!(impact.destinations_removed.iter().any(|d| d == "b:11211"));
        assert_eq!(impact.simulation.status, "unsupported");
    }
}
