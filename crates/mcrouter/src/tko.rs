//! Interpretation of mcrouter TKO, destination-health and failover evidence from documented stats.
//!
//! Runtime stats show current state and cumulative observations, not exact transition times. This
//! module reports soft/hard evidence and missing telemetry without inventing recovery timing.

use std::collections::BTreeMap;

use diagnostics::{Severity, Stats};
use serde::Serialize;
use serde_json::Value;

use crate::{FailoverScope, MAX_CONFIG_BYTES};

pub const TKO_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TkoSettings {
    pub failures_until_tko: Option<u64>,
    pub maximum_soft_tkos: Option<u64>,
    pub probe_delay_initial_ms: Option<u64>,
    pub probe_delay_max_ms: Option<u64>,
    pub server_timeout_ms: Option<u64>,
    pub disable_tko_tracking: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TkoFinding {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TkoReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub servers: BTreeMap<String, u64>,
    pub result_counters: BTreeMap<String, u64>,
    pub queue: BTreeMap<String, u64>,
    pub failover_requests: Option<u64>,
    pub shadow_requests: Option<u64>,
    pub config_age_seconds: Option<u64>,
    pub config_failures: Option<u64>,
    pub settings: TkoSettings,
    pub has_failover: bool,
    pub failover_scope: FailoverScope,
    pub findings: Vec<TkoFinding>,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

fn num(stats: &Stats, key: &str) -> Option<u64> {
    stats.get(key)?.parse().ok()
}

fn settings_from_config(json: &str) -> TkoSettings {
    let parsed = if json.len() <= MAX_CONFIG_BYTES {
        serde_json::from_str::<Value>(json).ok()
    } else {
        None
    };
    let root = parsed.as_ref().and_then(Value::as_object);
    let number = |key: &str| root.and_then(|o| o.get(key)).and_then(Value::as_u64);
    let boolean = |key: &str| root.and_then(|o| o.get(key)).and_then(Value::as_bool);
    TkoSettings {
        failures_until_tko: number("failures_until_tko"),
        maximum_soft_tkos: number("maximum_soft_tkos"),
        probe_delay_initial_ms: number("probe_delay_initial_ms"),
        probe_delay_max_ms: number("probe_delay_max_ms"),
        server_timeout_ms: number("server_timeout_ms"),
        disable_tko_tracking: boolean("disable_tko_tracking"),
    }
}

fn finding(
    code: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
) -> TkoFinding {
    TkoFinding {
        code,
        severity,
        confidence,
        message,
    }
}

fn result_count(stats: &Stats, operation: &str) -> Option<u64> {
    // mcrouter exposes cumulative result counters as `result_<name>_count`; some builds also
    // expose `result_<name>_all`.
    num(stats, &format!("result_{operation}_count"))
        .or_else(|| num(stats, &format!("result_{operation}_all")))
}

fn sum_prefixed(stats: &Stats, prefix: &str, suffix: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut seen = false;
    for (key, value) in stats {
        if key.starts_with(prefix) && key.ends_with(suffix) {
            if let Ok(v) = value.parse::<u64>() {
                total = total.saturating_add(v);
                seen = true;
            }
        }
    }
    seen.then_some(total)
}

/// Analyze one mcrouter stats snapshot plus its live config metadata.
pub fn analyze_tko(
    json: &str,
    stats: &Stats,
    has_failover: bool,
    scope: FailoverScope,
) -> TkoReport {
    let total = num(stats, "num_servers");
    let down = num(stats, "num_servers_down");
    let suspect = num(stats, "num_suspect_servers");
    let closed = num(stats, "num_servers_closed");
    let mut servers = BTreeMap::new();
    for (k, v) in [
        ("total", total),
        ("down", down),
        ("suspect", suspect),
        ("closed", closed),
    ] {
        if let Some(v) = v {
            servers.insert(k.to_owned(), v);
        }
    }
    let mut results = BTreeMap::new();
    for op in [
        "tko",
        "connect_error",
        "connect_timeout",
        "timeout",
        "busy",
        "local_error",
        "remote_error",
    ] {
        if let Some(v) = result_count(stats, op) {
            results.insert(op.to_owned(), v);
        }
    }
    let mut queue = BTreeMap::new();
    for key in ["proxy_reqs_processing", "proxy_reqs_waiting"] {
        if let Some(v) = num(stats, key) {
            queue.insert(key.to_owned(), v);
        }
    }
    let failover_requests = sum_prefixed(stats, "cmd_", "_out_failover");
    let shadow_requests = sum_prefixed(stats, "cmd_", "_out_shadow");
    let config_age_seconds = num(stats, "config_age");
    let config_failures = num(stats, "config_failures");
    let settings = settings_from_config(json);
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    if total.is_none() {
        missing.push("num_servers".to_owned());
    }
    if down.is_none() && suspect.is_none() {
        missing.push("num_servers_down/num_suspect_servers".to_owned());
    }
    if results.is_empty() {
        missing.push("result_* TKO/failure counters".to_owned());
    }
    if failover_requests.is_none() {
        missing.push("cmd_*_out_failover".to_owned());
    }
    if settings.failures_until_tko.is_none() {
        missing.push("failures_until_tko (config)".to_owned());
    }
    if settings.probe_delay_initial_ms.is_none() {
        missing.push("probe_delay_initial_ms (config)".to_owned());
    }
    if let Some(d) = down.filter(|d| *d > 0) {
        let severity = if total.is_some_and(|t| t > 0 && d >= t) {
            Severity::Critical
        } else {
            Severity::Warning
        };
        findings.push(finding(
            "hard_tko_evidence",
            severity,
            "high",
            format!(
                "{d} destination(s) are marked down (hard TKO). Writes to their keys fail; reads may return misses unless a failover route covers them."
            ),
        ));
        if !has_failover {
            findings.push(finding(
                "hard_tko_without_failover",
                Severity::Critical,
                "high",
                "Destinations are down and the route has no failover handle; affected keys lose write success and reads look like misses.".to_owned(),
            ));
        } else {
            findings.push(finding(
                "failover_implication",
                Severity::Warning,
                scope.confidence(),
                format!(
                    "Failover is present at scope '{}'; affected operations depend on failover_errors and the live route state.",
                    format!("{scope:?}").to_ascii_lowercase()
                ),
            ));
        }
    }
    if let Some(s) = suspect.filter(|s| *s > 0) {
        findings.push(finding(
            "soft_tko_evidence",
            Severity::Warning,
            "high",
            format!("{s} destination(s) are suspect; this is soft/TKO-probe evidence, not proof of a completed hard TKO."),
        ));
    }
    if let Some(t) = results.get("tko").filter(|v| **v > 0) {
        findings.push(finding(
            "tko_rejections_observed",
            Severity::Warning,
            "high",
            format!("{t} requests were rejected because a destination was marked TKO."),
        ));
    }
    if let Some(f) = failover_requests.filter(|f| *f > 0) {
        findings.push(finding(
            "failover_requests_observed",
            Severity::Info,
            "medium",
            format!("{f} cumulative failover requests were observed; compare with normal request volume before drawing availability conclusions."),
        ));
    }
    if let Some(w) = queue.get("proxy_reqs_waiting").filter(|w| **w > 0) {
        findings.push(finding(
            "proxy_queue_backlog",
            Severity::Warning,
            "medium",
            format!("{w} requests are waiting in the proxy queue; latency may be elevated while TKO/failover is active."),
        ));
    }
    if config_failures.is_some_and(|f| f > 0) {
        findings.push(finding(
            "config_reload_failures",
            Severity::Warning,
            "high",
            format!("mcrouter reports {} failed config reload(s); route/TKO behavior may reflect an older configuration.", config_failures.unwrap_or(0)),
        ));
    }
    if settings.disable_tko_tracking == Some(true) {
        findings.push(finding(
            "tko_tracking_disabled",
            Severity::Warning,
            "high",
            "disable_tko_tracking is set in the configuration; down/suspect counters may not reflect normal TKO behavior.".to_owned(),
        ));
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let status = if total.is_none() && down.is_none() && results.is_empty() {
        "insufficient_evidence"
    } else if findings.iter().any(|f| f.severity >= Severity::Warning) {
        "actionable"
    } else if findings.is_empty() {
        "healthy"
    } else {
        "watch"
    };
    let summary = match status {
        "insufficient_evidence" => "No usable TKO/destination-health counters were returned.".to_owned(),
        "actionable" => format!(
            "{} TKO/destination-health finding(s); runtime transitions and recovery timing require continued observation.",
            findings.iter().filter(|f| f.severity >= Severity::Warning).count()
        ),
        "watch" => "Only informational TKO/failover findings.".to_owned(),
        _ => "No down/suspect destination or TKO rejection evidence in this snapshot.".to_owned(),
    };
    TkoReport {
        schema_version: TKO_SCHEMA_VERSION,
        analysis: "mcrouter_tko",
        status,
        summary,
        servers,
        result_counters: results,
        queue,
        failover_requests,
        shadow_requests,
        config_age_seconds,
        config_failures,
        settings,
        has_failover,
        failover_scope: scope,
        findings,
        missing_evidence: missing,
        limitations: vec![
            "Stats describe current/cumulative state; exact soft-to-hard TKO transitions and recovery times are not available.".to_owned(),
            "TKO behavior depends on mcrouter version/config; unavailable counters are reported as missing, not inferred.".to_owned(),
            "No request is sent and no TKO state or route is changed.".to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> Stats {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn hard_tko_without_failover_is_actionable() {
        let r = analyze_tko(
            "{}",
            &map(&[
                ("num_servers", "3"),
                ("num_servers_down", "1"),
                ("result_tko_count", "5"),
                ("proxy_reqs_waiting", "2"),
                ("config_failures", "1"),
            ]),
            false,
            FailoverScope::None,
        );
        assert_eq!(r.status, "actionable");
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "hard_tko_without_failover"));
        assert!(r.findings.iter().any(|f| f.code == "proxy_queue_backlog"));
    }

    #[test]
    fn soft_tko_and_failover_are_distinct() {
        let r = analyze_tko(
            r#"{"failures_until_tko":3,"maximum_soft_tkos":40}"#,
            &map(&[
                ("num_servers", "3"),
                ("num_suspect_servers", "1"),
                ("cmd_get_out_failover", "12"),
            ]),
            true,
            FailoverScope::Root,
        );
        assert!(r.findings.iter().any(|f| f.code == "soft_tko_evidence"));
        assert_eq!(r.settings.failures_until_tko, Some(3));
        assert_eq!(r.failover_requests, Some(12));
    }

    #[test]
    fn missing_telemetry_is_explicit() {
        let r = analyze_tko("{}", &Stats::new(), false, FailoverScope::NoRoute);
        assert_eq!(r.status, "insufficient_evidence");
        assert!(r.missing_evidence.iter().any(|m| m.contains("num_servers")));
    }
}
