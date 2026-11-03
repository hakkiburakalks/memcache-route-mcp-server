//! Safe adapter for Memcached's built-in proxy.
//!
//! The proxy is available only in proxy-capable builds starting at Memcached 1.6.23. This module
//! reads the proxy's documented `stats proxy`/`stats proxyfuncs` views and reports them without
//! executing or evaluating Lua. Dynamic routing configuration is deliberately reported as
//! unanalysed/UNKNOWN rather than guessed from source text.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{Severity, Stats};

pub const PROXY_SCHEMA_VERSION: &str = "1.0";
pub const PROXY_MIN_VERSION: (u64, u64, u64) = (1, 6, 23);
const MAX_PROXY_FIELDS: usize = 128;
const MAX_PROXY_TEXT: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProxyFinding {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProxyReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub target: String,
    pub version: String,
    pub supported_since: &'static str,
    pub version_supported: bool,
    /// Explicit `proxy_enabled` value when it is present and well-formed (`yes`/`no`).
    pub enabled: Option<bool>,
    pub detected: bool,
    /// True only when both documented proxy views were read and at least one field was returned.
    pub statistics_available: bool,
    /// Bounded error text when a proxy stats command failed; never a silent empty success.
    pub statistics_error: Option<String>,
    pub status: &'static str,
    pub summary: String,
    pub stats: BTreeMap<String, String>,
    pub functions: BTreeMap<String, String>,
    pub settings: BTreeMap<String, String>,
    pub findings: Vec<ProxyFinding>,
    pub limitations: Vec<String>,
}

fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split('-')
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

fn at_least(version: (u64, u64, u64), minimum: (u64, u64, u64)) -> bool {
    version >= minimum
}

/// Whether this version is documented to include the built-in proxy. An unparseable version is
/// not treated as supported.
pub fn version_supports_proxy(version: &str) -> bool {
    parse_version(version).is_some_and(|v| at_least(v, PROXY_MIN_VERSION))
}

fn clip(value: &str) -> String {
    value.chars().take(MAX_PROXY_TEXT).collect()
}

fn numeric(map: &Stats, key: &str) -> Option<u64> {
    map.get(key)?.parse().ok()
}

fn proxy_only(map: &Stats) -> BTreeMap<String, String> {
    map.iter()
        .filter(|(k, _)| k.to_ascii_lowercase().contains("proxy"))
        .take(MAX_PROXY_FIELDS)
        .map(|(k, v)| (clip(k), clip(v)))
        .collect()
}

fn finding(
    code: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
) -> ProxyFinding {
    ProxyFinding {
        code,
        severity,
        confidence,
        message,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxySetting {
    Enabled,
    Disabled,
    Missing,
    Malformed(String),
}

fn proxy_setting(settings: &Stats) -> ProxySetting {
    let Some(raw) = settings
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy_enabled"))
        .map(|(_, v)| v)
    else {
        return ProxySetting::Missing;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "yes" => ProxySetting::Enabled,
        "no" => ProxySetting::Disabled,
        _ => ProxySetting::Malformed(clip(raw)),
    }
}

/// Interpret proxy stats from a proxy-capable server. `stats` is the normal node stats map;
/// `proxy` is the result of `stats proxy`; `functions` is the result of `stats proxyfuncs`;
/// `settings` is `stats settings`.
///
/// Command errors are passed through instead of being converted to empty maps, so an enabled proxy
/// whose statistics are unavailable cannot be reported as successfully observed.
pub fn analyze_proxy(
    target: &str,
    version: &str,
    stats: &Stats,
    proxy: Result<&Stats, String>,
    functions: Result<&Stats, String>,
    settings: &Stats,
) -> ProxyReport {
    let parsed = parse_version(version);
    let supported = parsed.is_some_and(|v| at_least(v, PROXY_MIN_VERSION));
    let setting = proxy_setting(settings);
    let enabled = match &setting {
        ProxySetting::Enabled => Some(true),
        ProxySetting::Disabled => Some(false),
        ProxySetting::Missing | ProxySetting::Malformed(_) => None,
    };
    let proxy_map = proxy.as_ref().ok().copied();
    let functions_map = functions.as_ref().ok().copied();
    let statistics_error = proxy
        .as_ref()
        .err()
        .cloned()
        .or_else(|| functions.as_ref().err().cloned())
        .map(|e| clip(&e));
    let statistics_available = proxy.is_ok()
        && functions.is_ok()
        && (proxy_map.is_some_and(|m| !m.is_empty())
            || functions_map.is_some_and(|m| !m.is_empty()));
    let detected = statistics_available || matches!(&setting, ProxySetting::Enabled);
    let config_present = settings
        .keys()
        .any(|k| k == "proxy_config" || k == "proxy_arg");

    let mut findings = Vec::new();
    if parsed.is_none() {
        findings.push(finding(
            "version_unparseable",
            Severity::Info,
            "low",
            format!(
                "Could not parse server version '{version}'; proxy support cannot be established."
            ),
        ));
    } else if !supported {
        findings.push(finding(
            "proxy_requires_1_6_23",
            Severity::Info,
            "high",
            format!("Memcached {version} predates the built-in proxy (1.6.23); proxy analysis is not applicable."),
        ));
    } else {
        match &setting {
            ProxySetting::Disabled => findings.push(finding(
                "proxy_disabled",
                Severity::Info,
                "high",
                format!("Memcached {version} reports proxy_enabled=no; proxy analysis is not applicable."),
            )),
            ProxySetting::Missing => findings.push(finding(
                "proxy_enabled_missing",
                Severity::Info,
                "low",
                "Proxy statistics are unavailable and proxy_enabled is missing; proxy capability is unknown.".to_owned(),
            )),
            ProxySetting::Malformed(raw) => findings.push(finding(
                "proxy_enabled_malformed",
                Severity::Info,
                "low",
                format!("proxy_enabled has an unrecognized value '{raw}'; proxy capability is unknown."),
            )),
            ProxySetting::Enabled if !statistics_available => findings.push(finding(
                "proxy_statistics_unavailable",
                Severity::Warning,
                "high",
                "Proxy is enabled, but stats proxy/proxyfuncs returned no usable fields or failed; no counters are inferred.".to_owned(),
            )),
            ProxySetting::Enabled => {}
        }
    }

    if statistics_available {
        if let Some(proxy_stats) = proxy_map {
            for (key, value) in proxy_stats {
                let Some(n) = value.parse::<u64>().ok() else {
                    continue;
                };
                if n > 0 && key.to_ascii_lowercase().contains("error") {
                    findings.push(finding(
                        "proxy_error_counters",
                        Severity::Warning,
                        "medium",
                        format!(
                            "Proxy counter '{key}' reports {n}; inspect proxy logs and backend health."
                        ),
                    ));
                    break;
                }
            }
        }
        if numeric(stats, "curr_connections").is_some_and(|c| c > 0) {
            findings.push(finding(
                "proxy_observed",
                Severity::Info,
                "high",
                "Proxy-specific stats were returned; counters are reported verbatim because their semantics vary by build and route library.".to_owned(),
            ));
        }
    }
    if config_present {
        findings.push(finding(
            "proxy_config_not_analysed",
            Severity::Info,
            "high",
            "A proxy configuration setting is present, but Lua/configuration is intentionally not evaluated. Use the proxy's own documented stats/API for dynamic behavior.".to_owned(),
        ));
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let status = if parsed.is_none() {
        "insufficient_evidence"
    } else if !supported {
        "not_applicable"
    } else {
        match &setting {
            ProxySetting::Disabled => "disabled",
            ProxySetting::Enabled if statistics_available => "observed",
            ProxySetting::Enabled => "statistics_unavailable",
            ProxySetting::Missing | ProxySetting::Malformed(_) if statistics_available => {
                "observed"
            }
            ProxySetting::Missing | ProxySetting::Malformed(_) => "insufficient_evidence",
        }
    };

    let summary = match status {
        "not_applicable" => format!("Memcached {version} is older than the built-in proxy (1.6.23)."),
        "disabled" => format!("Proxy is explicitly disabled on Memcached {version} (proxy_enabled=no)."),
        "statistics_unavailable" => format!(
            "Proxy is enabled on Memcached {version}, but proxy statistics were unavailable; no counters are inferred."
        ),
        "insufficient_evidence" => match &setting {
            ProxySetting::Missing => {
                "Proxy capability is unknown: proxy_enabled is missing and no proxy statistics were returned."
                    .to_owned()
            }
            ProxySetting::Malformed(raw) => format!(
                "Proxy capability is unknown: proxy_enabled has an unrecognized value '{raw}' and no proxy statistics were returned."
            ),
            _ => "Server version is unavailable; proxy support is unknown.".to_owned(),
        },
        _ => format!(
            "Proxy observed on {version}: {} proxy stat(s), {} function stat(s), {} proxy-related setting(s).",
            proxy_map.map_or(0, |m| m.len()),
            functions_map.map_or(0, |m| m.len()),
            proxy_only(settings).len()
        ),
    };

    ProxyReport {
        schema_version: PROXY_SCHEMA_VERSION,
        analysis: "memcached_proxy",
        target: target.to_owned(),
        version: version.to_owned(),
        supported_since: "1.6.23",
        version_supported: supported,
        enabled,
        detected,
        statistics_available,
        statistics_error,
        status,
        summary,
        stats: proxy_map
            .into_iter()
            .flat_map(|m| m.iter())
            .take(MAX_PROXY_FIELDS)
            .map(|(k, v)| (clip(k), clip(v)))
            .collect(),
        functions: functions_map
            .into_iter()
            .flat_map(|m| m.iter())
            .take(MAX_PROXY_FIELDS)
            .map(|(k, v)| (clip(k), clip(v)))
            .collect(),
        settings: proxy_only(settings),
        findings,
        limitations: vec![
            "Proxy support requires a build with proxy features; official package builds may omit it.".to_owned(),
            "Proxy detection uses proxy_enabled and the documented stats proxy/proxyfuncs views; missing, malformed or unavailable evidence is reported as unknown, never inferred.".to_owned(),
            "Lua route configuration is never executed, parsed as code or treated as trusted instructions.".to_owned(),
            "Proxy counter semantics vary by version and route library; raw values are reported without inferred causality.".to_owned(),
            "Dynamic route behavior is UNKNOWN unless verified through the proxy's own documented interfaces.".to_owned(),
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

    fn empty() -> Stats {
        Stats::new()
    }

    #[test]
    fn older_versions_are_not_applicable() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.22",
            &empty(),
            Ok(&empty()),
            Ok(&empty()),
            &empty(),
        );
        assert_eq!(r.status, "not_applicable");
        assert!(!r.version_supported);
        assert_eq!(r.enabled, None);
        assert!(!r.statistics_available);
    }

    #[test]
    fn detects_proxy_stats_and_redacts_to_bounded_fields() {
        let settings = map(&[
            ("proxy_enabled", "yes"),
            ("proxy_config", "/etc/mc.lua"),
            ("other", "x"),
        ]);
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &map(&[("curr_connections", "1")]),
            Ok(&map(&[("proxy_reqs", "5"), ("proxy_backend_errors", "2")])),
            Ok(&map(&[("route_direct", "1")])),
            &settings,
        );
        assert!(r.detected);
        assert_eq!(r.enabled, Some(true));
        assert!(r.statistics_available);
        assert_eq!(r.status, "observed");
        assert!(r.stats.contains_key("proxy_reqs"));
        assert!(r.functions.contains_key("route_direct"));
        assert!(!r.settings.contains_key("other"));
        assert!(r.findings.iter().any(|f| f.code == "proxy_error_counters"));
        assert!(r.findings.iter().any(|f| f.code == "proxy_observed"));
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "proxy_config_not_analysed"));
    }

    #[test]
    fn proxy_disabled_is_explicit_and_not_detected() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Ok(&empty()),
            Ok(&empty()),
            &map(&[("proxy_enabled", "no")]),
        );
        assert_eq!(r.status, "disabled");
        assert_eq!(r.enabled, Some(false));
        assert!(!r.detected);
        assert!(!r.statistics_available);
        assert!(r.findings.iter().any(|f| f.code == "proxy_disabled"));
    }

    #[test]
    fn missing_proxy_enabled_is_unknown_without_statistics() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Ok(&empty()),
            Ok(&empty()),
            &empty(),
        );
        assert_eq!(r.status, "insufficient_evidence");
        assert_eq!(r.enabled, None);
        assert!(!r.detected);
        assert!(r.findings.iter().any(|f| f.code == "proxy_enabled_missing"));
    }

    #[test]
    fn malformed_proxy_enabled_is_unknown() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Ok(&empty()),
            Ok(&empty()),
            &map(&[("proxy_enabled", "maybe")]),
        );
        assert_eq!(r.status, "insufficient_evidence");
        assert_eq!(r.enabled, None);
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "proxy_enabled_malformed"));
    }

    #[test]
    fn statistics_are_present_but_proxy_enabled_is_missing() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Ok(&map(&[("cmd_get", "4")])),
            Ok(&empty()),
            &empty(),
        );
        assert_eq!(r.status, "observed");
        assert!(r.statistics_available);
        assert!(r.detected);
        assert!(r.findings.iter().any(|f| f.code == "proxy_enabled_missing"));
    }

    #[test]
    fn enabled_proxy_with_empty_statistics_is_unavailable() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Ok(&empty()),
            Ok(&empty()),
            &map(&[("proxy_enabled", "yes")]),
        );
        assert_eq!(r.status, "statistics_unavailable");
        assert_eq!(r.enabled, Some(true));
        assert!(r.detected);
        assert!(!r.statistics_available);
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "proxy_statistics_unavailable"));
    }

    #[test]
    fn proxy_stats_command_error_is_not_a_silent_empty_success() {
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Err("stats proxy failed: ERROR".to_owned()),
            Ok(&empty()),
            &map(&[("proxy_enabled", "yes")]),
        );
        assert_eq!(r.status, "statistics_unavailable");
        assert!(r.stats.is_empty());
        assert!(!r.statistics_available);
        assert_eq!(
            r.statistics_error.as_deref(),
            Some("stats proxy failed: ERROR")
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "proxy_statistics_unavailable"));
    }

    #[test]
    fn unparseable_version_is_insufficient_evidence() {
        let r = analyze_proxy(
            "cache:11211",
            "unknown",
            &empty(),
            Ok(&empty()),
            Ok(&empty()),
            &map(&[("proxy_enabled", "yes")]),
        );
        assert_eq!(r.status, "insufficient_evidence");
        assert!(r.findings.iter().any(|f| f.code == "version_unparseable"));
    }

    #[test]
    fn proxy_fields_are_bounded() {
        let proxy: Stats = (0..300)
            .map(|i| (format!("proxy_field_{i}"), "x".repeat(400)))
            .collect();
        let functions: Stats = (0..300)
            .map(|i| (format!("func_{i}"), "y".repeat(400)))
            .collect();
        let r = analyze_proxy(
            "cache:11211",
            "1.6.45",
            &empty(),
            Ok(&proxy),
            Ok(&functions),
            &map(&[("proxy_enabled", "yes")]),
        );
        assert_eq!(r.status, "observed");
        assert_eq!(r.stats.len(), MAX_PROXY_FIELDS);
        assert_eq!(r.functions.len(), MAX_PROXY_FIELDS);
        assert!(r.stats.values().all(|v| v.len() <= MAX_PROXY_TEXT));
        assert!(r.functions.values().all(|v| v.len() <= MAX_PROXY_TEXT));
    }
}
