//! Pure analysis of mcrouter output: the live config (`__mcrouter__.preprocessed_config`)
//! and `stats`. Fetching is done by the caller over the memcached protocol.

use std::collections::{BTreeMap, BTreeSet};

use diagnostics::{Finding, Severity};
use serde::Serialize;
use serde_json::Value;

/// Key that returns the config mcrouter is currently running.
pub const CONFIG_KEY: &str = "__mcrouter__.preprocessed_config";

/// Key that asks mcrouter which destination a request would go to.
pub fn route_key(op: &str, key: &str) -> String {
    format!("__mcrouter__.route({op},{key})")
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pool {
    pub name: String,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigSummary {
    pub pools: Vec<Pool>,
    /// Pool names the route tree refers to (`PoolRoute|name` or `"pool": "name"`).
    pub referenced_pools: Vec<String>,
}

fn finding(severity: Severity, code: &'static str, message: String) -> Finding {
    Finding {
        severity,
        code,
        message,
    }
}

fn collect_pool_refs(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            if let Some(name) = s.strip_prefix("PoolRoute|") {
                out.insert(name.to_owned());
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_pool_refs(x, out)),
        Value::Object(o) => {
            for (k, x) in o {
                if k == "pool" {
                    if let Value::String(name) = x {
                        out.insert(name.clone());
                    }
                }
                collect_pool_refs(x, out);
            }
        }
        _ => {}
    }
}

/// Parses the JSON config. Pools defined inline inside the route tree are not listed.
pub fn parse_config(json: &str) -> Result<ConfigSummary, String> {
    let root: Value =
        serde_json::from_str(json).map_err(|e| format!("invalid mcrouter config: {e}"))?;
    let mut pools = Vec::new();
    if let Some(Value::Object(defs)) = root.get("pools") {
        for (name, def) in defs {
            let servers = def
                .get("servers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            pools.push(Pool {
                name: name.clone(),
                servers,
            });
        }
    }
    let mut refs = BTreeSet::new();
    for key in ["route", "routes"] {
        if let Some(r) = root.get(key) {
            collect_pool_refs(r, &mut refs);
        }
    }
    Ok(ConfigSummary {
        pools,
        referenced_pools: refs.into_iter().collect(),
    })
}

/// Structural checks on a parsed config.
pub fn analyze_config(cfg: &ConfigSummary) -> Vec<Finding> {
    let mut out = Vec::new();
    let defined: BTreeSet<&str> = cfg.pools.iter().map(|p| p.name.as_str()).collect();
    let referenced: BTreeSet<&str> = cfg.referenced_pools.iter().map(String::as_str).collect();
    for name in referenced.difference(&defined) {
        out.push(finding(
            Severity::Warning,
            "pool_undefined",
            format!("route refers to pool '{name}' which is not defined in `pools` (it may be defined inline)"),
        ));
    }
    for name in defined.difference(&referenced) {
        out.push(finding(
            Severity::Info,
            "pool_unused",
            format!("pool '{name}' is defined but no PoolRoute refers to it"),
        ));
    }
    for p in &cfg.pools {
        if p.servers.is_empty() {
            out.push(finding(
                Severity::Warning,
                "pool_empty",
                format!("pool '{}' has no servers", p.name),
            ));
        }
        let mut seen = BTreeSet::new();
        for s in &p.servers {
            if !seen.insert(s) {
                out.push(finding(
                    Severity::Warning,
                    "duplicate_server",
                    format!("pool '{}' lists {s} more than once", p.name),
                ));
            }
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

fn num(stats: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    stats.get(key)?.parse().ok()
}

/// Health checks from mcrouter `stats`.
pub fn analyze_stats(stats: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let total = num(stats, "num_servers").unwrap_or(0);
    let down = num(stats, "num_servers_down").unwrap_or(0);
    let suspect = num(stats, "num_suspect_servers").unwrap_or(0);
    if total > 0 && down >= total {
        out.push(finding(
            Severity::Critical,
            "all_destinations_down",
            format!("all {total} destinations are marked down"),
        ));
    } else if down > 0 {
        out.push(finding(
            Severity::Warning,
            "destinations_down",
            format!("{down} of {total} destinations are marked down; requests hashed to them fail or miss unless the route has a failover handle"),
        ));
    }
    if suspect > 0 {
        out.push(finding(
            Severity::Warning,
            "destinations_suspect",
            format!("{suspect} destinations are suspect (recent failures)"),
        ));
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"{
        "pools": {
            "main": {"servers": ["a:11211", "b:11211", "a:11211"]},
            "spare": {"servers": []},
            "old": {"servers": ["c:11211"]}
        },
        "route": {"type": "OperationSelectorRoute",
                  "default_policy": "PoolRoute|main",
                  "operation_policies": {"set": {"type": "PoolRoute", "pool": "ghost"}}}
    }"#;

    fn codes(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.code).collect()
    }

    #[test]
    fn parses_pools_and_references() {
        let c = parse_config(CFG).unwrap();
        assert_eq!(c.pools.len(), 3);
        assert_eq!(c.referenced_pools, ["ghost", "main"]);
        assert!(parse_config("{nope").is_err());
    }

    #[test]
    fn flags_config_problems() {
        let f = analyze_config(&parse_config(CFG).unwrap());
        let mut got = codes(&f);
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "duplicate_server",
                "pool_empty",
                "pool_undefined",
                "pool_unused",
                "pool_unused"
            ]
        );
        assert_eq!(f.last().unwrap().severity, Severity::Info);
    }

    #[test]
    fn clean_config_has_no_findings() {
        let c =
            parse_config(r#"{"pools":{"p":{"servers":["a:1"]}},"route":"PoolRoute|p"}"#).unwrap();
        assert!(analyze_config(&c).is_empty());
    }

    #[test]
    fn stats_health() {
        let s = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect()
        };
        let all = analyze_stats(&s(&[("num_servers", "2"), ("num_servers_down", "2")]));
        assert_eq!(
            (all[0].code, all[0].severity),
            ("all_destinations_down", Severity::Critical)
        );
        let some = analyze_stats(&s(&[
            ("num_servers", "3"),
            ("num_servers_down", "1"),
            ("num_suspect_servers", "1"),
        ]));
        assert_eq!(codes(&some), ["destinations_down", "destinations_suspect"]);
        assert!(analyze_stats(&s(&[("num_servers", "2"), ("num_servers_down", "0")])).is_empty());
    }

    #[test]
    fn builds_route_key() {
        assert_eq!(route_key("get", "foo"), "__mcrouter__.route(get,foo)");
    }
}
