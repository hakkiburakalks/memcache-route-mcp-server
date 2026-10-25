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
    /// Whether any route handle in the tree is a failover handle (`FailoverRoute`, ...).
    pub has_failover: bool,
}

/// What `__mcrouter__.route(op,key)` answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteTrace {
    Destination {
        address: String,
    },
    /// Empty answer. Seen when the key hashes to a destination that is marked down and nothing
    /// fails over.
    NoDestination,
}

pub fn interpret_route(raw: &[u8]) -> RouteTrace {
    let s = String::from_utf8_lossy(raw);
    let s = s.trim();
    if s.is_empty() {
        RouteTrace::NoDestination
    } else {
        RouteTrace::Destination {
            address: s.to_owned(),
        }
    }
}

fn mentions_failover(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains("Failover"),
        Value::Array(a) => a.iter().any(mentions_failover),
        Value::Object(o) => o
            .iter()
            .any(|(k, x)| k.contains("Failover") || mentions_failover(x)),
        _ => false,
    }
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
    let mut has_failover = false;
    for key in ["route", "routes"] {
        if let Some(r) = root.get(key) {
            collect_pool_refs(r, &mut refs);
            has_failover |= mentions_failover(r);
        }
    }
    Ok(ConfigSummary {
        pools,
        referenced_pools: refs.into_iter().collect(),
        has_failover,
    })
}

/// Every distinct server named in `pools`, in first-seen order.
pub fn destinations(cfg: &ConfigSummary) -> Vec<String> {
    let mut seen = BTreeSet::new();
    cfg.pools
        .iter()
        .flat_map(|p| p.servers.iter())
        .filter(|s| seen.insert(s.as_str()))
        .cloned()
        .collect()
}

/// Parses `internal=reachable,internal2=reachable2`. mcrouter names destinations as it sees
/// them (often container or service names); this maps them to addresses we can connect to.
pub fn parse_dest_map(spec: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for pair in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (from, to) = pair
            .split_once('=')
            .map(|(a, b)| (a.trim(), b.trim()))
            .filter(|(a, b)| !a.is_empty() && !b.is_empty())
            .ok_or_else(|| {
                format!("bad destination mapping '{pair}'; expected internal=reachable")
            })?;
        if map.insert(from.to_owned(), to.to_owned()).is_some() {
            return Err(format!("destination '{from}' is mapped twice"));
        }
    }
    Ok(map)
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

/// Combines the config (is there a failover handle?) with live stats (is anything down?).
///
/// Behaviour behind the wording was observed on mcrouter 34 with a plain `PoolRoute`: once a
/// destination is down, writes to its keys fail with `SERVER_ERROR` while reads return `END`,
/// which looks like an ordinary miss.
pub fn diagnose_failover(cfg: &ConfigSummary, stats: &BTreeMap<String, String>) -> Vec<Finding> {
    let total = num(stats, "num_servers").unwrap_or(0);
    let down = num(stats, "num_servers_down").unwrap_or(0);
    let mut out = Vec::new();
    match (down > 0, cfg.has_failover) {
        (true, false) => out.push(finding(
            Severity::Critical,
            "down_without_failover",
            format!(
                "{down} of {total} destinations are down and the route has no failover handle: \
                 writes to their keys fail and reads come back as misses, so the hit ratio drops without errors"
            ),
        )),
        (true, true) => {
            out.push(finding(
                Severity::Warning,
                "failover_active",
                format!("{down} of {total} destinations are down; the route has a failover handle, so their keys should be served by the fallback"),
            ));
            if total > 0 && down * 2 >= total {
                out.push(finding(
                    Severity::Warning,
                    "failover_capacity",
                    "half or more of the destinations are down; the remaining servers may be overloaded".into(),
                ));
            }
        }
        (false, false) => out.push(finding(
            Severity::Info,
            "no_failover_configured",
            "the route has no failover handle; losing any destination will fail writes and turn reads into misses for its keys".into(),
        )),
        (false, true) => {}
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
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
    fn detects_failover_handles() {
        let plain =
            parse_config(r#"{"pools":{"p":{"servers":["a:1"]}},"route":"PoolRoute|p"}"#).unwrap();
        assert!(!plain.has_failover);
        let fo = parse_config(
            r#"{"pools":{"a":{"servers":["a:1"]},"b":{"servers":["b:1"]}},
                "route":{"type":"FailoverRoute","children":["PoolRoute|a","PoolRoute|b"]}}"#,
        )
        .unwrap();
        assert!(fo.has_failover);
        let nested = parse_config(r#"{"route":{"type":"PrefixSelectorRoute","policies":{"x":"FailoverWithExptimeRoute|a"}}}"#).unwrap();
        assert!(nested.has_failover);
    }

    #[test]
    fn failover_diagnosis_matrix() {
        let s = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect()
        };
        let cfg = |failover| ConfigSummary {
            pools: vec![],
            referenced_pools: vec![],
            has_failover: failover,
        };
        let down1 = s(&[("num_servers", "3"), ("num_servers_down", "1")]);
        let down2 = s(&[("num_servers", "3"), ("num_servers_down", "2")]);
        let healthy = s(&[("num_servers", "3"), ("num_servers_down", "0")]);

        let f = diagnose_failover(&cfg(false), &down1);
        assert_eq!(
            (f[0].code, f[0].severity),
            ("down_without_failover", Severity::Critical)
        );
        assert_eq!(
            codes(&diagnose_failover(&cfg(true), &down1)),
            ["failover_active"]
        );
        assert_eq!(
            codes(&diagnose_failover(&cfg(true), &down2)),
            ["failover_active", "failover_capacity"]
        );
        assert_eq!(
            codes(&diagnose_failover(&cfg(false), &healthy)),
            ["no_failover_configured"]
        );
        assert!(diagnose_failover(&cfg(true), &healthy).is_empty());
    }

    #[test]
    fn interprets_route_answers() {
        assert_eq!(
            interpret_route(b"mc-b:11211"),
            RouteTrace::Destination {
                address: "mc-b:11211".into()
            }
        );
        assert_eq!(interpret_route(b""), RouteTrace::NoDestination);
        assert_eq!(interpret_route(b" \r\n"), RouteTrace::NoDestination);
    }

    #[test]
    fn lists_distinct_destinations() {
        let c = parse_config(
            r#"{"pools":{"a":{"servers":["x:1","y:1"]},"b":{"servers":["y:1","z:1","x:1"]}}}"#,
        )
        .unwrap();
        assert_eq!(destinations(&c), ["x:1", "y:1", "z:1"]);
    }

    #[test]
    fn parses_destination_map() {
        let m = parse_dest_map(" mc-a:11211=127.0.0.1:1 , mc-b:11211=127.0.0.1:2,").unwrap();
        assert_eq!(m["mc-a:11211"], "127.0.0.1:1");
        assert_eq!(m.len(), 2);
        assert!(parse_dest_map("").unwrap().is_empty());
        assert!(parse_dest_map("novalue").is_err());
        assert!(parse_dest_map("a=").is_err());
        assert!(parse_dest_map("a=b,a=c").is_err());
    }

    #[test]
    fn builds_route_key() {
        assert_eq!(route_key("get", "foo"), "__mcrouter__.route(get,foo)");
    }
}
