//! Pure analysis of mcrouter output: the live config (`__mcrouter__.preprocessed_config`)
//! and `stats`. Fetching is done by the caller over the memcached protocol.

use std::collections::{BTreeMap, BTreeSet};

use diagnostics::{Finding, Severity};

pub mod cluster;
pub mod migration;
pub mod rca;
pub mod routing;
pub mod snapshot;
pub mod tko;
use serde::Serialize;
use serde_json::Value;

/// Key that returns the config mcrouter is currently running.
pub const CONFIG_KEY: &str = "__mcrouter__.preprocessed_config";

/// A running mcrouter config is normally well below this; the cap prevents a hostile or broken
/// proxy from making the parser allocate an unbounded `serde_json` tree.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_CONFIG_POOLS: usize = 1_024;
pub const MAX_SERVERS_PER_POOL: usize = 4_096;
pub const MAX_DEST_MAP_BYTES: usize = 64 * 1024;
pub const MAX_DEST_MAP_ENTRIES: usize = 4_096;
/// A route answer is a destination address, not a payload.
pub const MAX_ROUTE_ANSWER_BYTES: usize = 512;

/// Key that asks mcrouter which destination a request would go to. The key is embedded in
/// mcrouter's route expression; callers must reject keys that contain route syntax.
pub fn route_key(op: &str, key: &str) -> String {
    format!("__mcrouter__.route({op},{key})")
}

/// Rejects keys that cannot be represented safely in `__mcrouter__.route(op,key)`.
///
/// mcrouter uses commas and parentheses as route-expression syntax, and memcached limits a key
/// to 250 bytes. Rejecting is safer than guessing an escape syntax; the caller gets a clear
/// error instead of a misleading destination.
pub fn validate_route_key(op: &str, key: &str) -> Result<(), String> {
    if !matches!(op, "get" | "set" | "delete") {
        return Err(format!("operation must be get, set or delete, got '{op}'"));
    }
    if key.is_empty() {
        return Err("route key must not be empty".to_owned());
    }
    if key.len() > 250 {
        return Err("route key is too long (memcached limit is 250 bytes)".to_owned());
    }
    if key
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || matches!(b, b',' | b'(' | b')' | b'\\'))
    {
        return Err(
            "route key contains syntax that cannot be represented safely (comma, parenthesis, backslash, whitespace or control character)"
                .to_owned(),
        );
    }
    if route_key(op, key).len() > 250 {
        return Err(format!(
            "route key is too long: mcrouter's probe key would be {} bytes (memcached limit is 250); shorten the key",
            route_key(op, key).len()
        ));
    }
    Ok(())
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
    /// Whether any route handle in the tree is a failover handle (`FailoverRoute`, ...). Only
    /// presence is known, not which keys or operations it covers.
    pub has_failover: bool,
    /// Where the failover handle sits, and how sure that makes us about what it covers.
    pub failover_scope: FailoverScope,
}

/// How much can be said about failover from the route tree alone. The config says nothing about
/// which operations a handle fails over (that depends on its `failover_errors`), so even the best
/// case is `Inferred`, never a promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverScope {
    /// No failover handle anywhere in the route tree. Confirmed.
    None,
    /// The route itself is a failover handle, so it sits in front of every key. Inferred:
    /// operations and error types are not checked.
    Root,
    /// A failover handle appears below other route handles (selectors, hashing, ...). Which keys
    /// or operations reach it is not determined. Unknown.
    Nested,
    /// The config has no route to analyse. Unknown.
    NoRoute,
}

impl FailoverScope {
    pub fn confidence(self) -> &'static str {
        match self {
            FailoverScope::None => "confirmed",
            FailoverScope::Root => "inferred",
            FailoverScope::Nested | FailoverScope::NoRoute => "unknown",
        }
    }
}

fn is_failover_handle(v: &Value) -> bool {
    match v {
        Value::String(s) => s.starts_with("Failover"),
        Value::Object(o) => o
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.contains("Failover")),
        _ => false,
    }
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
    try_interpret_route(raw).unwrap_or(RouteTrace::NoDestination)
}

/// Like [`interpret_route`], but rejects an implausibly long answer or one containing control
/// characters. Callers that expose the answer to a user should use this form.
pub fn try_interpret_route(raw: &[u8]) -> Result<RouteTrace, String> {
    let s = String::from_utf8_lossy(raw);
    let s = s.trim();
    if s.len() > MAX_ROUTE_ANSWER_BYTES {
        return Err(format!(
            "route answer is {} bytes; the limit is {MAX_ROUTE_ANSWER_BYTES}",
            s.len()
        ));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err("route answer contains a control character".to_owned());
    }
    if s.is_empty() {
        Ok(RouteTrace::NoDestination)
    } else {
        Ok(RouteTrace::Destination {
            address: s.to_owned(),
        })
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
    if json.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "mcrouter config is {} bytes; the limit is {MAX_CONFIG_BYTES}",
            json.len()
        ));
    }
    let root: Value =
        serde_json::from_str(json).map_err(|e| format!("invalid mcrouter config: {e}"))?;
    let mut pools = Vec::new();
    if let Some(Value::Object(defs)) = root.get("pools") {
        if defs.len() > MAX_CONFIG_POOLS {
            return Err(format!(
                "mcrouter config has {} pools; the limit is {MAX_CONFIG_POOLS}",
                defs.len()
            ));
        }
        for (name, def) in defs {
            let servers = def
                .get("servers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .take(MAX_SERVERS_PER_POOL + 1)
                        .filter_map(|s| s.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if servers.len() > MAX_SERVERS_PER_POOL {
                return Err(format!(
                    "mcrouter pool '{name}' has more than {MAX_SERVERS_PER_POOL} servers"
                ));
            }
            pools.push(Pool {
                name: name.clone(),
                servers,
            });
        }
    }
    let mut refs = BTreeSet::new();
    let mut has_failover = false;
    let mut at_root = false;
    let mut any_route = false;
    for key in ["route", "routes"] {
        if let Some(r) = root.get(key) {
            any_route = true;
            collect_pool_refs(r, &mut refs);
            has_failover |= mentions_failover(r);
            at_root |= is_failover_handle(r);
        }
    }
    let failover_scope = match (any_route, has_failover, at_root) {
        (false, _, _) => FailoverScope::NoRoute,
        (true, false, _) => FailoverScope::None,
        (true, true, true) => FailoverScope::Root,
        (true, true, false) => FailoverScope::Nested,
    };
    Ok(ConfigSummary {
        pools,
        referenced_pools: refs.into_iter().collect(),
        has_failover,
        failover_scope,
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
    if spec.len() > MAX_DEST_MAP_BYTES {
        return Err(format!(
            "destination map is {} bytes; the limit is {MAX_DEST_MAP_BYTES}",
            spec.len()
        ));
    }
    let mut map = BTreeMap::new();
    for pair in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if map.len() >= MAX_DEST_MAP_ENTRIES {
            return Err(format!(
                "destination map has more than {MAX_DEST_MAP_ENTRIES} entries"
            ));
        }
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
                match cfg.failover_scope {
                    FailoverScope::Root => format!("{down} of {total} destinations are down; the route itself is a failover handle, so their keys should be served by the fallback (confidence: inferred; which operations fail over depends on its failover_errors, which is not checked)"),
                    _ => format!("{down} of {total} destinations are down; a failover handle appears in the route below other handles, so whether these keys and operations are protected is unknown (confidence: unknown)"),
                },
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
        // How much the route tree lets us say.
        assert_eq!(plain.failover_scope, FailoverScope::None);
        assert_eq!(plain.failover_scope.confidence(), "confirmed");
        assert_eq!(fo.failover_scope, FailoverScope::Root);
        assert_eq!(fo.failover_scope.confidence(), "inferred");
        assert_eq!(nested.failover_scope, FailoverScope::Nested);
        assert_eq!(nested.failover_scope.confidence(), "unknown");
        let shorthand = parse_config(r#"{"route":"FailoverRoute|x"}"#).unwrap();
        assert_eq!(shorthand.failover_scope, FailoverScope::Root);
        let no_route = parse_config(r#"{"pools":{}}"#).unwrap();
        assert_eq!(no_route.failover_scope, FailoverScope::NoRoute);
        assert_eq!(no_route.failover_scope.confidence(), "unknown");
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
            failover_scope: if failover {
                FailoverScope::Root
            } else {
                FailoverScope::None
            },
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
        assert!(try_interpret_route(&vec![b'x'; MAX_ROUTE_ANSWER_BYTES + 1]).is_err());
        assert!(try_interpret_route(b"mc\nb").is_err());
    }

    #[test]
    fn config_and_destination_map_are_bounded() {
        let huge = "x".repeat(MAX_CONFIG_BYTES + 1);
        assert!(parse_config(&huge).is_err());
        let huge_map = (0..=MAX_DEST_MAP_ENTRIES)
            .map(|i| format!("a{i}=b"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_dest_map(&huge_map).is_err());
        let servers = vec!["\"x:1\""; MAX_SERVERS_PER_POOL + 1].join(",");
        let too_big = format!("{{\"pools\":{{\"p\":{{\"servers\":[{servers}]}}}}}}");
        assert!(parse_config(&too_big).is_err());
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

    #[test]
    fn route_keys_with_protocol_syntax_are_rejected() {
        assert!(validate_route_key("get", "normal:key").is_ok());
        assert!(validate_route_key("delete", "a-b_c.1").is_ok());
        for key in ["", "a,b", "a)b", "a(b", "a\\b", "a b", "a\tb", "a\nb"] {
            assert!(validate_route_key("get", key).is_err(), "{key:?}");
        }
        assert!(validate_route_key("flush_all", "k").is_err());
        let too_long = "x".repeat(250);
        let err = validate_route_key("get", &too_long).unwrap_err();
        assert!(err.contains("too long"), "{err}");
    }
}
