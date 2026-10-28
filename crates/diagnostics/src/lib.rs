//! Pure analysis over memcached `stats` output. No I/O, so every rule is unit-testable.

use std::collections::BTreeMap;

use serde::Serialize;

pub mod inventory;
pub mod prometheus;

pub type Stats = BTreeMap<String, String>;

/// Item-count outliers are only reported when the larger of the two counts reaches this.
const MIN_ITEMS_FOR_OUTLIER: u64 = 100;

/// Below this many gets the hit ratio says little.
const MIN_GETS_FOR_RATIO: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

fn finding(severity: Severity, code: &'static str, message: String) -> Finding {
    Finding {
        severity,
        code,
        message,
    }
}

fn num(stats: &Stats, key: &str) -> Option<u64> {
    stats.get(key)?.parse().ok()
}

/// `get_hits / (get_hits + get_misses)`, or None when absent or there were no gets.
pub fn hit_ratio(stats: &Stats) -> Option<f64> {
    let hits = num(stats, "get_hits")?;
    let total = hits + num(stats, "get_misses")?;
    (total > 0).then(|| hits as f64 / total as f64)
}

/// Per-node checks. `items` is the output of `stats items`, `settings` of `stats settings`;
/// pass empty maps if unavailable and the dependent rules are skipped.
pub fn analyze_node(stats: &Stats, items: &Stats, settings: &Stats) -> Vec<Finding> {
    let mut out = Vec::new();
    check_hit_ratio(stats, &mut out);
    check_memory(stats, &mut out);
    check_connections(stats, settings, &mut out);
    check_eviction_skew(items, &mut out);
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

fn gets(stats: &Stats) -> u64 {
    num(stats, "get_hits").unwrap_or(0) + num(stats, "get_misses").unwrap_or(0)
}

fn check_hit_ratio(stats: &Stats, out: &mut Vec<Finding>) {
    let gets = gets(stats);
    let Some(ratio) = hit_ratio(stats) else {
        return;
    };
    let pct = ratio * 100.0;
    if gets < MIN_GETS_FOR_RATIO {
        out.push(finding(
            Severity::Info,
            "hit_ratio_insufficient_data",
            format!("only {gets} gets since start; hit ratio not meaningful yet"),
        ));
    } else if ratio < 0.5 {
        out.push(finding(
            Severity::Critical,
            "hit_ratio_low",
            format!("hit ratio {pct:.1}%"),
        ));
    } else if ratio < 0.8 {
        out.push(finding(
            Severity::Warning,
            "hit_ratio_low",
            format!("hit ratio {pct:.1}%"),
        ));
    }
}

fn check_memory(stats: &Stats, out: &mut Vec<Finding>) {
    let (Some(used), Some(limit)) = (num(stats, "bytes"), num(stats, "limit_maxbytes")) else {
        return;
    };
    if limit == 0 {
        return;
    }
    let pct = used as f64 / limit as f64 * 100.0;
    let evictions = num(stats, "evictions").unwrap_or(0);
    if evictions > 0 {
        let sev = if pct >= 90.0 {
            Severity::Critical
        } else {
            Severity::Warning
        };
        out.push(finding(
            sev,
            "evictions",
            format!("{evictions} items evicted before expiry; memory {pct:.1}% of limit"),
        ));
    } else if pct >= 90.0 {
        out.push(finding(
            Severity::Warning,
            "memory_near_limit",
            format!("memory {pct:.1}% of limit"),
        ));
    }
}

fn check_connections(stats: &Stats, settings: &Stats, out: &mut Vec<Finding>) {
    if num(stats, "listen_disabled_num").unwrap_or(0) > 0 {
        out.push(finding(
            Severity::Critical,
            "connection_limit_hit",
            "listen_disabled_num > 0: the server stopped accepting connections at its limit".into(),
        ));
    }
    if let (Some(cur), Some(max)) = (num(stats, "curr_connections"), num(settings, "maxconns")) {
        if max > 0 && cur as f64 / max as f64 >= 0.8 {
            out.push(finding(
                Severity::Warning,
                "connections_near_limit",
                format!("{cur} of {max} connections in use"),
            ));
        }
    }
}

/// `stats items` keys look like `items:<slab>:evicted`.
fn per_slab(items: &Stats, field: &str) -> Vec<(String, u64)> {
    items
        .iter()
        .filter_map(|(k, v)| {
            let (slab, f) = k.strip_prefix("items:")?.split_once(':')?;
            if f != field {
                return None;
            }
            Some((slab.to_owned(), v.parse().ok()?))
        })
        .collect()
}

fn check_eviction_skew(items: &Stats, out: &mut Vec<Finding>) {
    let evicted = per_slab(items, "evicted");
    let total: u64 = evicted.iter().map(|(_, n)| n).sum();
    if total < 100 {
        return;
    }
    // With a single populated class all evictions land there by construction, so skew says nothing.
    // Servers that omit `number` are not judged either.
    let populated = per_slab(items, "number")
        .iter()
        .filter(|(_, n)| *n > 0)
        .count();
    if populated < 2 {
        return;
    }
    if let Some((slab, n)) = evicted.iter().max_by_key(|(_, n)| *n) {
        if *n as f64 / total as f64 >= 0.8 {
            out.push(finding(
                Severity::Warning,
                "eviction_skew",
                format!(
                    "slab class {slab} accounts for {n} of {total} evictions; item sizes may not fit the slab layout"
                ),
            ));
        }
    }
}

/// One node's `stats` output, labelled for reporting.
#[derive(Debug, Clone)]
pub struct NodeSummary<'a> {
    pub name: &'a str,
    pub stats: &'a Stats,
}

/// Flags nodes whose item count or hit ratio is far from their peers. Needs at least 3 nodes.
pub fn compare_nodes(nodes: &[NodeSummary<'_>]) -> Vec<Finding> {
    let mut out = Vec::new();
    if nodes.len() < 3 {
        out.push(finding(
            Severity::Info,
            "compare_needs_three_nodes",
            "outlier detection needs at least 3 nodes".into(),
        ));
        return out;
    }
    let mut counts: Vec<u64> = nodes
        .iter()
        .filter_map(|n| num(n.stats, "curr_items"))
        .collect();
    counts.sort_unstable();
    if let Some(&median) = counts.get(counts.len() / 2) {
        if median > 0 {
            for n in nodes {
                if let Some(c) = num(n.stats, "curr_items") {
                    let r = c as f64 / median as f64;
                    // Ratios of tiny counts are noise; both sides small means nothing to report.
                    if c.max(median) >= MIN_ITEMS_FOR_OUTLIER && !(0.5..=2.0).contains(&r) {
                        out.push(finding(
                            Severity::Warning,
                            "item_count_outlier",
                            format!("{}: {c} items vs median {median} ({r:.2}x)", n.name),
                        ));
                    }
                }
            }
        }
    }
    let ratios: Vec<(&str, f64)> = nodes
        .iter()
        // A node that has barely been read says nothing about its hit ratio.
        .filter(|n| gets(n.stats) >= MIN_GETS_FOR_RATIO)
        .filter_map(|n| hit_ratio(n.stats).map(|r| (n.name, r)))
        .collect();
    if let (Some(lo), Some(hi)) = (
        ratios.iter().min_by(|a, b| a.1.total_cmp(&b.1)),
        ratios.iter().max_by(|a, b| a.1.total_cmp(&b.1)),
    ) {
        if hi.1 - lo.1 > 0.2 {
            out.push(finding(
                Severity::Warning,
                "hit_ratio_spread",
                format!(
                    "hit ratio {:.1}% on {} vs {:.1}% on {}",
                    lo.1 * 100.0,
                    lo.0,
                    hi.1 * 100.0,
                    hi.0
                ),
            ));
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
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

    fn codes(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.code).collect()
    }

    #[test]
    fn hit_ratio_math_and_thresholds() {
        let none = Stats::new();
        let s = st(&[("get_hits", "300"), ("get_misses", "700")]);
        assert_eq!(hit_ratio(&s), Some(0.3));
        assert_eq!(
            analyze_node(&s, &none, &none)[0].severity,
            Severity::Critical
        );
        let s = st(&[("get_hits", "700"), ("get_misses", "300")]);
        assert_eq!(
            analyze_node(&s, &none, &none)[0].severity,
            Severity::Warning
        );
        let s = st(&[("get_hits", "950"), ("get_misses", "50")]);
        assert!(analyze_node(&s, &none, &none).is_empty());
    }

    #[test]
    fn small_samples_are_not_judged() {
        let none = Stats::new();
        let s = st(&[("get_hits", "1"), ("get_misses", "9")]);
        assert_eq!(
            codes(&analyze_node(&s, &none, &none)),
            ["hit_ratio_insufficient_data"]
        );
    }

    #[test]
    fn evictions_with_full_memory_are_critical() {
        let none = Stats::new();
        let s = st(&[
            ("bytes", "95"),
            ("limit_maxbytes", "100"),
            ("evictions", "12"),
        ]);
        let f = analyze_node(&s, &none, &none);
        assert_eq!(
            (f[0].code, f[0].severity),
            ("evictions", Severity::Critical)
        );
    }

    #[test]
    fn connection_rules() {
        let none = Stats::new();
        let s = st(&[("listen_disabled_num", "2"), ("curr_connections", "90")]);
        let settings = st(&[("maxconns", "100")]);
        let f = analyze_node(&s, &none, &settings);
        assert_eq!(
            codes(&f),
            ["connection_limit_hit", "connections_near_limit"]
        );
    }

    #[test]
    fn eviction_skew_detected() {
        let none = Stats::new();
        let skewed = st(&[
            ("items:3:evicted", "900"),
            ("items:5:evicted", "50"),
            ("items:7:evicted", "50"),
        ]);
        let with_populated = |base: &Stats| -> Stats {
            let mut m = base.clone();
            for slab in ["3", "5", "7"] {
                m.insert(format!("items:{slab}:number"), "10".into());
            }
            m
        };
        assert_eq!(
            codes(&analyze_node(&none, &with_populated(&skewed), &none)),
            ["eviction_skew"]
        );
        let even = st(&[
            ("items:3:evicted", "400"),
            ("items:5:evicted", "300"),
            ("items:7:evicted", "300"),
        ]);
        assert!(analyze_node(&none, &with_populated(&even), &none).is_empty());
        // Only one populated class: everything evicts there by construction.
        let single = st(&[("items:3:evicted", "900"), ("items:3:number", "10")]);
        assert!(analyze_node(&none, &single, &none).is_empty());
    }

    #[test]
    fn compare_ignores_ratios_of_tiny_counts_but_not_extremes() {
        let mk = |n: &str| st(&[("curr_items", n)]);
        let (a, b, c) = (mk("6"), mk("14"), mk("14"));
        let tiny = [
            NodeSummary {
                name: "a",
                stats: &a,
            },
            NodeSummary {
                name: "b",
                stats: &b,
            },
            NodeSummary {
                name: "c",
                stats: &c,
            },
        ];
        assert!(compare_nodes(&tiny).is_empty());

        let big = mk("3010");
        let skewed = [
            NodeSummary {
                name: "a",
                stats: &a,
            },
            NodeSummary {
                name: "b",
                stats: &b,
            },
            NodeSummary {
                name: "c",
                stats: &big,
            },
        ];
        let f = compare_nodes(&skewed);
        assert_eq!(codes(&f), ["item_count_outlier"]);
        assert!(f[0].message.starts_with("c:"));
    }

    #[test]
    fn compare_finds_outliers() {
        let a = st(&[
            ("curr_items", "1000"),
            ("get_hits", "9000"),
            ("get_misses", "1000"),
        ]);
        let b = st(&[
            ("curr_items", "1100"),
            ("get_hits", "9000"),
            ("get_misses", "1000"),
        ]);
        let c = st(&[
            ("curr_items", "5000"),
            ("get_hits", "5000"),
            ("get_misses", "5000"),
        ]);
        let nodes = [
            NodeSummary {
                name: "a",
                stats: &a,
            },
            NodeSummary {
                name: "b",
                stats: &b,
            },
            NodeSummary {
                name: "c",
                stats: &c,
            },
        ];
        let f = compare_nodes(&nodes);
        assert_eq!(codes(&f), ["item_count_outlier", "hit_ratio_spread"]);
        assert!(f[0].message.starts_with("c:"));
        assert_eq!(
            compare_nodes(&nodes[..2])[0].code,
            "compare_needs_three_nodes"
        );
    }

    #[test]
    fn compare_ignores_hit_ratio_of_barely_read_nodes() {
        let busy = st(&[("get_hits", "9000"), ("get_misses", "1000")]);
        let idle = st(&[("get_hits", "0"), ("get_misses", "5")]);
        let nodes = [
            NodeSummary {
                name: "a",
                stats: &busy,
            },
            NodeSummary {
                name: "b",
                stats: &busy,
            },
            NodeSummary {
                name: "c",
                stats: &idle,
            },
        ];
        assert!(compare_nodes(&nodes).is_empty());
    }
}
