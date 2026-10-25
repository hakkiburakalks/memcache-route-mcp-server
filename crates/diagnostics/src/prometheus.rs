//! Prometheus text exposition of memcached `stats`. Raw counters and gauges only: ratios and
//! rates are left to PromQL, which can compute them over any window.

use std::fmt::Write;

use crate::Stats;

#[derive(Clone, Copy)]
enum Kind {
    Counter,
    Gauge,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
        }
    }
}

/// (memcached stat, metric name, kind, help)
const MEMCACHED_METRICS: &[(&str, &str, Kind, &str)] = &[
    (
        "uptime",
        "memcached_uptime_seconds",
        Kind::Gauge,
        "Seconds since the server started.",
    ),
    (
        "curr_connections",
        "memcached_current_connections",
        Kind::Gauge,
        "Open client connections.",
    ),
    (
        "total_connections",
        "memcached_connections_total",
        Kind::Counter,
        "Connections accepted since start.",
    ),
    (
        "listen_disabled_num",
        "memcached_listen_disabled_total",
        Kind::Counter,
        "Times the connection limit stopped accepting.",
    ),
    (
        "cmd_get",
        "memcached_commands_get_total",
        Kind::Counter,
        "Get commands processed.",
    ),
    (
        "cmd_set",
        "memcached_commands_set_total",
        Kind::Counter,
        "Set commands processed.",
    ),
    (
        "get_hits",
        "memcached_get_hits_total",
        Kind::Counter,
        "Gets that found the key.",
    ),
    (
        "get_misses",
        "memcached_get_misses_total",
        Kind::Counter,
        "Gets that did not find the key.",
    ),
    (
        "evictions",
        "memcached_evictions_total",
        Kind::Counter,
        "Items evicted before they expired.",
    ),
    (
        "reclaimed",
        "memcached_reclaimed_total",
        Kind::Counter,
        "Expired items whose space was reused.",
    ),
    (
        "curr_items",
        "memcached_current_items",
        Kind::Gauge,
        "Items currently stored.",
    ),
    (
        "total_items",
        "memcached_items_total",
        Kind::Counter,
        "Items stored since start.",
    ),
    (
        "bytes",
        "memcached_used_bytes",
        Kind::Gauge,
        "Bytes used to store items.",
    ),
    (
        "limit_maxbytes",
        "memcached_limit_bytes",
        Kind::Gauge,
        "Configured memory limit.",
    ),
    (
        "bytes_read",
        "memcached_read_bytes_total",
        Kind::Counter,
        "Bytes read from the network.",
    ),
    (
        "bytes_written",
        "memcached_written_bytes_total",
        Kind::Counter,
        "Bytes written to the network.",
    ),
];

/// mcrouter's own `stats`. Per-destination detail is not exposed, only the pool-wide counts.
const MCROUTER_METRICS: &[(&str, &str, Kind, &str)] = &[
    (
        "uptime",
        "mcrouter_uptime_seconds",
        Kind::Gauge,
        "Seconds since mcrouter started.",
    ),
    (
        "num_servers",
        "mcrouter_destinations",
        Kind::Gauge,
        "Destinations mcrouter knows about.",
    ),
    (
        "num_servers_up",
        "mcrouter_destinations_up",
        Kind::Gauge,
        "Destinations currently connected and healthy.",
    ),
    (
        "num_servers_down",
        "mcrouter_destinations_down",
        Kind::Gauge,
        "Destinations marked down.",
    ),
    (
        "num_suspect_servers",
        "mcrouter_destinations_suspect",
        Kind::Gauge,
        "Destinations with recent failures.",
    ),
    (
        "num_clients",
        "mcrouter_current_clients",
        Kind::Gauge,
        "Open client connections.",
    ),
    (
        "successful_client_connections",
        "mcrouter_client_connections_total",
        Kind::Counter,
        "Client connections accepted since start.",
    ),
    (
        "cmd_get_count",
        "mcrouter_commands_get_total",
        Kind::Counter,
        "Get requests routed.",
    ),
    (
        "cmd_set_count",
        "mcrouter_commands_set_total",
        Kind::Counter,
        "Set requests routed.",
    ),
    (
        "cmd_delete_count",
        "mcrouter_commands_delete_total",
        Kind::Counter,
        "Delete requests routed.",
    ),
    (
        "destination_pending_reqs",
        "mcrouter_destination_pending_requests",
        Kind::Gauge,
        "Requests queued for destinations.",
    ),
    (
        "destination_inflight_reqs",
        "mcrouter_destination_inflight_requests",
        Kind::Gauge,
        "Requests sent to destinations and awaiting a reply.",
    ),
    (
        "ps_rss",
        "mcrouter_resident_memory_bytes",
        Kind::Gauge,
        "Resident memory of the mcrouter process.",
    ),
];

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// One scrape result per target: `Some(stats)` when reachable, `None` when it was not.
pub fn render(nodes: &[(String, Option<Stats>)]) -> String {
    render_with(
        "memcached_up",
        "Whether the last scrape of the server succeeded.",
        MEMCACHED_METRICS,
        nodes,
    )
}

/// Same shape as [`render`], for mcrouter instances.
pub fn render_mcrouter(nodes: &[(String, Option<Stats>)]) -> String {
    render_with(
        "mcrouter_up",
        "Whether the last scrape of the mcrouter succeeded.",
        MCROUTER_METRICS,
        nodes,
    )
}

fn render_with(
    up_name: &str,
    up_help: &str,
    table: &[(&str, &str, Kind, &str)],
    nodes: &[(String, Option<Stats>)],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# HELP {up_name} {up_help}");
    let _ = writeln!(out, "# TYPE {up_name} gauge");
    for (addr, stats) in nodes {
        let _ = writeln!(
            out,
            "{up_name}{{instance=\"{}\"}} {}",
            escape_label(addr),
            u8::from(stats.is_some())
        );
    }
    for (stat, name, kind, help) in table {
        let samples: Vec<_> = nodes
            .iter()
            .filter_map(|(addr, stats)| {
                let v: f64 = stats.as_ref()?.get(*stat)?.parse().ok()?;
                Some((addr, v))
            })
            .collect();
        if samples.is_empty() {
            continue;
        }
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {}", kind.as_str());
        for (addr, v) in samples {
            let _ = writeln!(out, "{name}{{instance=\"{}\"}} {v}", escape_label(addr));
        }
    }
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

    #[test]
    fn renders_counters_gauges_and_up() {
        let out = render(&[
            (
                "a:1".into(),
                Some(st(&[("get_hits", "7"), ("curr_items", "3"), ("pid", "99")])),
            ),
            ("b:1".into(), None),
        ]);
        assert!(out.contains("memcached_up{instance=\"a:1\"} 1\n"));
        assert!(out.contains("memcached_up{instance=\"b:1\"} 0\n"));
        assert!(out.contains("# TYPE memcached_get_hits_total counter\n"));
        assert!(out.contains("memcached_get_hits_total{instance=\"a:1\"} 7\n"));
        assert!(out.contains("# TYPE memcached_current_items gauge\n"));
        assert!(out.contains("memcached_current_items{instance=\"a:1\"} 3\n"));
        // Unknown stats are not exported, and unreachable nodes have no samples.
        assert!(!out.contains("pid"));
        assert!(!out.contains("instance=\"b:1\"} 7"));
    }

    #[test]
    fn help_and_type_appear_once_per_metric() {
        let s = st(&[("get_hits", "1")]);
        let out = render(&[("a:1".into(), Some(s.clone())), ("b:1".into(), Some(s))]);
        assert_eq!(out.matches("# TYPE memcached_get_hits_total").count(), 1);
        assert_eq!(out.matches("memcached_get_hits_total{").count(), 2);
    }

    #[test]
    fn skips_metrics_without_samples_and_non_numeric_values() {
        let out = render(&[("a:1".into(), Some(st(&[("evictions", "n/a")])))]);
        assert!(!out.contains("memcached_evictions_total"));
    }

    #[test]
    fn escapes_label_values() {
        let out = render(&[("we\"ird\\host".into(), None)]);
        assert!(out.contains(r#"instance="we\"ird\\host""#));
    }

    #[test]
    fn renders_mcrouter_stats() {
        let out = render_mcrouter(&[
            (
                "r:5000".into(),
                Some(st(&[
                    ("num_servers_down", "1"),
                    ("cmd_get_count", "9"),
                    ("version", "34"),
                ])),
            ),
            ("s:5000".into(), None),
        ]);
        assert!(out.contains(
            "mcrouter_up{instance=\"r:5000\"} 1
"
        ));
        assert!(out.contains(
            "mcrouter_up{instance=\"s:5000\"} 0
"
        ));
        assert!(out.contains(
            "# TYPE mcrouter_destinations_down gauge
"
        ));
        assert!(out.contains(
            "mcrouter_destinations_down{instance=\"r:5000\"} 1
"
        ));
        assert!(out.contains(
            "# TYPE mcrouter_commands_get_total counter
"
        ));
        assert!(
            !out.contains("memcached_"),
            "no memcached metrics for mcrouter"
        );
        assert!(!out.contains("version"));
    }
}
