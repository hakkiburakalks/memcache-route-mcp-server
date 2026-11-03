//! Read-only slab allocation, chunk efficiency and storage-pressure analysis.
//!
//! `stats slabs`/`stats items` expose per-class allocation data, but not allocator-internal
//! fragmentation. Reports label computed values as slab/chunk waste and never claim a precise
//! allocator fragmentation or a rebalance outcome.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{num, Severity, Stats};

pub const SLAB_SCHEMA_VERSION: &str = "1.0";
pub const MAX_SLAB_CLASSES: usize = 64;
pub const MAX_SLAB_FINDINGS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlabStatus {
    Healthy,
    Watch,
    Actionable,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SlabClassReport {
    pub class: u32,
    pub chunk_size: u64,
    pub chunks_per_page: u64,
    pub total_pages: u64,
    pub total_chunks: u64,
    pub used_chunks: u64,
    pub free_chunks: u64,
    pub free_chunks_end: u64,
    pub mem_requested_bytes: u64,
    pub items: u64,
    pub evicted: u64,
    pub out_of_memory: u64,
    pub reclaimed: u64,
    pub expired_unfetched: u64,
    pub evicted_unfetched: u64,
    pub crawler_reclaimed: u64,
    pub moves_to_cold: u64,
    pub moves_to_warm: u64,
    pub moves_within_lru: u64,
    pub used_pct: f64,
    pub internal_waste_pct: f64,
    pub page_utilization_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SlabTotals {
    pub classes: usize,
    pub total_chunks: u64,
    pub used_chunks: u64,
    pub free_chunks: u64,
    pub mem_requested_bytes: u64,
    pub allocated_chunk_bytes: u64,
    pub used_pct: f64,
    pub internal_waste_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LruSettings {
    pub segmented_lru: Option<bool>,
    pub maintainer_thread: Option<bool>,
    pub hot_lru_pct: Option<u64>,
    pub warm_lru_pct: Option<u64>,
    pub hot_max_factor: Option<u64>,
    pub warm_max_factor: Option<u64>,
    pub temp_lru: Option<bool>,
    pub slab_reassign: Option<bool>,
    pub slab_automove: Option<u64>,
    pub slab_automove_window: Option<u64>,
    pub slab_automove_ratio: Option<u64>,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExtstoreInfo {
    pub detected: bool,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SlabFinding {
    pub code: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SlabReport {
    pub schema_version: &'static str,
    pub analysis: &'static str,
    pub target: String,
    pub status: SlabStatus,
    pub summary: String,
    pub classes: Vec<SlabClassReport>,
    pub totals: SlabTotals,
    pub lru: LruSettings,
    pub extstore: ExtstoreInfo,
    pub findings: Vec<SlabFinding>,
    pub missing_evidence: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Default)]
struct ParsedClass {
    chunk_size: u64,
    chunks_per_page: u64,
    total_pages: u64,
    total_chunks: u64,
    used_chunks: u64,
    free_chunks: u64,
    free_chunks_end: u64,
    mem_requested: u64,
    items: u64,
    evicted: u64,
    out_of_memory: u64,
    reclaimed: u64,
    expired_unfetched: u64,
    evicted_unfetched: u64,
    crawler_reclaimed: u64,
    moves_to_cold: u64,
    moves_to_warm: u64,
    moves_within_lru: u64,
}

fn set(map: &mut BTreeMap<u32, ParsedClass>, class: u32, field: &str, value: u64) {
    let entry = map.entry(class).or_default();
    match field {
        "chunk_size" => entry.chunk_size = value,
        "chunks_per_page" => entry.chunks_per_page = value,
        "total_pages" => entry.total_pages = value,
        "total_chunks" => entry.total_chunks = value,
        "used_chunks" => entry.used_chunks = value,
        "free_chunks" => entry.free_chunks = value,
        "free_chunks_end" => entry.free_chunks_end = value,
        "mem_requested" => entry.mem_requested = value,
        "number" => entry.items = value,
        "evicted" => entry.evicted = value,
        "outofmemory" => entry.out_of_memory = value,
        "reclaimed" => entry.reclaimed = value,
        "expired_unfetched" => entry.expired_unfetched = value,
        "evicted_unfetched" => entry.evicted_unfetched = value,
        "crawler_reclaimed" => entry.crawler_reclaimed = value,
        "moves_to_cold" => entry.moves_to_cold = value,
        "moves_to_warm" => entry.moves_to_warm = value,
        "moves_within_lru" => entry.moves_within_lru = value,
        _ => {}
    }
}

fn parse_classes(items: &Stats, slabs: &Stats) -> Vec<SlabClassReport> {
    let mut map: BTreeMap<u32, ParsedClass> = BTreeMap::new();
    for (source, prefix) in [(items, "items:"), (slabs, "")] {
        for (key, value) in source {
            let rest = key.strip_prefix(prefix).unwrap_or(key);
            let Some((class, field)) = rest.split_once(':') else {
                continue;
            };
            let Ok(class) = class.parse::<u32>() else {
                continue;
            };
            let Ok(value) = value.parse::<u64>() else {
                continue;
            };
            set(&mut map, class, field, value);
        }
    }
    map.into_iter()
        .take(MAX_SLAB_CLASSES)
        .map(|(class, c)| {
            let allocated = c.total_chunks.saturating_mul(c.chunk_size);
            let used_bytes = c.used_chunks.saturating_mul(c.chunk_size);
            let used_pct = if c.total_chunks > 0 {
                c.used_chunks as f64 * 100.0 / c.total_chunks as f64
            } else {
                0.0
            };
            let internal_waste_pct = if used_bytes > 0 {
                (1.0 - c.mem_requested.min(used_bytes) as f64 / used_bytes as f64) * 100.0
            } else {
                0.0
            };
            let page_utilization_pct = if allocated > 0 {
                c.mem_requested.min(allocated) as f64 * 100.0 / allocated as f64
            } else {
                0.0
            };
            SlabClassReport {
                class,
                chunk_size: c.chunk_size,
                chunks_per_page: c.chunks_per_page,
                total_pages: c.total_pages,
                total_chunks: c.total_chunks,
                used_chunks: c.used_chunks,
                free_chunks: c.free_chunks,
                free_chunks_end: c.free_chunks_end,
                mem_requested_bytes: c.mem_requested,
                items: c.items,
                evicted: c.evicted,
                out_of_memory: c.out_of_memory,
                reclaimed: c.reclaimed,
                expired_unfetched: c.expired_unfetched,
                evicted_unfetched: c.evicted_unfetched,
                crawler_reclaimed: c.crawler_reclaimed,
                moves_to_cold: c.moves_to_cold,
                moves_to_warm: c.moves_to_warm,
                moves_within_lru: c.moves_within_lru,
                used_pct,
                internal_waste_pct,
                page_utilization_pct,
            }
        })
        .collect()
}

fn bool_setting(settings: &Stats, key: &str) -> Option<bool> {
    match settings.get(key).map(String::as_str) {
        Some("1") | Some("yes") | Some("true") => Some(true),
        Some("0") | Some("no") | Some("false") => Some(false),
        _ => None,
    }
}

fn lru(settings: &Stats) -> LruSettings {
    LruSettings {
        segmented_lru: bool_setting(settings, "lru_segmented"),
        maintainer_thread: bool_setting(settings, "lru_maintainer_thread"),
        hot_lru_pct: num(settings, "hot_lru_pct"),
        warm_lru_pct: num(settings, "warm_lru_pct"),
        hot_max_factor: num(settings, "hot_max_factor"),
        warm_max_factor: num(settings, "warm_max_factor"),
        temp_lru: bool_setting(settings, "temp_lru"),
        slab_reassign: bool_setting(settings, "slab_reassign"),
        slab_automove: num(settings, "slab_automove"),
        slab_automove_window: num(settings, "slab_automove_window"),
        slab_automove_ratio: num(settings, "slab_automove_ratio"),
        note: "Segmented-LRU configuration is reported; per-segment HOT/WARM/COLD/TEMP population is not exposed by the stable stats/meta interface and is not guessed.",
    }
}

fn extstore(stats: &Stats) -> ExtstoreInfo {
    let fields: BTreeMap<_, _> = stats
        .iter()
        .filter(|(k, _)| k.starts_with("extstore_"))
        .take(64)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    ExtstoreInfo {
        detected: !fields.is_empty(),
        fields,
    }
}

fn finding(
    code: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
) -> SlabFinding {
    SlabFinding {
        code,
        severity,
        confidence,
        message,
    }
}

/// Analyze `stats`, `stats items`, `stats slabs` and `stats settings` for one node.
pub fn analyze_slabs(
    target: &str,
    stats: &Stats,
    items: &Stats,
    slabs: &Stats,
    settings: &Stats,
) -> SlabReport {
    let classes = parse_classes(items, slabs);
    let total_chunks: u64 = classes.iter().map(|c| c.total_chunks).sum();
    let used_chunks: u64 = classes.iter().map(|c| c.used_chunks).sum();
    let free_chunks: u64 = classes.iter().map(|c| c.free_chunks).sum();
    let mem_requested: u64 = classes.iter().map(|c| c.mem_requested_bytes).sum();
    let allocated: u64 = classes
        .iter()
        .map(|c| c.total_chunks.saturating_mul(c.chunk_size))
        .sum();
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    if classes.is_empty() {
        missing.push("stats slabs/items class data".to_owned());
    }
    for c in &classes {
        if c.out_of_memory > 0 {
            findings.push(finding(
                "slab_out_of_memory",
                Severity::Critical,
                "high",
                format!("Slab class {} reported {} out-of-memory events; the allocator could not grow this class.", c.class, c.out_of_memory),
            ));
        }
        if c.evicted > 0 {
            findings.push(finding(
                "slab_eviction_pressure",
                Severity::Warning,
                "high",
                format!(
                    "Slab class {} evicted {} items; class-level capacity is under pressure.",
                    c.class, c.evicted
                ),
            ));
        }
        if c.used_chunks > 0 && c.internal_waste_pct >= 30.0 {
            findings.push(finding(
                "slab_internal_waste",
                Severity::Warning,
                "medium",
                format!(
                    "Slab class {} has {:.1}% unused bytes inside used chunks (requested {} of {} allocated used bytes); this is chunk-size waste, not a whole-allocator fragmentation measurement.",
                    c.class, c.internal_waste_pct, c.mem_requested_bytes, c.used_chunks.saturating_mul(c.chunk_size)
                ),
            ));
        }
        if c.total_chunks > 0 && c.free_chunks * 2 >= c.total_chunks {
            let pressure = classes.iter().any(|o| o.evicted > 0 || o.out_of_memory > 0);
            if pressure {
                findings.push(finding(
                    "slab_rebalance_opportunity",
                    Severity::Warning,
                    "medium",
                    format!("Slab class {} has {} free of {} chunks while another class reports eviction/OOM pressure; rebalancing may be worth evaluating under change control.", c.class, c.free_chunks, c.total_chunks),
                ));
            }
        }
    }
    if classes.iter().any(|c| c.items > 0) {
        let total_items: u64 = classes.iter().map(|c| c.items).sum();
        if let Some(top) = classes.iter().max_by_key(|c| c.items) {
            if total_items >= 100 && top.items * 100 >= total_items * 80 {
                findings.push(finding(
                    "slab_class_concentration",
                    Severity::Info,
                    "medium",
                    format!("Slab class {} holds {:.1}% of sampled items; verify item-size distribution before changing slab settings.", top.class, top.items as f64 * 100.0 / total_items as f64),
                ));
            }
        }
    }
    if lru(settings).segmented_lru == Some(false) {
        findings.push(finding(
            "segmented_lru_disabled",
            Severity::Info,
            "high",
            "Segmented LRU is disabled in settings; HOT/WARM/COLD/TEMP behavior does not apply to this server.".to_owned(),
        ));
    }
    let ext = extstore(stats);
    if ext.detected
        && ext
            .fields
            .get("extstore_pages_free")
            .and_then(|v| v.parse::<u64>().ok())
            == Some(0)
    {
        findings.push(finding(
            "extstore_no_free_pages",
            Severity::Warning,
            "medium",
            "Extstore reports no free pages; external storage pressure may affect eviction behavior.".to_owned(),
        ));
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings.truncate(MAX_SLAB_FINDINGS);
    let status = if classes.is_empty() {
        SlabStatus::InsufficientEvidence
    } else if findings.iter().any(|f| f.severity >= Severity::Warning) {
        SlabStatus::Actionable
    } else if findings.is_empty() {
        SlabStatus::Healthy
    } else {
        SlabStatus::Watch
    };
    let total_used_pct = if total_chunks > 0 {
        used_chunks as f64 * 100.0 / total_chunks as f64
    } else {
        0.0
    };
    let total_waste = if used_chunks > 0 {
        let usable = classes
            .iter()
            .map(|c| c.used_chunks.saturating_mul(c.chunk_size))
            .sum::<u64>();
        if usable > 0 {
            (1.0 - mem_requested.min(usable) as f64 / usable as f64) * 100.0
        } else {
            0.0
        }
    } else {
        0.0
    };
    let class_count = classes.len();
    let summary = match status {
        SlabStatus::InsufficientEvidence => {
            "No per-class slab data was returned; slab conclusions are not reliable.".to_owned()
        }
        SlabStatus::Actionable => format!(
            "{} slab class finding(s) require review; no rebalance is performed.",
            findings
                .iter()
                .filter(|f| f.severity >= Severity::Warning)
                .count()
        ),
        SlabStatus::Watch => "Only informational slab findings; continue observing.".to_owned(),
        SlabStatus::Healthy => {
            "No slab allocation, eviction or internal-waste finding in this snapshot.".to_owned()
        }
    };
    SlabReport {
        schema_version: SLAB_SCHEMA_VERSION,
        analysis: "slab_fragmentation",
        target: target.to_owned(),
        status,
        summary,
        classes,
        totals: SlabTotals {
            classes: class_count,
            total_chunks,
            used_chunks,
            free_chunks,
            mem_requested_bytes: mem_requested,
            allocated_chunk_bytes: allocated,
            used_pct: total_used_pct,
            internal_waste_pct: total_waste,
        },
        lru: lru(settings),
        extstore: ext,
        findings,
        missing_evidence: missing,
        limitations: vec![
            "Slab/chunk waste is computed from stable stats and is not a precise allocator fragmentation metric.".to_owned(),
            "HOT/WARM/COLD/TEMP population is not exposed by the stable stats interface; only settings are reported.".to_owned(),
            "No slab reassignment, automove or eviction behavior is changed by this analysis.".to_owned(),
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
    fn computes_class_efficiency_and_pressure() {
        let report = analyze_slabs(
            "cache:11211",
            &map(&[("extstore_pages_free", "0")]),
            &map(&[
                ("items:1:number", "1000"),
                ("items:1:evicted", "10"),
                ("items:1:outofmemory", "1"),
            ]),
            &map(&[
                ("1:chunk_size", "96"),
                ("1:chunks_per_page", "10922"),
                ("1:total_pages", "2"),
                ("1:total_chunks", "21844"),
                ("1:used_chunks", "1000"),
                ("1:free_chunks", "20844"),
                ("1:mem_requested", "64000"),
            ]),
            &map(&[
                ("lru_segmented", "yes"),
                ("hot_lru_pct", "20"),
                ("warm_lru_pct", "40"),
            ]),
        );
        assert_eq!(report.classes.len(), 1);
        assert!(report.classes[0].internal_waste_pct > 30.0);
        assert_eq!(report.status, SlabStatus::Actionable);
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "slab_out_of_memory"));
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "slab_rebalance_opportunity"));
    }

    #[test]
    fn missing_data_is_insufficient() {
        let report = analyze_slabs(
            "cache:11211",
            &Stats::new(),
            &Stats::new(),
            &Stats::new(),
            &Stats::new(),
        );
        assert_eq!(report.status, SlabStatus::InsufficientEvidence);
        assert_eq!(report.totals.classes, 0);
    }
}
