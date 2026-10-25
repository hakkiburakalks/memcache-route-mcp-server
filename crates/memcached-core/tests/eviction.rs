//! Fills a small (-m 4) server and checks the diagnostics flag the evictions.
//! Set MEMCACHED_SMALL_ADDR to a server started with `-m 4`; skipped otherwise.

use std::time::Duration;

use diagnostics::{analyze_node, Severity};
use memcached_core::Client;
use memcached_protocol::text::StoreCmd;

#[tokio::test]
async fn filling_memory_produces_eviction_finding() {
    let Ok(addr) = std::env::var("MEMCACHED_SMALL_ADDR") else {
        eprintln!("MEMCACHED_SMALL_ADDR not set, skipping");
        return;
    };
    let mut c = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap();
    let value = vec![b'x'; 10_000];
    for i in 0..2_000 {
        let key = format!("evict:{i}");
        c.store(StoreCmd::Set, key.as_bytes(), 0, 0, &value)
            .await
            .unwrap();
    }

    let stats = c.stats(None).await.unwrap();
    let items = c.stats(Some("items")).await.unwrap();
    let settings = c.stats(Some("settings")).await.unwrap_or_default();
    let findings = analyze_node(&stats, &items, &settings);
    println!("{findings:#?}");
    let ev = findings
        .iter()
        .find(|f| f.code == "evictions")
        .expect("evictions finding");
    assert!(ev.severity >= Severity::Warning);
    // Uniform item sizes land in one slab class, so skew must not be reported.
    assert!(findings.iter().all(|f| f.code != "eviction_skew"));
}
