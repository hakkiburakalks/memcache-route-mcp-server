//! Runs against a real server. Set MEMCACHED_ADDR (e.g. 127.0.0.1:11211); skipped otherwise.

use std::time::Duration;

use memcached_core::Client;
use memcached_protocol::text::{Status, StoreCmd};

#[tokio::test]
async fn roundtrip_and_probe() {
    let Ok(addr) = std::env::var("MEMCACHED_ADDR") else {
        eprintln!("MEMCACHED_ADDR not set, skipping");
        return;
    };
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let caps = c.probe().await.unwrap();
    println!("capabilities: {caps:?}");
    assert_eq!(
        c.store(StoreCmd::Set, b"mcp:test", 7, 60, b"hello")
            .await
            .unwrap(),
        Status::Stored
    );
    assert_eq!(
        c.get(b"mcp:test").await.unwrap(),
        Some((7, b"hello".to_vec()))
    );
    assert_eq!(c.get(b"mcp:missing").await.unwrap(), None);
    assert!(c.stats(None).await.unwrap().contains_key("pid"));
}

#[tokio::test]
async fn meta_info_reports_without_disturbing_the_item() {
    let Ok(addr) = std::env::var("MEMCACHED_ADDR") else {
        return;
    };
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    if !c.probe().await.unwrap().meta {
        eprintln!("no meta support on this server, skipping");
        return;
    }
    c.store(StoreCmd::Set, b"mcp:meta", 3, 100, b"abcde")
        .await
        .unwrap();

    let first = c.meta_info(b"mcp:meta").await.unwrap().expect("hit");
    assert_eq!((first.size, first.client_flags), (5, 3));
    assert!(matches!(first.ttl_seconds, Some(t) if (95..=100).contains(&t)));
    assert!(!first.hit_before);
    // The inspection itself must not mark the item as fetched.
    let second = c.meta_info(b"mcp:meta").await.unwrap().expect("hit");
    assert!(!second.hit_before);
    assert_eq!(first.cas, second.cas);

    assert_eq!(c.meta_info(b"mcp:no-such-key").await.unwrap(), None);
}
