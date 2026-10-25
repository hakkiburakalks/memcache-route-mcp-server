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
