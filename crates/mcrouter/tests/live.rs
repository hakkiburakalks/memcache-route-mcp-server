//! Runs against the mcrouter from tests/compat/docker-compose.yml (pools `main` = mc-a, mc-b).
//! Set MCROUTER_ADDR (e.g. 127.0.0.1:11218); skipped otherwise.

use std::time::Duration;

use memcached_core::Client;

#[tokio::test]
async fn reads_config_and_traces_routes() {
    let Ok(addr) = std::env::var("MCROUTER_ADDR") else {
        eprintln!("MCROUTER_ADDR not set, skipping");
        return;
    };
    let mut c = Client::connect(&addr, Duration::from_secs(3))
        .await
        .unwrap();

    let (_, raw) = c
        .get(mcrouter::CONFIG_KEY.as_bytes())
        .await
        .unwrap()
        .expect("config");
    let cfg = mcrouter::parse_config(std::str::from_utf8(&raw).unwrap()).unwrap();
    assert_eq!(cfg.pools.len(), 1);
    assert_eq!(cfg.pools[0].servers, ["mc-a:11211", "mc-b:11211"]);
    assert!(mcrouter::analyze_config(&cfg).is_empty());

    // Routing is deterministic and lands on a configured server.
    let key = mcrouter::route_key("get", "some-key");
    let (_, first) = c.get(key.as_bytes()).await.unwrap().expect("route");
    let (_, second) = c.get(key.as_bytes()).await.unwrap().expect("route");
    assert_eq!(first, second);
    assert!(cfg.pools[0]
        .servers
        .contains(&String::from_utf8(first).unwrap()));
}
