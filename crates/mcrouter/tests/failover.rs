//! Behaviour of two mcrouters (tests/compat/docker-compose.yml) while `mc-a` is stopped.
//! Set MCROUTER_PLAIN_ADDR (plain PoolRoute over mc-a, mc-b) and MCROUTER_FAILOVER_ADDR
//! (FailoverRoute mc-a -> mc-b), then stop mc-a. Skipped otherwise.

use std::time::Duration;

use mcrouter::RouteTrace;
use memcached_core::{Client, ClientError};
use memcached_protocol::text::{ProtocolError, Status, StoreCmd};

// The first request to a dead destination waits for mcrouter's connect timeout.
const SLOW: Duration = Duration::from_secs(20);

async fn trace(c: &mut Client, key: &str) -> RouteTrace {
    let (_, raw) = c
        .get(mcrouter::route_key("set", key).as_bytes())
        .await
        .unwrap()
        .expect("route answer");
    mcrouter::interpret_route(&raw)
}

#[tokio::test]
async fn dead_destination_with_and_without_failover() {
    let (Ok(plain), Ok(failover)) = (
        std::env::var("MCROUTER_PLAIN_ADDR"),
        std::env::var("MCROUTER_FAILOVER_ADDR"),
    ) else {
        eprintln!("MCROUTER_PLAIN_ADDR / MCROUTER_FAILOVER_ADDR not set, skipping");
        return;
    };
    let mut p = Client::connect(&plain, SLOW).await.unwrap();
    let mut f = Client::connect(&failover, SLOW).await.unwrap();

    // Provoke the plain router until it has marked mc-a down, then find a key that hashes there.
    let mut victim = None;
    for i in 0..200 {
        let key = format!("failover-test:{i}");
        let _ = p.store(StoreCmd::Set, key.as_bytes(), 0, 60, b"x").await;
        if trace(&mut p, &key).await == RouteTrace::NoDestination {
            victim = Some(key);
            break;
        }
    }
    let key = victim.expect("no key hashed to the stopped destination; is mc-a stopped?");

    // Plain pool: writes fail loudly, reads look like a miss.
    let write = p.store(StoreCmd::Set, key.as_bytes(), 0, 60, b"x").await;
    assert!(
        matches!(write, Err(ClientError::Protocol(ProtocolError::Server(_)))),
        "expected SERVER_ERROR, got {write:?}"
    );
    assert_eq!(p.get(key.as_bytes()).await.unwrap(), None);

    // The same key through the failover route is stored on the backup.
    let write = f
        .store(StoreCmd::Set, key.as_bytes(), 0, 60, b"x")
        .await
        .unwrap();
    assert_eq!(write, Status::Stored);
    assert_eq!(
        trace(&mut f, &key).await,
        RouteTrace::Destination {
            address: "mc-b:11211".into()
        }
    );
    assert_eq!(
        f.get(key.as_bytes()).await.unwrap().map(|(_, v)| v),
        Some(b"x".to_vec())
    );

    // And the diagnosis matches what was just observed.
    let cfg_of = |raw: Vec<u8>| mcrouter::parse_config(std::str::from_utf8(&raw).unwrap()).unwrap();
    let plain_cfg = cfg_of(
        p.get(mcrouter::CONFIG_KEY.as_bytes())
            .await
            .unwrap()
            .unwrap()
            .1,
    );
    let fail_cfg = cfg_of(
        f.get(mcrouter::CONFIG_KEY.as_bytes())
            .await
            .unwrap()
            .unwrap()
            .1,
    );
    assert!(!plain_cfg.has_failover && fail_cfg.has_failover);
    let plain_codes: Vec<_> =
        mcrouter::diagnose_failover(&plain_cfg, &p.stats(None).await.unwrap())
            .iter()
            .map(|x| x.code)
            .collect();
    assert_eq!(plain_codes, ["down_without_failover"]);
    let fail_codes: Vec<_> = mcrouter::diagnose_failover(&fail_cfg, &f.stats(None).await.unwrap())
        .iter()
        .map(|x| x.code)
        .collect();
    assert!(fail_codes.contains(&"failover_active"));
}
