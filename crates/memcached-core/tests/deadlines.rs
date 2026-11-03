//! A server that drips a reply must not hold one command open forever. These tests use fake
//! in-process servers and a short client operation deadline; no memcached/Docker is involved.

use std::sync::Arc;
use std::time::{Duration, Instant};

use memcached_core::{Client, ClientError, MemoryBudget};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn slow_server<F, Fut>(reply: F) -> String
where
    F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = sock.read(&mut buf).await;
        reply(sock).await;
    });
    addr
}

fn deadline_error(err: &ClientError) -> bool {
    matches!(err, ClientError::Deadline | ClientError::Timeout)
}

#[tokio::test]
async fn stats_slow_drip_stops_at_the_operation_deadline() {
    let addr = slow_server(|mut sock| async move {
        for i in 0..10_000u32 {
            let line = format!("STAT key_{i} {}\r\n", "x".repeat(32));
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_operation_deadline(Duration::from_millis(120));
    let started = Instant::now();
    let err = client.stats(None).await.unwrap_err();
    assert!(deadline_error(&err), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stats took {:?}",
        started.elapsed()
    );
    // The connection is retired, so leftover STAT lines cannot be read as another answer.
    assert!(matches!(client.stats(None).await, Err(ClientError::Closed)));
}

#[tokio::test]
async fn proxy_stats_slow_drip_stops_at_the_operation_deadline() {
    let addr = slow_server(|mut sock| async move {
        for i in 0..10_000u32 {
            let line = format!("STAT proxy_{i} {}\r\n", "x".repeat(32));
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_operation_deadline(Duration::from_millis(120));
    let started = Instant::now();
    let err = client.stats_proxy().await.unwrap_err();
    assert!(deadline_error(&err), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "proxy stats took {:?}",
        started.elapsed()
    );
    assert!(matches!(
        client.stats_proxy().await,
        Err(ClientError::Closed)
    ));
}

#[tokio::test]
async fn metadump_slow_drip_stops_at_the_operation_deadline() {
    let addr = slow_server(|mut sock| async move {
        if sock.write_all(b"OK\r\n").await.is_err() {
            return;
        }
        for i in 0..10_000u32 {
            let line = format!("key=k{i} exp=-1 la=1 cas=1 fetch=no cls=1 size=10 flags=0\r\n");
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_operation_deadline(Duration::from_millis(120));
    let started = Instant::now();
    let err = client.dump_keys(10_000).await.unwrap_err();
    assert!(deadline_error(&err), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "dump took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn metadata_slow_drip_is_bounded_while_discarding_the_value() {
    let addr = slow_server(|mut sock| async move {
        if sock.write_all(b"VALUE k 0 1000000\r\n").await.is_err() {
            return;
        }
        for _ in 0..200 {
            if sock.write_all(&[b'x'; 8192]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_operation_deadline(Duration::from_millis(100));
    let started = Instant::now();
    let err = client.get_metadata(b"k").await.unwrap_err();
    assert!(deadline_error(&err), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "metadata read took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn value_slow_drip_is_bounded_by_the_operation_deadline() {
    let addr = slow_server(|mut sock| async move {
        if sock.write_all(b"VALUE k 0 1000000\r\n").await.is_err() {
            return;
        }
        for _ in 0..200 {
            if sock.write_all(&[b'x'; 8192]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let mut client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_operation_deadline(Duration::from_millis(100));
    let started = Instant::now();
    let err = client.get(b"k").await.unwrap_err();
    assert!(deadline_error(&err), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "value read took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn uniform_scan_turns_its_deadline_into_an_incomplete_sample() {
    let addr = slow_server(|mut sock| async move {
        if sock.write_all(b"OK\r\n").await.is_err() {
            return;
        }
        for i in 0..10_000u32 {
            let line = format!("key=k{i} exp=-1 la=1 cas=1 fetch=no cls=1 size=10 flags=0\r\n");
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_operation_deadline(Duration::from_secs(30));
    let started = Instant::now();
    let sample = client
        .sample_keys_uniform(10, 1_000, Duration::from_millis(100))
        .await
        .unwrap();
    assert!(!sample.complete);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "uniform scan took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn dropping_a_slow_drip_operation_releases_its_reservations() {
    let addr = slow_server(|mut sock| async move {
        for i in 0..10_000u32 {
            let line = format!("STAT key_{i} {}\r\n", "x".repeat(32));
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let budget = Arc::new(MemoryBudget::new(1024 * 1024));
    let capacity = budget.capacity_bytes();
    let held = Arc::clone(&budget);
    let task = tokio::spawn(async move {
        let mut client = Client::connect(&addr, Duration::from_secs(2))
            .await
            .unwrap()
            .with_operation_deadline(Duration::from_secs(30))
            .with_memory_budget(held);
        let _ = client.stats(None).await;
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while budget.available_bytes() == capacity {
        assert!(
            Instant::now() < deadline,
            "stats never reserved memory before cancellation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        budget.available_bytes(),
        capacity,
        "cancelled slow-drip stats leaked a reservation"
    );
}

#[tokio::test]
async fn dropping_a_slow_drip_proxy_stats_operation_releases_its_reservations() {
    let addr = slow_server(|mut sock| async move {
        for i in 0..10_000u32 {
            let line = format!("STAT proxy_{i} {}\r\n", "x".repeat(32));
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let budget = Arc::new(MemoryBudget::new(1024 * 1024));
    let capacity = budget.capacity_bytes();
    let held = Arc::clone(&budget);
    let task = tokio::spawn(async move {
        let mut client = Client::connect(&addr, Duration::from_secs(2))
            .await
            .unwrap()
            .with_operation_deadline(Duration::from_secs(30))
            .with_memory_budget(held);
        let _ = client.stats_proxy().await;
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while budget.available_bytes() == capacity {
        assert!(
            Instant::now() < deadline,
            "proxy stats never reserved memory before cancellation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        budget.available_bytes(),
        capacity,
        "cancelled slow-drip proxy stats leaked a reservation"
    );
}
