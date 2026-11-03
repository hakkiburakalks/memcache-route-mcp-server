//! Process-wide reservation budget behaviour under concurrent, cancelled and hostile reads.
//! These use fake in-process servers, so no memcached or Docker is involved.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use memcached_core::{Client, MemoryBudget};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

const VALUE_BYTES: usize = 16 * 1024 * 1024;

/// Accepts exactly `connections` clients. Each gets a `VALUE` of `value.len()` bytes after its
/// request, delivered in bounded writes rather than one 16 MiB copy per connection.
async fn serve_values(connections: usize, value: Arc<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        for _ in 0..connections {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let value = Arc::clone(&value);
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf).await;
                let header = format!("VALUE k 0 {}\r\n", value.len());
                if sock.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                if sock.write_all(&value).await.is_err() {
                    return;
                }
                let _ = sock.write_all(b"\r\nEND\r\n").await;
            });
        }
    });
    addr
}

fn value_budget() -> MemoryBudget {
    // The same 96 MiB default the server uses. Each 16 MiB value needs a 16 MiB + 1 KiB
    // reservation (the trailing CRLF is included), so only five may be live at once.
    MemoryBudget::new(96 * 1024 * 1024)
}

async fn concurrent_large_values(concurrency: usize) {
    let value = Arc::new(vec![b'x'; VALUE_BYTES]);
    let addr = serve_values(concurrency, Arc::clone(&value)).await;
    let budget = Arc::new(value_budget());
    let capacity = budget.capacity_bytes();
    let per_value = (VALUE_BYTES + 2).div_ceil(1024) * 1024;
    let expected = (capacity / per_value).min(concurrency);

    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut set = JoinSet::new();
    for _ in 0..concurrency {
        let addr = addr.clone();
        let budget = Arc::clone(&budget);
        let barrier = Arc::clone(&barrier);
        set.spawn(async move {
            let mut client = Client::connect(&addr, Duration::from_secs(10))
                .await
                .unwrap()
                .with_memory_budget(budget);
            let result = client.get(b"k").await;
            // Hold every successful reservation until all attempts have been made, so the
            // budget—not scheduling—decides how many large responses may be live together.
            barrier.wait().await;
            match result {
                Ok(Some((_, data))) => {
                    assert_eq!(data.len(), VALUE_BYTES);
                    true
                }
                Ok(None) => panic!("fake server returned a miss"),
                Err(e) => {
                    assert!(e.to_string().contains("memory budget"), "{e}");
                    false
                }
            }
        });
    }
    barrier.wait().await;
    let mut succeeded = 0usize;
    while let Some(result) = set.join_next().await {
        succeeded += usize::from(result.unwrap());
    }
    assert_eq!(
        succeeded, expected,
        "with {concurrency} concurrent 16 MiB values, {succeeded} succeeded and {expected} were expected"
    );
    assert_eq!(
        budget.available_bytes(),
        capacity,
        "a reservation leaked after {concurrency} concurrent reads"
    );
    println!(
        "MEASURED concurrent_values={concurrency} succeeded={succeeded} rejected={} budget_mib={}",
        concurrency - succeeded,
        capacity / (1024 * 1024)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_values_are_bounded_at_1_8_16_and_64_concurrent_calls() {
    for concurrency in [1usize, 8, 16, 64] {
        concurrent_large_values(concurrency).await;
    }
}

/// Sends a valid header, then never finishes the body.
async fn serve_stalled_value(bytes: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 256];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(format!("VALUE k 0 {bytes}\r\n").as_bytes())
            .await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    addr
}

#[tokio::test]
async fn timeout_truncation_and_cancellation_release_their_reservations() {
    // Timeout after the value buffer was reserved.
    let budget = Arc::new(MemoryBudget::new(32 * 1024 * 1024));
    let capacity = budget.capacity_bytes();
    let addr = serve_stalled_value(8 * 1024 * 1024).await;
    {
        let mut client = Client::connect(&addr, Duration::from_millis(200))
            .await
            .unwrap()
            .with_memory_budget(Arc::clone(&budget));
        let err = client.get(b"k").await.unwrap_err().to_string();
        assert!(err.contains("timed out"), "{err}");
    }
    assert_eq!(
        budget.available_bytes(),
        capacity,
        "timeout leaked a reservation"
    );

    // Truncated body (the connection ends before the declared length).
    let budget = Arc::new(MemoryBudget::new(32 * 1024 * 1024));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = sock.read(&mut buf).await;
        let _ = sock.write_all(b"VALUE k 0 100000\r\nshort").await;
        let _ = sock.shutdown().await;
    });
    {
        let mut client = Client::connect(&addr, Duration::from_secs(2))
            .await
            .unwrap()
            .with_memory_budget(Arc::clone(&budget));
        assert!(client.get(b"k").await.is_err());
    }
    assert_eq!(
        budget.available_bytes(),
        budget.capacity_bytes(),
        "truncated reply leaked a reservation"
    );

    // Abort while the value read is in flight.
    let budget = Arc::new(MemoryBudget::new(32 * 1024 * 1024));
    let capacity = budget.capacity_bytes();
    let addr = serve_stalled_value(8 * 1024 * 1024).await;
    let watched = Arc::clone(&budget);
    let task = tokio::spawn(async move {
        let mut client = Client::connect(&addr, Duration::from_secs(30))
            .await
            .unwrap()
            .with_memory_budget(budget);
        let _ = client.get(b"k").await;
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while watched.available_bytes() == capacity {
        assert!(
            tokio::time::Instant::now() < deadline,
            "client never reserved the value buffer"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        watched.available_bytes(),
        capacity,
        "cancellation leaked a reservation"
    );
}

#[tokio::test]
async fn a_budget_smaller_than_the_reply_fails_closed_without_partial_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let sent = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&sent);
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = sock.read(&mut buf).await;
        observed.store(true, Ordering::SeqCst);
        let _ = sock.write_all(b"VALUE k 0 16384\r\n").await;
    });

    // Enough for the 16 KiB line buffer, not for the 16 KiB value it announces.
    let budget = Arc::new(MemoryBudget::new(32 * 1024));
    let mut client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_memory_budget(Arc::clone(&budget));
    let err = client.get(b"k").await.unwrap_err().to_string();
    assert!(err.contains("memory budget"), "{err}");
    assert!(sent.load(Ordering::SeqCst));
    assert_eq!(budget.available_bytes(), budget.capacity_bytes());
}

async fn serve_stat_lines(count: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        let _ = sock.read(&mut buf).await;
        for i in 0..count {
            let line = format!("STAT key_{i:06} {}\r\n", "v".repeat(200));
            if sock.write_all(line.as_bytes()).await.is_err() {
                return;
            }
        }
        let _ = sock.write_all(b"END\r\n").await;
    });
    addr
}

#[tokio::test]
async fn stat_maps_hold_a_reservation_that_is_transferable_and_released() {
    let addr = serve_stat_lines(2_000).await;
    let budget = Arc::new(MemoryBudget::new(96 * 1024 * 1024));
    let capacity = budget.capacity_bytes();
    let mut client = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap()
        .with_memory_budget(Arc::clone(&budget));
    let stats = client.stats(None).await.unwrap();
    assert_eq!(stats.len(), 2_000);
    let held = capacity - budget.available_bytes();
    assert!(held >= 2_000 * 200, "map bytes were not reserved: {held}");
    let guards = client.take_memory_guards();
    assert!(!guards.is_empty());
    assert_eq!(budget.available_bytes(), capacity - held);
    drop(guards);
    assert_eq!(
        budget.available_bytes(),
        capacity,
        "stats reservations leaked after transfer"
    );
}

#[tokio::test]
async fn a_stats_reply_that_does_not_fit_is_rejected_whole() {
    let addr = serve_stat_lines(1).await;
    // Enough for the line buffer, not for the 64 KiB first map-reservation chunk.
    let budget = Arc::new(MemoryBudget::new(16 * 1024));
    let mut client = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap()
        .with_memory_budget(Arc::clone(&budget));
    let err = client.stats(None).await.unwrap_err().to_string();
    assert!(err.contains("memory budget"), "{err}");
    assert_eq!(budget.available_bytes(), budget.capacity_bytes());
}
