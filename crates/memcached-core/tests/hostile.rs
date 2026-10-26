//! A misbehaving server must not make the client allocate without bound or loop forever.
//! Uses a fake in-process server, so it needs no memcached.

use std::time::Duration;

use memcached_core::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Accepts one connection, waits for the request, then runs `reply` on the socket.
async fn fake_server<F, Fut>(reply: F) -> String
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

#[tokio::test]
async fn huge_value_length_is_refused_not_allocated() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"VALUE k 0 18446744073709551000\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.get(b"k").await.unwrap_err().to_string();
    assert!(err.contains("exceeds"), "{err}");
}

#[tokio::test]
async fn endless_line_is_cut_off() {
    let addr = fake_server(|mut s| async move {
        let junk = vec![b'x'; 64 * 1024];
        for _ in 0..64 {
            if s.write_all(&junk).await.is_err() {
                return;
            }
        }
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.version().await.unwrap_err().to_string();
    assert!(err.contains("too long"), "{err}");
}

#[tokio::test]
async fn endless_stat_stream_is_cut_off() {
    let addr = fake_server(|mut s| async move {
        let mut chunk = Vec::new();
        for i in 0..1000 {
            chunk.extend_from_slice(format!("STAT s{i} 1\r\n").as_bytes());
        }
        // 200 chunks of 1000 lines: far more than the client should accept.
        for n in 0..200 {
            let mut c = chunk.clone();
            c.extend_from_slice(format!("STAT n{n} 1\r\n").as_bytes());
            if s.write_all(&c).await.is_err() {
                return;
            }
        }
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap();
    let err = c.stats(None).await.unwrap_err().to_string();
    assert!(err.contains("too many"), "{err}");
}

#[tokio::test]
async fn stats_group_with_a_second_command_never_reaches_the_wire() {
    // The server would answer END to anything, so a leak would show as a second command in
    // what it received.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), sock.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    });
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(c.stats(Some("settings\r\nflush_all")).await.is_err());
    drop(c);
    assert!(seen.await.unwrap().is_empty());
}

fn dump_lines(n: usize) -> Vec<u8> {
    let mut out = b"OK\r\n".to_vec();
    for i in 0..n {
        out.extend_from_slice(
            format!("key=k%3A{i} exp=-1 la=1 cas=1 fetch=no cls=1 size=10 flags=0\r\n").as_bytes(),
        );
    }
    out.extend_from_slice(b"END\r\n");
    out
}

#[tokio::test]
async fn uniform_sample_covers_the_whole_dump_not_just_its_start() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(&dump_lines(20_000)).await;
    })
    .await;
    let c = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap();
    let sample = c
        .sample_keys_uniform(1_000, 1_000_000, Duration::from_secs(30))
        .await
        .unwrap();
    assert!(sample.complete);
    assert_eq!((sample.seen, sample.entries.len()), (20_000, 1_000));
    let index = |e: &memcached_protocol::text::DumpEntry| -> usize {
        e.key.rsplit(':').next().unwrap().parse().unwrap()
    };
    // Expected 500 from each half (sd about 16); a prefix-only sample would give 1000 / 0.
    let late = sample.entries.iter().filter(|e| index(e) >= 10_000).count();
    assert!(
        (380..=620).contains(&late),
        "{late} of 1000 from the second half"
    );
    let mut keys: Vec<_> = sample.entries.iter().map(|e| e.key.clone()).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 1_000, "no item may be kept twice");
}

#[tokio::test]
async fn uniform_sample_reports_a_capped_scan_as_incomplete() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(&dump_lines(5_000)).await;
    })
    .await;
    let c = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap();
    let sample = c
        .sample_keys_uniform(100, 1_000, Duration::from_secs(30))
        .await
        .unwrap();
    assert!(!sample.complete);
    assert_eq!((sample.seen, sample.entries.len()), (1_000, 100));
}
