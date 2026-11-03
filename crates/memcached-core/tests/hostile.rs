//! A misbehaving server must not make the client allocate without bound or loop forever.
//! Uses a fake in-process server, so it needs no memcached.

use std::time::Duration;

use memcached_core::Client;
use memcached_protocol::text::StoreCmd;
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
    assert!(c.stats(Some("proxy")).await.is_err());
    assert!(c.stats(Some("proxyfuncs")).await.is_err());
    drop(c);
    assert!(seen.await.unwrap().is_empty());
}

#[tokio::test]
async fn proxy_stats_commands_are_fixed_and_parsed() {
    for (expected, call) in [("stats proxy\r\n", 0u8), ("stats proxyfuncs\r\n", 1u8)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = sock.read(&mut buf).await.unwrap();
            let got = String::from_utf8_lossy(&buf[..n]).into_owned();
            sock.write_all(b"STAT proxy_field 7\r\nEND\r\n")
                .await
                .unwrap();
            got
        });
        let mut c = Client::connect(&addr, Duration::from_secs(2))
            .await
            .unwrap();
        let stats = if call == 0 {
            c.stats_proxy().await.unwrap()
        } else {
            c.stats_proxyfuncs().await.unwrap()
        };
        assert_eq!(stats.get("proxy_field").map(String::as_str), Some("7"));
        assert_eq!(seen.await.unwrap(), expected);
    }
}

#[tokio::test]
async fn proxy_stats_error_is_not_an_empty_success() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"ERROR\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.stats_proxy().await.unwrap_err().to_string();
    assert!(err.contains("ERROR"), "{err}");
}

#[tokio::test]
async fn proxy_stats_endless_reply_is_cut_off() {
    let addr = fake_server(|mut s| async move {
        for i in 0..200_000u32 {
            if s.write_all(format!("STAT p{i} 1\r\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap();
    let err = c.stats_proxy().await.unwrap_err().to_string();
    assert!(err.contains("too many") || err.contains("exceeds"), "{err}");
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
async fn uniform_sample_keeps_at_most_the_sampling_limit() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(&dump_lines(100_001)).await;
    })
    .await;
    let c = Client::connect(&addr, Duration::from_secs(5))
        .await
        .unwrap();
    let sample = c
        .sample_keys_uniform(200_000, 1_000_000, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(sample.entries.len(), 100_000);
    assert!(sample.complete);
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

/// After a reply was cut short the next command must fail, not read the leftovers as its answer.
#[tokio::test]
async fn connection_is_unusable_after_a_stalled_reply() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"STAT a 1\r\n").await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let _ = s.write_all(b"STAT b 2\r\nEND\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_millis(300))
        .await
        .unwrap();
    assert!(c.stats(Some("items")).await.is_err());
    let err = c.stats(Some("settings")).await.unwrap_err().to_string();
    assert!(err.contains("closed"), "{err}");
}

#[tokio::test]
async fn stats_total_bytes_are_capped_and_connection_is_retired() {
    let addr = fake_server(|mut s| async move {
        for i in 0..20 {
            let line = format!("STAT k{i} {}\r\n", "x".repeat(100));
            if s.write_all(line.as_bytes()).await.is_err() {
                return;
            }
        }
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.stats_with_limit(None, 256).await.unwrap_err().to_string();
    assert!(err.contains("byte limit"), "{err}");
    let err = c.stats(None).await.unwrap_err().to_string();
    assert!(err.contains("closed"), "connection was reused: {err}");
}

#[tokio::test]
async fn malformed_stats_reply_retires_the_connection() {
    let addr = fake_server(|mut s| async move {
        let _ = s
            .write_all(b"STAT good 1\r\nNOT A STAT\r\nSTAT later 2\r\nEND\r\n")
            .await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.stats(None).await.unwrap_err().to_string();
    assert!(err.contains("malformed"), "{err}");
    let err = c.stats(None).await.unwrap_err().to_string();
    assert!(err.contains("closed"), "connection was reused: {err}");
}

#[tokio::test]
async fn metadump_total_bytes_are_capped() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(&dump_lines(20)).await;
    })
    .await;
    let c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c
        .dump_keys_with_limit(1_000, 32)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("byte limit"), "{err}");
}

#[tokio::test]
async fn uniform_sample_reports_a_byte_capped_scan_as_incomplete() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(&dump_lines(100)).await;
    })
    .await;
    let c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let sample = c
        .sample_keys_uniform_with_limit(10, 1_000, 128, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(!sample.complete);
    assert!(sample.entries.len() <= 10);
    assert!(sample.seen > 0);
}

#[tokio::test]
async fn metadata_read_discards_the_value_and_respects_its_budget() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"VALUE k 7 100\r\n").await;
        let _ = s.write_all(&[b'x'; 100]).await;
        let _ = s.write_all(b"\r\nEND\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        c.get_metadata_with_limit(b"k", 1_024).await.unwrap(),
        Some((7, 100))
    );

    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"VALUE k 0 100\r\n").await;
        let _ = s.write_all(&[b'x'; 100]).await;
        let _ = s.write_all(b"\r\nEND\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c
        .get_metadata_with_limit(b"k", 64)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("exceeds"), "{err}");
}

#[tokio::test]
async fn get_total_bytes_are_capped() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"VALUE k 0 20\r\n").await;
        let _ = s.write_all(&[b'x'; 20]).await;
        let _ = s.write_all(b"\r\nEND\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.get_with_limit(b"k", 16).await.unwrap_err().to_string();
    assert!(err.contains("exceeds"), "{err}");
    let err = c.get(b"k").await.unwrap_err().to_string();
    assert!(err.contains("closed"), "connection was reused: {err}");
}

#[tokio::test]
async fn malformed_meta_reply_retires_the_connection() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"WAT\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.meta_info(b"k").await.unwrap_err().to_string();
    assert!(err.contains("malformed"), "{err}");
    let err = c.meta_info(b"k").await.unwrap_err().to_string();
    assert!(err.contains("closed"), "connection was reused: {err}");
}

#[tokio::test]
async fn partial_value_reply_retires_the_connection() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"VALUE k 0 10\r\nabc").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(c.get(b"k").await.is_err());
    let err = c.get(b"k").await.unwrap_err().to_string();
    assert!(err.contains("closed"), "connection was reused: {err}");
}

#[tokio::test]
async fn truncated_status_line_is_rejected() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"STORED").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c
        .store(StoreCmd::Set, b"k", 0, 0, b"v")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("newline"), "{err}");
}

#[tokio::test]
async fn mismatched_value_key_is_rejected() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"VALUE other 0 1\r\nx\r\nEND\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.get(b"k").await.unwrap_err().to_string();
    assert!(err.contains("does not match"), "{err}");
}

#[tokio::test]
async fn multiple_value_blocks_for_one_get_are_rejected() {
    let addr = fake_server(|mut s| async move {
        let _ = s
            .write_all(b"VALUE k 0 1\r\nx\r\nVALUE k 0 1\r\ny\r\nEND\r\n")
            .await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.get(b"k").await.unwrap_err().to_string();
    assert!(err.contains("multiple VALUE"), "{err}");
}

#[tokio::test]
async fn negative_meta_values_are_rejected() {
    let addr = fake_server(|mut s| async move {
        let _ = s.write_all(b"HD s-1 f-1 t-2 l-1 c-1\r\n").await;
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    let err = c.meta_info(b"k").await.unwrap_err().to_string();
    assert!(err.contains("negative") || err.contains("mg flag"), "{err}");
}

#[tokio::test]
async fn write_failure_retires_the_connection() {
    let addr = fake_server(|s| async move {
        drop(s);
    })
    .await;
    let mut c = Client::connect(&addr, Duration::from_secs(2))
        .await
        .unwrap();
    // The peer is gone; a large write must not leave the client reusable.
    let value = vec![b'x'; 4 * 1024 * 1024];
    assert!(c.store(StoreCmd::Set, b"k", 0, 0, &value).await.is_err());
    let err = c.stats(None).await.unwrap_err().to_string();
    assert!(err.contains("closed"), "connection was reused: {err}");
}
