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
