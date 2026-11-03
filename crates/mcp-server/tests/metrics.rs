//! Local `/metrics` resource tests. Fake upstreams and the real MCP binary run on loopback;
//! no Docker and no production server is involved.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::task::{JoinHandle, JoinSet};
/// These tests each start many fake upstreams; run them one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Default)]
struct Load {
    active: Arc<AtomicUsize>,
    max: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
}

struct Upstream {
    addr: String,
    task: JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_upstream(load: Load, delay: Duration, fail: bool) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let load = load.clone();
            tokio::spawn(async move {
                let now = load.active.fetch_add(1, Ordering::SeqCst) + 1;
                load.max.fetch_max(now, Ordering::SeqCst);
                load.total.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let request = String::from_utf8_lossy(&buf);
                let reply: &[u8] = if fail {
                    b"ERROR\r\n"
                } else if request.starts_with("version") {
                    b"VERSION 1.6.0\r\n"
                } else if request.starts_with("stats") {
                    b"STAT pid 1\r\nSTAT uptime 1\r\nSTAT bytes 1\r\nSTAT limit_maxbytes 100\r\nEND\r\n"
                } else {
                    b"END\r\n"
                };
                let _ = sock.write_all(reply).await;
                load.active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Upstream { addr, task }
}

fn token_for(index: usize) -> String {
    format!("metrics-user-{index:02}-token-0123456789abcdef")
}

/// A fake memcached that answers every request with a 16 MiB value and then holds the connection
/// open, so the tool's reply-buffer reservation stays live while other calls arrive.
async fn start_large_value_upstream(value: Arc<Vec<u8>>, hold: Duration) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let value = Arc::clone(&value);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "VALUE __mcrouter__.preprocessed_config 0 {}\r\n",
                    value.len()
                );
                if sock.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                if sock.write_all(&value).await.is_err() {
                    return;
                }
                tokio::time::sleep(hold).await;
                let _ = sock.write_all(b"\r\nEND\r\n").await;
            });
        }
    });
    Upstream { addr, task }
}
fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn temp_dir(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "memcached-mcp-{tag}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Mcp {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Mcp {
    async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    fn rss_mb(&self) -> Option<f64> {
        process_rss_mb(self.child.id()?)
    }
}

/// Current resident set of the child. This is a point sample, not a peak measurement, and is
/// used only to report local simulated scenarios; it is not a Helm sizing result.
fn process_rss_mb(pid: u32) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest.split_whitespace().next()?.parse::<f64>().ok()?;
                return Some(kb / 1024.0);
            }
        }
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let kb = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<f64>()
            .ok()?;
        return Some(kb / 1024.0);
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {pid}).WorkingSet64"),
            ])
            .output()
            .ok()?;
        let bytes = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<f64>()
            .ok()?;
        return Some(bytes / (1024.0 * 1024.0));
    }
    #[allow(unreachable_code)]
    None
}

async fn start_mcp(upstreams: &[Upstream], users: &[String], envs: &[(&str, &str)]) -> Mcp {
    let dir = temp_dir("metrics");
    let tokens = dir.join("tokens.json");
    let entries: Vec<Value> = users
        .iter()
        .enumerate()
        .map(|(i, token)| {
            json!({
                "name": format!("user-{i}"),
                "token_sha256": sha256_hex(token),
                "permissions": ["read", "metrics"],
            })
        })
        .collect();
    std::fs::write(&tokens, json!({"users": entries}).to_string()).unwrap();
    let addrs = upstreams
        .iter()
        .map(|u| u.addr.clone())
        .collect::<Vec<_>>()
        .join(",");

    let mut command = Command::new(env!("CARGO_BIN_EXE_memcached-mcp"));
    command
        .args(["--http", "127.0.0.1:0"])
        .env_remove("MEMCACHED_MCP_ALLOW_WRITE")
        .env_remove("MEMCACHED_MCP_WRITE_PREFIX")
        .env_remove("MEMCACHED_MCP_AUDIT_LOG")
        .env_remove("MEMCACHED_MCP_HTTP_TOKEN")
        .env("MEMCACHED_MCP_HTTP_TOKEN_FILE", &tokens)
        .env("MEMCACHED_MCP_ALLOWLIST", &addrs)
        .env("MEMCACHED_MCP_METRICS_TARGETS", &addrs)
        .env("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "100")
        .env("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100")
        .env("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "1000")
        .env("MEMCACHED_MCP_METRICS_MAX_CONCURRENT", "16")
        .env("MEMCACHED_MCP_METRICS_FANOUT", "16")
        .env("MEMCACHED_MCP_METRICS_TIMEOUT_MS", "5000")
        .env("MEMCACHED_MCP_METRICS_CACHE_MS", "0")
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let port = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut line = String::new();
            assert!(
                err.read_line(&mut line).await.unwrap() > 0,
                "server exited before listening"
            );
            if let Some(rest) = line.trim().strip_prefix("listening on http://127.0.0.1:") {
                return rest.split('/').next().unwrap().parse::<u16>().unwrap();
            }
        }
    })
    .await
    .expect("server never reported its port");
    tokio::spawn(async move {
        let mut sink = String::new();
        while err.read_line(&mut sink).await.unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    Mcp { child, port, dir }
}

async fn raw(port: u16, request: Vec<u8>) -> (u16, String, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(&request).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), sock.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_ascii_lowercase(), body.to_owned())
}

async fn get_metrics(port: u16, token: &str) -> (u16, String) {
    let request = format!(
        "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    let (status, _, body) = raw(port, request.into_bytes()).await;
    (status, body)
}

async fn post(port: u16, token: &str, session: Option<&str>, body: &str) -> (u16, String, String) {
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(session) = session {
        request.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    raw(port, request.into_bytes()).await
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"metrics","version":"0"}}}"#;

async fn session(port: u16, token: &str) -> String {
    let (status, head, body) = post(port, token, None, INIT).await;
    assert_eq!(status, 200, "{body}");
    head.lines()
        .find_map(|line| line.strip_prefix("mcp-session-id:"))
        .expect("session id")
        .trim()
        .to_owned()
}

fn up_values(body: &str) -> Vec<&str> {
    body.lines()
        .filter(|line| line.starts_with("memcached_up{"))
        .map(|line| line.rsplit(' ').next().unwrap_or_default())
        .collect()
}

fn gauge(body: &str, name: &str) -> Option<u64> {
    body.lines()
        .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
}

#[tokio::test]
async fn metrics_fanout_is_bounded_for_16_64_256_nodes() {
    let _guard = SERIAL.lock().await;
    for nodes in [16usize, 64, 256] {
        let load = Load::default();
        let mut upstreams = Vec::new();
        for _ in 0..nodes {
            upstreams.push(start_upstream(load.clone(), Duration::ZERO, false).await);
        }
        let token = token_for(0);
        let mcp = start_mcp(&upstreams, std::slice::from_ref(&token), &[]).await;
        let started = Instant::now();
        let (status, body) = get_metrics(mcp.port, &token).await;
        let elapsed = started.elapsed();
        assert_eq!(status, 200, "{body}");
        assert_eq!(up_values(&body).len(), nodes);
        assert!(
            up_values(&body).iter().all(|v| *v == "1"),
            "some targets were reported unhealthy"
        );
        let max = load.max.load(Ordering::SeqCst);
        assert!(
            max <= 16,
            "metrics fan-out {max} exceeded the configured 16 for {nodes} nodes"
        );
        println!(
            "MEASURED nodes={nodes} elapsed_ms={} max_active={max} total_connections={} rss_mb={:.1}",
            elapsed.as_millis(),
            load.total.load(Ordering::SeqCst),
            mcp.rss_mb().unwrap_or(f64::NAN)
        );
        mcp.stop().await;
    }
}

#[tokio::test]
async fn metrics_handles_1_8_16_concurrent_users() {
    let _guard = SERIAL.lock().await;
    let nodes = 64usize;
    let load = Load::default();
    let mut upstreams = Vec::new();
    for _ in 0..nodes {
        upstreams.push(start_upstream(load.clone(), Duration::ZERO, false).await);
    }
    let tokens: Vec<String> = (0..16).map(token_for).collect();
    let mcp = start_mcp(&upstreams, &tokens, &[]).await;
    for users in [1usize, 8, 16] {
        let started = Instant::now();
        let mut tasks = Vec::new();
        for token in tokens.iter().take(users) {
            let token = token.clone();
            let port = mcp.port;
            tasks.push(tokio::spawn(
                async move { get_metrics(port, &token).await.0 },
            ));
        }
        let mut statuses = Vec::new();
        for task in tasks {
            statuses.push(task.await.unwrap());
        }
        let elapsed = started.elapsed();
        assert!(
            statuses.iter().all(|s| *s == 200),
            "users={users} statuses={statuses:?}"
        );
        let max = load.max.load(Ordering::SeqCst);
        assert!(max <= 16, "users={users} max_active={max}");
        println!(
            "MEASURED users={users} nodes={nodes} elapsed_ms={} max_active={max} statuses={statuses:?} rss_mb={:.1}",
            elapsed.as_millis(),
            mcp.rss_mb().unwrap_or(f64::NAN)
        );
    }
    mcp.stop().await;
}

#[tokio::test]
async fn sixty_four_concurrent_16mib_tool_replies_stay_within_the_budget() {
    let _guard = SERIAL.lock().await;
    let value = Arc::new(vec![b'x'; 16 * 1024 * 1024]);
    let mut upstreams = Vec::new();
    for _ in 0..64 {
        upstreams
            .push(start_large_value_upstream(Arc::clone(&value), Duration::from_millis(500)).await);
    }
    let addr = upstreams[0].addr.clone();
    let tokens: Vec<String> = (0..64).map(token_for).collect();
    let mcp = start_mcp(
        &upstreams,
        &tokens,
        &[
            ("MEMCACHED_MCP_MEMORY_BUDGET_MB", "96"),
            ("MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS", "64"),
        ],
    )
    .await;

    // Open sessions one at a time; only the tool calls need to be simultaneous. A panic before
    // the barrier in a spawned task would otherwise deadlock every other task.
    let mut sessions = Vec::new();
    for token in &tokens {
        let sid = session(mcp.port, token).await;
        let _ = post(
            mcp.port,
            token,
            Some(&sid),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        sessions.push((token.clone(), sid));
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(sessions.len() + 1));
    let mut set = JoinSet::new();
    for (token, sid) in sessions {
        let addr = addr.clone();
        let barrier = Arc::clone(&barrier);
        let port = mcp.port;
        set.spawn(async move {
            barrier.wait().await;
            let req = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "mcrouter_inspect_config",
                    "arguments": {"addr": addr},
                },
            })
            .to_string();
            match tokio::time::timeout(
                Duration::from_secs(20),
                post(port, &token, Some(&sid), &req),
            )
            .await
            {
                Ok((status, _, body)) => (status, body),
                Err(_) => (0, "tool call timed out".to_owned()),
            }
        });
    }
    barrier.wait().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let rss_with_replies = mcp.rss_mb();

    let mut rejected = 0usize;
    let mut other = 0usize;
    let mut statuses = Vec::new();
    while let Some(result) = set.join_next().await {
        let (status, body) = result.unwrap();
        statuses.push(status);
        if body.contains("memory budget") {
            rejected += 1;
        } else {
            other += 1;
        }
    }
    assert!(
        statuses.iter().all(|s| *s == 200),
        "HTTP statuses: {statuses:?}"
    );
    assert!(
        rejected > 0,
        "64 concurrent 16 MiB reads did not hit the 96 MiB budget"
    );
    assert!(
        other > 0,
        "every request was rejected; the test did not exercise a read"
    );
    let rss_after = mcp.rss_mb();
    println!(
        "MEASURED tool_values=64 value_mib=16 budget_mib=96 rejected={rejected} other={other} rss_during_mib={} rss_after_mib={}",
        rss_with_replies.map_or("n/a".to_owned(), |v| format!("{v:.1}")),
        rss_after.map_or("n/a".to_owned(), |v| format!("{v:.1}"))
    );
    if let Some(rss) = rss_with_replies {
        // A runaway would be 64 × 16 MiB = 1 GiB before JSON/HTTP overhead. This is a local
        // simulation bound, not a Helm 256 MiB sizing result.
        assert!(rss < 512.0, "RSS during replies was {rss:.1} MiB");
    }
    mcp.stop().await;
}

#[tokio::test]
async fn metrics_cache_and_singleflight_avoid_duplicate_scrapes() {
    let _guard = SERIAL.lock().await;
    let load = Load::default();
    let mut upstreams = Vec::new();
    for _ in 0..4 {
        upstreams.push(start_upstream(load.clone(), Duration::ZERO, false).await);
    }
    let tokens = vec![token_for(0), token_for(1)];
    let mcp = start_mcp(
        &upstreams,
        &tokens,
        &[("MEMCACHED_MCP_METRICS_CACHE_MS", "5000")],
    )
    .await;
    let (first, second) = tokio::join!(
        get_metrics(mcp.port, &tokens[0]),
        get_metrics(mcp.port, &tokens[1])
    );
    assert_eq!(first.0, 200, "{}", first.1);
    assert_eq!(second.0, 200, "{}", second.1);
    assert_eq!(
        load.total.load(Ordering::SeqCst),
        upstreams.len(),
        "cache/singleflight did not prevent a duplicate target fan-out"
    );
    let combined = format!("{}\n{}", first.1, second.1);
    assert!(
        combined.contains("memcached_mcp_metrics_cache_misses_total 1"),
        "{combined}"
    );
    assert!(
        combined.contains("memcached_mcp_metrics_cache_hits_total 1"),
        "{combined}"
    );
    assert!(
        combined.contains("memcached_mcp_metrics_cache_age_seconds"),
        "{combined}"
    );
    assert!(
        combined.contains("memcached_mcp_metrics_last_refresh_timestamp_seconds"),
        "{combined}"
    );
    let budget = 96u64 * 1024 * 1024;
    let available = gauge(&combined, "memcached_mcp_memory_budget_available_bytes")
        .expect("budget gauge missing");
    assert!(
        available < budget,
        "the cached body was not reserved: available={available} budget={budget}"
    );
    assert!(
        available > budget - 1024 * 1024,
        "cached body reservation is implausibly large: available={available}"
    );
    println!(
        "MEASURED cache_test upstream_connections={} combined_has_hit=true memory_available_bytes={available}",
        load.total.load(Ordering::SeqCst)
    );
    mcp.stop().await;
}

#[tokio::test]
async fn metrics_cache_refresh_releases_its_reservation() {
    let _guard = SERIAL.lock().await;
    let load = Load::default();
    let mut upstreams = Vec::new();
    for _ in 0..4 {
        upstreams.push(start_upstream(load.clone(), Duration::ZERO, false).await);
    }
    let token = token_for(0);
    let mcp = start_mcp(
        &upstreams,
        std::slice::from_ref(&token),
        &[
            ("MEMCACHED_MCP_METRICS_CACHE_MS", "200"),
            ("MEMCACHED_MCP_MEMORY_BUDGET_MB", "8"),
        ],
    )
    .await;
    let budget = 8u64 * 1024 * 1024;
    for round in 0..5 {
        let (status, body) = get_metrics(mcp.port, &token).await;
        assert_eq!(status, 200, "{body}");
        let available = gauge(&body, "memcached_mcp_memory_budget_available_bytes")
            .expect("budget gauge missing");
        assert!(
            available <= budget,
            "round {round}: available={available} exceeds budget {budget}"
        );
        assert!(
            available > budget - 1024 * 1024,
            "round {round}: reservation leaked or cache entry was not released: available={available}"
        );
        println!("MEASURED cache_refresh round={round} available_bytes={available}");
        if round < 4 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    mcp.stop().await;
}

#[tokio::test]
async fn metrics_deadline_returns_503_and_does_not_claim_health() {
    let _guard = SERIAL.lock().await;
    let load = Load::default();
    let upstream = start_upstream(load.clone(), Duration::from_secs(3), false).await;
    let token = token_for(0);
    let mcp = start_mcp(
        std::slice::from_ref(&upstream),
        std::slice::from_ref(&token),
        &[
            ("MEMCACHED_MCP_METRICS_TIMEOUT_MS", "300"),
            ("MEMCACHED_MCP_METRICS_FANOUT", "1"),
        ],
    )
    .await;
    let started = Instant::now();
    let (status, body) = get_metrics(mcp.port, &token).await;
    let elapsed = started.elapsed();
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("metrics unavailable"), "{body}");
    assert!(!body.contains("memcached_up"), "{body}");
    assert!(
        elapsed < Duration::from_millis(1_500),
        "deadline took {elapsed:?}"
    );
    println!(
        "MEASURED deadline_ms={} status={status}",
        elapsed.as_millis()
    );
    mcp.stop().await;
}

#[tokio::test]
async fn failed_upstream_is_reported_as_down_not_healthy() {
    let _guard = SERIAL.lock().await;
    let load = Load::default();
    let upstream = start_upstream(load, Duration::ZERO, true).await;
    let token = token_for(0);
    let mcp = start_mcp(
        std::slice::from_ref(&upstream),
        std::slice::from_ref(&token),
        &[],
    )
    .await;
    let (status, body) = get_metrics(mcp.port, &token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(up_values(&body), vec!["0"], "{body}");
    mcp.stop().await;
}

#[tokio::test]
async fn global_metrics_request_limit_fails_closed() {
    let _guard = SERIAL.lock().await;
    let load = Load::default();
    let upstream = start_upstream(load.clone(), Duration::from_secs(1), false).await;
    let token = token_for(0);
    let mcp = start_mcp(
        std::slice::from_ref(&upstream),
        std::slice::from_ref(&token),
        &[
            ("MEMCACHED_MCP_METRICS_MAX_CONCURRENT", "1"),
            ("MEMCACHED_MCP_METRICS_FANOUT", "1"),
            ("MEMCACHED_MCP_METRICS_TIMEOUT_MS", "3000"),
        ],
    )
    .await;
    let port = mcp.port;
    let first_token = token.clone();
    let first = tokio::spawn(async move { get_metrics(port, &first_token).await });
    let started = Instant::now();
    while load.active.load(Ordering::SeqCst) == 0 && started.elapsed() < Duration::from_secs(3) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        load.active.load(Ordering::SeqCst) > 0,
        "first scrape never started"
    );
    let (second, second_body) = get_metrics(mcp.port, &token).await;
    assert_eq!(second, 429, "{second_body}");
    let (first_status, first_body) = first.await.unwrap();
    assert_eq!(first_status, 200, "{first_body}");
    println!("MEASURED global_metrics_limit first=200 second=429");
    mcp.stop().await;
}

#[tokio::test]
async fn process_wide_tool_connection_limit_fails_closed() {
    let _guard = SERIAL.lock().await;
    let load = Load::default();
    let upstream = start_upstream(load.clone(), Duration::from_secs(1), false).await;
    let token = token_for(0);
    let mcp = start_mcp(
        std::slice::from_ref(&upstream),
        std::slice::from_ref(&token),
        &[
            ("MEMCACHED_MCP_MAX_UPSTREAM_CONNECTIONS", "1"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "1000"),
        ],
    )
    .await;
    let first_session = session(mcp.port, &token).await;
    let second_session = session(mcp.port, &token).await;
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let _ = post(mcp.port, &token, Some(&first_session), note).await;
    let _ = post(mcp.port, &token, Some(&second_session), note).await;
    let call = json!({
        "jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"get_stats","arguments":{"addr":upstream.addr}}
    })
    .to_string();

    let port = mcp.port;
    let first_token = token.clone();
    let first_session_clone = first_session.clone();
    let first_call = call.clone();
    let first = tokio::spawn(async move {
        post(port, &first_token, Some(&first_session_clone), &first_call).await
    });
    let started = Instant::now();
    while load.active.load(Ordering::SeqCst) == 0 && started.elapsed() < Duration::from_secs(3) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        load.active.load(Ordering::SeqCst) > 0,
        "first tool call never connected"
    );
    let (_, _, second_body) = post(mcp.port, &token, Some(&second_session), &call).await;
    assert!(
        second_body.contains("upstream connection limit"),
        "second tool call did not fail closed: {second_body}"
    );
    let (first_status, _, first_body) = first.await.unwrap();
    assert_eq!(first_status, 200, "{first_body}");
    assert!(
        !first_body.contains("upstream connection limit"),
        "{first_body}"
    );
    println!("MEASURED tool_connection_limit first=ok second=fail_closed");
    mcp.stop().await;
}
