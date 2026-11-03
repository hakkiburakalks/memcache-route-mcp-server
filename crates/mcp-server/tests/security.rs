//! Security regression tests of the HTTP transport. They need no memcached: every check here
//! happens before (or instead of) a connection to a cache server.

use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

fn command(envs: &[(&str, &str)], args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_memcached-mcp"));
    c.args(args)
        .env_remove("MEMCACHED_MCP_ALLOW_WRITE")
        .env_remove("MEMCACHED_MCP_WRITE_PREFIX")
        .env_remove("MEMCACHED_MCP_AUDIT_LOG")
        .env_remove("MEMCACHED_MCP_HTTP_TOKEN")
        .env_remove("MEMCACHED_MCP_HTTP_TOKEN_FILE")
        .env_remove("MEMCACHED_MCP_METRICS_TARGETS")
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

async fn listening_port(child: &mut Child) -> u16 {
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let port = tokio::time::timeout(Duration::from_secs(10), async {
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
    // Keep draining stderr so the server never blocks on a full pipe.
    tokio::spawn(async move {
        let mut sink = String::new();
        while err.read_line(&mut sink).await.unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    port
}

/// Raw HTTP/1.1 request; returns (status, lower-cased head, body). Status 0 means the server
/// closed the connection without answering.
async fn raw(port: u16, request: Vec<u8>) -> (u16, String, String) {
    let mut s = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(s) => s,
        Err(_) => return (0, String::new(), String::new()),
    };
    let _ = s.write_all(&request).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_ascii_lowercase(), body.to_owned())
}

async fn post(port: u16, token: &str, session: Option<&str>, body: &str) -> (u16, String, String) {
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(sid) = session {
        req.push_str(&format!("Mcp-Session-Id: {sid}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    raw(port, req.into_bytes()).await
}

async fn get(port: u16, path: &str, token: &str) -> (u16, String, String) {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    raw(port, req.into_bytes()).await
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sec","version":"0"}}}"#;

/// Opens a session and returns its id.
async fn session(port: u16, token: &str) -> String {
    let (status, head, body) = post(port, token, None, INIT).await;
    assert_eq!(status, 200, "{body}");
    head.lines()
        .find_map(|l| l.strip_prefix("mcp-session-id:"))
        .expect("session id")
        .trim()
        .to_owned()
}

/// A fresh token and its token-file entry, from the real `new-token` subcommand.
async fn new_token(name: &str, perms: &str) -> (String, Value) {
    let out = command(&[], &["new-token", name, perms])
        .output()
        .await
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let token = text
        .lines()
        .next()
        .unwrap()
        .rsplit(": ")
        .next()
        .unwrap()
        .to_owned();
    let json = text.split_once('\n').unwrap().1;
    (
        token,
        serde_json::from_str(&json[json.find('{').unwrap()..]).unwrap(),
    )
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("memcached-mcp-sec-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Any status that is not 401 means the token was accepted (the request itself may still be
/// refused for another reason).
async fn accepted(port: u16, token: &str) -> bool {
    post(port, token, None, "{}").await.0 != 401
}

/// Like [`accepted`], but with a session id header so it never consumes a session slot. Useful
/// while waiting for a token reload in a test whose global cap is already full.
async fn token_accepted(port: u16, token: &str) -> bool {
    post(port, token, Some("probe-session"), "{}").await.0 != 401
}

/// Replace a token file the way a Secret/config tool does: stage the new file, then rename over
/// the old one. The reload task never sees a half-written file.
fn write_tokens(path: &std::path::Path, users: Value) {
    let staged = path.with_extension("new");
    std::fs::write(&staged, users.to_string()).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

/// Replacing the token file atomically (write a new file, rename over the old one, which is how
/// `kubectl`, Secrets and config tools do it) revokes the old token and admits the new one, within
/// a few seconds. The measured delay is printed.
#[tokio::test]
async fn atomic_replacement_revokes_within_seconds() {
    let dir = temp_dir("atomic");
    let tokens = dir.join("tokens.json");
    let (a_token, a) = new_token("a", "read").await;
    let (b_token, b) = new_token("b", "read").await;
    std::fs::write(&tokens, json!({"users": [a]}).to_string()).unwrap();
    let mut child = command(
        &[("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap())],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;
    assert!(accepted(port, &a_token).await);
    assert!(!accepted(port, &b_token).await);

    let staged = dir.join("tokens.json.new");
    std::fs::write(&staged, json!({"users": [b]}).to_string()).unwrap();
    let started = Instant::now();
    std::fs::rename(&staged, &tokens).unwrap();

    let mut revoked_after = None;
    while started.elapsed() < Duration::from_secs(15) {
        if !accepted(port, &a_token).await {
            revoked_after = Some(started.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let delay = revoked_after.expect("old token was never revoked");
    println!("token revocation delay after atomic replacement: {delay:?}");
    assert!(delay < Duration::from_secs(8), "{delay:?}");
    assert!(accepted(port, &b_token).await);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A damaged, empty-of-users-at-startup-style, or missing token file never opens the door: unknown
/// tokens stay at 401 and the previous valid tokens keep working until a good file arrives.
#[tokio::test]
async fn reload_failures_never_fail_open() {
    let dir = temp_dir("failopen");
    let tokens = dir.join("tokens.json");
    let (a_token, a) = new_token("a", "read").await;
    let stranger = "stranger-token-stranger-token-0123456789";
    std::fs::write(&tokens, json!({"users": [a]}).to_string()).unwrap();
    let mut child = command(
        &[("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap())],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    for (label, content) in [
        ("garbage", "{ not json".to_owned()),
        ("truncated", r#"{"users":[{"name":"x","token_sh"#.to_owned()),
        ("bad hash", r#"{"users":[{"name":"x","token_sha256":"zz","permissions":["read"]}]}"#.to_owned()),
        ("unknown permission", r#"{"users":[{"name":"x","token_sha256":"0000000000000000000000000000000000000000000000000000000000000000","permissions":["root"]}]}"#.to_owned()),
        ("empty file", String::new()),
    ] {
        std::fs::write(&tokens, content).unwrap();
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(!accepted(port, stranger).await, "{label}: unknown token accepted");
        assert!(accepted(port, &a_token).await, "{label}: valid token dropped");
    }

    // A deleted file behaves the same way.
    std::fs::remove_file(&tokens).unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        !accepted(port, stranger).await,
        "missing file: unknown token accepted"
    );
    assert!(
        accepted(port, &a_token).await,
        "missing file: valid token dropped"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// While the token file flips between two valid contents, concurrent requests only ever see a
/// clean accept or a clean 401 - never a server error or a dropped connection.
#[tokio::test]
async fn reload_race_has_no_server_errors() {
    let dir = temp_dir("race");
    let tokens = dir.join("tokens.json");
    let (a_token, a) = new_token("a", "read").await;
    let (b_token, b) = new_token("b", "read").await;
    let only_a = json!({"users": [a.clone()]}).to_string();
    let only_b = json!({"users": [b.clone()]}).to_string();
    let both = json!({"users": [a, b]}).to_string();
    std::fs::write(&tokens, &only_a).unwrap();
    let mut child = command(
        &[("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap())],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut workers = Vec::new();
    for token in [
        a_token.clone(),
        b_token.clone(),
        a_token.clone(),
        b_token.clone(),
    ] {
        let stop = stop.clone();
        workers.push(tokio::spawn(async move {
            let mut bad = Vec::new();
            let mut total = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let (status, _, _) = post(port, &token, None, "{}").await;
                total += 1;
                if status == 0 || status >= 500 {
                    bad.push(status);
                }
            }
            (total, bad)
        }));
    }
    for round in 0..24 {
        let content = [&only_a, &only_b, &both][round % 3];
        let staged = dir.join("tokens.json.new");
        std::fs::write(&staged, content).unwrap();
        std::fs::rename(&staged, &tokens).unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut total = 0;
    for w in workers {
        let (t, bad) = w.await.unwrap();
        total += t;
        assert!(bad.is_empty(), "server errors during reload: {bad:?}");
    }
    assert!(total > 100, "only {total} requests were made");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Garbage, truncated and oversized requests get an error status and the server keeps serving.
#[tokio::test]
async fn malformed_and_oversized_requests_are_survivable() {
    let token = "sec-token-sec-token-sec-token-0123456789";
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_TOKEN", token),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    for (label, body) in [
        ("not json", "this is not json".to_owned()),
        (
            "truncated json",
            r#"{"jsonrpc":"2.0","id":1,"method":"init"#.to_owned(),
        ),
        ("wrong shape", r#"{"hello":"world"}"#.to_owned()),
        ("batch of nothing", "[]".to_owned()),
        ("deep nesting", "[".repeat(5000) + &"]".repeat(5000)),
        (
            "method of 100k",
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"{}"}}"#,
                "x".repeat(100_000)
            ),
        ),
    ] {
        let (status, _, _) = post(port, token, None, &body).await;
        assert!(
            (400..500).contains(&status) || status == 200,
            "{label}: status {status}"
        );
    }

    // 6 MiB body: refused (413) or the connection is closed, never accepted and never a crash.
    let big = "x".repeat(6 * 1024 * 1024);
    let (status, _, _) = post(port, token, None, &big).await;
    assert!(
        status == 413 || status == 0 || (400..500).contains(&status),
        "oversized: {status}"
    );

    // Bad framing: a header block with no end, a negative length, a path with control characters.
    for req in [
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -5\r\n\r\n".to_owned(),
        "GET /mcp\u{0}\u{1} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_owned(),
        format!(
            "GET /{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "a".repeat(70_000)
        ),
    ] {
        let (status, _, _) = raw(port, req.into_bytes()).await;
        assert!(
            status == 0 || (400..500).contains(&status),
            "bad framing: {status}"
        );
    }

    // Still alive and answering a proper request.
    let sid = session(port, token).await;
    assert!(!sid.is_empty());
    let _ = child.kill().await;
}

/// A session id is not a credential: permissions come from the token on every request, so a
/// read-only token cannot use a write user's session to write, and the write is refused before
/// any connection is made.
#[tokio::test]
async fn session_ids_do_not_carry_permissions() {
    let (rw_token, rw) = new_token("rw", "read,write").await;
    let (ro_token, ro) = new_token("ro", "read").await;
    let dir = temp_dir("hijack");
    let tokens = dir.join("tokens.json");
    let audit = dir.join("audit.log");
    std::fs::write(&tokens, json!({"users": [rw, ro]}).to_string()).unwrap();
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_ALLOW_WRITE", "1"),
            ("MEMCACHED_MCP_AUDIT_LOG", audit.to_str().unwrap()),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let rw_session = session(port, &rw_token).await;
    // initialized notification so the session accepts calls
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let _ = post(port, &rw_token, Some(&rw_session), note).await;

    for tool in ["set_key", "delete_key", "touch_key"] {
        let args = json!({"addr":"127.0.0.1:1","key":"k","value":"v","ttl_seconds":1});
        let req = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":tool,"arguments":args}}).to_string();
        let (status, _, body) = post(port, &ro_token, Some(&rw_session), &req).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains("does not have the 'write' permission"),
            "{tool} with a read-only token on a write user's session: {body}"
        );
    }
    let audit_text = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(
        audit_text.contains("\"user\":\"ro\""),
        "denials must name the real caller: {audit_text}"
    );
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Many sessions opened at the same instant still respect the per-user cap.
#[tokio::test]
async fn concurrent_session_creation_respects_the_cap() {
    let token = "sec-token-sec-token-sec-token-0123456789";
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_TOKEN", token),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "5"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let mut tasks = Vec::new();
    for _ in 0..40 {
        tasks.push(tokio::spawn(async move {
            post(port, token, None, INIT).await.0
        }));
    }
    let mut opened = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            200 => opened += 1,
            503 => refused += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    println!("per-user cap 5, 40 simultaneous initialize: {opened} opened, {refused} refused");
    assert_eq!(opened + refused, 40);
    assert!(opened <= 5, "{opened} sessions opened with a cap of 5");
    let _ = child.kill().await;
}

/// Many sessions opened at the same instant still respect the global cap.
#[tokio::test]
async fn concurrent_session_creation_respects_the_global_cap() {
    let token = "sec-token-sec-token-sec-token-0123456789";
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_TOKEN", token),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "5"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let mut tasks = Vec::new();
    for _ in 0..40 {
        tasks.push(tokio::spawn(async move {
            post(port, token, None, INIT).await.0
        }));
    }
    let mut opened = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            200 => opened += 1,
            503 => refused += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    println!("global cap 5, 40 simultaneous initialize: {opened} opened, {refused} refused");
    assert_eq!(opened + refused, 40);
    assert!(
        opened <= 5,
        "{opened} sessions opened with a global cap of 5"
    );
    let _ = child.kill().await;
}

/// `/metrics` is a GET but still does a bounded fan-out; a per-user request permit must cover it.
#[tokio::test]
async fn metrics_gets_are_limited_per_user() {
    let token = "sec-token-sec-token-sec-token-0123456789";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut accepted_tx = Some(accepted_tx);
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            if let Some(tx) = accepted_tx.take() {
                let _ = tx.send(());
            }
            tokio::spawn(async move {
                // Read the stats request, then stay silent so the scrape waits for its timeout.
                let mut buf = [0u8; 256];
                let _ = socket.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            });
        }
    });

    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", target.as_str()),
            ("MEMCACHED_MCP_HTTP_TOKEN", token),
            ("MEMCACHED_MCP_METRICS_TARGETS", target.as_str()),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "1"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let first = tokio::spawn(async move { get(port, "/metrics", token).await });
    // The permit is already held by the time the scrape opens its connection.
    accepted_rx.await.expect("metrics never scraped the target");
    let (second, _, _) = get(port, "/metrics", token).await;
    assert_eq!(
        second, 429,
        "a second concurrent /metrics GET must be refused"
    );
    let (first_status, _, first_body) = first.await.unwrap();
    assert_eq!(first_status, 200, "{first_body}");
    let _ = child.kill().await;
}

/// Removing a token closes that user's sessions and gives the slots back to other users.
#[tokio::test]
async fn revoked_user_frees_session_slots_for_another_user() {
    let dir = temp_dir("revoke-capacity");
    let tokens = dir.join("tokens.json");
    let (a_token, a) = new_token("a", "read").await;
    let (b_token, b) = new_token("b", "read").await;
    std::fs::write(&tokens, json!({"users": [a]}).to_string()).unwrap();
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "5"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let mut a_sid = String::new();
    for i in 0..5 {
        let sid = session(port, &a_token).await;
        if i == 0 {
            a_sid = sid;
        }
    }
    write_tokens(&tokens, json!({"users": [b]}));
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if !token_accepted(port, &a_token).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!token_accepted(port, &a_token).await, "A was never revoked");
    assert_eq!(
        post(port, &a_token, Some(&a_sid), INIT).await.0,
        401,
        "revoked token used an existing session"
    );
    // The reload task swaps the token store before it finishes closing old sessions.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // All five slots are free again for B.
    for i in 0..5 {
        let (status, _, body) = post(port, &b_token, None, INIT).await;
        assert_eq!(status, 200, "B session {i}: {body}");
    }
    let (status, _, body) = post(port, &b_token, None, INIT).await;
    assert_eq!(status, 503, "global cap was not restored: {body}");
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Revoking A must not close B's session or give B A's slots.
#[tokio::test]
async fn revoking_one_user_does_not_close_another_users_session() {
    let dir = temp_dir("revoke-other");
    let tokens = dir.join("tokens.json");
    let (a_token, a) = new_token("a", "read").await;
    let (b_token, b) = new_token("b", "read").await;
    std::fs::write(&tokens, json!({"users": [a, b]}).to_string()).unwrap();
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "2"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let _a_sid = session(port, &a_token).await;
    let b_sid = session(port, &b_token).await;
    write_tokens(&tokens, json!({"users": [b]}));
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if !token_accepted(port, &a_token).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!token_accepted(port, &a_token).await, "A was never revoked");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let (status, _, body) = post(port, &b_token, Some(&b_sid), note).await;
    assert!(
        matches!(status, 200 | 202),
        "B's session was closed by A's revocation: {body}"
    );
    // B still has its one session; A's slot is free, so exactly one more fits.
    let (status, _, body) = post(port, &b_token, None, INIT).await;
    assert_eq!(status, 200, "A's slot was not returned to B: {body}");
    let (status, _, body) = post(port, &b_token, None, INIT).await;
    assert_eq!(status, 503, "B exceeded the global cap: {body}");
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A new token for the same user closes sessions opened with the old token.
#[tokio::test]
async fn rotating_a_token_closes_old_sessions_and_admits_the_new_one() {
    let dir = temp_dir("rotate-token");
    let tokens = dir.join("tokens.json");
    let (old_token, old_entry) = new_token("a", "read").await;
    let (new_token, new_entry) = new_token("a", "read").await;
    std::fs::write(&tokens, json!({"users": [old_entry]}).to_string()).unwrap();
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let old_sid = session(port, &old_token).await;
    write_tokens(&tokens, json!({"users": [new_entry]}));
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if !token_accepted(port, &old_token).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !token_accepted(port, &old_token).await,
        "old token was never revoked"
    );
    assert_eq!(
        post(port, &old_token, Some(&old_sid), INIT).await.0,
        401,
        "old token used its old session"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (status, _, body) = post(port, &new_token, None, INIT).await;
    assert_eq!(
        status, 200,
        "new token could not open a session after rotation: {body}"
    );
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// An expired token's open session is closed on the reload tick and its slot is reusable.
#[tokio::test]
async fn expired_token_closes_its_sessions() {
    let dir = temp_dir("expired-session");
    let tokens = dir.join("tokens.json");
    let (a_token, mut a) = new_token("a", "read").await;
    let (b_token, b) = new_token("b", "read").await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    a["expires_at"] = json!(now + 5);
    write_tokens(&tokens, json!({"users": [a, b]}));
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let _sid = session(port, &a_token).await;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if !token_accepted(port, &a_token).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!token_accepted(port, &a_token).await, "token never expired");

    // The session is closed on the next reload tick; retry until its slot is free.
    let started = Instant::now();
    let mut opened = false;
    while started.elapsed() < Duration::from_secs(10) {
        let (status, _, body) = post(port, &b_token, None, INIT).await;
        if status == 200 {
            opened = true;
            break;
        }
        assert_eq!(status, 503, "unexpected status: {body}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(opened, "expired user's session slot was not released");
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// An invalid token file keeps both the current tokens and their open sessions.
#[tokio::test]
async fn invalid_token_file_keeps_tokens_and_open_sessions() {
    let dir = temp_dir("invalid-keeps-sessions");
    let tokens = dir.join("tokens.json");
    let (token, entry) = new_token("a", "read").await;
    std::fs::write(&tokens, json!({"users": [entry]}).to_string()).unwrap();
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "2"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "100"),
            ("MEMCACHED_MCP_HTTP_MAX_CONCURRENT", "100"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let sid = session(port, &token).await;
    std::fs::write(&tokens, "{ not json").unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        token_accepted(port, &token).await,
        "a broken token file revoked a valid token"
    );
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let (status, _, body) = post(port, &token, Some(&sid), note).await;
    assert!(
        matches!(status, 200 | 202),
        "a broken token file closed a valid session: {body}"
    );
    let (status, _, body) = post(port, &token, None, INIT).await;
    assert_eq!(
        status, 200,
        "valid token could not open another session: {body}"
    );
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Neither the audit log nor an error body ever contains a token.
#[tokio::test]
async fn tokens_do_not_leak_into_logs_or_errors() {
    let (token, entry) = new_token("leaky", "read").await;
    let dir = temp_dir("leak");
    let tokens = dir.join("tokens.json");
    let audit = dir.join("audit.log");
    std::fs::write(&tokens, json!({"users": [entry]}).to_string()).unwrap();
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_AUDIT_LOG", audit.to_str().unwrap()),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .unwrap();
    let port = listening_port(&mut child).await;

    let wrong = "wrong-token-wrong-token-wrong-token-0123";
    let (status, head, body) = post(port, wrong, None, INIT).await;
    assert_eq!(status, 401);
    assert!(!head.contains(wrong) && !body.contains(wrong));
    let sid = session(port, &token).await;
    let _ = post(
        port,
        &token,
        Some(&sid),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    let req = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_stats","arguments":{"addr":"10.9.9.9:11211"}}}).to_string();
    let (_, _, body) = post(port, &token, Some(&sid), &req).await;
    assert!(!body.contains(&token), "token echoed in a reply");

    let _ = child.kill().await;
    let log = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(!log.is_empty(), "denials should have been audited");
    for secret in [token.as_str(), wrong] {
        assert!(!log.contains(secret), "secret found in the audit log");
    }
    assert!(
        !log.to_ascii_lowercase().contains("authorization"),
        "authorization header found in the audit log: {log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
