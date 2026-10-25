//! Drives the real `memcached-mcp` binary. Set MEMCACHED_ADDR to a live memcached
//! (e.g. 127.0.0.1:11216); skipped otherwise.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const TOKEN: &str = "e2e-token-0123456789-0123456789";
const SECRET: &str = "SECRET_E2E_VALUE";

fn memcached_addr() -> Option<String> {
    let addr = std::env::var("MEMCACHED_ADDR").ok();
    if addr.is_none() {
        eprintln!("MEMCACHED_ADDR not set, skipping");
    }
    addr
}

fn command(envs: &[(&str, &str)], args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_memcached-mcp"));
    c.args(args)
        .env_remove("MEMCACHED_MCP_ALLOW_WRITE")
        .env_remove("MEMCACHED_MCP_WRITE_PREFIX")
        .env_remove("MEMCACHED_MCP_AUDIT_LOG")
        .env_remove("MEMCACHED_MCP_HTTP_TOKEN")
        .env_remove("MEMCACHED_MCP_METRICS_TARGETS")
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

/// A stdio MCP session. Calls are sequential: the server answers concurrently, so tests wait
/// for each reply before sending the next request.
struct Stdio_ {
    _child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
    next_id: u64,
}

impl Stdio_ {
    async fn start(envs: &[(&str, &str)]) -> Self {
        let mut child = command(envs, &[]).spawn().expect("spawn memcached-mcp");
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut s = Self {
            _child: child,
            stdin,
            out,
            next_id: 1,
        };
        s.request(
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}),
        )
        .await;
        s.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        s
    }

    async fn send(&mut self, v: &Value) {
        self.stdin
            .write_all(format!("{v}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(Duration::from_secs(10), self.out.read_line(&mut line))
                .await
                .expect("timed out waiting for a reply")
                .unwrap();
            assert!(n > 0, "server closed stdout");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    /// Returns (is_error, text).
    async fn call(&mut self, tool: &str, args: Value) -> (bool, String) {
        let v = self
            .request("tools/call", json!({"name":tool,"arguments":args}))
            .await;
        if let Some(err) = v.get("error") {
            return (true, err["message"].as_str().unwrap_or_default().to_owned());
        }
        let r = &v["result"];
        (
            r["isError"] == json!(true),
            r["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    }

    async fn tool_names(&mut self) -> Vec<String> {
        let v = self.request("tools/list", json!({})).await;
        v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    }
}

#[tokio::test]
async fn stdio_is_read_only_and_allowlisted_by_default() {
    let Some(addr) = memcached_addr() else { return };
    let mut s = Stdio_::start(&[("MEMCACHED_MCP_ALLOWLIST", &addr)]).await;

    let tools = s.tool_names().await;
    for t in [
        "server_info",
        "get_stats",
        "get_key_metadata",
        "diagnose_node",
        "mcrouter_compare_destinations",
    ] {
        assert!(tools.iter().any(|n| n == t), "missing tool {t}");
    }
    for t in ["set_key", "delete_key", "touch_key"] {
        assert!(
            !tools.iter().any(|n| n == t),
            "{t} must be hidden without MEMCACHED_MCP_ALLOW_WRITE"
        );
    }
    let (err, _) = s
        .call("set_key", json!({"addr":addr,"key":"e2e:x","value":"v"}))
        .await;
    assert!(err, "calling a hidden write tool must fail");

    let (err, text) = s.call("server_info", json!({"addr":addr})).await;
    assert!(!err && text.contains("version:"), "{text}");

    let (err, text) = s
        .call("server_info", json!({"addr":"203.0.113.9:11211"}))
        .await;
    assert!(err && text.contains("ALLOWLIST"), "{text}");
}

#[tokio::test]
async fn stdio_writes_are_gated_prefixed_and_audited() {
    let Some(addr) = memcached_addr() else { return };
    let audit: PathBuf =
        std::env::temp_dir().join(format!("memcached-mcp-e2e-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&audit);
    let mut s = Stdio_::start(&[
        ("MEMCACHED_MCP_ALLOWLIST", &addr),
        ("MEMCACHED_MCP_ALLOW_WRITE", "1"),
        ("MEMCACHED_MCP_WRITE_PREFIX", "e2e:"),
        ("MEMCACHED_MCP_AUDIT_LOG", audit.to_str().unwrap()),
    ])
    .await;

    let tools = s.tool_names().await;
    assert!(["set_key", "delete_key", "touch_key"]
        .iter()
        .all(|t| tools.iter().any(|n| n == t)));

    let (err, text) = s
        .call(
            "set_key",
            json!({"addr":addr,"key":"e2e:k","value":SECRET,"ttl_seconds":60}),
        )
        .await;
    assert!(!err && text == "Stored", "{text}");

    let (err, text) = s
        .call("get_key_metadata", json!({"addr":addr,"key":"e2e:k"}))
        .await;
    let meta: Value = serde_json::from_str(&text).unwrap();
    assert!(!err && meta["found"] == json!(true), "{text}");
    assert_eq!(meta["info"]["size"], json!(SECRET.len()));
    assert!(!text.contains(SECRET), "the value must never be returned");

    let (err, text) = s
        .call(
            "touch_key",
            json!({"addr":addr,"key":"e2e:k","ttl_seconds":120}),
        )
        .await;
    assert!(!err && text == "Touched", "{text}");

    // Outside the write prefix: refused for every write tool.
    for (tool, args) in [
        ("set_key", json!({"addr":addr,"key":"other:k","value":"v"})),
        ("delete_key", json!({"addr":addr,"key":"other:k"})),
        (
            "touch_key",
            json!({"addr":addr,"key":"other:k","ttl_seconds":5}),
        ),
    ] {
        let (err, text) = s.call(tool, args).await;
        assert!(
            err && text.contains("outside the allowed write prefixes"),
            "{tool}: {text}"
        );
    }

    let (err, text) = s
        .call("delete_key", json!({"addr":addr,"key":"e2e:k"}))
        .await;
    assert!(!err && text == "Deleted", "{text}");
    let (_, text) = s
        .call("get_key_metadata", json!({"addr":addr,"key":"e2e:k"}))
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["found"],
        json!(false)
    );

    let log = std::fs::read_to_string(&audit).unwrap();
    let _ = std::fs::remove_file(&audit);
    assert!(log.contains(r#""tool":"set_key""#) && log.contains(r#""key":"e2e:k""#));
    assert!(log.contains("denied: key outside MEMCACHED_MCP_WRITE_PREFIX"));
    assert!(
        !log.contains(SECRET),
        "the audit log must not contain values"
    );
}

/// Minimal HTTP/1.1 client: returns (status, body).
async fn http_get(port: u16, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let mut req = format!("GET {path} HTTP/1.1\r\nConnection: close\r\n");
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    let status = raw.split(' ').nth(1).unwrap().parse().unwrap();
    (
        status,
        raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned(),
    )
}

#[tokio::test]
async fn http_requires_token_and_serves_metrics() {
    let Some(addr) = memcached_addr() else { return };
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", &addr),
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
            ("MEMCACHED_MCP_METRICS_TARGETS", &addr),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");

    // The server prints "listening on http://127.0.0.1:<port>/mcp" once it is ready.
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

    let auth = format!("Bearer {TOKEN}");
    assert_eq!(http_get(port, "/metrics", &[]).await.0, 401);
    assert_eq!(
        http_get(port, "/metrics", &[("Authorization", "Bearer wrong")])
            .await
            .0,
        401
    );
    assert_eq!(http_get(port, "/mcp", &[]).await.0, 401);

    let (status, body) = http_get(port, "/metrics", &[("Authorization", &auth)]).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(&format!("memcached_up{{instance=\"{addr}\"}} 1")),
        "{body}"
    );
    assert!(
        body.contains("# TYPE memcached_get_hits_total counter"),
        "{body}"
    );

    // A valid token does not excuse a foreign Host header (DNS rebinding).
    let (status, _) = http_get(
        port,
        "/metrics",
        &[("Authorization", &auth), ("Host", "evil.example.com")],
    )
    .await;
    assert_ne!(status, 200);
    let (status, _) = http_get(
        port,
        "/mcp",
        &[("Authorization", &auth), ("Host", "evil.example.com")],
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn http_refuses_to_start_unsafely() {
    for (envs, args, needle) in [
        (
            vec![],
            vec!["--http", "127.0.0.1:0"],
            "MEMCACHED_MCP_HTTP_TOKEN",
        ),
        (
            vec![("MEMCACHED_MCP_HTTP_TOKEN", "short")],
            vec!["--http", "127.0.0.1:0"],
            "at least",
        ),
        (
            vec![("MEMCACHED_MCP_HTTP_TOKEN", TOKEN)],
            vec!["--http", "0.0.0.0:0"],
            "not a loopback",
        ),
        (
            vec![
                ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
                ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
                ("MEMCACHED_MCP_METRICS_TARGETS", "127.0.0.1:2"),
            ],
            vec!["--http", "127.0.0.1:0"],
            "not in MEMCACHED_MCP_ALLOWLIST",
        ),
    ] {
        let out = tokio::time::timeout(Duration::from_secs(10), command(&envs, &args).output())
            .await
            .expect("server should exit, not start")
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} should fail");
        assert!(stderr.contains(needle), "expected '{needle}' in: {stderr}");
    }
}

/// mcrouter tools over MCP, against the healthy three-node topology from
/// tests/compat/docker-compose.yml. Set MCROUTER_ADDR (e.g. 127.0.0.1:11218) and
/// MCROUTER_BACKENDS (the host addresses of mc-a, mc-b, mc-c in that order); skipped otherwise.
#[tokio::test]
async fn mcrouter_tools_over_mcp() {
    let (Ok(router), Ok(backends)) = (
        std::env::var("MCROUTER_ADDR"),
        std::env::var("MCROUTER_BACKENDS"),
    ) else {
        eprintln!("MCROUTER_ADDR / MCROUTER_BACKENDS not set, skipping");
        return;
    };
    let backends: Vec<&str> = backends.split(',').collect();
    assert_eq!(
        backends.len(),
        3,
        "MCROUTER_BACKENDS needs the addresses of mc-a, mc-b, mc-c"
    );
    let names = ["mc-a:11211", "mc-b:11211", "mc-c:11211"];
    let map = names
        .iter()
        .zip(&backends)
        .map(|(n, b)| format!("{n}={b}"))
        .collect::<Vec<_>>()
        .join(",");
    let allow = format!("{router},{}", backends.join(","));

    let mut s = Stdio_::start(&[
        ("MEMCACHED_MCP_ALLOWLIST", &allow),
        ("MEMCACHED_MCP_DEST_MAP", &map),
    ])
    .await;
    let json = |text: &str| {
        serde_json::from_str::<Value>(text).unwrap_or_else(|_| panic!("not JSON: {text}"))
    };

    let (err, text) = s
        .call("mcrouter_inspect_config", json!({"addr":router}))
        .await;
    assert!(!err, "{text}");
    let cfg = json(&text);
    assert_eq!(cfg["config"]["pools"][0]["servers"], json!(names));
    assert_eq!(cfg["config"]["has_failover"], json!(false));
    assert_eq!(cfg["findings"], json!([]));

    let (err, text) = s
        .call(
            "mcrouter_trace_key_route",
            json!({"addr":router,"key":"some-key","op":"set"}),
        )
        .await;
    assert!(
        !err && names.iter().any(|n| text == format!("destination: {n}")),
        "{text}"
    );
    let (err, text) = s
        .call(
            "mcrouter_trace_key_route",
            json!({"addr":router,"key":"k","op":"flush"}),
        )
        .await;
    assert!(err && text.contains("get, set or delete"), "{text}");

    let (err, text) = s.call("mcrouter_get_stats", json!({"addr":router})).await;
    assert!(
        !err && json(&text)["stats"]["num_servers"] == json!("3"),
        "{text}"
    );

    let (err, text) = s
        .call("mcrouter_diagnose_failover", json!({"addr":router}))
        .await;
    let codes: Vec<_> = json(&text)["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].clone())
        .collect();
    assert!(!err && codes == [json!("no_failover_configured")], "{text}");

    // Every destination mapped and allowlisted: all three are inspected.
    let (err, text) = s
        .call("mcrouter_compare_destinations", json!({"addr":router}))
        .await;
    assert!(!err, "{text}");
    let all = json(&text);
    assert_eq!(all["inspected"], json!(names));
    assert_eq!(all["unmapped"], json!([]));
    assert_eq!(all["unreachable"], json!([]));

    // A plain memcached is not an mcrouter.
    let (err, text) = s
        .call("mcrouter_inspect_config", json!({"addr":backends[0]}))
        .await;
    assert!(err && text.contains("mcrouter"), "{text}");

    // Missing mapping and a mapping outside the allowlist are reported, never guessed or followed.
    let partial_map = format!("{}={},{}={}", names[0], backends[0], names[1], backends[1]);
    let partial_allow = format!("{router},{}", backends[0]);
    let mut p = Stdio_::start(&[
        ("MEMCACHED_MCP_ALLOWLIST", &partial_allow),
        ("MEMCACHED_MCP_DEST_MAP", &partial_map),
    ])
    .await;
    let (err, text) = p
        .call("mcrouter_compare_destinations", json!({"addr":router}))
        .await;
    assert!(!err, "{text}");
    let part = json(&text);
    assert_eq!(part["inspected"], json!([names[0]]));
    assert_eq!(part["unmapped"], json!([names[2]]));
    let unreachable = part["unreachable"].as_array().unwrap();
    assert!(
        unreachable.len() == 1 && unreachable[0].as_str().unwrap().contains("ALLOWLIST"),
        "{text}"
    );
}
