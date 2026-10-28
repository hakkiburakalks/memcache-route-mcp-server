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
        .env_remove("MEMCACHED_MCP_HTTP_TOKEN_FILE")
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

/// Read access must not become write access through a tool argument that is spliced into a
/// memcached command line.
#[tokio::test]
async fn read_tools_cannot_smuggle_commands() {
    let Some(addr) = memcached_addr() else { return };
    let mut w = Stdio_::start(&[
        ("MEMCACHED_MCP_ALLOWLIST", &addr),
        ("MEMCACHED_MCP_ALLOW_WRITE", "1"),
    ])
    .await;
    let (err, text) = w
        .call(
            "set_key",
            json!({"addr":addr,"key":"e2e:inject","value":"v","ttl_seconds":60}),
        )
        .await;
    assert!(!err, "{text}");

    let mut r = Stdio_::start(&[("MEMCACHED_MCP_ALLOWLIST", &addr)]).await;
    for group in [
        "settings\r\ndelete e2e:inject",
        "settings\ndelete e2e:inject",
        "items delete e2e:inject",
        // Plain words that still change the server.
        "reset",
        "sizes_enable",
    ] {
        let (err, text) = r
            .call("get_stats", json!({"addr":addr,"group":group}))
            .await;
        assert!(err && text.contains("stats group"), "{group:?}: {text}");
    }
    // Keys carry the same risk.
    let (err, _) = r
        .call(
            "get_key_metadata",
            json!({"addr":addr,"key":"x\r\ndelete e2e:inject"}),
        )
        .await;
    assert!(err);

    let (_, text) = r
        .call("get_key_metadata", json!({"addr":addr,"key":"e2e:inject"}))
        .await;
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["found"],
        json!(true),
        "the key must have survived"
    );

    let many: Vec<_> = (0..257).map(|_| addr.clone()).collect();
    let (err, text) = r.call("compare_nodes", json!({"addrs":many})).await;
    assert!(err && text.contains("at most"), "{text}");

    let (err, _) = w
        .call("delete_key", json!({"addr":addr,"key":"e2e:inject"}))
        .await;
    assert!(!err);
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

    // Above 30 days memcached would read the TTL as a unix time and expire the item at once.
    for ttl in [2_592_001_i64, 3_000_000] {
        let (err, text) = s
            .call(
                "set_key",
                json!({"addr":addr,"key":"e2e:k","value":"v","ttl_seconds":ttl}),
            )
            .await;
        assert!(err && text.contains("ttl_seconds"), "{ttl}: {text}");
    }

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

#[tokio::test]
async fn key_sampling_is_opt_in_and_private_by_default() {
    let Some(addr) = memcached_addr() else { return };

    // Off by default: the tool does not exist.
    let mut off = Stdio_::start(&[("MEMCACHED_MCP_ALLOWLIST", &addr)]).await;
    assert!(!off.tool_names().await.iter().any(|n| n == "sample_keys"));
    let (err, _) = off.call("sample_keys", json!({"addr":addr})).await;
    assert!(err);

    // Seed some keys with a known prefix structure.
    let audit: PathBuf = std::env::temp_dir().join(format!(
        "memcached-mcp-e2e-sample-{}.log",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&audit);
    let mut w = Stdio_::start(&[
        ("MEMCACHED_MCP_ALLOWLIST", &addr),
        ("MEMCACHED_MCP_ALLOW_WRITE", "1"),
        ("MEMCACHED_MCP_ALLOW_KEY_SAMPLING", "1"),
        ("MEMCACHED_MCP_AUDIT_LOG", audit.to_str().unwrap()),
    ])
    .await;
    for i in 0..6 {
        let (err, _) = w
            .call(
                "set_key",
                json!({"addr":addr,"key":format!("inv-a:{i}"),"value":"v"}),
            )
            .await;
        assert!(!err);
    }
    for i in 0..3 {
        let (err, _) = w
            .call(
                "set_key",
                json!({"addr":addr,"key":format!("inv-b:{i}"),"value":"vv"}),
            )
            .await;
        assert!(!err);
    }

    let (_, info) = w.call("server_info", json!({"addr":addr})).await;
    if info.contains("version: 1.4") {
        let (err, text) = w.call("sample_keys", json!({"addr":addr})).await;
        assert!(err && text.contains("-o lru_crawler"), "{text}");
        return;
    }

    // Prefix totals only: no key names, and asking for names is refused.
    let (err, text) = w
        .call("sample_keys", json!({"addr":addr,"prefix":"inv-"}))
        .await;
    assert!(!err, "{text}");
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["complete"], json!(true));
    assert_eq!(r["matched"], json!(9));
    assert_eq!(r["never_fetched"], json!(9));
    assert_eq!(r["prefixes"][0]["prefix"], json!("inv-a"));
    assert_eq!(r["prefixes"][0]["items"], json!(6));
    assert_eq!(r["prefixes"][1]["prefix"], json!("inv-b"));
    assert_eq!(r["keys"], json!([]));
    assert!(
        !text.contains("inv-a:0"),
        "key names must not leak without MEMCACHED_MCP_ALLOW_KEY_NAMES"
    );

    // Uniform mode reads the whole dump. With room for every item the numbers are exact...
    let (err, text) = w
        .call(
            "sample_keys",
            json!({"addr":addr,"prefix":"inv-","uniform":true,"max_scan":100000}),
        )
        .await;
    assert!(!err, "{text}");
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["estimated"], json!(true));
    assert_eq!(
        (r["matched"].clone(), r["prefixes"][0]["items"].clone()),
        (json!(9), json!(6))
    );
    // ...and with a sample smaller than the cache it still scans everything and says it estimates.
    let (err, text) = w
        .call(
            "sample_keys",
            json!({"addr":addr,"uniform":true,"max_scan":3}),
        )
        .await;
    assert!(!err, "{text}");
    let r: Value = serde_json::from_str(&text).unwrap();
    assert!(
        r["scanned"].as_u64().unwrap() >= 9 && r["complete"] == json!(true),
        "{text}"
    );
    assert!(
        text.contains("estimates:") && !text.contains("inv-a:0"),
        "{text}"
    );

    let (err, text) = w
        .call(
            "sample_keys",
            json!({"addr":addr,"prefix":"inv-","include_keys":true}),
        )
        .await;
    assert!(
        err && text.contains("MEMCACHED_MCP_ALLOW_KEY_NAMES"),
        "{text}"
    );
    let (err, text) = w
        .call("sample_keys", json!({"addr":addr,"delimiter":"ab"}))
        .await;
    assert!(err && text.contains("one character"), "{text}");

    // A scan cut short says so instead of passing the totals off as the whole cache.
    let (err, text) = w
        .call("sample_keys", json!({"addr":addr,"max_scan":2}))
        .await;
    let r: Value = serde_json::from_str(&text).unwrap();
    assert!(
        !err && r["complete"] == json!(false) && r["scanned"] == json!(2),
        "{text}"
    );
    assert!(text.contains("not representative"));

    // Names appear only when the server operator has also allowed them.
    let mut n = Stdio_::start(&[
        ("MEMCACHED_MCP_ALLOWLIST", &addr),
        ("MEMCACHED_MCP_ALLOW_KEY_SAMPLING", "1"),
        ("MEMCACHED_MCP_ALLOW_KEY_NAMES", "1"),
    ])
    .await;
    let (err, text) = n
        .call(
            "sample_keys",
            json!({"addr":addr,"prefix":"inv-a","include_keys":true,"max_keys":2}),
        )
        .await;
    assert!(!err, "{text}");
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["keys"].as_array().unwrap().len(), 2);
    assert!(r["keys"][0]["key"].as_str().unwrap().starts_with("inv-a:"));
    assert!(r["keys"][0].get("value").is_none());

    // The audit trail records that a sample happened, never which keys were seen.
    let log = std::fs::read_to_string(&audit).unwrap();
    let _ = std::fs::remove_file(&audit);
    assert!(log.contains(r#""tool":"sample_keys""#) && log.contains("names_returned=false"));
    for line in log.lines().filter(|l| l.contains("sample_keys")) {
        assert!(
            !line.contains("inv-"),
            "sample_keys audit lines must not carry key names: {line}"
        );
    }
}

/// POSTs JSON to /mcp. Returns (status, lowercased response headers, body).
async fn http_post(
    port: u16,
    token: &str,
    session: Option<&str>,
    body: &Value,
) -> (u16, String, String) {
    let body = body.to_string();
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(sid) = session {
        req.push_str(&format!("Mcp-Session-Id: {sid}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body);
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut raw))
        .await
        .expect("timed out reading the HTTP reply")
        .unwrap();
    let status = raw.split(' ').nth(1).unwrap().parse().unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    (status, head.to_ascii_lowercase(), body.to_owned())
}

/// The JSON-RPC reply with this id, from either a plain JSON body or an SSE stream.
fn rpc_reply(body: &str, id: u64) -> Value {
    body.lines()
        .map(|l| l.trim().strip_prefix("data:").unwrap_or(l.trim()).trim())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["id"] == json!(id))
        .unwrap_or_else(|| panic!("no reply with id {id} in: {body}"))
}

/// One MCP session over HTTP, authenticated as a single token.
struct HttpMcp {
    port: u16,
    token: String,
    session: String,
    next_id: u64,
}

impl HttpMcp {
    async fn start(port: u16, token: &str) -> Self {
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}});
        let (status, head, body) = http_post(port, token, None, &init).await;
        assert_eq!(status, 200, "{body}");
        let session = head
            .lines()
            .find_map(|l| l.strip_prefix("mcp-session-id:"))
            .expect("no session id")
            .trim()
            .to_owned();
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        let (status, _, _) = http_post(port, token, Some(&session), &note).await;
        assert_eq!(status, 202);
        Self {
            port,
            token: token.to_owned(),
            session,
            next_id: 2,
        }
    }

    /// Returns (is_error, text).
    async fn call(&mut self, tool: &str, args: Value) -> (bool, String) {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}});
        let (status, _, body) = http_post(self.port, &self.token, Some(&self.session), &req).await;
        assert_eq!(status, 200, "{body}");
        let v = rpc_reply(&body, id);
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
}

/// Reads the server's stderr until it reports the HTTP port.
async fn listening_port(child: &mut Child) -> u16 {
    let mut err = BufReader::new(child.stderr.take().unwrap());
    tokio::time::timeout(Duration::from_secs(10), async {
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
    .expect("server never reported its port")
}

#[tokio::test]
async fn http_users_get_only_their_permissions() {
    let Some(addr) = memcached_addr() else { return };
    let dir = std::env::temp_dir().join(format!("memcached-mcp-rbac-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (tokens, audit) = (dir.join("tokens.json"), dir.join("audit.log"));
    let _ = std::fs::remove_file(&audit);

    // Tokens come from the real `new-token` subcommand, so it is tested too.
    let mut entries = Vec::new();
    let mut issued = std::collections::HashMap::new();
    for (name, perms) in [
        ("reader", "read"),
        ("writer", "read,write,metrics"),
        ("sampler", "read,sample"),
    ] {
        let out = command(&[], &["new-token", name, perms])
            .output()
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
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
        let entry: Value = serde_json::from_str(&json[json.find('{').unwrap()..]).unwrap();
        assert_eq!(entry["name"], json!(name));
        assert!(!json.contains(&token), "the entry must hold only the hash");
        entries.push(entry);
        issued.insert(name, token);
    }
    std::fs::write(&tokens, json!({"users": entries}).to_string()).unwrap();

    // A bad permission name is rejected when the token is issued.
    let bad = command(&[], &["new-token", "x", "root"])
        .output()
        .await
        .unwrap();
    assert!(!bad.status.success());

    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", &addr),
            ("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap()),
            ("MEMCACHED_MCP_METRICS_TARGETS", &addr),
            ("MEMCACHED_MCP_ALLOW_WRITE", "1"),
            ("MEMCACHED_MCP_WRITE_PREFIX", "rbac:"),
            ("MEMCACHED_MCP_ALLOW_KEY_SAMPLING", "1"),
            ("MEMCACHED_MCP_AUDIT_LOG", audit.to_str().unwrap()),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;

    // Unknown token: 401.
    assert_eq!(http_post(port, "nobody", None, &json!({})).await.0, 401);

    let mut reader = HttpMcp::start(port, &issued["reader"]).await;
    let (err, text) = reader.call("get_stats", json!({"addr":addr})).await;
    assert!(!err, "{text}");
    for (tool, args) in [
        ("set_key", json!({"addr":addr,"key":"rbac:k","value":"v"})),
        ("sample_keys", json!({"addr":addr})),
    ] {
        let (err, text) = reader.call(tool, args).await;
        assert!(
            err && text.contains("forbidden") && text.contains("'reader'"),
            "{tool}: {text}"
        );
    }

    let mut writer = HttpMcp::start(port, &issued["writer"]).await;
    let (err, text) = writer
        .call(
            "set_key",
            json!({"addr":addr,"key":"rbac:k","value":SECRET,"ttl_seconds":30}),
        )
        .await;
    assert!(!err && text == "Stored", "{text}");
    let (err, text) = writer.call("sample_keys", json!({"addr":addr})).await;
    assert!(err && text.contains("'writer'"), "{text}");

    let mut sampler = HttpMcp::start(port, &issued["sampler"]).await;
    let (err, text) = sampler.call("sample_keys", json!({"addr":addr})).await;
    // Allowed to run; it may still fail on servers without the crawler, but never for permissions.
    assert!(!text.contains("forbidden"), "err={err} {text}");

    // /metrics needs the metrics permission.
    for (user, want) in [("reader", 403), ("writer", 200)] {
        let auth = format!("Bearer {}", issued[user]);
        let (status, body) = http_get(port, "/metrics", &[("Authorization", &auth)]).await;
        assert_eq!(status, want, "{user}: {body}");
    }

    // Clean up the key we wrote, then check who is on record.
    let (err, _) = writer
        .call("delete_key", json!({"addr":addr,"key":"rbac:k"}))
        .await;
    assert!(!err);
    let log = std::fs::read_to_string(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        log.contains(r#""user":"writer""#) && log.contains(r#""tool":"set_key""#),
        "{log}"
    );
    assert!(
        log.contains(r#""user":"reader""#) && log.contains("denied: missing permission"),
        "{log}"
    );
    assert!(!log.contains(SECRET));
    for t in issued.values() {
        assert!(!log.contains(t.as_str()), "tokens must never be logged");
    }
}

/// A flood of bad tokens must not turn into a flood of audit lines.
#[tokio::test]
async fn failed_logins_do_not_flood_the_audit_log() {
    let dir = std::env::temp_dir().join(format!("memcached-mcp-flood-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.log");
    let _ = std::fs::remove_file(&audit);
    let mut child = command(
        &[
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
            ("MEMCACHED_MCP_AUDIT_LOG", audit.to_str().unwrap()),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;
    let started = std::time::Instant::now();
    for i in 0..200 {
        assert_eq!(
            http_post(port, &format!("wrong-{i}"), None, &json!({}))
                .await
                .0,
            401
        );
    }
    let seconds = started.elapsed().as_secs() + 2;
    let lines = std::fs::read_to_string(&audit).unwrap().lines().count();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(lines >= 1, "denials must still be recorded");
    // At most 20 per second, plus one summary line per second.
    assert!(
        lines as u64 <= 21 * seconds,
        "{lines} audit lines for 200 failures over ~{seconds}s"
    );
    assert!(lines < 200, "{lines} audit lines: the cap did nothing");
}

/// Needs no memcached: only the authentication layer is exercised.
#[tokio::test]
async fn expired_tokens_are_refused() {
    let dir = std::env::temp_dir().join(format!("memcached-mcp-expiry-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let tokens = dir.join("tokens.json");

    let issue = |name: &'static str, extra: &'static [&'static str]| async move {
        let mut args = vec!["new-token", name, "read"];
        args.extend_from_slice(extra);
        let out = command(&[], &args).output().await.unwrap();
        (
            out.status.success(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let parse = |text: &str| -> (String, Value) {
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
    };

    let (ok, text, _) = issue("fresh", &["7"]).await;
    assert!(ok);
    let (fresh_token, fresh) = parse(&text);
    let expires = fresh["expires_at"].as_u64().expect("expires_at is set");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        (now + 7 * 86_400 - 5..=now + 7 * 86_400 + 5).contains(&expires),
        "{expires} vs {now}"
    );
    // Without DAYS the token never expires; bad DAYS is rejected when issuing.
    let (ok, text, _) = issue("forever", &[]).await;
    assert!(ok && parse(&text).1.get("expires_at").is_none());
    for bad in ["0", "x", "-1", "99999"] {
        let args: &'static [&'static str] = Box::leak(Box::new([bad]));
        let (ok, _, err) = issue("bad", args).await;
        assert!(!ok && err.contains("DAYS"), "{bad}: {err}");
    }

    // The same token with its deadline moved into the past stops working.
    let (old_token, mut old) = parse(&issue("old", &["1"]).await.1);
    old["expires_at"] = json!(now - 60);
    std::fs::write(&tokens, json!({"users": [fresh, old]}).to_string()).unwrap();
    let mut child = command(
        &[("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap())],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;
    assert_eq!(http_post(port, &old_token, None, &json!({})).await.0, 401);
    assert_ne!(http_post(port, &fresh_token, None, &json!({})).await.0, 401);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Needs no memcached. Revoking a token by editing the file takes effect without a restart,
/// and a broken edit keeps the previous tokens.
#[tokio::test]
async fn token_file_is_reloaded_while_running() {
    let dir = std::env::temp_dir().join(format!("memcached-mcp-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let tokens = dir.join("tokens.json");
    let issue = |name: &'static str| async move {
        let out = command(&[], &["new-token", name, "read"])
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
        let entry: Value = serde_json::from_str(&json[json.find('{').unwrap()..]).unwrap();
        (token, entry)
    };
    let (a_token, a) = issue("a").await;
    let (b_token, b) = issue("b").await;
    std::fs::write(&tokens, json!({"users": [a]}).to_string()).unwrap();
    let mut child = command(
        &[("MEMCACHED_MCP_HTTP_TOKEN_FILE", tokens.to_str().unwrap())],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;
    assert_ne!(http_post(port, &a_token, None, &json!({})).await.0, 401);
    assert_eq!(http_post(port, &b_token, None, &json!({})).await.0, 401);

    // A broken edit changes nothing.
    std::fs::write(&tokens, "{ not json").unwrap();
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_ne!(http_post(port, &a_token, None, &json!({})).await.0, 401);

    // Replace a with b: a is revoked, b is admitted.
    std::fs::write(&tokens, json!({"users": [b]}).to_string()).unwrap();
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(http_post(port, &a_token, None, &json!({})).await.0, 401);
    assert_ne!(http_post(port, &b_token, None, &json!({})).await.0, 401);

    // An empty list revokes everyone.
    std::fs::write(&tokens, r#"{"users":[]}"#).unwrap();
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(http_post(port, &b_token, None, &json!({})).await.0, 401);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn http_refuses_ambiguous_or_broken_auth_config() {
    let dir = std::env::temp_dir().join(format!("memcached-mcp-authcfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad_file = dir.join("bad.json");
    std::fs::write(&bad_file, r#"{"users":[]}"#).unwrap();
    let missing = dir.join("missing.json");
    for (envs, needle) in [
        (
            vec![
                ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
                ("MEMCACHED_MCP_HTTP_TOKEN_FILE", bad_file.to_str().unwrap()),
            ],
            "not both",
        ),
        (
            vec![("MEMCACHED_MCP_HTTP_TOKEN_FILE", bad_file.to_str().unwrap())],
            "no users",
        ),
        (
            vec![("MEMCACHED_MCP_HTTP_TOKEN_FILE", missing.to_str().unwrap())],
            "cannot read",
        ),
    ] {
        let out = tokio::time::timeout(
            Duration::from_secs(10),
            command(&envs, &["--http", "127.0.0.1:0"]).output(),
        )
        .await
        .expect("server should exit, not start")
        .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success());
        assert!(stderr.contains(needle), "expected '{needle}' in: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// mcrouter counters on /metrics. Set MCROUTER_ADDR (e.g. 127.0.0.1:11218); skipped otherwise.
#[tokio::test]
async fn metrics_include_mcrouter_and_flag_unreachable_targets() {
    let Ok(router) = std::env::var("MCROUTER_ADDR") else {
        eprintln!("MCROUTER_ADDR not set, skipping");
        return;
    };
    let dead = "127.0.0.1:1";
    let allow = format!("{router},{dead}");
    let targets = format!("{router},{dead}");
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", &allow),
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
            ("MEMCACHED_MCP_MCROUTER_METRICS_TARGETS", &targets),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;
    let auth = format!("Bearer {TOKEN}");
    let (status, body) = http_get(port, "/metrics", &[("Authorization", &auth)]).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(&format!("mcrouter_up{{instance=\"{router}\"}} 1")),
        "{body}"
    );
    assert!(
        body.contains(&format!("mcrouter_up{{instance=\"{dead}\"}} 0")),
        "{body}"
    );
    assert!(
        body.contains(&format!("mcrouter_destinations{{instance=\"{router}\"}} 3")),
        "{body}"
    );
    assert!(!body.contains("memcached_up"), "{body}");
}

/// Many sessions at once, each with several calls, must all succeed and stay independent.
#[tokio::test]
async fn concurrent_http_sessions_do_not_interfere() {
    let Some(addr) = memcached_addr() else { return };
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", &addr),
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;

    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..16 {
        let addr = addr.clone();
        tasks.spawn(async move {
            let mut s = HttpMcp::start(port, TOKEN).await;
            for _ in 0..5 {
                let (err, text) = s.call("get_stats", json!({"addr":addr})).await;
                assert!(!err, "session {n}: {text}");
                let (err, text) = s
                    .call(
                        "get_key_metadata",
                        json!({"addr":addr,"key":format!("conc:{n}")}),
                    )
                    .await;
                assert!(!err, "session {n}: {text}");
            }
            n
        });
    }
    let mut done = 0;
    while let Some(r) = tasks.join_next().await {
        r.expect("a session panicked");
        done += 1;
    }
    assert_eq!(done, 16);
}

/// Once the session cap is reached new sessions get 503, while open ones keep working.
#[tokio::test]
async fn http_session_cap_refuses_new_sessions() {
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "2"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;

    let first = HttpMcp::start(port, TOKEN).await;
    let _second = HttpMcp::start(port, TOKEN).await;

    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}});
    let (status, head, _) = http_post(port, TOKEN, None, &init).await;
    assert_eq!(status, 503, "{head}");
    assert!(head.contains("retry-after:"), "{head}");

    let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    let (status, _, body) = http_post(port, TOKEN, Some(&first.session), &list).await;
    assert_eq!(status, 200, "{body}");
    let _ = child.kill().await;
}

/// One user cannot hold more than its share of the sessions, even below the global cap.
#[tokio::test]
async fn http_session_cap_is_also_per_user() {
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", "10"),
            ("MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER", "1"),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;

    let first = HttpMcp::start(port, TOKEN).await;
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}});
    let (status, _, body) = http_post(port, TOKEN, None, &init).await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("for this user"), "{body}");

    let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    let (status, _, body) = http_post(port, TOKEN, Some(&first.session), &list).await;
    assert_eq!(status, 200, "{body}");
    let _ = child.kill().await;
}

#[tokio::test]
async fn http_max_sessions_must_be_a_positive_number() {
    for bad in ["0", "many", "-1"] {
        let out = command(
            &[
                ("MEMCACHED_MCP_ALLOWLIST", "127.0.0.1:1"),
                ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
                ("MEMCACHED_MCP_HTTP_MAX_SESSIONS", bad),
            ],
            &["--http", "127.0.0.1:0"],
        )
        .output()
        .await
        .expect("run memcached-mcp");
        assert!(!out.status.success(), "{bad} was accepted");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("MEMCACHED_MCP_HTTP_MAX_SESSIONS"), "{err}");
    }
}

fn fake_reply(line: &str, config: &str) -> String {
    if line.starts_with("get ") {
        format!(
            "VALUE __mcrouter__.preprocessed_config 0 {}\r\n{config}\r\nEND\r\n",
            config.len()
        )
    } else if line == "version" {
        "VERSION 1.6.0\r\n".to_owned()
    } else {
        "STAT num_servers 2\r\nEND\r\n".to_owned()
    }
}

/// A stand-in that answers just enough text protocol for the metrics scrape: the mcrouter config
/// key, `stats` and `version`. Returns its address.
async fn fake_mcrouter(config: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let config = config.to_owned();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let config = config.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let (rd, mut wr) = sock.into_split();
                let mut lines = BufReader::new(rd).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let reply = fake_reply(&line, &config);
                    if wr.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Per-destination reachability on /metrics: mapped and allowlisted destinations are probed
/// directly, unmapped or non-allowlisted ones are left out.
#[tokio::test]
async fn metrics_report_each_mapped_destination() {
    let alive = fake_mcrouter("{}").await;
    let dead = "127.0.0.1:1";
    let config = r#"{"pools":{"p":{"servers":["mc-a:11211","mc-b:11211","mc-c:11211","mc-d:11211"]}},"route":"PoolRoute|p"}"#;
    let router = fake_mcrouter(config).await;
    // mc-c has no mapping; mc-d maps to an address that is not allowlisted.
    let map = format!("mc-a:11211={alive},mc-b:11211={dead},mc-d:11211=127.0.0.1:2");
    let allow = format!("{router},{alive},{dead}");
    let mut child = command(
        &[
            ("MEMCACHED_MCP_ALLOWLIST", &allow),
            ("MEMCACHED_MCP_HTTP_TOKEN", TOKEN),
            ("MEMCACHED_MCP_MCROUTER_METRICS_TARGETS", &router),
            ("MEMCACHED_MCP_DEST_MAP", &map),
        ],
        &["--http", "127.0.0.1:0"],
    )
    .spawn()
    .expect("spawn memcached-mcp");
    let port = listening_port(&mut child).await;
    let auth = format!("Bearer {TOKEN}");
    let (status, body) = http_get(port, "/metrics", &[("Authorization", &auth)]).await;
    assert_eq!(status, 200, "{body}");
    let line = |dest: &str, up: u8| {
        format!("mcrouter_destination_up{{instance=\"{router}\",destination=\"{dest}\"}} {up}")
    };
    assert!(body.contains(&line("mc-a:11211", 1)), "{body}");
    assert!(body.contains(&line("mc-b:11211", 0)), "{body}");
    assert!(!body.contains("mc-c:11211"), "{body}");
    assert!(!body.contains("mc-d:11211"), "{body}");
    let _ = child.kill().await;
}
