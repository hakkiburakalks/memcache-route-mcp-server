//! MCP server for memcached. Read-only unless MEMCACHED_MCP_ALLOW_WRITE=1. Targets must be listed in MEMCACHED_MCP_ALLOWLIST.

mod audit;
mod http;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use audit::Audit;
use memcached_core::Client;
use memcached_protocol::text::StoreCmd;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, transport::stdio, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;

const OP_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest value memcached accepts by default (1 MiB item size limit).
const MAX_VALUE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct MemcachedServer {
    allowlist: HashSet<String>,
    audit: Arc<Audit>,
    write_prefixes: Vec<String>,
    allow_key_names: bool,
    /// mcrouter's own destination names -> addresses this server can reach.
    dest_map: Arc<BTreeMap<String, String>>,
    router: ToolRouter<Self>,
}

#[derive(Deserialize, JsonSchema)]
struct Target {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
}

#[derive(Deserialize, JsonSchema)]
struct StatsArgs {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
    /// Optional stats group: `settings`, `items`, `slabs`, `sizes`, `conns`.
    group: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct CompareArgs {
    /// Server addresses as `host:port`; each must be in the allowlist.
    addrs: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct TraceArgs {
    /// mcrouter address as `host:port`; must be in the allowlist.
    addr: String,
    /// Key to trace.
    key: String,
    /// Operation: `get` (default), `set` or `delete`.
    op: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct KeyArgs {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
    /// Key to inspect.
    key: String,
}

impl MemcachedServer {
    /// Write tools are only registered when `MEMCACHED_MCP_ALLOW_WRITE=1`; otherwise they are
    /// neither listed nor callable.
    fn from_env() -> std::io::Result<Self> {
        let allowlist = std::env::var("MEMCACHED_MCP_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        let write_prefixes = std::env::var("MEMCACHED_MCP_WRITE_PREFIX")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let dest_map =
            mcrouter::parse_dest_map(&std::env::var("MEMCACHED_MCP_DEST_MAP").unwrap_or_default())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("MEMCACHED_MCP_DEST_MAP: {e}"),
                    )
                })?;
        let mut router = Self::tool_router();
        if std::env::var("MEMCACHED_MCP_ALLOW_WRITE").as_deref() == Ok("1") {
            router.merge(Self::write_router());
        }
        if std::env::var("MEMCACHED_MCP_ALLOW_KEY_SAMPLING").as_deref() == Ok("1") {
            router.merge(Self::inventory_router());
        }
        Ok(Self {
            allowlist,
            audit: Arc::new(Audit::from_env()?),
            write_prefixes,
            allow_key_names: std::env::var("MEMCACHED_MCP_ALLOW_KEY_NAMES").as_deref() == Ok("1"),
            dest_map: Arc::new(dest_map),
            router,
        })
    }

    async fn connect(&self, addr: &str) -> Result<Client, String> {
        if !self.allowlist.contains(addr) {
            self.audit
                .record("connect", addr, None, "denied: not in allowlist");
            return Err(format!("{addr} is not in MEMCACHED_MCP_ALLOWLIST"));
        }
        Client::connect(addr, OP_TIMEOUT)
            .await
            .map_err(|e| e.to_string())
    }
}

#[tool_router]
impl MemcachedServer {
    #[tool(
        description = "Connect to a memcached server and report its version and detected capabilities (meta commands).",
        annotations(read_only_hint = true)
    )]
    async fn server_info(&self, Parameters(a): Parameters<Target>) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let caps = c.probe().await.map_err(|e| e.to_string())?;
        Ok(format!(
            "version: {}\nmeta_commands: {}",
            caps.version, caps.meta
        ))
    }

    #[tool(
        description = "Return memcached `stats` (optionally a group such as settings, items, slabs) as JSON.",
        annotations(read_only_hint = true)
    )]
    async fn get_stats(&self, Parameters(a): Parameters<StatsArgs>) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let stats = c
            .stats(a.group.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())
    }

    #[tool(
        description = "Check whether a key exists and return its metadata; the value itself is never returned. On servers with meta commands (1.6+) this also reports remaining TTL, seconds since last access, whether it was fetched before, and CAS; older servers report only flags and size. Does not change the item's LRU position or fetched-before state, but the lookup still counts in the server's get_hits/get_misses totals.",
        annotations(read_only_hint = true)
    )]
    async fn get_key_metadata(&self, Parameters(a): Parameters<KeyArgs>) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let caps = c.probe().await.map_err(|e| e.to_string())?;
        let key = a.key.as_bytes();
        let body = if caps.meta {
            let info = c.meta_info(key).await.map_err(|e| e.to_string())?;
            serde_json::json!({ "source": "meta", "found": info.is_some(), "info": info })
        } else {
            let hit = c.get(key).await.map_err(|e| e.to_string())?;
            serde_json::json!({
                "source": "classic",
                "found": hit.is_some(),
                "info": hit.map(|(flags, data)| serde_json::json!({
                    "client_flags": flags, "size": data.len(),
                })),
            })
        };
        serde_json::to_string_pretty(&body).map_err(|e| e.to_string())
    }

    #[tool(
        description = "Analyze one node: hit ratio, evictions vs memory, connection limits, eviction skew across slab classes. Returns findings ranked by severity.",
        annotations(read_only_hint = true)
    )]
    async fn diagnose_node(&self, Parameters(a): Parameters<Target>) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let stats = c.stats(None).await.map_err(|e| e.to_string())?;
        // Older servers may lack these groups; the rules that need them are skipped.
        let items = c.stats(Some("items")).await.unwrap_or_default();
        let settings = c.stats(Some("settings")).await.unwrap_or_default();
        let findings = diagnostics::analyze_node(&stats, &items, &settings);
        serde_json::to_string_pretty(&findings).map_err(|e| e.to_string())
    }

    #[tool(
        description = "Compare 3 or more nodes and flag outliers in item count and hit ratio. Unreachable nodes are reported and skipped.",
        annotations(read_only_hint = true)
    )]
    async fn compare_nodes(
        &self,
        Parameters(a): Parameters<CompareArgs>,
    ) -> Result<String, String> {
        let mut collected = Vec::new();
        let mut unreachable = Vec::new();
        for addr in &a.addrs {
            let res = match self.connect(addr).await {
                Ok(mut c) => c.stats(None).await.map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            match res {
                Ok(s) => collected.push((addr.as_str(), s)),
                Err(e) => unreachable.push(format!("{addr}: {e}")),
            }
        }
        let nodes: Vec<_> = collected
            .iter()
            .map(|(name, stats)| diagnostics::NodeSummary { name, stats })
            .collect();
        let findings = diagnostics::compare_nodes(&nodes);
        serde_json::to_string_pretty(&serde_json::json!({
            "findings": findings,
            "unreachable": unreachable,
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(
        description = "Read mcrouter's `stats` and report destination health (down or suspect servers). Target must be an mcrouter, not a plain memcached.",
        annotations(read_only_hint = true)
    )]
    async fn mcrouter_get_stats(
        &self,
        Parameters(a): Parameters<Target>,
    ) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let stats = c.stats(None).await.map_err(|e| e.to_string())?;
        let findings = mcrouter::analyze_stats(&stats);
        serde_json::to_string_pretty(&serde_json::json!({ "findings": findings, "stats": stats }))
            .map_err(|e| e.to_string())
    }

    #[tool(
        description = "Fetch the config mcrouter is running (via __mcrouter__.preprocessed_config), list pools and their servers, and flag undefined, unused or empty pools and duplicate servers.",
        annotations(read_only_hint = true)
    )]
    async fn mcrouter_inspect_config(
        &self,
        Parameters(a): Parameters<Target>,
    ) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let (_, raw) = c
            .get(mcrouter::CONFIG_KEY.as_bytes())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("server returned no config; is this an mcrouter?")?;
        let text = String::from_utf8(raw).map_err(|e| e.to_string())?;
        let cfg = mcrouter::parse_config(&text)?;
        let findings = mcrouter::analyze_config(&cfg);
        serde_json::to_string_pretty(&serde_json::json!({ "config": cfg, "findings": findings }))
            .map_err(|e| e.to_string())
    }

    #[tool(
        description = "Inspect and compare the memcached servers behind an mcrouter: reads the mcrouter's pools, then looks at each destination's own stats and flags outliers and per-node problems. mcrouter names destinations as it sees them, so MEMCACHED_MCP_DEST_MAP must map those names to reachable addresses (which must also be allowlisted); unmapped or unreachable destinations are reported, not guessed.",
        annotations(read_only_hint = true)
    )]
    async fn mcrouter_compare_destinations(
        &self,
        Parameters(a): Parameters<Target>,
    ) -> Result<String, String> {
        let mut router = self.connect(&a.addr).await?;
        let (_, raw) = router
            .get(mcrouter::CONFIG_KEY.as_bytes())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("server returned no config; is this an mcrouter?")?;
        let cfg = mcrouter::parse_config(&String::from_utf8(raw).map_err(|e| e.to_string())?)?;

        let mut unmapped = Vec::new();
        let mut unreachable = Vec::new();
        let mut collected = Vec::new();
        for dest in mcrouter::destinations(&cfg) {
            let Some(real) = self.dest_map.get(&dest) else {
                unmapped.push(dest);
                continue;
            };
            let res = async {
                let mut c = self.connect(real).await?;
                let stats = c.stats(None).await.map_err(|e| e.to_string())?;
                let items = c.stats(Some("items")).await.unwrap_or_default();
                let settings = c.stats(Some("settings")).await.unwrap_or_default();
                Ok::<_, String>((stats, items, settings))
            }
            .await;
            match res {
                Ok(data) => collected.push((dest, data)),
                Err(e) => unreachable.push(format!("{dest} -> {real}: {e}")),
            }
        }

        let nodes: Vec<_> = collected
            .iter()
            .map(|(name, (stats, _, _))| diagnostics::NodeSummary { name, stats })
            .collect();
        let comparison = diagnostics::compare_nodes(&nodes);
        let per_node: BTreeMap<_, _> = collected
            .iter()
            .map(|(name, (stats, items, settings))| {
                (name, diagnostics::analyze_node(stats, items, settings))
            })
            .filter(|(_, f)| !f.is_empty())
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "inspected": collected.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            "comparison": comparison,
            "per_node": per_node,
            "unmapped": unmapped,
            "unreachable": unreachable,
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(
        description = "Diagnose failover on an mcrouter: combines its running config (is there a failover handle?) with live stats (are destinations down?) and explains what that means for reads and writes.",
        annotations(read_only_hint = true)
    )]
    async fn mcrouter_diagnose_failover(
        &self,
        Parameters(a): Parameters<Target>,
    ) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        let (_, raw) = c
            .get(mcrouter::CONFIG_KEY.as_bytes())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("server returned no config; is this an mcrouter?")?;
        let cfg = mcrouter::parse_config(&String::from_utf8(raw).map_err(|e| e.to_string())?)?;
        let stats = c.stats(None).await.map_err(|e| e.to_string())?;
        let findings = mcrouter::diagnose_failover(&cfg, &stats);
        serde_json::to_string_pretty(&serde_json::json!({
            "has_failover": cfg.has_failover,
            "findings": findings,
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(
        description = "Ask mcrouter which destination server a key would be routed to for an operation (get, set or delete). Nothing is read or written.",
        annotations(read_only_hint = true)
    )]
    async fn mcrouter_trace_key_route(
        &self,
        Parameters(a): Parameters<TraceArgs>,
    ) -> Result<String, String> {
        let op = a.op.as_deref().unwrap_or("get");
        if !matches!(op, "get" | "set" | "delete") {
            return Err(format!("op must be get, set or delete, got '{op}'"));
        }
        let mut c = self.connect(&a.addr).await?;
        let probe = mcrouter::route_key(op, &a.key);
        match c.get(probe.as_bytes()).await.map_err(|e| e.to_string())? {
            Some((_, dest)) => Ok(match mcrouter::interpret_route(&dest) {
                mcrouter::RouteTrace::Destination { address } => format!("destination: {address}"),
                mcrouter::RouteTrace::NoDestination => "destination: none. The key hashes to a destination that is marked down and the route does not fail over: writes will fail and reads will look like misses.".to_owned(),
            }),
            None => Err("mcrouter returned no route; is this an mcrouter?".to_owned()),
        }
    }
}

#[derive(Deserialize, JsonSchema)]
struct SetArgs {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
    /// Key to write.
    key: String,
    /// Value to store (text, at most 1 MiB).
    value: String,
    /// Time to live in seconds; 0 or omitted means no expiry.
    ttl_seconds: Option<i64>,
    /// Opaque client flags; defaults to 0.
    flags: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct TouchArgs {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
    /// Key to update.
    key: String,
    /// New time to live in seconds.
    ttl_seconds: i64,
}

#[derive(Deserialize, JsonSchema)]
struct SampleArgs {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
    /// Only count keys starting with this prefix (applied after scanning).
    prefix: Option<String>,
    /// Character that separates the prefix from the rest of the key; defaults to `:`.
    delimiter: Option<String>,
    /// Stop after scanning this many items (default 10000, at most 100000).
    max_scan: Option<usize>,
    /// Also return individual keys. Needs MEMCACHED_MCP_ALLOW_KEY_NAMES=1.
    include_keys: Option<bool>,
    /// How many individual keys to return when include_keys is set (default 50, at most 500).
    max_keys: Option<usize>,
}

const DEFAULT_SCAN: usize = 10_000;
const MAX_SCAN: usize = 100_000;

#[tool_router(router = inventory_router)]
impl MemcachedServer {
    #[tool(
        description = "Sample what is stored in a memcached by walking its LRU crawler metadata dump (values are never read). Returns items, bytes and never-fetched counts per key prefix, plus individual keys only if enabled. Imposes crawler load, scans in the crawler's order rather than randomly (a partial scan is biased), and needs the LRU crawler enabled (off by default on 1.4).",
        annotations(read_only_hint = true)
    )]
    async fn sample_keys(&self, Parameters(a): Parameters<SampleArgs>) -> Result<String, String> {
        let want_keys = a.include_keys.unwrap_or(false);
        if want_keys && !self.allow_key_names {
            return Err("returning key names is disabled; set MEMCACHED_MCP_ALLOW_KEY_NAMES=1 on the server, or omit include_keys to get prefix totals only".to_owned());
        }
        let mut delim = a.delimiter.as_deref().unwrap_or(":").chars();
        let (Some(delim), None) = (delim.next(), delim.next()) else {
            return Err("delimiter must be exactly one character".to_owned());
        };
        let scan = a.max_scan.unwrap_or(DEFAULT_SCAN).clamp(1, MAX_SCAN);
        let max_keys = a.max_keys.unwrap_or(50).min(500);

        let c = self.connect(&a.addr).await?;
        let sample = c.dump_keys(scan).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("disabled") {
                "the LRU crawler is disabled on this server; start memcached with `-o lru_crawler` to allow metadump".to_owned()
            } else if msg.contains("ERROR") {
                format!("this server does not support `lru_crawler metadump` ({msg})")
            } else {
                msg
            }
        })?;
        self.audit.record(
            "sample_keys",
            &a.addr,
            None,
            &format!(
                "scanned={} complete={} names_returned={want_keys}",
                sample.entries.len(),
                sample.complete
            ),
        );

        let scanned = sample.entries.len();
        let kept: Vec<_> = sample
            .entries
            .iter()
            .filter(|e| a.prefix.as_deref().is_none_or(|p| e.key.starts_with(p)))
            .collect();
        let prefixes = diagnostics::inventory::summarize(
            kept.iter().map(|e| diagnostics::inventory::Item {
                key: &e.key,
                size: e.size,
                fetched: e.fetched,
            }),
            delim,
        );
        let never_fetched = kept.iter().filter(|e| !e.fetched).count();
        let keys: Vec<_> = if want_keys {
            kept.iter()
                .take(max_keys)
                .map(|e| {
                    serde_json::json!({
                        "key": e.key, "size": e.size, "fetched": e.fetched,
                        "expires_at": e.expires_at, "last_access": e.last_access,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut notes = vec![
            "size is the item's total size including overhead, not the value length".to_owned(),
            "expires_at and last_access are unix times on the server's clock; last_access is updated lazily".to_owned(),
        ];
        if !sample.complete {
            notes.push(format!(
                "scan stopped after {scanned} items before reaching the end; the crawler does not visit items randomly, so these totals are not representative of the whole cache"
            ));
        }
        serde_json::to_string_pretty(&serde_json::json!({
            "scanned": scanned,
            "complete": sample.complete,
            "matched": kept.len(),
            "never_fetched": never_fetched,
            "prefixes": prefixes.iter().take(50).collect::<Vec<_>>(),
            "keys": keys,
            "notes": notes,
        }))
        .map_err(|e| e.to_string())
    }
}

#[tool_router(router = write_router)]
impl MemcachedServer {
    #[tool(
        description = "WRITES to the cache: store a value under a key, replacing any existing value.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn set_key(&self, Parameters(a): Parameters<SetArgs>) -> Result<String, String> {
        self.check_write_key(&a.addr, &a.key, "set_key")?;
        let ttl = a.ttl_seconds.unwrap_or(0);
        if ttl < 0 {
            return Err("ttl_seconds must not be negative".to_owned());
        }
        if a.value.len() > MAX_VALUE_BYTES {
            return Err(format!(
                "value is {} bytes; the limit is {MAX_VALUE_BYTES}",
                a.value.len()
            ));
        }
        let mut c = self.connect(&a.addr).await?;
        let res = c
            .store(
                StoreCmd::Set,
                a.key.as_bytes(),
                a.flags.unwrap_or(0),
                ttl,
                a.value.as_bytes(),
            )
            .await
            .map(|s| format!("{s:?}"))
            .map_err(|e| e.to_string());
        self.audit_result("set_key", &a.addr, &a.key, &res);
        res
    }

    #[tool(
        description = "WRITES to the cache: delete a key.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn delete_key(&self, Parameters(a): Parameters<KeyArgs>) -> Result<String, String> {
        self.check_write_key(&a.addr, &a.key, "delete_key")?;
        let mut c = self.connect(&a.addr).await?;
        let res = c
            .delete(a.key.as_bytes())
            .await
            .map(|s| format!("{s:?}"))
            .map_err(|e| e.to_string());
        self.audit_result("delete_key", &a.addr, &a.key, &res);
        res
    }

    #[tool(
        description = "WRITES to the cache: change a key's time to live without touching its value.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn touch_key(&self, Parameters(a): Parameters<TouchArgs>) -> Result<String, String> {
        self.check_write_key(&a.addr, &a.key, "touch_key")?;
        if a.ttl_seconds < 0 {
            return Err("ttl_seconds must not be negative".to_owned());
        }
        let mut c = self.connect(&a.addr).await?;
        let res = c
            .touch(a.key.as_bytes(), a.ttl_seconds)
            .await
            .map(|s| format!("{s:?}"))
            .map_err(|e| e.to_string());
        self.audit_result("touch_key", &a.addr, &a.key, &res);
        res
    }
}

impl MemcachedServer {
    /// With `MEMCACHED_MCP_WRITE_PREFIX` set, writes are limited to keys with one of these prefixes.
    fn check_write_key(&self, addr: &str, key: &str, tool: &str) -> Result<(), String> {
        if self.write_prefixes.is_empty() || self.write_prefixes.iter().any(|p| key.starts_with(p))
        {
            return Ok(());
        }
        self.audit.record(
            tool,
            addr,
            Some(key),
            "denied: key outside MEMCACHED_MCP_WRITE_PREFIX",
        );
        Err(format!(
            "key '{key}' is outside the allowed write prefixes ({})",
            self.write_prefixes.join(", ")
        ))
    }

    fn audit_result(&self, tool: &str, addr: &str, key: &str, res: &Result<String, String>) {
        let outcome = match res {
            Ok(s) => format!("ok: {s}"),
            Err(e) => format!("error: {e}"),
        };
        self.audit.record(tool, addr, Some(key), &outcome);
    }
}

#[tool_handler(router = self.router, name = "memcached-mcp")]
impl rmcp::ServerHandler for MemcachedServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = MemcachedServer::from_env()?;
    if server.allowlist.is_empty() {
        eprintln!("warning: MEMCACHED_MCP_ALLOWLIST is empty; every target will be rejected");
    }
    if server.router.has_route("set_key") && server.write_prefixes.is_empty() {
        eprintln!("warning: writes are enabled with no MEMCACHED_MCP_WRITE_PREFIX; any key on an allowlisted server can be written");
    }
    match http_bind_from_args()? {
        Some(bind) => {
            let cfg = http_config(bind, &server.allowlist)?;
            let audit = server.audit.clone();
            http::serve(server, audit, cfg).await?;
        }
        None => {
            let service = server.serve(stdio()).await?;
            service.waiting().await?;
        }
    }
    Ok(())
}

/// `--http <addr:port>` switches from stdio to Streamable HTTP.
fn http_bind_from_args() -> Result<Option<std::net::SocketAddr>, String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => Ok(None),
        Some("--http") => {
            let addr = args
                .next()
                .ok_or("--http needs an address, e.g. --http 127.0.0.1:8080")?;
            addr.parse()
                .map(Some)
                .map_err(|e| format!("bad --http address '{addr}': {e}"))
        }
        Some(other) => Err(format!(
            "unknown argument '{other}'; usage: memcached-mcp [--http ADDR:PORT]"
        )),
    }
}

/// Authentication is mandatory over HTTP, and plaintext is only allowed on loopback unless
/// explicitly opted into (the bearer token would otherwise cross the network in the clear).
fn http_config(
    bind: std::net::SocketAddr,
    allowlist: &HashSet<String>,
) -> Result<http::HttpConfig, String> {
    let token = std::env::var("MEMCACHED_MCP_HTTP_TOKEN").unwrap_or_default();
    if token.len() < http::MIN_TOKEN_LEN {
        return Err(format!(
            "set MEMCACHED_MCP_HTTP_TOKEN to a secret of at least {} characters",
            http::MIN_TOKEN_LEN
        ));
    }
    if !bind.ip().is_loopback()
        && std::env::var("MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT").as_deref() != Ok("1")
    {
        return Err(format!(
            "{bind} is not a loopback address and this server speaks plain HTTP; bind to 127.0.0.1 behind a TLS proxy, or set MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1 to accept the risk"
        ));
    }
    let allowed_hosts = std::env::var("MEMCACHED_MCP_HTTP_ALLOWED_HOSTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    // /metrics must not become a way around the allowlist.
    let metrics_targets: Vec<String> = std::env::var("MEMCACHED_MCP_METRICS_TARGETS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(bad) = metrics_targets.iter().find(|t| !allowlist.contains(*t)) {
        return Err(format!(
            "MEMCACHED_MCP_METRICS_TARGETS lists {bad}, which is not in MEMCACHED_MCP_ALLOWLIST"
        ));
    }
    Ok(http::HttpConfig {
        bind,
        token,
        allowed_hosts,
        metrics_targets,
    })
}
