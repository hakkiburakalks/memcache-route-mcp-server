//! Read-only MCP server for memcached. Targets must be listed in MEMCACHED_MCP_ALLOWLIST.

use std::collections::HashSet;
use std::time::Duration;

use memcached_core::Client;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, transport::stdio, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;

const OP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct MemcachedServer {
    allowlist: HashSet<String>,
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
struct KeyArgs {
    /// Server address as `host:port`; must be in the allowlist.
    addr: String,
    /// Key to inspect.
    key: String,
}

impl MemcachedServer {
    fn from_env() -> Self {
        let allowlist = std::env::var("MEMCACHED_MCP_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        Self { allowlist }
    }

    async fn connect(&self, addr: &str) -> Result<Client, String> {
        if !self.allowlist.contains(addr) {
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
        description = "Check whether a key exists and return its flags and size. The value itself is never returned.",
        annotations(read_only_hint = true)
    )]
    async fn get_key_metadata(&self, Parameters(a): Parameters<KeyArgs>) -> Result<String, String> {
        let mut c = self.connect(&a.addr).await?;
        match c.get(a.key.as_bytes()).await.map_err(|e| e.to_string())? {
            Some((flags, data)) => Ok(format!(
                "found: true\nflags: {flags}\nbytes: {}",
                data.len()
            )),
            None => Ok("found: false".to_owned()),
        }
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
}

#[tool_handler(name = "memcached-mcp")]
impl rmcp::ServerHandler for MemcachedServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = MemcachedServer::from_env();
    if server.allowlist.is_empty() {
        eprintln!("warning: MEMCACHED_MCP_ALLOWLIST is empty; every target will be rejected");
    }
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
