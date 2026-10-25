//! Streamable HTTP transport with mandatory bearer-token authentication.
//!
//! There is no TLS here: keep the listener on loopback or put a TLS-terminating proxy in front.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use memcached_core::Client;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::ServerHandler;

use crate::audit::Audit;

/// Shorter tokens are refused at startup.
pub const MIN_TOKEN_LEN: usize = 24;

pub struct HttpConfig {
    pub bind: SocketAddr,
    pub token: String,
    /// Extra `Host` values to accept besides loopback (for use behind a proxy).
    pub allowed_hosts: Vec<String>,
    /// memcached servers exposed on `/metrics`. Empty disables the endpoint.
    pub metrics_targets: Vec<String>,
}

const SCRAPE_TIMEOUT: Duration = Duration::from_secs(3);

async fn scrape(addr: &str) -> Option<diagnostics::Stats> {
    Client::connect(addr, SCRAPE_TIMEOUT)
        .await
        .ok()?
        .stats(None)
        .await
        .ok()
}

/// Scrapes every target concurrently; an unreachable one is reported as `memcached_up 0`.
async fn metrics(State(targets): State<Arc<Vec<String>>>) -> Response {
    let mut set = tokio::task::JoinSet::new();
    for (i, addr) in targets.iter().cloned().enumerate() {
        set.spawn(async move {
            let stats = scrape(&addr).await;
            (i, addr, stats)
        });
    }
    let mut nodes = Vec::new();
    while let Some(Ok(node)) = set.join_next().await {
        nodes.push(node);
    }
    nodes.sort_by_key(|(i, _, _)| *i);
    let nodes: Vec<_> = nodes
        .into_iter()
        .map(|(_, addr, stats)| (addr, stats))
        .collect();
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        diagnostics::prometheus::render(&nodes),
    )
        .into_response()
}

/// Compares without stopping at the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

fn bearer_matches(header: Option<&str>, token: &str) -> bool {
    header
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|t| constant_time_eq(t.as_bytes(), token.as_bytes()))
}

#[derive(Clone)]
struct Auth {
    token: Arc<String>,
    audit: Arc<Audit>,
}

async fn require_token(
    State(auth): State<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if bearer_matches(header, &auth.token) {
        return next.run(req).await;
    }
    auth.audit.record(
        "http",
        &peer.to_string(),
        None,
        "denied: missing or wrong bearer token",
    );
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Bearer")],
        "unauthorized\n",
    )
        .into_response()
}

pub async fn serve<S>(server: S, audit: Arc<Audit>, cfg: HttpConfig) -> std::io::Result<()>
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    hosts.extend(cfg.allowed_hosts);
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_allowed_hosts(hosts),
    );
    let auth = Auth {
        token: Arc::new(cfg.token),
        audit,
    };
    let mut app = Router::new().nest_service("/mcp", mcp);
    if !cfg.metrics_targets.is_empty() {
        let metrics_routes = Router::new()
            .route("/metrics", get(metrics))
            .with_state(Arc::new(cfg.metrics_targets));
        app = app.merge(metrics_routes);
    }
    // Added last so it covers every route, /metrics included.
    let app = app.layer(middleware::from_fn_with_state(auth, require_token));

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    eprintln!("listening on http://{}/mcp", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn bearer_header_parsing() {
        assert!(bearer_matches(Some("Bearer s3cret"), "s3cret"));
        assert!(!bearer_matches(Some("Bearer wrong"), "s3cret"));
        assert!(!bearer_matches(Some("Basic s3cret"), "s3cret"));
        assert!(!bearer_matches(Some("s3cret"), "s3cret"));
        assert!(!bearer_matches(None, "s3cret"));
    }
}
