//! Streamable HTTP transport with mandatory bearer-token authentication.
//!
//! There is no TLS here: keep the listener on loopback or put a TLS-terminating proxy in front.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, WWW_AUTHENTICATE};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use memcached_core::Client;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::ServerHandler;

use crate::audit::Audit;
use crate::auth::{Identity, Perm, TokenStore};

/// Shorter tokens are refused at startup.
pub const MIN_TOKEN_LEN: usize = 24;

pub struct HttpConfig {
    pub bind: SocketAddr,
    pub tokens: TokenStore,
    /// Extra `Host` values to accept besides loopback (for use behind a proxy).
    pub allowed_hosts: Vec<String>,
    pub metrics: MetricsTargets,
}

/// Servers exposed on `/metrics`. With both lists empty the endpoint is absent.
#[derive(Default)]
pub struct MetricsTargets {
    pub memcached: Vec<String>,
    pub mcrouter: Vec<String>,
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

/// Scrapes every target concurrently; results keep the order of `targets`.
async fn scrape_all(targets: &[String]) -> Vec<(String, Option<diagnostics::Stats>)> {
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
    nodes
        .into_iter()
        .map(|(_, addr, stats)| (addr, stats))
        .collect()
}

/// An unreachable target is reported as `*_up 0`.
async fn metrics(
    State(targets): State<Arc<MetricsTargets>>,
    Extension(who): Extension<Identity>,
) -> Response {
    if let Err(e) = who.require(Perm::Metrics) {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "{e}
"
            ),
        )
            .into_response();
    }
    let (memcached, mcrouter) = tokio::join!(
        scrape_all(&targets.memcached),
        scrape_all(&targets.mcrouter)
    );
    let mut body = String::new();
    if !memcached.is_empty() {
        body.push_str(&diagnostics::prometheus::render(&memcached));
    }
    if !mcrouter.is_empty() {
        body.push_str(&diagnostics::prometheus::render_mcrouter(&mcrouter));
    }
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

/// The token from an `Authorization: Bearer <token>` header.
fn bearer_token(header: Option<&str>) -> Option<&str> {
    header.and_then(|h| h.strip_prefix("Bearer "))
}

/// The hostname in a `Host` header, without port or IPv6 brackets.
fn host_name(header: &str) -> &str {
    if let Some(rest) = header.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match header.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => header,
    }
}

/// Entries are bare hostnames (any port) or `host:port` authorities.
fn host_allowed(header: &str, allowed: &[String]) -> bool {
    let name = host_name(header);
    allowed
        .iter()
        .any(|a| a.eq_ignore_ascii_case(header) || a.eq_ignore_ascii_case(name))
}

/// Applies the DNS-rebinding check to every route, `/metrics` included.
async fn require_known_host(
    State(allowed): State<Arc<Vec<String>>>,
    req: Request,
    next: Next,
) -> Response {
    let ok = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| host_allowed(h, &allowed));
    if ok {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "forbidden host\n").into_response()
    }
}

#[derive(Clone)]
struct Auth {
    tokens: Arc<TokenStore>,
    audit: Arc<Audit>,
}

async fn require_token(
    State(auth): State<Auth>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if let Some(identity) = bearer_token(header).and_then(|t| auth.tokens.lookup(t)) {
        req.extensions_mut().insert(identity);
        return next.run(req).await;
    }
    auth.audit.record(
        "-",
        "http",
        &peer.to_string(),
        None,
        "denied: missing, wrong or expired bearer token",
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
    let known_hosts = Arc::new(hosts.clone());
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_allowed_hosts(hosts),
    );
    let auth = Auth {
        tokens: Arc::new(cfg.tokens),
        audit,
    };
    let mut app = Router::new().nest_service("/mcp", mcp);
    if !cfg.metrics.memcached.is_empty() || !cfg.metrics.mcrouter.is_empty() {
        let metrics_routes = Router::new()
            .route("/metrics", get(metrics))
            .with_state(Arc::new(cfg.metrics));
        app = app.merge(metrics_routes);
    }
    // Layers added last run first and cover every route, /metrics included: host check, then token.
    let app = app
        .layer(middleware::from_fn_with_state(auth, require_token))
        .layer(middleware::from_fn_with_state(
            known_hosts,
            require_known_host,
        ));

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
    fn host_header_matching() {
        let allowed: Vec<String> = ["localhost", "127.0.0.1", "::1", "cache.example.com:8443"]
            .map(String::from)
            .to_vec();
        for ok in [
            "localhost",
            "localhost:8080",
            "127.0.0.1:9",
            "[::1]:8080",
            "[::1]",
            "LOCALHOST",
            "cache.example.com:8443",
        ] {
            assert!(host_allowed(ok, &allowed), "{ok} should be allowed");
        }
        for bad in [
            "evil.example.com",
            "evil.example.com:8080",
            "127.0.0.1.evil.com",
            "cache.example.com",
            "cache.example.com:1",
            "",
            "localhost.evil.com:80",
        ] {
            assert!(!host_allowed(bad, &allowed), "{bad} should be refused");
        }
    }

    #[test]
    fn bearer_header_parsing() {
        assert_eq!(bearer_token(Some("Bearer s3cret")), Some("s3cret"));
        assert_eq!(bearer_token(Some("Basic s3cret")), None);
        assert_eq!(bearer_token(Some("s3cret")), None);
        assert_eq!(bearer_token(None), None);
    }
}
