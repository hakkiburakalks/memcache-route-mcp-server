//! Streamable HTTP transport with mandatory bearer-token authentication.
//!
//! There is no TLS here: keep the listener on loopback or put a TLS-terminating proxy in front.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use memcached_core::Client;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::ServerHandler;

use crate::audit::{Admit, Audit, Throttle};
use crate::auth::{Identity, Perm, TokenStore};

/// Shorter tokens are refused at startup.
pub const MIN_TOKEN_LEN: usize = 24;

/// Open sessions allowed when `MEMCACHED_MCP_HTTP_MAX_SESSIONS` is not set.
pub const DEFAULT_MAX_SESSIONS: usize = 256;

pub struct HttpConfig {
    pub bind: SocketAddr,
    pub tokens: TokenStore,
    /// Extra `Host` values to accept besides loopback (for use behind a proxy).
    pub allowed_hosts: Vec<String>,
    pub metrics: MetricsTargets,
    /// New sessions are refused with 503 while this many are open.
    pub max_sessions: usize,
}

/// Servers exposed on `/metrics`. With both lists empty the endpoint is absent.
#[derive(Default)]
pub struct MetricsTargets {
    pub memcached: Vec<String>,
    pub mcrouter: Vec<String>,
    /// mcrouter's name for a destination -> an allowlisted address we can probe.
    pub dest_map: BTreeMap<String, String>,
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

/// Probes every mapped destination of one mcrouter, concurrently. A router that cannot be read
/// yields no rows (its `mcrouter_up` already says so); unmapped destinations cannot be probed.
async fn probe_destinations(
    router: String,
    dest_map: &BTreeMap<String, String>,
) -> Vec<(String, String, bool)> {
    let config = async {
        let mut c = Client::connect(&router, SCRAPE_TIMEOUT).await.ok()?;
        let (_, raw) = c.get(mcrouter::CONFIG_KEY.as_bytes()).await.ok()??;
        mcrouter::parse_config(&String::from_utf8(raw).ok()?).ok()
    }
    .await;
    let Some(config) = config else {
        return Vec::new();
    };
    let mut set = tokio::task::JoinSet::new();
    for (i, dest) in mcrouter::destinations(&config).into_iter().enumerate() {
        let Some(real) = dest_map.get(&dest).cloned() else {
            continue;
        };
        set.spawn(async move {
            let up = match Client::connect(&real, SCRAPE_TIMEOUT).await {
                Ok(mut c) => c.version().await.is_ok(),
                Err(_) => false,
            };
            (i, dest, up)
        });
    }
    let mut rows = Vec::new();
    while let Some(Ok(row)) = set.join_next().await {
        rows.push(row);
    }
    rows.sort_by_key(|(i, _, _)| *i);
    rows.into_iter()
        .map(|(_, dest, up)| (router.clone(), dest, up))
        .collect()
}

async fn probe_all_destinations(
    routers: &[String],
    dest_map: &BTreeMap<String, String>,
) -> Vec<(String, String, bool)> {
    if dest_map.is_empty() {
        return Vec::new();
    }
    let mut set = tokio::task::JoinSet::new();
    for (i, router) in routers.iter().cloned().enumerate() {
        let dest_map = dest_map.clone();
        set.spawn(async move { (i, probe_destinations(router, &dest_map).await) });
    }
    let mut all = Vec::new();
    while let Some(Ok(rows)) = set.join_next().await {
        all.push(rows);
    }
    all.sort_by_key(|(i, _)| *i);
    all.into_iter().flat_map(|(_, rows)| rows).collect()
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
    let (memcached, mcrouter, destinations) = tokio::join!(
        scrape_all(&targets.memcached),
        scrape_all(&targets.mcrouter),
        probe_all_destinations(&targets.mcrouter, &targets.dest_map)
    );
    let mut body = String::new();
    if !memcached.is_empty() {
        body.push_str(&diagnostics::prometheus::render(&memcached));
    }
    if !mcrouter.is_empty() {
        body.push_str(&diagnostics::prometheus::render_mcrouter(&mcrouter));
    }
    body.push_str(&diagnostics::prometheus::render_mcrouter_destinations(
        &destinations,
    ));
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
struct SessionCap {
    sessions: Arc<LocalSessionManager>,
    max: usize,
}

/// A POST to /mcp without `Mcp-Session-Id` opens a session; refuse it when the cap is reached.
/// Sessions leave the map when they are closed or idle out, so the count is the live number.
async fn cap_sessions(State(cap): State<SessionCap>, req: Request, next: Next) -> Response {
    let opens_session =
        req.method() == Method::POST && !req.headers().contains_key("mcp-session-id");
    if opens_session && cap.sessions.sessions.read().await.len() >= cap.max {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "30")],
            "too many open sessions
",
        )
            .into_response();
    }
    next.run(req).await
}

#[derive(Clone)]
struct Auth {
    tokens: Arc<TokenStore>,
    audit: Arc<Audit>,
    /// Bad-token attempts come from anyone who can reach the port, so their audit lines are capped.
    denials: Arc<Throttle>,
}

/// Audit lines for failed authentication per second, before the rest are only counted.
const MAX_DENIAL_LOGS_PER_SEC: u32 = 20;

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
    let admit = auth.denials.admit();
    if let Admit::AfterDropped(n) = admit {
        auth.audit.record(
            "-",
            "http",
            "-",
            None,
            &format!("{n} more failed authentications in the previous second were not logged"),
        );
    }
    if admit != Admit::No {
        auth.audit.record(
            "-",
            "http",
            &peer.to_string(),
            None,
            "denied: missing, wrong or expired bearer token",
        );
    }
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
    let sessions = Arc::new(LocalSessionManager::default());
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        sessions.clone(),
        StreamableHttpServerConfig::default().with_allowed_hosts(hosts),
    );
    let cap = SessionCap {
        sessions,
        max: cfg.max_sessions,
    };
    let auth = Auth {
        tokens: Arc::new(cfg.tokens),
        audit,
        denials: Arc::new(Throttle::new(MAX_DENIAL_LOGS_PER_SEC)),
    };
    let mut app = Router::new().nest_service(
        "/mcp",
        Router::new()
            .fallback_service(mcp)
            .layer(middleware::from_fn_with_state(cap, cap_sessions)),
    );
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
