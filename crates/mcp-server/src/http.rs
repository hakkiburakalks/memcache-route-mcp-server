//! Streamable HTTP transport with mandatory bearer-token authentication.
//!
//! There is no TLS here: keep the listener on loopback or put a TLS-terminating proxy in front.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::serve::ListenerExt;
use axum::Extension;
use axum::Router;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::session::SessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::ServerHandler;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

use crate::audit::{Admit, Audit, Throttle};
use crate::auth::{Identity, Perm, TokenStore};

/// Shorter tokens are refused at startup.
pub const MIN_TOKEN_LEN: usize = 24;

/// Open sessions allowed when `MEMCACHED_MCP_HTTP_MAX_SESSIONS` is not set.
pub const DEFAULT_MAX_SESSIONS: usize = 256;

/// Sessions one user may hold when `MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER` is not set, so a
/// single token cannot use up the global cap.
pub const DEFAULT_MAX_SESSIONS_PER_USER: usize = 32;

/// Requests one user may have in flight at once when `MEMCACHED_MCP_HTTP_MAX_CONCURRENT` is not
/// set. Every tool call opens its own connection to memcached, so this bounds what one token
/// can do to a server.
pub const DEFAULT_MAX_CONCURRENT: usize = 16;

/// Process-wide `/metrics` requests allowed at once when
/// `MEMCACHED_MCP_METRICS_MAX_CONCURRENT` is not set.
pub const DEFAULT_METRICS_MAX_CONCURRENT: usize = 4;

/// Maximum upstream tasks one `/metrics` refresh holds at once when
/// `MEMCACHED_MCP_METRICS_FANOUT` is not set.
pub const DEFAULT_METRICS_FANOUT: usize = 16;

/// Overall `/metrics` refresh deadline when `MEMCACHED_MCP_METRICS_TIMEOUT_MS` is not set.
pub const DEFAULT_METRICS_DEADLINE: Duration = Duration::from_secs(8);

/// How long a successful `/metrics` body is reused when `MEMCACHED_MCP_METRICS_CACHE_MS` is not
/// set. Zero disables reuse.
pub const DEFAULT_METRICS_CACHE_TTL: Duration = Duration::from_secs(5);

pub struct HttpConfig {
    pub bind: SocketAddr,
    pub tokens: TokenStore,
    /// When set, this file is re-read while running so tokens can be revoked or added without a restart.
    pub token_file: Option<String>,
    /// Extra `Host` values to accept besides loopback (for use behind a proxy).
    pub allowed_hosts: Vec<String>,
    pub metrics: MetricsTargets,
    /// New sessions are refused with 503 while this many are open.
    pub max_sessions: usize,
    /// Open sessions one user may hold; more get 503.
    pub max_sessions_per_user: usize,
    /// Requests per user in flight at once; more get 429.
    pub max_concurrent: usize,
    /// Process-wide `/metrics` requests in flight at once.
    pub metrics_max_concurrent: usize,
    /// Upstream tasks one `/metrics` refresh may hold at once.
    pub metrics_fanout: usize,
    /// Total deadline for one `/metrics` refresh.
    pub metrics_deadline: Duration,
    /// TTL for a successful `/metrics` body.
    pub metrics_cache_ttl: Duration,
    /// Deadline for reading a POST request body. It does not apply to SSE response streams.
    pub body_timeout: Duration,
}

/// Wraps an inbound body with a deadline that starts on the first poll. The body is consumed by
/// rmcp before a POST response is produced, so a client that drips its JSON body cannot hold a
/// request permit forever. GET SSE responses do not use this wrapper.
struct TimedBody {
    inner: Pin<Box<axum::body::Body>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    expired: bool,
}

impl TimedBody {
    fn new(inner: axum::body::Body, timeout: Duration) -> Self {
        Self {
            inner: Box::pin(inner),
            deadline: Box::pin(tokio::time::sleep(timeout)),
            expired: false,
        }
    }
}

impl HttpBody for TimedBody {
    type Data = <axum::body::Body as HttpBody>::Data;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.expired {
            return Poll::Ready(Some(Err(body_timeout_error())));
        }
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.expired = true;
            return Poll::Ready(Some(Err(body_timeout_error())));
        }
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::other(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn body_timeout_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "POST request body exceeded its deadline",
    )
}

async fn bound_post_body(State(timeout): State<Duration>, req: Request, next: Next) -> Response {
    if req.method() != Method::POST {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let body = axum::body::Body::new(TimedBody::new(body, timeout));
    next.run(Request::from_parts(parts, body)).await
}

/// Hands out at most `max` permits per user name.
struct ConcurrencyLimit {
    max: usize,
    users: Mutex<HashMap<Arc<str>, Arc<Semaphore>>>,
}

impl ConcurrencyLimit {
    fn new(max: usize) -> Self {
        Self {
            max,
            users: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(&self, user: &Arc<str>) -> Option<OwnedSemaphorePermit> {
        let sem = self
            .users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(user.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max)))
            .clone();
        sem.try_acquire_owned().ok()
    }
}

/// Servers exposed on `/metrics`. With both lists empty the endpoint is absent.
#[derive(Default, Clone)]
pub struct MetricsTargets {
    pub memcached: Vec<String>,
    pub mcrouter: Vec<String>,
    /// mcrouter's name for a destination -> an allowlisted address we can probe.
    pub dest_map: BTreeMap<String, String>,
}

const SCRAPE_TIMEOUT: Duration = Duration::from_secs(3);
/// Metrics targets are expected to return small stats/config payloads. A stricter per-target
/// byte budget keeps a hostile upstream from making the 16-task fan-out allocate hundreds of MiB.
const METRICS_STATS_BYTES: u64 = 64 * 1024;
const METRICS_CONFIG_BYTES: usize = 256 * 1024;

async fn scrape(
    addr: &str,
) -> (
    Option<diagnostics::Stats>,
    Vec<memcached_core::MemoryReservation>,
) {
    tokio::time::timeout(SCRAPE_TIMEOUT, async {
        let mut c = match crate::target::open_metrics(addr, SCRAPE_TIMEOUT).await {
            Ok(c) => c,
            Err(_) => return (None, Vec::new()),
        };
        let stats = c.stats_with_limit(None, METRICS_STATS_BYTES).await.ok();
        // Keep the reply-buffer reservations while the returned map is rendered.
        let guards = c.take_memory_guards();
        (stats, guards)
    })
    .await
    .unwrap_or((None, Vec::new()))
}

/// Runs at most `limit` futures at once, preserving input order. Unlike spawning one task per
/// item, this bounds task creation even for a 256-node target list.
async fn fan_out<I, T, F, Fut>(items: Vec<I>, limit: usize, work: F) -> Vec<T>
where
    I: Send + 'static,
    T: Send + 'static,
    F: Fn(I) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = T> + Send,
{
    let limit = limit.max(1);
    let total = items.len();
    let mut out: Vec<Option<T>> = (0..total).map(|_| None).collect();
    let mut items = items.into_iter().enumerate();
    loop {
        let mut set = tokio::task::JoinSet::new();
        let mut spawned = false;
        for _ in 0..limit {
            let Some((index, item)) = items.next() else {
                break;
            };
            spawned = true;
            let work = work.clone();
            set.spawn(async move { (index, work(item).await) });
        }
        if !spawned {
            break;
        }
        while let Some(result) = set.join_next().await {
            if let Ok((index, value)) = result {
                out[index] = Some(value);
            }
        }
    }
    out.into_iter()
        .map(|value| value.expect("fan_out lost a completed item"))
        .collect()
}

/// Scrapes every target with bounded fan-out; results keep the order of `targets`. The guards
/// keep the stats maps' reservations alive until the caller has rendered them.
async fn scrape_all(
    targets: &[String],
    fanout: usize,
) -> (
    Vec<(String, Option<diagnostics::Stats>)>,
    Vec<memcached_core::MemoryReservation>,
) {
    let rows = fan_out(targets.to_vec(), fanout, |addr| async move {
        let (stats, guards) = scrape(&addr).await;
        (addr, stats, guards)
    })
    .await;
    let mut out = Vec::with_capacity(rows.len());
    let mut guards = Vec::new();
    for (addr, stats, held) in rows {
        out.push((addr, stats));
        guards.extend(held);
    }
    (out, guards)
}

async fn router_config(
    router: &str,
) -> (
    Option<mcrouter::ConfigSummary>,
    Vec<memcached_core::MemoryReservation>,
) {
    tokio::time::timeout(SCRAPE_TIMEOUT, async {
        let mut c = match crate::target::open_metrics(router, SCRAPE_TIMEOUT).await {
            Ok(c) => c,
            Err(_) => return (None, Vec::new()),
        };
        let Some((_, raw)) = c
            .get_with_limit(mcrouter::CONFIG_KEY.as_bytes(), METRICS_CONFIG_BYTES)
            .await
            .ok()
            .flatten()
        else {
            return (None, Vec::new());
        };
        let parsed = std::str::from_utf8(&raw)
            .ok()
            .and_then(|text| mcrouter::parse_config(text).ok());
        let guards = c.take_memory_guards();
        (parsed, guards)
    })
    .await
    .unwrap_or((None, Vec::new()))
}

/// Probes mapped destinations with one global fan-out for the whole refresh. A router whose
/// config cannot be read yields no rows; unmapped destinations are not probed.
async fn probe_all_destinations(
    routers: &[String],
    dest_map: &BTreeMap<String, String>,
    fanout: usize,
) -> Vec<(String, String, bool)> {
    if dest_map.is_empty() {
        return Vec::new();
    }
    let configs = fan_out(routers.to_vec(), fanout, |router| async move {
        let (config, guards) = router_config(&router).await;
        (router, config, guards)
    })
    .await;
    let mut jobs = Vec::new();
    for (router, config, guards) in configs {
        let Some(config) = config else {
            continue;
        };
        for dest in mcrouter::destinations(&config) {
            let Some(real) = dest_map.get(&dest) else {
                continue;
            };
            jobs.push((router.clone(), dest, real.clone()));
        }
        // The parsed summary and its raw reply reservation end together here.
        drop(guards);
    }
    fan_out(jobs, fanout, |(router, dest, real)| async move {
        let up = tokio::time::timeout(SCRAPE_TIMEOUT, async {
            match crate::target::open_metrics(&real, SCRAPE_TIMEOUT).await {
                Ok(mut c) => c.version().await.is_ok(),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false);
        (router, dest, up)
    })
    .await
}

struct CacheState {
    cached: Option<CachedMetrics>,
}

struct CachedMetrics {
    body: String,
    at: Instant,
    refreshed_unix: u64,
    /// Holds the process-wide reservation for `body` for as long as the cached copy lives.
    _body_budget: Option<memcached_core::MemoryReservation>,
}

/// Shared `/metrics` state: one refresh at a time, a short successful-body cache, a
/// process-wide request cap, and an overall refresh deadline.
#[derive(Clone)]
struct MetricsEngine {
    targets: Arc<MetricsTargets>,
    cache: Arc<AsyncMutex<CacheState>>,
    request_limit: Arc<Semaphore>,
    fanout: usize,
    deadline: Duration,
    cache_ttl: Duration,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    scrapes: Arc<AtomicU64>,
    scrape_errors: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    audit: Arc<Audit>,
}

impl MetricsEngine {
    fn new(
        targets: MetricsTargets,
        max_concurrent: usize,
        fanout: usize,
        deadline: Duration,
        cache_ttl: Duration,
        audit: Arc<Audit>,
    ) -> Self {
        Self {
            targets: Arc::new(targets),
            cache: Arc::new(AsyncMutex::new(CacheState { cached: None })),
            request_limit: Arc::new(Semaphore::new(max_concurrent.max(1))),
            fanout: fanout.max(1),
            deadline,
            cache_ttl,
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            scrapes: Arc::new(AtomicU64::new(0)),
            scrape_errors: Arc::new(AtomicU64::new(0)),
            rejected: Arc::new(AtomicU64::new(0)),
            audit,
        }
    }

    async fn body(&self) -> Result<String, String> {
        // Holding this lock across a refresh is the singleflight: concurrent callers wait for
        // the one in-flight target fan-out instead of repeating it.
        let mut state = self.cache.lock().await;
        if let Some(cached) = &state.cached {
            let age = cached.at.elapsed();
            if age <= self.cache_ttl {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                let mut body = cached.body.clone();
                self.append_internal(&mut body, age, cached.refreshed_unix);
                return Ok(body);
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        let (mut body, _stats_guards) =
            match tokio::time::timeout(self.deadline, self.refresh()).await {
                Ok(result) => result,
                Err(_) => {
                    self.scrape_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(format!("scrape exceeded its {:?} deadline", self.deadline));
                }
            };
        // The cached clone outlives the refresh's reply buffers, so reserve it separately before
        // cloning. Exhaustion fails the scrape instead of caching an unaccounted body.
        let body_budget = match memcached_core::memory::global() {
            Some(budget) => Some(budget.try_reserve(body.len())?),
            None => None,
        };
        let now = Instant::now();
        let refreshed_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        state.cached = Some(CachedMetrics {
            body: body.clone(),
            at: now,
            refreshed_unix,
            _body_budget: body_budget,
        });
        self.scrapes.fetch_add(1, Ordering::Relaxed);
        self.append_internal(&mut body, Duration::ZERO, refreshed_unix);
        Ok(body)
    }

    /// Returns the rendered body together with the reservations for every upstream reply that
    /// was used to build it. The caller must keep the guards alive while the body is cached.
    async fn refresh(&self) -> (String, Vec<memcached_core::MemoryReservation>) {
        let ((memcached, mut guards), (mcrouter, router_guards), destinations) = tokio::join!(
            scrape_all(&self.targets.memcached, self.fanout),
            scrape_all(&self.targets.mcrouter, self.fanout),
            probe_all_destinations(&self.targets.mcrouter, &self.targets.dest_map, self.fanout)
        );
        guards.extend(router_guards);
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
        (body, guards)
    }

    fn append_internal(&self, body: &mut String, age: Duration, refreshed_unix: u64) {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let scrapes = self.scrapes.load(Ordering::Relaxed);
        let errors = self.scrape_errors.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        let audit_dropped = self.audit.dropped();
        let audit_failed = self.audit.failed();
        let (budget_bytes, budget_available) = match memcached_core::memory::global() {
            Some(budget) => (budget.capacity_bytes(), budget.available_bytes()),
            None => (0, 0),
        };
        let _ = writeln!(
            body,
            "# HELP memcached_mcp_metrics_cache_hits_total /metrics responses served from the cache.\n\
             # TYPE memcached_mcp_metrics_cache_hits_total counter\n\
             memcached_mcp_metrics_cache_hits_total {hits}\n\
             # HELP memcached_mcp_metrics_cache_misses_total /metrics refreshes that had to query upstreams.\n\
             # TYPE memcached_mcp_metrics_cache_misses_total counter\n\
             memcached_mcp_metrics_cache_misses_total {misses}\n\
             # HELP memcached_mcp_metrics_scrapes_total Successful whole-scrape refreshes.\n\
             # TYPE memcached_mcp_metrics_scrapes_total counter\n\
             memcached_mcp_metrics_scrapes_total {scrapes}\n\
             # HELP memcached_mcp_metrics_scrape_errors_total Refreshes that failed or exceeded the deadline.\n\
             # TYPE memcached_mcp_metrics_scrape_errors_total counter\n\
             memcached_mcp_metrics_scrape_errors_total {errors}\n\
             # HELP memcached_mcp_metrics_requests_rejected_total /metrics requests rejected by the process-wide limit.\n\
             # TYPE memcached_mcp_metrics_requests_rejected_total counter\n\
             memcached_mcp_metrics_requests_rejected_total {rejected}\n\
             # HELP memcached_mcp_audit_dropped_total Audit lines lost to throttling, queue pressure or a disconnected writer.\n\
             # TYPE memcached_mcp_audit_dropped_total counter\n\
             memcached_mcp_audit_dropped_total {audit_dropped}\n\
             # HELP memcached_mcp_audit_write_errors_total Audit lines the writer could not persist.\n\
             # TYPE memcached_mcp_audit_write_errors_total counter\n\
             memcached_mcp_audit_write_errors_total {audit_failed}\n\
             # HELP memcached_mcp_memory_budget_bytes Configured process-wide reservation budget (not a process RSS limit).\n\
             # TYPE memcached_mcp_memory_budget_bytes gauge\n\
             memcached_mcp_memory_budget_bytes {budget_bytes}\n\
             # HELP memcached_mcp_memory_budget_available_bytes Bytes still available to reserve.\n\
             # TYPE memcached_mcp_memory_budget_available_bytes gauge\n\
             memcached_mcp_memory_budget_available_bytes {budget_available}\n\
             # HELP memcached_mcp_metrics_cache_age_seconds Age of the served cached body.\n\
             # TYPE memcached_mcp_metrics_cache_age_seconds gauge\n\
             memcached_mcp_metrics_cache_age_seconds {}\n\
             # HELP memcached_mcp_metrics_last_refresh_timestamp_seconds Unix time of the last successful refresh.\n\
             # TYPE memcached_mcp_metrics_last_refresh_timestamp_seconds gauge\n\
             memcached_mcp_metrics_last_refresh_timestamp_seconds {refreshed_unix}\n",
            age.as_secs_f64()
        );
    }
}

/// `/metrics` is authenticated and permission-checked by the layers around this handler. A
/// process-wide request permit bounds waiters; one successful body is reused for its TTL and
/// concurrent requests share a single refresh. Failed refreshes return 503, never a healthy
/// substitute.
async fn metrics(
    State(engine): State<Arc<MetricsEngine>>,
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
    let permit = match engine.request_limit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            engine.rejected.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(RETRY_AFTER, "1")],
                "too many concurrent metrics scrapes
",
            )
                .into_response();
        }
    };
    let body = match engine.body().await {
        Ok(body) => body,
        Err(e) => {
            let _held = permit;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(RETRY_AFTER, "5")],
                format!("metrics unavailable: {e}\n"),
            )
                .into_response();
        }
    };
    let _held = permit;
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

/// RFC 6750 auth-scheme matching is case-insensitive and allows one or more OWS characters. The
/// token itself must be one non-empty field; anything after it is rejected rather than silently
/// truncated.
fn bearer_token(header: Option<&str>) -> Option<&str> {
    let mut parts = header?.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(token)
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

/// Sessions are counted from rmcp's live map plus reservations for initializes that are still in
/// flight. The reservation is what makes check-and-create one step: without it, many concurrent
/// initializes all see the same count and open more sessions than the cap allows.
#[derive(Default)]
struct CapState {
    /// Sessions reserved by initialize requests that have not answered yet.
    reserved: usize,
    users: HashMap<Arc<str>, UserSessions>,
    /// Users whose tokens were removed or expired. New sessions are refused and a session id
    /// that arrives late is closed instead of being adopted.
    revoked: HashSet<Arc<str>>,
}

#[derive(Default)]
struct UserSessions {
    reserved: usize,
    ids: Vec<String>,
}

#[derive(Clone)]
struct SessionCap {
    sessions: Arc<LocalSessionManager>,
    max: usize,
    max_per_user: usize,
    state: Arc<AsyncMutex<CapState>>,
}

impl SessionCap {
    /// Drops open sessions for `names`. `block` replaces the set of users whose late-arriving
    /// session ids must be closed instead of adopted. Returns (closed, failed) session counts.
    async fn release_users(
        &self,
        names: &HashSet<String>,
        block: Option<HashSet<String>>,
    ) -> (usize, usize) {
        let mut ids = Vec::new();
        {
            let mut state = self.state.lock().await;
            if let Some(blocked) = block {
                state.revoked = blocked
                    .iter()
                    .map(|name| Arc::<str>::from(name.as_str()))
                    .collect();
            }
            for name in names {
                if let Some(entry) = state.users.remove(name.as_str()) {
                    ids.extend(entry.ids);
                }
            }
        }
        let (mut closed, mut failed) = (0, 0);
        for id in ids {
            let session_id: Arc<str> = Arc::from(id.as_str());
            match self.sessions.close_session(&session_id).await {
                Ok(()) => closed += 1,
                Err(_) => failed += 1,
            }
        }
        (closed, failed)
    }
}

/// Releases a reservation if the request is dropped before it can record its session id.
struct SessionReservation {
    state: Arc<AsyncMutex<CapState>>,
    user: Option<Arc<str>>,
    active: bool,
}

impl SessionReservation {
    async fn finish(mut self, id: Option<String>) -> Option<String> {
        let mut state = self.state.lock().await;
        // No await after this point: cancellation cannot interleave with the decrement.
        state.reserved = state.reserved.saturating_sub(1);
        let close = match (&self.user, id) {
            (Some(user), Some(id)) => {
                let revoked = state.revoked.contains(user.as_ref());
                match state.users.get_mut(user) {
                    Some(entry) => {
                        entry.reserved = entry.reserved.saturating_sub(1);
                        if revoked {
                            Some(id)
                        } else {
                            entry.ids.push(id);
                            None
                        }
                    }
                    // The account was released while the request was in flight.
                    None => Some(id),
                }
            }
            (Some(user), None) => {
                if let Some(entry) = state.users.get_mut(user) {
                    entry.reserved = entry.reserved.saturating_sub(1);
                }
                None
            }
            (None, id) => id,
        };
        state
            .users
            .retain(|_, entry| entry.reserved > 0 || !entry.ids.is_empty());
        self.active = false;
        close
    }
}

impl Drop for SessionReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // A panicked or cancelled request must not leak a slot. Drop is synchronous, so hand
        // the decrement back to the runtime.
        let state = self.state.clone();
        let user = self.user.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut state = state.lock().await;
                state.reserved = state.reserved.saturating_sub(1);
                if let Some(user) = &user {
                    if let Some(entry) = state.users.get_mut(user) {
                        entry.reserved = entry.reserved.saturating_sub(1);
                    }
                }
                state
                    .users
                    .retain(|_, entry| entry.reserved > 0 || !entry.ids.is_empty());
            });
        }
    }
}

/// A POST to /mcp without `Mcp-Session-Id` opens a session; refuse it when the cap is reached,
/// either overall or for this user. Sessions leave the map when they are closed or idle out, so
/// the live count falls on its own. A reservation is taken under one lock before the session is
/// created, so concurrent initializes cannot all pass the same check.
async fn cap_sessions(State(cap): State<SessionCap>, req: Request, next: Next) -> Response {
    let opens_session =
        req.method() == Method::POST && !req.headers().contains_key("mcp-session-id");
    if !opens_session {
        return next.run(req).await;
    }
    let user = req.extensions().get::<Identity>().map(|i| i.name.clone());
    let refuse = |why: &'static str| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "30")],
            format!(
                "{why}
"
            ),
        )
            .into_response()
    };

    let reservation = {
        let mut state = cap.state.lock().await;
        let live = cap.sessions.sessions.read().await;
        // Ids of sessions that have closed are dropped lazily.
        for entry in state.users.values_mut() {
            entry.ids.retain(|id| live.contains_key(id.as_str()));
        }
        state
            .users
            .retain(|_, entry| entry.reserved > 0 || !entry.ids.is_empty());
        // `live` already contains sessions whose initialize has created them but whose
        // reservation has not been turned into an id yet; counting both is conservative, never
        // permissive.
        if live.len().saturating_add(state.reserved) >= cap.max {
            return refuse("too many open sessions");
        }
        if let Some(user) = &user {
            if state.revoked.contains(user.as_ref()) {
                return refuse("session owner revoked");
            }
            let entry = state.users.entry(user.clone()).or_default();
            if entry.ids.len().saturating_add(entry.reserved) >= cap.max_per_user {
                return refuse("too many open sessions for this user");
            }
            entry.reserved += 1;
        }
        state.reserved += 1;
        SessionReservation {
            state: cap.state.clone(),
            user: user.clone(),
            active: true,
        }
    };
    let resp = next.run(req).await;
    let id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|id| id.to_str().ok())
        .map(str::to_owned);
    let close = reservation.finish(id).await;
    if let Some(id) = close {
        // A session created for a revoked account (or after its owner was released) is never
        // adopted; close it so it cannot hold a slot or be used with another token.
        let session_id: Arc<str> = Arc::from(id.as_str());
        let _ = cap.sessions.close_session(&session_id).await;
    }
    resp
}

#[derive(Clone)]
struct Auth {
    tokens: Arc<RwLock<Arc<TokenStore>>>,
    audit: Arc<Audit>,
    /// Bad-token attempts come from anyone who can reach the port, so their audit lines are capped.
    denials: Arc<Throttle>,
    concurrency: Arc<ConcurrencyLimit>,
}

impl Auth {
    fn current_tokens(&self) -> Arc<TokenStore> {
        // A poisoned lock still holds a complete store: writers only swap the Arc.
        self.tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// How often the token file is checked for changes.
const TOKEN_RELOAD_EVERY: Duration = Duration::from_secs(5);

/// Re-reads the token file when its contents change. A file that does not parse (or cannot be
/// read) is reported once and the previous tokens stay in force, so a bad edit never locks
/// everyone out. Removing or rotating a user closes that user's sessions; an expired token's
/// sessions are closed on the same five-second tick.
async fn reload_tokens(
    file: String,
    store: Arc<RwLock<Arc<TokenStore>>>,
    audit: Arc<Audit>,
    cap: SessionCap,
) {
    let mut seen = std::fs::read_to_string(&file).ok();
    let mut reported_bad = false;
    loop {
        tokio::time::sleep(TOKEN_RELOAD_EVERY).await;
        let Ok(json) = std::fs::read_to_string(&file) else {
            if !reported_bad {
                audit.record(
                    "-",
                    "http",
                    "-",
                    None,
                    "token file unreadable; keeping the previous tokens",
                );
                reported_bad = true;
            }
            // Whatever comes back is re-checked, even if it equals what was loaded before.
            seen = None;
            continue;
        };
        if seen.as_deref() == Some(json.as_str()) {
            // Expiry is time-based; it changes without the file changing.
            let expired: HashSet<String> = {
                let current = store.read().unwrap_or_else(|e| e.into_inner()).clone();
                current.expired().into_iter().map(str::to_owned).collect()
            };
            if !expired.is_empty() {
                let (closed, failed) = cap.release_users(&expired, None).await;
                if closed + failed > 0 {
                    audit.record(
                        "-",
                        "http",
                        "-",
                        None,
                        &format!("expired token sessions: closed={closed} failed={failed}"),
                    );
                }
            }
            continue;
        }
        match TokenStore::reload_from_json(&json) {
            Ok(new) => {
                let new = Arc::new(new);
                let old = store.read().unwrap_or_else(|e| e.into_inner()).clone();
                let old_accounts = old.account_hashes();
                let new_accounts = new.account_hashes();
                let removed: HashSet<String> = old_accounts
                    .keys()
                    .filter(|name| !new_accounts.contains_key(*name))
                    .cloned()
                    .collect();
                // A new token for the same user must not keep sessions opened with the old one.
                let rotated: HashSet<String> = old_accounts
                    .iter()
                    .filter_map(|(name, hash)| {
                        new_accounts
                            .get(name)
                            .filter(|new_hash| *new_hash != hash)
                            .map(|_| name.clone())
                    })
                    .collect();
                let expired: HashSet<String> =
                    new.expired().into_iter().map(str::to_owned).collect();
                let blocked: HashSet<String> = removed.union(&expired).cloned().collect();
                let to_close: HashSet<String> = blocked.union(&rotated).cloned().collect();
                let n = new.len();
                *store.write().unwrap_or_else(|e| e.into_inner()) = new;
                let (closed, failed) = cap.release_users(&to_close, Some(blocked)).await;
                audit.record(
                    "-",
                    "http",
                    "-",
                    None,
                    &format!(
                        "token file reloaded: {n} user(s); sessions closed={closed} failed={failed}"
                    ),
                );
                reported_bad = false;
            }
            Err(e) => {
                if !reported_bad || seen.as_deref() != Some(json.as_str()) {
                    audit.record(
                        "-",
                        "http",
                        "-",
                        None,
                        &format!(
                            "token file changed but is invalid ({e}); keeping the previous tokens"
                        ),
                    );
                }
                reported_bad = true;
            }
        }
        seen = Some(json);
    }
}

/// Audit lines for failed authentication per second, before the rest are only counted.
const MAX_DENIAL_LOGS_PER_SEC: u32 = 20;

/// POSTs carry tool calls; a `/metrics` GET also does bounded work. A `GET /mcp` is a long-lived
/// SSE stream, and the session cap bounds how many of those a user can hold.
fn needs_concurrency_permit(method: &Method, path: &str) -> bool {
    *method == Method::POST || (*method == Method::GET && path == "/metrics")
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
    if let Some(identity) = bearer_token(header).and_then(|t| auth.current_tokens().lookup(t)) {
        // POSTs carry tool calls and `/metrics` performs a scrape; both count against the
        // per-user in-flight limit. A `GET /mcp` is a long-lived SSE stream and is bounded by
        // the session cap instead.
        let permit = if needs_concurrency_permit(req.method(), req.uri().path()) {
            match auth.concurrency.try_acquire(&identity.name) {
                Some(p) => Some(p),
                None => {
                    auth.audit.record(
                        &identity.name,
                        "http",
                        &peer.to_string(),
                        None,
                        "denied: too many concurrent requests",
                    );
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(RETRY_AFTER, "1")],
                        "too many concurrent requests
",
                    )
                        .into_response();
                }
            }
        } else {
            None
        };
        req.extensions_mut().insert(identity);
        let resp = next.run(req).await;
        // The reply is an event stream whose body is produced while the tool runs, so the
        // permit has to live as long as the body, not just until the headers are ready.
        return match permit {
            Some(permit) => {
                let (parts, body) = resp.into_parts();
                let body = body.map_frame(move |frame| {
                    let _held = &permit;
                    frame
                });
                Response::from_parts(parts, axum::body::Body::new(body))
            }
            None => resp,
        };
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
        max_per_user: cfg.max_sessions_per_user,
        state: Arc::new(AsyncMutex::new(CapState::default())),
    };
    let auth = Auth {
        tokens: Arc::new(RwLock::new(Arc::new(cfg.tokens))),
        audit: audit.clone(),
        denials: Arc::new(Throttle::new(MAX_DENIAL_LOGS_PER_SEC)),
        concurrency: Arc::new(ConcurrencyLimit::new(cfg.max_concurrent)),
    };
    if let Some(file) = cfg.token_file {
        tokio::spawn(reload_tokens(
            file,
            auth.tokens.clone(),
            auth.audit.clone(),
            cap.clone(),
        ));
    }
    let mut app = Router::new().nest_service(
        "/mcp",
        Router::new()
            .fallback_service(mcp)
            .layer(middleware::from_fn_with_state(cap, cap_sessions))
            .layer(middleware::from_fn_with_state(
                cfg.body_timeout,
                bound_post_body,
            )),
    );
    if !cfg.metrics.memcached.is_empty() || !cfg.metrics.mcrouter.is_empty() {
        let engine = MetricsEngine::new(
            cfg.metrics.clone(),
            cfg.metrics_max_concurrent,
            cfg.metrics_fanout,
            cfg.metrics_deadline,
            cfg.metrics_cache_ttl,
            audit,
        );
        let metrics_routes = Router::new()
            .route("/metrics", get(metrics))
            .with_state(Arc::new(engine));
        app = app.merge(metrics_routes);
    }
    // Layers added last run first and cover every route, /metrics included: host check, then token.
    let app = app
        .layer(middleware::from_fn_with_state(auth, require_token))
        .layer(middleware::from_fn_with_state(
            known_hosts,
            require_known_host,
        ));

    // Added after the layers, so it needs neither a token nor a known Host header: kubelet probes
    // use the pod IP. It reveals nothing but that the process is serving.
    let app = app.route(
        "/healthz",
        get(|| async {
            "ok
"
        }),
    );

    // Small SSE replies go out as header and body writes; with Nagle on, a client that delays
    // its ACKs makes each of them wait ~40 ms. Measured with the lab benchmark.
    let tcp = tokio::net::TcpListener::bind(cfg.bind).await?;
    eprintln!("listening on http://{}/mcp", tcp.local_addr()?);
    let listener = tcp.tap_io(|tcp| {
        let _ = tcp.set_nodelay(true);
    });
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        shutdown_signal().await;
        eprintln!("shutdown: signal received, draining");
    });
    // Long-lived streams (SSE) never finish on their own, so draining is bounded.
    let mut serve = std::pin::pin!(serve.into_future());
    tokio::select! {
        r = &mut serve => r,
        () = async {
            shutdown_signal().await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            eprintln!("shutdown: open connections did not finish within {SHUTDOWN_GRACE:?}; exiting");
            Ok(())
        }
    }
}

/// How long in-flight requests get to finish after SIGTERM/SIGINT.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Resolves on SIGINT, or on SIGTERM where that exists. As PID 1 in a container the process gets
/// no default signal action, so without this `docker stop` and rollouts end in SIGKILL.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrency_is_limited_per_user() {
        let limit = ConcurrencyLimit::new(2);
        let (a, b): (Arc<str>, Arc<str>) = ("a".into(), "b".into());
        let p1 = limit.try_acquire(&a).expect("first");
        let _p2 = limit.try_acquire(&a).expect("second");
        assert!(limit.try_acquire(&a).is_none(), "third must be refused");
        assert!(
            limit.try_acquire(&b).is_some(),
            "other users are unaffected"
        );
        drop(p1);
        assert!(limit.try_acquire(&a).is_some(), "a freed slot is reusable");
    }

    #[test]
    fn concurrency_permit_covers_posts_and_metrics_get() {
        assert!(needs_concurrency_permit(&Method::POST, "/mcp"));
        assert!(needs_concurrency_permit(&Method::GET, "/metrics"));
        assert!(
            !needs_concurrency_permit(&Method::GET, "/mcp"),
            "a long-lived SSE stream is bounded by the session cap, not by request permits"
        );
        assert!(!needs_concurrency_permit(&Method::GET, "/healthz"));
    }

    #[tokio::test]
    async fn a_dropped_session_reservation_returns_its_slot() {
        let cap = SessionCap {
            sessions: Arc::new(LocalSessionManager::default()),
            max: 1,
            max_per_user: 1,
            state: Arc::new(AsyncMutex::new(CapState::default())),
        };
        {
            let mut state = cap.state.lock().await;
            state.reserved = 1;
            state.users.entry("u".into()).or_default().reserved = 1;
        }
        drop(SessionReservation {
            state: cap.state.clone(),
            user: Some("u".into()),
            active: true,
        });
        let started = tokio::time::Instant::now();
        loop {
            {
                let state = cap.state.lock().await;
                if state.reserved == 0 {
                    assert!(state.users.is_empty());
                    break;
                }
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "a dropped reservation leaked its slot"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

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
        for header in [
            "Bearer s3cret",
            "bearer s3cret",
            "BEARER s3cret",
            "Bearer  s3cret",
            "Bearer\ts3cret",
            "  Bearer s3cret  ",
        ] {
            assert_eq!(bearer_token(Some(header)), Some("s3cret"), "{header:?}");
        }
        for header in [
            "Basic s3cret",
            "Bearer",
            "Bearer ",
            "Bearer s3cret extra",
            "s3cret",
            "",
        ] {
            assert_eq!(bearer_token(Some(header)), None, "{header:?}");
        }
        assert_eq!(bearer_token(None), None);
    }
}
