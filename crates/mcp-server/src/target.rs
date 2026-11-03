//! Where the server may connect to.
//!
//! The allowlist (exact `host:port` strings) decides which targets are managed. Two things are
//! checked on top of it, because a hostname is resolved at connect time:
//!
//! * A name that resolves to a link-local, unspecified or multicast address is refused. That
//!   covers cloud metadata endpoints (169.254.169.254, fd00:ec2::254) and a DNS-rebinding record
//!   that points an allowlisted name at one. Loopback and private ranges stay allowed: managing
//!   private memcached networks is the point of this server.
//! * The connection goes to the address that was checked, not to a second lookup of the name.
//!
//! `MEMCACHED_MCP_ALLOW_LINK_LOCAL=1` lifts the address check for the rare setup that really
//! runs memcached on a link-local address.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use memcached_core::Client;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Process-wide cap for tool/upstream connections. `/metrics` uses its own bounded fan-out and
/// does not consume this budget, so a slow metric scrape cannot starve tool calls.
pub const DEFAULT_MAX_UPSTREAM_CONNECTIONS: usize = 64;

/// A resolver can return many A/AAAA records; trying all of them would multiply connection
/// latency. This cap still covers the common dual-stack case and bounds a hostile DNS answer.
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_HOSTNAME_BYTES: usize = 253;
/// The resolver runs on Tokio's blocking pool. A bounded number of outstanding lookups prevents
/// a slow/hostile resolver from consuming every blocking thread.
const MAX_CONCURRENT_DNS_LOOKUPS: usize = 16;
/// A small floor stops one black-holed IPv6 record from starving every later address when many
/// records were returned.
const MIN_CONNECT_ATTEMPT: Duration = Duration::from_millis(250);

static UPSTREAM_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static DNS_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Configures the process-wide tool connection budget. Called once at startup.
pub fn configure_upstream_limit(max: usize) -> Result<(), String> {
    if max == 0 {
        return Err("upstream connection limit must be positive".to_owned());
    }
    UPSTREAM_LIMIT
        .set(Arc::new(Semaphore::new(max)))
        .map_err(|_| "upstream connection limit was already configured".to_owned())
}

fn acquire_upstream() -> Result<Option<OwnedSemaphorePermit>, String> {
    let Some(sem) = UPSTREAM_LIMIT.get() else {
        return Ok(None);
    };
    sem.clone()
        .try_acquire_owned()
        .map(Some)
        .map_err(|_| "upstream connection limit reached; retry later".to_owned())
}

/// Link-local, unspecified and multicast addresses are not memcached servers.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_multicast(),
        IpAddr::V6(v6) => {
            // fe80::/10 and fd00:ec2::254 (AWS metadata over IPv6); IPv4-mapped forms are
            // judged by the IPv4 rules.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked(IpAddr::V4(v4));
            }
            v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

fn allow_link_local() -> bool {
    std::env::var("MEMCACHED_MCP_ALLOW_LINK_LOCAL").as_deref() == Ok("1")
}

/// Checks an allowlist entry at startup. An entry that is not a strict `host:port` can never
/// match a target, so it is an error rather than a silent no-op. IPv6 literals must be bracketed;
/// URLs, paths, userinfo, whitespace and malformed DNS labels are refused.
pub fn validate_allowlist_entry(entry: &str) -> Result<(), String> {
    let bad = |why: &str| format!("MEMCACHED_MCP_ALLOWLIST entry '{entry}': {why}");
    let (raw_host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| bad("expected host:port"))?;
    if raw_host.is_empty() {
        return Err(bad("empty host; expected host:port"));
    }
    if raw_host.contains("://") {
        return Err(bad("expected host:port, not a URL"));
    }
    let host = if let Some(rest) = raw_host.strip_prefix('[') {
        let inner = rest
            .strip_suffix(']')
            .ok_or_else(|| bad("IPv6 address must be fully bracketed"))?;
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(bad("invalid bracketed IPv6 address"));
        }
        inner
    } else {
        if raw_host.contains(':') {
            return Err(bad("IPv6 addresses must be bracketed, e.g. [::1]:11211"));
        }
        if raw_host.contains(['[', ']']) {
            return Err(bad("unmatched brackets in host"));
        }
        if !raw_host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(bad(
                "host contains invalid characters; expected host:port without scheme, path or userinfo",
            ));
        }
        raw_host
    };
    if host.len() > MAX_HOSTNAME_BYTES {
        return Err(bad("host is longer than 253 bytes"));
    }
    if host.trim_matches('.').split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    }) {
        return Err(bad("invalid DNS label in host"));
    }
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("port must be 1-65535"));
    }
    let _port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| bad("port must be 1-65535"))?;
    if !allow_link_local() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_blocked(ip) {
                return Err(bad(
                    "link-local, unspecified and multicast addresses are refused (set MEMCACHED_MCP_ALLOW_LINK_LOCAL=1 to allow)",
                ));
            }
        }
    }
    Ok(())
}

/// Resolves `addr` and returns every usable address, preserving resolver order. Blocked
/// addresses are dropped; the caller connects only to these checked addresses. A resolver that
/// never answers must not hold the call forever, so the lookup has its own deadline.
pub async fn resolve_all(addr: &str, deadline: Duration) -> Result<Vec<SocketAddr>, String> {
    let started = Instant::now();
    let dns = DNS_LIMIT.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_LOOKUPS)));
    let _permit = tokio::time::timeout(deadline, dns.clone().acquire_owned())
        .await
        .map_err(|_| format!("resolving {addr} timed out waiting for a DNS slot"))?
        .map_err(|_| "DNS lookup limiter was closed".to_owned())?;
    let remaining = deadline.saturating_sub(started.elapsed());
    let all: Vec<SocketAddr> = tokio::time::timeout(remaining, tokio::net::lookup_host(addr))
        .await
        .map_err(|_| format!("resolving {addr} timed out"))?
        .map_err(|e| format!("cannot resolve {addr}: {e}"))?
        .collect();
    if all.is_empty() {
        return Err(format!("{addr} resolved to no address"));
    }

    // Keep resolver order within each family, but make sure a large IPv6 (or IPv4) answer cannot
    // fill the cap before the other family is considered.
    let skip = allow_link_local();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut seen = Vec::new();
    for sa in all {
        if (!skip && is_blocked(sa.ip())) || seen.contains(&sa) {
            continue;
        }
        seen.push(sa);
        match sa {
            SocketAddr::V4(_) => v4.push(sa),
            SocketAddr::V6(_) => v6.push(sa),
        }
        if v4.len() + v6.len() >= MAX_RESOLVED_ADDRESSES * 4 {
            break;
        }
    }
    let mut usable = Vec::with_capacity(MAX_RESOLVED_ADDRESSES);
    let mut i4 = 0;
    let mut i6 = 0;
    while usable.len() < MAX_RESOLVED_ADDRESSES && (i4 < v4.len() || i6 < v6.len()) {
        if let Some(sa) = v4.get(i4) {
            usable.push(*sa);
            i4 += 1;
            if usable.len() == MAX_RESOLVED_ADDRESSES {
                break;
            }
        }
        if let Some(sa) = v6.get(i6) {
            usable.push(*sa);
            i6 += 1;
        }
    }
    if usable.is_empty() {
        return Err(format!(
            "{addr} resolves only to link-local, unspecified or multicast addresses; refused"
        ));
    }
    Ok(usable)
}

/// Tries each checked address, spending at most `op_timeout` overall. The remaining budget is
/// divided across the untried addresses so one black-holed IPv6 record cannot consume the whole
/// fallback window. Connection errors and per-attempt timeouts move on to the next address.
async fn connect_any(addrs: &[SocketAddr], op_timeout: Duration) -> Result<Client, String> {
    if addrs.is_empty() {
        return Err("no resolved address to connect to".to_owned());
    }
    let started = Instant::now();
    let mut last_error = format!("{} address(es) tried", addrs.len());
    for (index, sa) in addrs.iter().enumerate() {
        let remaining = op_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            last_error = format!("connecting to {sa} ran out of the {op_timeout:?} budget");
            break;
        }
        let left = (addrs.len() - index).max(1) as u32;
        let attempt = (remaining / left).max(MIN_CONNECT_ATTEMPT).min(remaining);
        match tokio::time::timeout(attempt, Client::connect(&sa.to_string(), op_timeout)).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) => last_error = format!("{sa}: {e}"),
            Err(_) => last_error = format!("{sa}: connect timed out"),
        }
    }
    Err(format!(
        "cannot connect to {} address(es) within {op_timeout:?}: {last_error}",
        addrs.len()
    ))
}

/// The only way the server opens a tool connection to a target. It consumes the process-wide
/// upstream budget; if that budget is exhausted, the call fails closed instead of spawning more
/// work.
pub async fn open(addr: &str, op_timeout: Duration) -> Result<Client, String> {
    let permit = acquire_upstream()?;
    let started = Instant::now();
    // DNS + all connection attempts share one bounded budget. Previously each phase could spend
    // the full op_timeout, so one call could hold an upstream permit for twice as long.
    let total = op_timeout.saturating_mul(2);
    let addrs = resolve_all(addr, op_timeout.min(total)).await?;
    let remaining = total.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(format!("opening {addr} exceeded the {total:?} deadline"));
    }
    let mut client = connect_any(&addrs, remaining).await?;
    if let Some(permit) = permit {
        client.attach_permit(permit);
    }
    Ok(client)
}

/// A connection used by the `/metrics` engine. Its fan-out and total deadline are bounded by the
/// metrics engine, so it does not share the tool budget.
pub async fn open_metrics(addr: &str, op_timeout: Duration) -> Result<Client, String> {
    let started = Instant::now();
    let total = op_timeout.saturating_mul(2);
    let addrs = resolve_all(addr, op_timeout.min(total)).await?;
    let remaining = total.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(format!("opening {addr} exceeded the {total:?} deadline"));
    }
    connect_any(&addrs, remaining).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_metadata_and_link_local_but_not_private_or_loopback() {
        for blocked in [
            "169.254.169.254",
            "169.254.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
            "::",
            "ff02::1",
        ] {
            assert!(is_blocked(blocked.parse().unwrap()), "{blocked}");
        }
        for ok in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "100.64.0.1",
            "::1",
            "fd12:3456::1",
            "8.8.8.8",
        ] {
            assert!(!is_blocked(ok.parse().unwrap()), "{ok}");
        }
    }

    #[test]
    fn allowlist_entries_are_validated() {
        for ok in [
            "127.0.0.1:11211",
            "cache-0.cache.svc:11211",
            "cache_0:11211",
            "[::1]:11211",
            "mcrouter:5000",
            "cache.example.com.:11211",
        ] {
            assert!(validate_allowlist_entry(ok).is_ok(), "{ok}");
        }
        for bad in [
            "memcached",
            ":11211",
            "host:0",
            "host:99999",
            "host:abc",
            "host:+11211",
            "host:11211:extra",
            "bad host:11211",
            "http://cache:11211",
            "cache/path:11211",
            "cache?x:11211",
            "cache#x:11211",
            "user@cache:11211",
            "::1:11211",
            "[cache]:11211",
            "[::1]11211",
            "-cache:11211",
            "cache-:11211",
            "a..b:11211",
            "169.254.169.254:80",
            "[fe80::1]:11211",
        ] {
            assert!(validate_allowlist_entry(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn resolve_refuses_a_blocked_literal() {
        let d = Duration::from_secs(2);
        assert!(resolve_all("169.254.169.254:80", d).await.is_err());
        assert!(resolve_all("127.0.0.1:80", d).await.is_ok());
        assert_eq!(resolve_all("127.0.0.1:80", d).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resolve_all_bounds_concurrent_lookups() {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..32 {
            set.spawn(async { resolve_all("127.0.0.1:1", Duration::from_secs(2)).await });
        }
        while let Some(result) = set.join_next().await {
            let addrs = result.unwrap().expect("loopback lookup");
            assert!(!addrs.is_empty());
        }
    }

    #[tokio::test]
    async fn open_has_one_bounded_deadline() {
        let started = Instant::now();
        let _ = open("203.0.113.1:11211", Duration::from_millis(50)).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "open exceeded its combined DNS/connect budget: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn connect_falls_back_from_an_unreachable_first_address() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let addresses = [
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ];
        let client = connect_any(&addresses, Duration::from_secs(2))
            .await
            .expect("IPv4 fallback should succeed");
        drop(client);
        accepted.await.unwrap();
    }
}
