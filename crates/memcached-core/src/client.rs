use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use memcached_protocol::text::{
    self, DumpEntry, DumpLine, MetaGet, ProtocolError, Status, StoreCmd,
};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

use crate::memory::{MemoryBudget, MemoryReservation};

/// Longest single response line accepted (metadump lines are about 1 KiB at most).
pub const MAX_LINE_BYTES: u64 = 16 * 1024;
/// Largest value read back; memcached's default item limit is 1 MiB, mcrouter's config is smaller.
pub const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
/// Total bytes one `stats` reply may contain (all lines, not just the line count).
pub const MAX_STATS_BYTES: u64 = 8 * 1024 * 1024;
/// Total bytes one non-uniform metadump read may contain before it fails closed.
pub const MAX_METADUMP_BYTES: u64 = 16 * 1024 * 1024;
/// Total bytes a uniform metadump scan may read before it reports an incomplete sample.
pub const MAX_METADUMP_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// Total bytes one get/response may contain: the largest value plus its trailing CRLF.
pub const MAX_GET_BYTES: usize = MAX_VALUE_BYTES + 2;
/// More `STAT` lines than any real server sends.
pub const MAX_STAT_LINES: usize = 100_000;
/// Uniform sampling never keeps more than this many entries, even if a caller asks for more.
pub const MAX_UNIFORM_KEEP: usize = 100_000;
/// A single command may spend at most this long on the wire, regardless of how slowly the server
/// drips its reply. Per-read timeouts still apply; this bounds the whole operation.
pub const DEFAULT_OPERATION_DEADLINE: Duration = Duration::from_secs(60);
/// Approximate per-entry bookkeeping charged on top of the raw key/value bytes: two `String`
/// headers, one shared BTreeMap node and allocator slack. Deliberately conservative.
const STATS_ENTRY_OVERHEAD: usize = 192;
/// Map reservations grow in this step, so a normal reply holds one guard rather than one per line.
const STATS_RESERVE_CHUNK: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("operation deadline exceeded")]
    Deadline,
    #[error("connection closed by server")]
    Closed,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("memory: {0}")]
    Memory(String),
}

/// What the server was observed to support; probed, not inferred from version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub version: String,
    pub meta: bool,
}

/// What `mg` reports about a stored item, without its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyInfo {
    pub size: u64,
    pub client_flags: u32,
    /// None when the item never expires.
    pub ttl_seconds: Option<i64>,
    pub seconds_since_access: Option<u64>,
    /// Whether the item has been fetched since it was stored.
    pub hit_before: bool,
    /// Whether memcached marked the item stale (meta `X` response flag).
    pub stale: bool,
    pub cas: Option<u64>,
}

/// Result of [`Client::dump_keys`].
#[derive(Debug, Clone)]
pub struct KeySample {
    pub entries: Vec<DumpEntry>,
    /// True only if the server's `END` was seen. Reaching the entry limit counts as incomplete,
    /// even when that was also the last item.
    pub complete: bool,
}

/// Result of [`Client::sample_keys_uniform`].
#[derive(Debug, Clone)]
pub struct UniformSample {
    /// At most the requested number of entries, each item equally likely to be among them.
    pub entries: Vec<DumpEntry>,
    /// How many items the server listed before the scan ended.
    pub seen: u64,
    /// True only if the server's `END` was seen, so `seen` is the whole cache and the sample is
    /// unbiased. A capped or timed-out scan is a sample of the crawler's prefix only.
    pub complete: bool,
}

/// splitmix64: small, fast and good enough to pick sample slots. Not for anything secret.
fn next_random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub struct Client {
    io: BufReader<TcpStream>,
    op_timeout: Duration,
    /// Whole-command deadline, checked between reads so a slow-dripping server cannot hold one
    /// operation open indefinitely.
    operation_deadline: Duration,
    /// Set after a failed read: the rest of the reply may still be on the wire, so the next
    /// command would read it as its own answer.
    broken: bool,
    /// Optional global upstream-connection permit; held for the connection's lifetime.
    _permit: Option<OwnedSemaphorePermit>,
    /// Process-wide memory budget (or an explicit one supplied by a test).
    budget: Option<Arc<MemoryBudget>>,
    /// Reservations for reply buffers held by this client. They are released when the client
    /// drops or when a caller transfers them with `take_memory_guards`.
    memory: Vec<MemoryReservation>,
}

impl Client {
    pub async fn connect(addr: &str, op_timeout: Duration) -> Result<Self, ClientError> {
        let stream = timeout(op_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        Ok(Self {
            io: BufReader::new(stream),
            op_timeout,
            operation_deadline: DEFAULT_OPERATION_DEADLINE,
            broken: false,
            _permit: None,
            budget: crate::memory::global(),
            memory: Vec::new(),
        })
    }

    /// Overrides the whole-command deadline (tests/embedding). Per-read timeouts are unchanged.
    pub fn with_operation_deadline(mut self, deadline: Duration) -> Self {
        self.operation_deadline = deadline;
        self
    }

    fn check_deadline(&mut self, started: Instant) -> Result<(), ClientError> {
        if started.elapsed() >= self.operation_deadline {
            self.broken = true;
            return Err(ClientError::Deadline);
        }
        Ok(())
    }

    /// Attaches a process-wide connection permit to this client. Dropping the client releases it.
    pub fn attach_permit(&mut self, permit: OwnedSemaphorePermit) {
        self._permit = Some(permit);
    }

    /// Uses an explicit memory budget instead of the process-wide one (tests/embedding).
    pub fn with_memory_budget(mut self, budget: Arc<MemoryBudget>) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Transfers the reply-buffer reservations to the caller. Use this when the data outlives
    /// the client (for example, when a node is fetched and compared later).
    pub fn take_memory_guards(&mut self) -> Vec<MemoryReservation> {
        std::mem::take(&mut self.memory)
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), ClientError> {
        if let Some(budget) = &self.budget {
            match budget.try_reserve(bytes) {
                Ok(reservation) => self.memory.push(reservation),
                Err(e) => {
                    self.broken = true;
                    return Err(ClientError::Memory(e));
                }
            }
        }
        Ok(())
    }

    fn reserve_temp(&self, bytes: usize) -> Result<Option<MemoryReservation>, String> {
        match &self.budget {
            Some(budget) => budget.try_reserve(bytes).map(Some),
            None => Ok(None),
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        if self.broken {
            return Err(ClientError::Closed);
        }
        match timeout(self.op_timeout, self.io.get_mut().write_all(bytes)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                // A partial write leaves the command stream in an unknown state.
                self.broken = true;
                Err(e.into())
            }
            Err(_) => {
                self.broken = true;
                Err(ClientError::Timeout)
            }
        }
    }

    async fn line(&mut self) -> Result<String, ClientError> {
        self.line_with_timeout(self.op_timeout).await
    }

    async fn line_with_timeout(&mut self, limit: Duration) -> Result<String, ClientError> {
        let r = self.read_line(limit).await;
        if r.is_err() {
            self.broken = true;
        }
        r
    }

    /// Reads a line without exceeding the whole-command deadline.
    async fn line_until(
        &mut self,
        started: Instant,
        deadline: Duration,
    ) -> Result<String, ClientError> {
        let limit = match self.remaining_timeout(started, deadline) {
            Ok(limit) => limit,
            Err(e) => {
                self.broken = true;
                return Err(e);
            }
        };
        self.line_with_timeout(limit).await
    }

    fn remaining_timeout(
        &self,
        started: Instant,
        deadline: Duration,
    ) -> Result<Duration, ClientError> {
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ClientError::Deadline);
        }
        Ok(self.op_timeout.min(remaining))
    }

    async fn read_line(&mut self, limit: Duration) -> Result<String, ClientError> {
        let mut buf = String::new();
        let n = timeout(
            limit,
            (&mut self.io).take(MAX_LINE_BYTES).read_line(&mut buf),
        )
        .await
        .map_err(|_| ClientError::Timeout)??;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        if !buf.ends_with('\n') {
            let reason = if n as u64 >= MAX_LINE_BYTES {
                "response line too long"
            } else {
                "response line is not newline-terminated"
            };
            return Err(ProtocolError::Malformed(reason.to_owned()).into());
        }
        Ok(buf)
    }

    pub async fn version(&mut self) -> Result<String, ClientError> {
        self.send(&text::encode_version()).await?;
        let l = self.line().await?;
        match l.trim_end().strip_prefix("VERSION ") {
            Some(v) => Ok(v.to_owned()),
            None => {
                self.broken = true;
                Err(ProtocolError::Malformed(l.trim_end().to_owned()).into())
            }
        }
    }

    pub async fn stats(
        &mut self,
        arg: Option<&str>,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        self.stats_with_limit(arg, MAX_STATS_BYTES).await
    }

    /// Like [`stats`](Self::stats), but with a total byte budget for the whole reply. A reply
    /// that exceeds it is rejected and the connection is retired; no partial map is returned.
    pub async fn stats_with_limit(
        &mut self,
        arg: Option<&str>,
        max_bytes: u64,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        let command = text::encode_stats(arg)?;
        self.stats_command(&command, max_bytes).await
    }

    /// Read the built-in proxy's documented `stats proxy` view.
    ///
    /// The command is a fixed literal, so callers cannot smuggle another statistics subcommand.
    /// The same reply limits, deadline and memory budget as `stats` apply.
    pub async fn stats_proxy(&mut self) -> Result<BTreeMap<String, String>, ClientError> {
        self.stats_command(text::encode_proxy_stats(), MAX_STATS_BYTES)
            .await
    }

    /// Read the built-in proxy's documented `stats proxyfuncs` view.
    ///
    /// The command is a fixed literal, so callers cannot smuggle another statistics subcommand.
    /// The same reply limits, deadline and memory budget as `stats` apply.
    pub async fn stats_proxyfuncs(&mut self) -> Result<BTreeMap<String, String>, ClientError> {
        self.stats_command(text::encode_proxyfuncs(), MAX_STATS_BYTES)
            .await
    }

    async fn stats_command(
        &mut self,
        command: &[u8],
        max_bytes: u64,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        self.send(command).await?;
        let started = Instant::now();
        let op_deadline = self.operation_deadline;
        let mut out = BTreeMap::new();
        let mut lines = 0usize;
        let mut bytes = 0u64;
        // One 16 KiB line buffer is live at a time. The map reservations grow in 64 KiB steps:
        // reserving per line would put up to 100k guards in `memory` for one reply.
        let _line_guard = match self.reserve_temp(MAX_LINE_BYTES as usize) {
            Ok(guard) => guard,
            Err(e) => {
                self.broken = true;
                return Err(ClientError::Memory(e));
            }
        };
        let mut map_reserved = 0usize;
        loop {
            self.check_deadline(started)?;
            let l = self.line_until(started, op_deadline).await?;
            lines += 1;
            bytes = bytes.saturating_add(l.len() as u64);
            if bytes > max_bytes {
                self.broken = true;
                return Err(ProtocolError::Malformed(format!(
                    "stats response exceeds the {max_bytes} byte limit"
                ))
                .into());
            }
            if lines > MAX_STAT_LINES {
                self.broken = true;
                return Err(ProtocolError::Malformed("too many stat lines".to_owned()).into());
            }
            match text::parse_stat_line(&l) {
                Ok(Some((k, v))) => {
                    // The map keeps its own key and value Strings plus node overhead; reserve
                    // that before inserting. Growth is rounded up so guards stay few.
                    let needed =
                        (bytes as usize).saturating_add(lines.saturating_mul(STATS_ENTRY_OVERHEAD));
                    if needed > map_reserved {
                        let target = needed
                            .checked_next_multiple_of(STATS_RESERVE_CHUNK)
                            .ok_or_else(|| {
                                ClientError::Memory("stats reservation overflow".to_owned())
                            })?;
                        self.reserve(target - map_reserved)?;
                        map_reserved = target;
                    }
                    out.insert(k.to_owned(), v.to_owned());
                }
                Ok(None) => return Ok(out),
                Err(e) => {
                    // The rest of a malformed reply may still be on the wire.
                    self.broken = true;
                    return Err(e.into());
                }
            }
        }
    }

    /// Returns `(flags, data)` for a hit.
    pub async fn get(&mut self, key: &[u8]) -> Result<Option<(u32, Vec<u8>)>, ClientError> {
        self.get_with_limit(key, MAX_GET_BYTES).await
    }

    /// Like [`get`](Self::get), but the whole reply must fit in `max_bytes`. Every value is
    /// checked before allocation, and an over-budget or malformed reply retires the connection.
    pub async fn get_with_limit(
        &mut self,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<(u32, Vec<u8>)>, ClientError> {
        self.send(&text::encode_get(&[key])?).await?;
        let started = Instant::now();
        let op_deadline = self.operation_deadline;
        let mut found = None;
        let mut total = 0usize;
        loop {
            self.check_deadline(started)?;
            let _line_guard = match self.reserve_temp(MAX_LINE_BYTES as usize) {
                Ok(guard) => guard,
                Err(e) => {
                    self.broken = true;
                    return Err(ClientError::Memory(e));
                }
            };
            let header =
                match text::parse_value_header(&self.line_until(started, op_deadline).await?) {
                    Ok(Some(header)) => header,
                    Ok(None) => break,
                    Err(e) => {
                        self.broken = true;
                        return Err(e.into());
                    }
                };
            if found.is_some() {
                self.broken = true;
                return Err(ProtocolError::Malformed(
                    "multiple VALUE blocks for a single-key get".to_owned(),
                )
                .into());
            }
            if header.key.as_bytes() != key {
                self.broken = true;
                return Err(ProtocolError::Malformed(
                    "VALUE key does not match the requested key".to_owned(),
                )
                .into());
            }
            // The length comes from the server; never let it decide how much memory we allocate.
            if header.len > MAX_VALUE_BYTES || header.len > max_bytes {
                self.broken = true;
                return Err(ProtocolError::Malformed(format!(
                    "value of {} bytes exceeds the {max_bytes} byte response limit",
                    header.len
                ))
                .into());
            }
            total = total.saturating_add(header.len + 2);
            if total > max_bytes {
                self.broken = true;
                return Err(ProtocolError::Malformed(format!(
                    "value response exceeds the {max_bytes} byte limit"
                ))
                .into());
            }
            // Reserve the value buffer before vec![] allocates it.
            self.reserve(header.len + 2)?;
            let mut data = vec![0u8; header.len + 2];
            let read_timeout = match self.remaining_timeout(started, op_deadline) {
                Ok(limit) => limit,
                Err(e) => {
                    self.broken = true;
                    return Err(e);
                }
            };
            match timeout(read_timeout, self.io.read_exact(&mut data)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    self.broken = true;
                    return Err(e.into());
                }
                Err(_) => {
                    self.broken = true;
                    return Err(if started.elapsed() >= op_deadline {
                        ClientError::Deadline
                    } else {
                        ClientError::Timeout
                    });
                }
            }
            data.truncate(header.len);
            found = Some((header.flags, data));
        }
        Ok(found)
    }

    /// Reads a value only to learn its flags and length; the bytes are discarded in fixed-size
    /// chunks. This is used by metadata lookups on servers without meta commands, so a large
    /// value does not have to be allocated.
    pub async fn get_metadata(&mut self, key: &[u8]) -> Result<Option<(u32, usize)>, ClientError> {
        self.get_metadata_with_limit(key, MAX_GET_BYTES).await
    }

    /// Like [`get_metadata`](Self::get_metadata) with a total response byte budget.
    pub async fn get_metadata_with_limit(
        &mut self,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<(u32, usize)>, ClientError> {
        self.send(&text::encode_get(&[key])?).await?;
        let started = Instant::now();
        let op_deadline = self.operation_deadline;
        let _line_guard = match self.reserve_temp(MAX_LINE_BYTES as usize) {
            Ok(guard) => guard,
            Err(e) => {
                self.broken = true;
                return Err(ClientError::Memory(e));
            }
        };
        let mut found = None;
        let mut total = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            self.check_deadline(started)?;
            let header =
                match text::parse_value_header(&self.line_until(started, op_deadline).await?) {
                    Ok(Some(header)) => header,
                    Ok(None) => break,
                    Err(e) => {
                        self.broken = true;
                        return Err(e.into());
                    }
                };
            if found.is_some() {
                self.broken = true;
                return Err(ProtocolError::Malformed(
                    "multiple VALUE blocks for a single-key get".to_owned(),
                )
                .into());
            }
            if header.key.as_bytes() != key {
                self.broken = true;
                return Err(ProtocolError::Malformed(
                    "VALUE key does not match the requested key".to_owned(),
                )
                .into());
            }
            if header.len > MAX_VALUE_BYTES || header.len > max_bytes {
                self.broken = true;
                return Err(ProtocolError::Malformed(format!(
                    "value of {} bytes exceeds the {max_bytes} byte response limit",
                    header.len
                ))
                .into());
            }
            total = total.saturating_add(header.len + 2);
            if total > max_bytes {
                self.broken = true;
                return Err(ProtocolError::Malformed(format!(
                    "value response exceeds the {max_bytes} byte limit"
                ))
                .into());
            }
            let mut remaining = header.len + 2;
            while remaining > 0 {
                self.check_deadline(started)?;
                let n = remaining.min(chunk.len());
                let read_timeout = match self.remaining_timeout(started, op_deadline) {
                    Ok(limit) => limit,
                    Err(e) => {
                        self.broken = true;
                        return Err(e);
                    }
                };
                match timeout(read_timeout, self.io.read_exact(&mut chunk[..n])).await {
                    Ok(Ok(_)) => remaining -= n,
                    Ok(Err(e)) => {
                        self.broken = true;
                        return Err(e.into());
                    }
                    Err(_) => {
                        self.broken = true;
                        return Err(if started.elapsed() >= op_deadline {
                            ClientError::Deadline
                        } else {
                            ClientError::Timeout
                        });
                    }
                }
            }
            found = Some((header.flags, header.len));
        }
        Ok(found)
    }

    pub async fn store(
        &mut self,
        cmd: StoreCmd,
        key: &[u8],
        flags: u32,
        exptime: i64,
        data: &[u8],
    ) -> Result<Status, ClientError> {
        self.send(&text::encode_store(cmd, key, flags, exptime, data)?)
            .await?;
        let line = self.line().await?;
        match text::parse_status_line(&line) {
            Ok(status) => Ok(status),
            Err(e) => {
                self.broken = true;
                Err(e.into())
            }
        }
    }

    pub async fn delete(&mut self, key: &[u8]) -> Result<Status, ClientError> {
        self.send(&text::encode_delete(key)?).await?;
        let line = self.line().await?;
        match text::parse_status_line(&line) {
            Ok(status) => Ok(status),
            Err(e) => {
                self.broken = true;
                Err(e.into())
            }
        }
    }

    pub async fn touch(&mut self, key: &[u8], exptime: i64) -> Result<Status, ClientError> {
        self.send(&text::encode_touch(key, exptime)?).await?;
        let line = self.line().await?;
        match text::parse_status_line(&line) {
            Ok(status) => Ok(status),
            Err(e) => {
                self.broken = true;
                Err(e.into())
            }
        }
    }

    /// Key metadata via `mg` without fetching the value. Requires meta support (see `probe`).
    ///
    /// Uses the `u` flag so the item's LRU position, last-access time and fetched-before bit are
    /// left alone. The server's global `get_hits`/`get_misses` counters still count the lookup.
    pub async fn meta_info(&mut self, key: &[u8]) -> Result<Option<KeyInfo>, ClientError> {
        self.send(&text::encode_meta_get(key, "s f t l h c u")?)
            .await?;
        let line = self.line().await?;
        let parsed = match text::parse_meta_get(&line) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.broken = true;
                return Err(e.into());
            }
        };
        match parsed {
            MetaGet::Miss => Ok(None),
            MetaGet::Hit(flags) => {
                let find = |c: char| flags.iter().find(|(f, _)| *f == c).map(|(_, v)| v.as_str());
                let malformed = |what: &str| ProtocolError::Malformed(format!("mg flag {what}"));
                let int = |c: char| -> Result<Option<i64>, ProtocolError> {
                    find(c)
                        .map(|v| v.parse().map_err(|_| malformed(v)))
                        .transpose()
                };
                let non_negative = |c: char| -> Result<Option<u64>, ProtocolError> {
                    int(c)?
                        .map(|v| {
                            u64::try_from(v)
                                .map_err(|_| malformed(&format!("{c} is negative or too large")))
                        })
                        .transpose()
                };
                let info = (|| -> Result<KeyInfo, ProtocolError> {
                    let ttl = int('t')?;
                    if ttl.is_some_and(|t| t < -1) {
                        return Err(malformed("t must be -1 or non-negative"));
                    }
                    let size = non_negative('s')?.unwrap_or(0);
                    let flags_value = non_negative('f')?.unwrap_or(0);
                    let client_flags =
                        u32::try_from(flags_value).map_err(|_| malformed("f does not fit u32"))?;
                    Ok(KeyInfo {
                        size,
                        client_flags,
                        // `t-1` means the item never expires.
                        ttl_seconds: ttl.filter(|t| *t >= 0),
                        seconds_since_access: non_negative('l')?,
                        hit_before: find('h') == Some("1"),
                        stale: find('X').is_some(),
                        cas: non_negative('c')?,
                    })
                })();
                match info {
                    Ok(info) => Ok(Some(info)),
                    Err(e) => {
                        self.broken = true;
                        Err(e.into())
                    }
                }
            }
        }
    }

    /// Reads item metadata with `lru_crawler metadump`, stopping after `max_entries`.
    ///
    /// The whole `max_bytes` response budget is reserved before the first line, so a hostile
    /// dump cannot grow past the process-wide budget. Order is the crawler's, not random, so a
    /// partial sample is biased toward whatever it visits first. The client is consumed: an
    /// early stop leaves unread dump lines on the connection.
    pub async fn dump_keys(self, max_entries: usize) -> Result<KeySample, ClientError> {
        self.dump_keys_with_limit(max_entries, MAX_METADUMP_BYTES)
            .await
    }

    /// Like [`dump_keys`](Self::dump_keys), with an explicit total response byte budget.
    pub async fn dump_keys_with_limit(
        mut self,
        max_entries: usize,
        max_bytes: u64,
    ) -> Result<KeySample, ClientError> {
        let max_entries = max_entries.max(1);
        let reservation = usize::try_from(max_bytes)
            .map_err(|_| ClientError::Memory("metadump budget does not fit usize".to_owned()))?;
        self.reserve(reservation)?;
        self.send(&text::encode_metadump()).await?;
        let started = Instant::now();
        let op_deadline = self.operation_deadline;
        let mut entries = Vec::new();
        let mut bytes = 0u64;
        loop {
            self.check_deadline(started)?;
            let line = self.line_until(started, op_deadline).await?;
            bytes = bytes.saturating_add(line.len() as u64);
            if bytes > max_bytes {
                self.broken = true;
                return Err(ProtocolError::Malformed(format!(
                    "metadump response exceeds the {max_bytes} byte limit"
                ))
                .into());
            }
            match text::parse_dump_line(&line) {
                Ok(DumpLine::Ok) => {}
                Ok(DumpLine::End) => {
                    return Ok(KeySample {
                        entries,
                        complete: true,
                    })
                }
                Ok(DumpLine::Entry(e)) => {
                    entries.push(e);
                    if entries.len() >= max_entries {
                        return Ok(KeySample {
                            entries,
                            complete: false,
                        });
                    }
                }
                Err(e) => {
                    self.broken = true;
                    return Err(e.into());
                }
            }
        }
    }

    /// Reads the whole metadump and keeps a uniform random sample of `keep` entries (reservoir
    /// sampling), so totals scaled by `seen / entries.len()` are unbiased. Costs a full crawl:
    /// stops at `max_read` items, after `deadline`, or after [`MAX_METADUMP_SCAN_BYTES`] bytes,
    /// and then reports `complete: false`. The scan budget is reserved before the first line.
    pub async fn sample_keys_uniform(
        self,
        keep: usize,
        max_read: u64,
        deadline: Duration,
    ) -> Result<UniformSample, ClientError> {
        self.sample_keys_uniform_with_limit(keep, max_read, MAX_METADUMP_SCAN_BYTES, deadline)
            .await
    }

    /// Like [`sample_keys_uniform`](Self::sample_keys_uniform) with an explicit scan byte budget.
    pub async fn sample_keys_uniform_with_limit(
        mut self,
        keep: usize,
        max_read: u64,
        max_bytes: u64,
        deadline: Duration,
    ) -> Result<UniformSample, ClientError> {
        let keep = keep
            .min(max_read.min(MAX_UNIFORM_KEEP as u64) as usize)
            .max(1);
        let reservation = usize::try_from(max_bytes)
            .map_err(|_| ClientError::Memory("metadump budget does not fit usize".to_owned()))?;
        self.reserve(reservation)?;
        self.send(&text::encode_metadump()).await?;
        let started = Instant::now();
        let deadline = deadline.min(self.operation_deadline);
        let mut rng = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
        let mut entries: Vec<DumpEntry> = Vec::with_capacity(keep.min(1 << 16));
        let mut seen = 0u64;
        let mut bytes = 0u64;
        loop {
            if started.elapsed() >= deadline {
                return Ok(UniformSample {
                    entries,
                    seen,
                    complete: false,
                });
            }
            let limit = self
                .op_timeout
                .min(deadline.saturating_sub(started.elapsed()));
            if limit.is_zero() {
                return Ok(UniformSample {
                    entries,
                    seen,
                    complete: false,
                });
            }
            let line = match self.line_with_timeout(limit).await {
                Ok(line) => line,
                Err(ClientError::Deadline) => {
                    return Ok(UniformSample {
                        entries,
                        seen,
                        complete: false,
                    })
                }
                // A timeout while the caller's deadline is the limiting factor is just an
                // incomplete sample, not a hard protocol error.
                Err(ClientError::Timeout)
                    if started.elapsed() >= deadline || limit < self.op_timeout =>
                {
                    return Ok(UniformSample {
                        entries,
                        seen,
                        complete: false,
                    })
                }
                Err(e) => return Err(e),
            };
            bytes = bytes.saturating_add(line.len() as u64);
            if bytes > max_bytes {
                return Ok(UniformSample {
                    entries,
                    seen,
                    complete: false,
                });
            }
            match text::parse_dump_line(&line) {
                Ok(DumpLine::Ok) => {}
                Ok(DumpLine::End) => {
                    return Ok(UniformSample {
                        entries,
                        seen,
                        complete: true,
                    })
                }
                Ok(DumpLine::Entry(e)) => {
                    seen += 1;
                    if entries.len() < keep {
                        entries.push(e);
                    } else {
                        // Algorithm R: item number `seen` replaces a random slot with p = keep/seen.
                        let j = next_random(&mut rng) % seen;
                        if (j as usize) < keep {
                            entries[j as usize] = e;
                        }
                    }
                    if seen >= max_read || started.elapsed() >= deadline {
                        return Ok(UniformSample {
                            entries,
                            seen,
                            complete: false,
                        });
                    }
                }
                Err(e) => {
                    self.broken = true;
                    return Err(e.into());
                }
            }
        }
    }

    /// Probes the server: `version`, then `mn` to detect meta command support.
    pub async fn probe(&mut self) -> Result<Capabilities, ClientError> {
        let version = self.version().await?;
        self.send(&text::encode_meta_noop()).await?;
        let meta = self.line().await?.trim_end() == "MN";
        Ok(Capabilities { version, meta })
    }
}
