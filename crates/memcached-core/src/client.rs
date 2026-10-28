use std::collections::BTreeMap;
use std::time::Duration;

use memcached_protocol::text::{
    self, DumpEntry, DumpLine, MetaGet, ProtocolError, Status, StoreCmd,
};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Longest single response line accepted (metadump lines are about 1 KiB at most).
const MAX_LINE_BYTES: u64 = 16 * 1024;
/// Largest value read back; memcached's default item limit is 1 MiB, mcrouter's config is smaller.
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
/// More `STAT` lines than any real server sends.
const MAX_STAT_LINES: usize = 100_000;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("connection closed by server")]
    Closed,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
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
    /// Set after a failed read: the rest of the reply may still be on the wire, so the next
    /// command would read it as its own answer.
    broken: bool,
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
            broken: false,
        })
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        if self.broken {
            return Err(ClientError::Closed);
        }
        timeout(self.op_timeout, self.io.get_mut().write_all(bytes))
            .await
            .map_err(|_| ClientError::Timeout)??;
        Ok(())
    }

    async fn line(&mut self) -> Result<String, ClientError> {
        let r = self.read_line().await;
        if r.is_err() {
            self.broken = true;
        }
        r
    }

    async fn read_line(&mut self) -> Result<String, ClientError> {
        let mut buf = String::new();
        let n = timeout(
            self.op_timeout,
            (&mut self.io).take(MAX_LINE_BYTES).read_line(&mut buf),
        )
        .await
        .map_err(|_| ClientError::Timeout)??;
        if n == 0 {
            return Err(ClientError::Closed);
        }
        if !buf.ends_with('\n') && n as u64 >= MAX_LINE_BYTES {
            return Err(ProtocolError::Malformed("response line too long".to_owned()).into());
        }
        Ok(buf)
    }

    pub async fn version(&mut self) -> Result<String, ClientError> {
        self.send(&text::encode_version()).await?;
        let l = self.line().await?;
        l.trim_end()
            .strip_prefix("VERSION ")
            .map(str::to_owned)
            .ok_or_else(|| ProtocolError::Malformed(l.trim_end().to_owned()).into())
    }

    pub async fn stats(
        &mut self,
        arg: Option<&str>,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        self.send(&text::encode_stats(arg)?).await?;
        let mut out = BTreeMap::new();
        let mut lines = 0usize;
        loop {
            let l = self.line().await?;
            lines += 1;
            if lines > MAX_STAT_LINES {
                self.broken = true;
                return Err(ProtocolError::Malformed("too many stat lines".to_owned()).into());
            }
            match text::parse_stat_line(&l)? {
                Some((k, v)) => {
                    out.insert(k.to_owned(), v.to_owned());
                }
                None => return Ok(out),
            }
        }
    }

    /// Returns `(flags, cas, data)` for a hit.
    pub async fn get(&mut self, key: &[u8]) -> Result<Option<(u32, Vec<u8>)>, ClientError> {
        self.send(&text::encode_get(&[key])?).await?;
        let mut found = None;
        while let Some(h) = text::parse_value_header(&self.line().await?)? {
            // The length comes from the server; never let it decide how much memory we allocate.
            if h.len > MAX_VALUE_BYTES {
                return Err(ProtocolError::Malformed(format!(
                    "value of {} bytes exceeds the {MAX_VALUE_BYTES} byte limit",
                    h.len
                ))
                .into());
            }
            let mut data = vec![0u8; h.len + 2];
            timeout(self.op_timeout, self.io.read_exact(&mut data))
                .await
                .map_err(|_| ClientError::Timeout)??;
            data.truncate(h.len);
            found = Some((h.flags, data));
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
        Ok(text::parse_status_line(&self.line().await?)?)
    }

    pub async fn delete(&mut self, key: &[u8]) -> Result<Status, ClientError> {
        self.send(&text::encode_delete(key)?).await?;
        Ok(text::parse_status_line(&self.line().await?)?)
    }

    pub async fn touch(&mut self, key: &[u8], exptime: i64) -> Result<Status, ClientError> {
        self.send(&text::encode_touch(key, exptime)?).await?;
        Ok(text::parse_status_line(&self.line().await?)?)
    }

    /// Key metadata via `mg` without fetching the value. Requires meta support (see `probe`).
    ///
    /// Uses the `u` flag so the item's LRU position, last-access time and fetched-before bit are
    /// left alone. The server's global `get_hits`/`get_misses` counters still count the lookup.
    pub async fn meta_info(&mut self, key: &[u8]) -> Result<Option<KeyInfo>, ClientError> {
        self.send(&text::encode_meta_get(key, "s f t l h c u")?)
            .await?;
        match text::parse_meta_get(&self.line().await?)? {
            MetaGet::Miss => Ok(None),
            MetaGet::Hit(flags) => {
                let find = |c: char| flags.iter().find(|(f, _)| *f == c).map(|(_, v)| v.as_str());
                let malformed = |what: &str| ProtocolError::Malformed(format!("mg flag {what}"));
                let int = |c: char| -> Result<Option<i64>, ProtocolError> {
                    find(c)
                        .map(|v| v.parse().map_err(|_| malformed(v)))
                        .transpose()
                };
                Ok(Some(KeyInfo {
                    size: int('s')?.unwrap_or(0) as u64,
                    client_flags: int('f')?.unwrap_or(0) as u32,
                    // `t-1` means the item never expires.
                    ttl_seconds: int('t')?.filter(|t| *t >= 0),
                    seconds_since_access: int('l')?.map(|l| l as u64),
                    hit_before: find('h') == Some("1"),
                    cas: find('c').and_then(|v| v.parse().ok()),
                }))
            }
        }
    }

    /// Reads item metadata with `lru_crawler metadump`, stopping after `max_entries`.
    ///
    /// Takes the client by value: once enough entries are read the connection is dropped, which
    /// ends the server-side dump (aborting it mid-way was observed to leave the server healthy).
    /// Order is the crawler's, not random, so a partial sample is biased toward whatever it
    /// visits first.
    pub async fn dump_keys(mut self, max_entries: usize) -> Result<KeySample, ClientError> {
        self.send(&text::encode_metadump()).await?;
        let mut entries = Vec::new();
        loop {
            match text::parse_dump_line(&self.line().await?)? {
                DumpLine::Ok => {}
                DumpLine::End => {
                    return Ok(KeySample {
                        entries,
                        complete: true,
                    })
                }
                DumpLine::Entry(e) => {
                    entries.push(e);
                    if entries.len() >= max_entries {
                        return Ok(KeySample {
                            entries,
                            complete: false,
                        });
                    }
                }
            }
        }
    }

    /// Reads the whole metadump and keeps a uniform random sample of `keep` entries (reservoir
    /// sampling), so totals scaled by `seen / entries.len()` are unbiased. Costs a full crawl:
    /// stops at `max_read` items or after `deadline`, and then reports `complete: false`.
    pub async fn sample_keys_uniform(
        mut self,
        keep: usize,
        max_read: u64,
        deadline: Duration,
    ) -> Result<UniformSample, ClientError> {
        self.send(&text::encode_metadump()).await?;
        let started = tokio::time::Instant::now();
        let mut rng = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
        let mut entries: Vec<DumpEntry> = Vec::with_capacity(keep.min(1 << 16));
        let mut seen = 0u64;
        loop {
            match text::parse_dump_line(&self.line().await?)? {
                DumpLine::Ok => {}
                DumpLine::End => {
                    return Ok(UniformSample {
                        entries,
                        seen,
                        complete: true,
                    })
                }
                DumpLine::Entry(e) => {
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
