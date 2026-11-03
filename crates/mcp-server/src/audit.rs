//! Append-only audit trail for mutating operations and denied targets.
//!
//! One JSON object per line, to `MEMCACHED_MCP_AUDIT_LOG` if set, otherwise stderr (stdout is
//! the MCP channel). Records key names and outcomes, never values.
//!
//! Writing is deliberately off the async runtime: `record` builds a bounded line and performs a
//! non-blocking `try_send` to a dedicated writer thread. A slow or stuck disk can therefore lose
//! audit lines, but cannot block a Tokio worker. Dropped/failed counts are observable.

use std::collections::HashMap;
#[cfg(test)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

/// No more than this many audit lines per second are written, whichever tool produces them.
pub const MAX_AUDIT_LINES_PER_SEC: u32 = 100;
/// A single identity may not consume the entire process-wide audit budget.
pub const MAX_AUDIT_LINES_PER_SOURCE_PER_SEC: u32 = 20;
const MAX_AUDIT_SOURCES: usize = 1_024;
const DEFAULT_AUDIT_QUEUE: usize = 4_096;
const MAX_AUDIT_FIELD_BYTES: usize = 256;

pub struct Audit {
    writer: AuditWriter,
    /// Lines lost to queue pressure, source/global throttling or a disconnected writer.
    dropped: AtomicU64,
    /// Write failures reported by the writer thread.
    failed: Arc<AtomicU64>,
    throttle: Throttle,
    sources: SourceThrottle,
}

struct AuditWriter {
    tx: SyncSender<Option<String>>,
    join: Option<JoinHandle<()>>,
}

impl Drop for AuditWriter {
    fn drop(&mut self) {
        // Ask the writer to drain and exit. This may wait for a slow disk during shutdown, but
        // never on the async request path.
        let _ = self.tx.send(None);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Audit {
    pub fn from_env() -> std::io::Result<Self> {
        let writer: Box<dyn Write + Send> = match std::env::var("MEMCACHED_MCP_AUDIT_LOG") {
            Ok(path) if !path.is_empty() => {
                Box::new(OpenOptions::new().create(true).append(true).open(path)?)
            }
            _ => Box::new(std::io::stderr()),
        };
        Self::with_writer(writer, MAX_AUDIT_LINES_PER_SEC, DEFAULT_AUDIT_QUEUE)
    }

    #[cfg(test)]
    fn with_file(file: Option<File>, limit: u32) -> Self {
        Self::with_file_and_capacity(file, limit, DEFAULT_AUDIT_QUEUE)
    }

    #[cfg(test)]
    fn with_file_and_capacity(file: Option<File>, limit: u32, capacity: usize) -> Self {
        let writer: Box<dyn Write + Send> = match file {
            Some(file) => Box::new(file),
            None => Box::new(std::io::stderr()),
        };
        Self::with_writer(writer, limit, capacity).expect("spawn audit writer")
    }

    fn with_writer(
        mut writer: Box<dyn Write + Send>,
        limit: u32,
        capacity: usize,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<Option<String>>(capacity);
        let failed = Arc::new(AtomicU64::new(0));
        let writer_failed = failed.clone();
        let join = thread::Builder::new()
            .name("memcached-mcp-audit".to_owned())
            .spawn(move || {
                while let Ok(Some(line)) = rx.recv() {
                    if let Err(e) = writer.write_all(line.as_bytes()) {
                        let n = writer_failed.fetch_add(1, Ordering::Relaxed) + 1;
                        if n.is_power_of_two() {
                            eprintln!(
                                "audit: cannot write to the audit log ({e}); {n} line(s) lost so far; this one: {}",
                                line.trim_end()
                            );
                        }
                    }
                }
                let _ = writer.flush();
            })?;
        Ok(Self {
            writer: AuditWriter {
                tx,
                join: Some(join),
            },
            dropped: AtomicU64::new(0),
            failed,
            throttle: Throttle::new(limit),
            sources: SourceThrottle::new(MAX_AUDIT_LINES_PER_SOURCE_PER_SEC),
        })
    }

    /// Lines lost to queue pressure, source/global throttling or a disconnected writer.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Lines the writer thread could not write.
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    /// `user` is the authenticated identity: a token-file name, `shared-token`, `stdio`, or `-`
    /// when the caller could not be identified.
    pub fn record(&self, user: &str, tool: &str, addr: &str, key: Option<&str>, outcome: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.record_at(ts, user, tool, addr, key, outcome);
    }

    fn record_at(
        &self,
        ts: u64,
        user: &str,
        tool: &str,
        addr: &str,
        key: Option<&str>,
        outcome: &str,
    ) {
        // Fairness first: one noisy identity cannot consume the process-wide budget.
        if !self.sources.admit_at(user, ts) {
            self.note_dropped();
            return;
        }
        match self.throttle.admit_at(ts) {
            Admit::No => {
                self.note_dropped();
                return;
            }
            Admit::AfterDropped(n) => {
                self.note_dropped_n(u64::from(n));
                self.write_line(&self.line(
                    ts,
                    "-",
                    "audit",
                    "-",
                    None,
                    &format!("{n} more audit lines were dropped in the previous second"),
                ));
            }
            Admit::Yes => {}
        }
        self.write_line(&self.line(ts, user, tool, addr, key, outcome));
    }

    fn line(
        &self,
        ts: u64,
        user: &str,
        tool: &str,
        addr: &str,
        key: Option<&str>,
        outcome: &str,
    ) -> String {
        let mut line = serde_json::json!({
            "ts": ts,
            "user": clip(user),
            "tool": clip(tool),
            "addr": clip(addr),
            "key": key.map(clip),
            "outcome": clip(outcome),
        })
        .to_string();
        line.push('\n');
        line
    }

    fn write_line(&self, line: &str) {
        match self.writer.tx.try_send(Some(line.to_owned())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.note_dropped(),
            Err(TrySendError::Disconnected(_)) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.note_dropped();
            }
        }
    }

    fn note_dropped(&self) {
        self.note_dropped_n(1);
    }

    fn note_dropped_n(&self, n: u64) {
        let total = self.dropped.fetch_add(n, Ordering::Relaxed) + n;
        if total.is_power_of_two() {
            eprintln!("audit: {total} audit line(s) have been dropped");
        }
    }
}

/// Keeps a single log line bounded even when a tool argument is attacker-sized. Clip on a UTF-8
/// boundary so the JSON serializer never panics.
fn clip(value: &str) -> &str {
    if value.len() <= MAX_AUDIT_FIELD_BYTES {
        return value;
    }
    let mut end = MAX_AUDIT_FIELD_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Caps how many audit lines an unauthenticated caller can cause: `limit` per second, and one
/// summary line for what was dropped. Without it, a flood of bad tokens fills the disk.
pub struct Throttle {
    limit: u32,
    state: Mutex<ThrottleState>,
}

#[derive(Default)]
struct ThrottleState {
    second: u64,
    admitted: u32,
    dropped: u32,
}

/// What to do with one event.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Record it.
    Yes,
    /// Record it, preceded by a note that this many events were dropped in the previous second.
    AfterDropped(u32),
    No,
}

impl Throttle {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            state: Mutex::default(),
        }
    }

    pub fn admit(&self) -> Admit {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.admit_at(now)
    }

    fn admit_at(&self, now: u64) -> Admit {
        let Ok(mut st) = self.state.lock() else {
            return Admit::No;
        };
        let mut dropped = 0;
        if st.second != now {
            dropped = st.dropped;
            *st = ThrottleState {
                second: now,
                ..ThrottleState::default()
            };
        }
        if st.admitted < self.limit {
            st.admitted += 1;
            if dropped > 0 {
                Admit::AfterDropped(dropped)
            } else {
                Admit::Yes
            }
        } else {
            st.dropped += 1;
            Admit::No
        }
    }
}

/// Per-identity token bucket expressed as a per-second cap. The map is bounded; excess identities
/// share one overflow bucket, so a token-file with many users cannot make audit memory unbounded.
struct SourceThrottle {
    limit: u32,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl SourceThrottle {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn admit_at(&self, source: &str, now: u64) -> bool {
        let source = clip(source).to_owned();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        let key = if state.len() < MAX_AUDIT_SOURCES || state.contains_key(&source) {
            source
        } else {
            "-overflow-".to_owned()
        };
        let entry = state.entry(key).or_insert((now, 0));
        if entry.0 != now {
            *entry = (now, 0);
        }
        if entry.1 < self.limit {
            entry.1 += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::time::Duration;

    use super::*;

    fn test_file(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "memcached-mcp-audit-{tag}-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn throttle_caps_per_second_and_reports_what_it_dropped() {
        let t = Throttle::new(3);
        for _ in 0..3 {
            assert_eq!(t.admit_at(10), Admit::Yes);
        }
        for _ in 0..5 {
            assert_eq!(t.admit_at(10), Admit::No);
        }
        // Next second: the first event carries the count of the 5 dropped ones.
        assert_eq!(t.admit_at(11), Admit::AfterDropped(5));
        assert_eq!(t.admit_at(11), Admit::Yes);
        // A quiet second drops nothing, so nothing is reported.
        assert_eq!(t.admit_at(20), Admit::Yes);
    }

    struct SlowWriter;
    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(100));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn audit_does_not_block_on_a_slow_writer() {
        let audit = Audit::with_writer(Box::new(SlowWriter), 100, 1).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..5 {
            audit.record_at(30, "u", "tool", "-", None, "held");
        }
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "audit blocked on a slow writer for {:?}",
            started.elapsed()
        );
        assert!(audit.dropped() > 0, "queue pressure was not counted");
    }

    #[test]
    fn a_single_source_cannot_starve_another() {
        let path = test_file("fairness");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let audit = Audit::with_file(Some(file), 100);
        for _ in 0..50 {
            audit.record_at(10, "noisy", "compare_nodes", "-", None, "denied");
        }
        audit.record_at(10, "quiet", "get_stats", "-", None, "denied");
        drop(audit);
        let mut text = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.contains("\"user\":\"quiet\""), "{text}");
        assert!(text.contains("\"user\":\"noisy\""), "{text}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn audit_caps_all_tools_and_clips_attacker_sized_fields() {
        let path = test_file("cap");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let audit = Audit::with_file(Some(file), 2);
        for _ in 0..5 {
            audit.record_at(10, "u", "compare_nodes", "-", None, "denied");
        }
        audit.record_at(11, "u", "compare_nodes", "-", None, "ok");
        let huge = "x".repeat(10_000);
        audit.record_at(20, "u", "tool", &huge, Some(&huge), &huge);
        drop(audit);

        let mut text = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.len() <= 5, "{text}");
        assert!(
            text.contains("more audit lines were dropped"),
            "missing drop summary: {text}"
        );
        for line in &lines {
            assert!(line.len() < 2048, "unbounded audit line: {line}");
            serde_json::from_str::<serde_json::Value>(line).expect("audit line is not JSON");
        }
        let _ = std::fs::remove_file(&path);
    }
}
