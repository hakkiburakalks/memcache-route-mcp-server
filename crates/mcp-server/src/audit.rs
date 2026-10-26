//! Append-only audit trail for mutating operations and denied targets.
//!
//! One JSON object per line, to `MEMCACHED_MCP_AUDIT_LOG` if set, otherwise stderr (stdout is
//! the MCP channel). Records key names and outcomes, never values.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Audit {
    file: Option<Mutex<File>>,
}

impl Audit {
    pub fn from_env() -> std::io::Result<Self> {
        let file = match std::env::var("MEMCACHED_MCP_AUDIT_LOG") {
            Ok(path) if !path.is_empty() => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(path)?,
            )),
            _ => None,
        };
        Ok(Self { file })
    }

    /// `user` is the authenticated identity: a token-file name, `shared-token`, `stdio`, or `-`
    /// when the caller could not be identified.
    pub fn record(&self, user: &str, tool: &str, addr: &str, key: Option<&str>, outcome: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut line = serde_json::json!({
            "ts": ts, "user": user, "tool": tool, "addr": addr, "key": key, "outcome": outcome,
        })
        .to_string();
        line.push('\n');
        match &self.file {
            Some(f) => {
                if let Ok(mut f) = f.lock() {
                    let _ = f.write_all(line.as_bytes());
                }
            }
            None => {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
