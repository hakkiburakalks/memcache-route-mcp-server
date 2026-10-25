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
