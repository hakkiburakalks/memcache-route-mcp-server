//! Who is calling, and what they may do (HTTP mode).
//!
//! Tokens are stored only as SHA-256 hashes. That is enough because tokens are long random
//! strings (see `new_token`), so there is nothing to brute-force and no need for a slow KDF.
//! These permissions sit inside the server-wide switches (`MEMCACHED_MCP_ALLOW_WRITE`, ...):
//! an action needs both.

use std::collections::HashSet;
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// Every read-only tool except key sampling.
    Read,
    /// `sample_keys` (prefix totals).
    Sample,
    /// Individual key names from `sample_keys`.
    KeyNames,
    /// `set_key`, `delete_key`, `touch_key`.
    Write,
    /// The `/metrics` endpoint.
    Metrics,
}

impl Perm {
    const ALL: [Perm; 5] = [
        Perm::Read,
        Perm::Sample,
        Perm::KeyNames,
        Perm::Write,
        Perm::Metrics,
    ];

    fn name(self) -> &'static str {
        match self {
            Perm::Read => "read",
            Perm::Sample => "sample",
            Perm::KeyNames => "key_names",
            Perm::Write => "write",
            Perm::Metrics => "metrics",
        }
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// The caller of a request. `Identity::none()` can do nothing.
#[derive(Debug, Clone)]
pub struct Identity {
    pub name: Arc<str>,
    perms: u8,
}

impl Identity {
    pub fn all(name: &str) -> Self {
        Self {
            name: name.into(),
            perms: Perm::ALL.iter().fold(0, |m, p| m | p.bit()),
        }
    }

    pub fn none() -> Self {
        Self {
            name: "-".into(),
            perms: 0,
        }
    }

    pub fn can(&self, p: Perm) -> bool {
        self.perms & p.bit() != 0
    }

    pub fn require(&self, p: Perm) -> Result<(), String> {
        if self.can(p) {
            Ok(())
        } else {
            Err(format!(
                "forbidden: '{}' does not have the '{}' permission",
                self.name,
                p.name()
            ))
        }
    }
}

pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 256 random bits, hex-encoded.
pub fn new_token() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

#[derive(Deserialize)]
struct FileUser {
    name: String,
    token_sha256: String,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
struct FileFormat {
    users: Vec<FileUser>,
}

pub struct TokenStore {
    users: Vec<(String, Identity)>, // (sha256 hex of the token, identity)
}

impl TokenStore {
    /// One shared token that grants everything: the pre-RBAC behaviour.
    pub fn shared(token: &str) -> Self {
        Self {
            users: vec![(sha256_hex(token), Identity::all("shared-token"))],
        }
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        let f: FileFormat =
            serde_json::from_str(json).map_err(|e| format!("invalid token file: {e}"))?;
        if f.users.is_empty() {
            return Err("token file has no users".to_owned());
        }
        let (mut names, mut hashes) = (HashSet::new(), HashSet::new());
        let mut users = Vec::new();
        for u in f.users {
            if u.name.trim().is_empty() || u.name.len() > 64 || u.name.chars().any(char::is_control)
            {
                return Err(format!("bad user name '{}'", u.name));
            }
            let hash = u.token_sha256.to_ascii_lowercase();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "user '{}': token_sha256 must be 64 hex characters",
                    u.name
                ));
            }
            if !names.insert(u.name.clone()) {
                return Err(format!("user '{}' appears twice", u.name));
            }
            if !hashes.insert(hash.clone()) {
                return Err(format!(
                    "user '{}' shares a token with another user",
                    u.name
                ));
            }
            let mut id = Identity {
                name: u.name.as_str().into(),
                perms: 0,
            };
            for p in &u.permissions {
                let perm = Perm::ALL
                    .iter()
                    .find(|x| x.name() == p)
                    .ok_or_else(|| format!("user '{}': unknown permission '{p}'", u.name))?;
                id.perms |= perm.bit();
            }
            users.push((hash, id));
        }
        Ok(Self { users })
    }

    /// Checks every entry rather than stopping at the first match, so timing does not reveal
    /// which user (or how many) a wrong token was close to.
    pub fn lookup(&self, presented: &str) -> Option<Identity> {
        let digest = sha256_hex(presented);
        let mut found = None;
        for (hash, id) in &self.users {
            if ct_eq(hash.as_bytes(), digest.as_bytes()) {
                found = Some(id.clone());
            }
        }
        found
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn tokens_are_long_and_distinct() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    fn file(users: &str) -> String {
        format!(r#"{{"users":[{users}]}}"#)
    }

    fn user(name: &str, token: &str, perms: &str) -> String {
        format!(
            r#"{{"name":"{name}","token_sha256":"{}","permissions":[{perms}]}}"#,
            sha256_hex(token)
        )
    }

    #[test]
    fn lookup_finds_the_right_user_with_the_right_permissions() {
        let json = file(&format!(
            "{},{}",
            user("alice", "tok-alice", r#""read","metrics""#),
            user("bob", "tok-bob", r#""read","write""#)
        ));
        let store = TokenStore::from_json(&json).unwrap();
        assert_eq!(store.len(), 2);
        let alice = store.lookup("tok-alice").unwrap();
        assert_eq!(&*alice.name, "alice");
        assert!(alice.can(Perm::Read) && alice.can(Perm::Metrics));
        assert!(!alice.can(Perm::Write) && !alice.can(Perm::Sample) && !alice.can(Perm::KeyNames));
        assert!(alice.require(Perm::Write).unwrap_err().contains("'alice'"));
        let bob = store.lookup("tok-bob").unwrap();
        assert!(bob.can(Perm::Write) && !bob.can(Perm::Metrics));
        assert!(store.lookup("tok-nobody").is_none());
        assert!(store.lookup("").is_none());
    }

    #[test]
    fn file_validation() {
        let h = sha256_hex("t");
        let bad = |json: String, needle: &str| {
            let e = TokenStore::from_json(&json)
                .err()
                .expect("should be rejected");
            assert!(e.contains(needle), "expected '{needle}' in '{e}'");
        };
        bad("{".into(), "invalid token file");
        bad(file(""), "no users");
        bad(file(&user("a", "t", r#""root""#)), "unknown permission");
        bad(
            file(&format!("{},{}", user("a", "t", ""), user("a", "u", ""))),
            "appears twice",
        );
        bad(
            file(&format!("{},{}", user("a", "t", ""), user("b", "t", ""))),
            "shares a token",
        );
        bad(
            file(r#"{"name":"a","token_sha256":"abc","permissions":[]}"#),
            "64 hex",
        );
        bad(
            file(&format!(
                r#"{{"name":"","token_sha256":"{h}","permissions":[]}}"#
            )),
            "bad user name",
        );
        // Hash case does not matter; a user with no permissions is allowed and can do nothing.
        let upper = file(&format!(
            r#"{{"name":"z","token_sha256":"{}","permissions":[]}}"#,
            h.to_uppercase()
        ));
        let z = TokenStore::from_json(&upper).unwrap().lookup("t").unwrap();
        assert!(!z.can(Perm::Read));
    }

    #[test]
    fn shared_token_grants_everything_and_none_grants_nothing() {
        let id = TokenStore::shared("s3cret").lookup("s3cret").unwrap();
        assert!(Perm::ALL.iter().all(|p| id.can(*p)));
        assert!(TokenStore::shared("s3cret").lookup("S3cret").is_none());
        let none = Identity::none();
        assert!(Perm::ALL.iter().all(|p| !none.can(*p)));
    }
}
