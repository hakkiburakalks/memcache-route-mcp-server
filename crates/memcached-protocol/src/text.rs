//! ASCII (text) protocol: request encoding and response parsing.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
    #[error("malformed response: {0}")]
    Malformed(String),
    #[error("server error: {0}")]
    Server(String),
}

/// Keys: 1..=250 bytes, no whitespace or control characters.
pub fn validate_key(key: &[u8]) -> Result<(), ProtocolError> {
    if key.is_empty() {
        return Err(ProtocolError::InvalidKey("empty"));
    }
    if key.len() > 250 {
        return Err(ProtocolError::InvalidKey("longer than 250 bytes"));
    }
    if key.iter().any(|b| b.is_ascii_control() || *b == b' ') {
        return Err(ProtocolError::InvalidKey("whitespace or control character"));
    }
    Ok(())
}

pub fn encode_get(keys: &[&[u8]]) -> Result<Vec<u8>, ProtocolError> {
    let mut out = b"get".to_vec();
    for k in keys {
        validate_key(k)?;
        out.push(b' ');
        out.extend_from_slice(k);
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

pub fn encode_stats(arg: Option<&str>) -> Vec<u8> {
    match arg {
        Some(a) => format!("stats {a}\r\n").into_bytes(),
        None => b"stats\r\n".to_vec(),
    }
}

pub fn encode_version() -> Vec<u8> {
    b"version\r\n".to_vec()
}

/// Storage commands that carry a data block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreCmd {
    Set,
    Add,
    Replace,
    Append,
    Prepend,
}

impl StoreCmd {
    fn as_str(self) -> &'static str {
        match self {
            StoreCmd::Set => "set",
            StoreCmd::Add => "add",
            StoreCmd::Replace => "replace",
            StoreCmd::Append => "append",
            StoreCmd::Prepend => "prepend",
        }
    }
}

pub fn encode_store(
    cmd: StoreCmd,
    key: &[u8],
    flags: u32,
    exptime: i64,
    data: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let mut out = format!("{} ", cmd.as_str()).into_bytes();
    out.extend_from_slice(key);
    out.extend_from_slice(format!(" {flags} {exptime} {}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

pub fn encode_cas(
    key: &[u8],
    flags: u32,
    exptime: i64,
    data: &[u8],
    cas_unique: u64,
) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let mut out = b"cas ".to_vec();
    out.extend_from_slice(key);
    out.extend_from_slice(format!(" {flags} {exptime} {} {cas_unique}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

pub fn encode_touch(key: &[u8], exptime: i64) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let mut out = b"touch ".to_vec();
    out.extend_from_slice(key);
    out.extend_from_slice(format!(" {exptime}\r\n").as_bytes());
    Ok(out)
}

/// `incr` (or `decr` when `incr` is false).
pub fn encode_arith(key: &[u8], delta: u64, incr: bool) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let mut out = if incr {
        b"incr ".to_vec()
    } else {
        b"decr ".to_vec()
    };
    out.extend_from_slice(key);
    out.extend_from_slice(format!(" {delta}\r\n").as_bytes());
    Ok(out)
}

/// Meta no-op; a `MN` reply proves the server speaks meta commands.
pub fn encode_meta_noop() -> Vec<u8> {
    b"mn\r\n".to_vec()
}

/// Single-line replies to storage/touch/delete/arith commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Stored,
    NotStored,
    Exists,
    NotFound,
    Deleted,
    Touched,
    Ok,
    /// Result of `incr`/`decr`.
    Number(u64),
}

pub fn parse_status_line(line: &str) -> Result<Status, ProtocolError> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line {
        "STORED" => Ok(Status::Stored),
        "NOT_STORED" => Ok(Status::NotStored),
        "EXISTS" => Ok(Status::Exists),
        "NOT_FOUND" => Ok(Status::NotFound),
        "DELETED" => Ok(Status::Deleted),
        "TOUCHED" => Ok(Status::Touched),
        "OK" => Ok(Status::Ok),
        _ if line.starts_with("ERROR")
            || line.starts_with("SERVER_ERROR")
            || line.starts_with("CLIENT_ERROR") =>
        {
            Err(ProtocolError::Server(line.to_owned()))
        }
        _ => line
            .parse::<u64>()
            .map(Status::Number)
            .map_err(|_| ProtocolError::Malformed(line.to_owned())),
    }
}

/// Header of a `get`/`gets` hit: `VALUE <key> <flags> <bytes> [<cas>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueHeader {
    pub key: String,
    pub flags: u32,
    pub len: usize,
    pub cas: Option<u64>,
}

/// Returns None for the terminating `END`.
pub fn parse_value_header(line: &str) -> Result<Option<ValueHeader>, ProtocolError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == "END" {
        return Ok(None);
    }
    let bad = || ProtocolError::Malformed(line.to_owned());
    let mut parts = line.strip_prefix("VALUE ").ok_or_else(bad)?.split(' ');
    let key = parts.next().ok_or_else(bad)?.to_owned();
    let flags = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let len = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let cas = parts
        .next()
        .map(|c| c.parse())
        .transpose()
        .map_err(|_| bad())?;
    Ok(Some(ValueHeader {
        key,
        flags,
        len,
        cas,
    }))
}

/// Parses one `STAT <name> <value>` line; returns None for `END`.
pub fn parse_stat_line(line: &str) -> Result<Option<(&str, &str)>, ProtocolError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == "END" {
        return Ok(None);
    }
    if let Some(rest) = line.strip_prefix("STAT ") {
        return rest
            .split_once(' ')
            .map(Some)
            .ok_or_else(|| ProtocolError::Malformed(line.to_owned()));
    }
    if line.starts_with("ERROR")
        || line.starts_with("SERVER_ERROR")
        || line.starts_with("CLIENT_ERROR")
    {
        return Err(ProtocolError::Server(line.to_owned()));
    }
    Err(ProtocolError::Malformed(line.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_multi_get() {
        assert_eq!(encode_get(&[b"a", b"b"]).unwrap(), b"get a b\r\n");
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(validate_key(b"").is_err());
        assert!(validate_key(b"has space").is_err());
        assert!(validate_key(&[b'x'; 251]).is_err());
    }

    #[test]
    fn parses_stat_lines() {
        assert_eq!(
            parse_stat_line("STAT pid 42\r\n").unwrap(),
            Some(("pid", "42"))
        );
        assert_eq!(parse_stat_line("END\r\n").unwrap(), None);
        assert!(matches!(
            parse_stat_line("SERVER_ERROR oom\r\n"),
            Err(ProtocolError::Server(_))
        ));
    }

    #[test]
    fn encodes_store_and_cas() {
        assert_eq!(
            encode_store(StoreCmd::Set, b"k", 0, 60, b"hi").unwrap(),
            b"set k 0 60 2\r\nhi\r\n"
        );
        assert_eq!(
            encode_cas(b"k", 1, 0, b"v", 99).unwrap(),
            b"cas k 1 0 1 99\r\nv\r\n"
        );
    }

    #[test]
    fn encodes_touch_arith_meta() {
        assert_eq!(encode_touch(b"k", 30).unwrap(), b"touch k 30\r\n");
        assert_eq!(encode_arith(b"c", 5, true).unwrap(), b"incr c 5\r\n");
        assert_eq!(encode_arith(b"c", 5, false).unwrap(), b"decr c 5\r\n");
        assert_eq!(encode_meta_noop(), b"mn\r\n");
    }

    #[test]
    fn parses_status_lines() {
        assert_eq!(parse_status_line("STORED\r\n").unwrap(), Status::Stored);
        assert_eq!(
            parse_status_line("NOT_FOUND\r\n").unwrap(),
            Status::NotFound
        );
        assert_eq!(parse_status_line("42\r\n").unwrap(), Status::Number(42));
        assert!(matches!(
            parse_status_line("CLIENT_ERROR bad\r\n"),
            Err(ProtocolError::Server(_))
        ));
        assert!(parse_status_line("???").is_err());
    }

    #[test]
    fn parses_value_headers() {
        let h = parse_value_header("VALUE k 5 3 77\r\n").unwrap().unwrap();
        assert_eq!(
            h,
            ValueHeader {
                key: "k".into(),
                flags: 5,
                len: 3,
                cas: Some(77)
            }
        );
        assert_eq!(
            parse_value_header("VALUE k 0 1\r\n").unwrap().unwrap().cas,
            None
        );
        assert_eq!(parse_value_header("END\r\n").unwrap(), None);
        assert!(parse_value_header("VALUE k x 1\r\n").is_err());
    }
}
