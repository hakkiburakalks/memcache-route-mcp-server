//! ASCII (text) protocol: request encoding and response parsing.

use std::collections::BTreeSet;

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

/// `stats` groups that only report. Others change the server (`reset` zeroes every counter,
/// `sizes_enable`/`sizes_disable` toggle a mode) or need arguments, and the group is spliced
/// into the command line, so only these exact words are sent.
const READ_ONLY_STATS_GROUPS: [&str; 6] =
    ["items", "slabs", "sizes", "settings", "conns", "extstore"];

pub fn encode_stats(arg: Option<&str>) -> Result<Vec<u8>, ProtocolError> {
    match arg {
        Some(a) => {
            if !READ_ONLY_STATS_GROUPS.contains(&a) {
                return Err(ProtocolError::InvalidKey(
                    "stats group must be one of items, slabs, sizes, settings, conns, extstore",
                ));
            }
            Ok(format!("stats {a}\r\n").into_bytes())
        }
        None => Ok(b"stats\r\n".to_vec()),
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

pub fn encode_delete(key: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let mut out = b"delete ".to_vec();
    out.extend_from_slice(key);
    out.extend_from_slice(b"\r\n");
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

/// `mg <key> <flags>`: meta get. Without the `v` flag the value is not sent back.
pub fn encode_meta_get(key: &[u8], flags: &str) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let mut out = b"mg ".to_vec();
    out.extend_from_slice(key);
    if !flags.is_empty() {
        out.push(b' ');
        out.extend_from_slice(flags.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// Reply to `mg` without the `v` flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaGet {
    /// `HD <flags>`: each returned flag is its letter plus value, e.g. `('s', "5")`.
    Hit(Vec<(char, String)>),
    /// `EN`
    Miss,
}

pub fn parse_meta_get(line: &str) -> Result<MetaGet, ProtocolError> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == "EN" {
        return Ok(MetaGet::Miss);
    }
    if line == "HD" || line.starts_with("HD ") {
        let mut seen = BTreeSet::new();
        let mut flags = Vec::new();
        for token in line.split(' ').skip(1).filter(|t| !t.is_empty()) {
            let mut ch = token.chars();
            let Some(flag) = ch.next() else {
                continue;
            };
            if !seen.insert(flag) {
                return Err(ProtocolError::Malformed(line.to_owned()));
            }
            flags.push((flag, ch.as_str().to_owned()));
        }
        return Ok(MetaGet::Hit(flags));
    }
    if line.starts_with("ERROR")
        || line.starts_with("SERVER_ERROR")
        || line.starts_with("CLIENT_ERROR")
    {
        return Err(ProtocolError::Server(line.to_owned()));
    }
    Err(ProtocolError::Malformed(line.to_owned()))
}

/// Starts a dump of every item's metadata. Needs the LRU crawler (off by default on 1.4).
pub fn encode_metadump() -> Vec<u8> {
    b"lru_crawler metadump all\r\n".to_vec()
}

/// One item from `lru_crawler metadump`. The value is never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpEntry {
    /// URL-decoded; non-UTF-8 bytes are replaced.
    pub key: String,
    /// Unix time the item expires, None if it never does.
    pub expires_at: Option<u64>,
    /// Unix time of the last recorded access. Updated lazily, so it can lag by about a minute.
    pub last_access: u64,
    /// Whether the item has been fetched since it was stored.
    pub fetched: bool,
    /// Total item size including overhead, not the value length.
    pub size: u64,
    pub slab_class: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpLine {
    Entry(DumpEntry),
    /// 1.6 sends `OK` before the entries.
    Ok,
    End,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_dump_line(line: &str) -> Result<DumpLine, ProtocolError> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line {
        "END" => return Ok(DumpLine::End),
        "OK" => return Ok(DumpLine::Ok),
        _ => {}
    }
    if line.starts_with("ERROR")
        || line.starts_with("SERVER_ERROR")
        || line.starts_with("CLIENT_ERROR")
    {
        return Err(ProtocolError::Server(line.to_owned()));
    }
    let bad = || ProtocolError::Malformed(line.to_owned());
    let (mut key, mut exp, mut la, mut fetch, mut size, mut cls) =
        (None, None, None, None, None, None);
    let mut seen = BTreeSet::new();
    for token in line.split(' ').filter(|t| !t.is_empty()) {
        let (k, v) = token.split_once('=').ok_or_else(bad)?;
        if !seen.insert(k) {
            return Err(bad());
        }
        match k {
            "key" => key = Some(percent_decode(v)),
            "exp" => exp = Some(v.parse::<i64>().map_err(|_| bad())?),
            "la" => la = Some(v.parse::<u64>().map_err(|_| bad())?),
            "fetch" => match v {
                "yes" => fetch = Some(true),
                "no" => fetch = Some(false),
                _ => return Err(bad()),
            },
            "size" => size = Some(v.parse::<u64>().map_err(|_| bad())?),
            "cls" => cls = Some(v.parse::<u32>().map_err(|_| bad())?),
            _ => {} // cas, flags and fields added by later versions
        }
    }
    let key = key.ok_or_else(bad)?;
    if key.is_empty() {
        return Err(bad());
    }
    validate_key(key.as_bytes())?;
    let exp = exp.ok_or_else(bad)?;
    if exp < -1 {
        return Err(bad());
    }
    Ok(DumpLine::Entry(DumpEntry {
        key,
        expires_at: (exp >= 0).then_some(exp as u64),
        last_access: la.ok_or_else(bad)?,
        fetched: fetch.ok_or_else(bad)?,
        size: size.ok_or_else(bad)?,
        slab_class: cls.ok_or_else(bad)?,
    }))
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
    let key = parts.next().ok_or_else(bad)?;
    if key.is_empty() {
        return Err(bad());
    }
    validate_key(key.as_bytes())?;
    let flags = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let len = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let cas = parts
        .next()
        .map(|c| c.parse())
        .transpose()
        .map_err(|_| bad())?;
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(Some(ValueHeader {
        key: key.to_owned(),
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
        let (name, value) = rest
            .split_once(' ')
            .ok_or_else(|| ProtocolError::Malformed(line.to_owned()))?;
        if name.is_empty() {
            return Err(ProtocolError::Malformed(line.to_owned()));
        }
        return Ok(Some((name, value)));
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
    fn stats_group_cannot_smuggle_a_second_command() {
        assert_eq!(encode_stats(None).unwrap(), b"stats\r\n");
        assert_eq!(encode_stats(Some("items")).unwrap(), b"stats items\r\n");
        let too_long = "a".repeat(33);
        for bad in [
            "settings\r\nflush_all",
            "settings\nflush_all",
            "a b",
            "",
            "x\0",
            "reset",
            "sizes_enable",
            "detail",
            "ITEMS",
            too_long.as_str(),
        ] {
            assert!(
                encode_stats(Some(bad)).is_err(),
                "{bad:?} should be refused"
            );
        }
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
        assert_eq!(encode_delete(b"k").unwrap(), b"delete k\r\n");
        assert!(encode_delete(b"bad key").is_err());
        assert_eq!(encode_arith(b"c", 5, true).unwrap(), b"incr c 5\r\n");
        assert_eq!(encode_arith(b"c", 5, false).unwrap(), b"decr c 5\r\n");
        assert_eq!(encode_meta_noop(), b"mn\r\n");
    }

    #[test]
    fn meta_get_roundtrip() {
        assert_eq!(encode_meta_get(b"k", "s t").unwrap(), b"mg k s t\r\n");
        assert_eq!(encode_meta_get(b"k", "").unwrap(), b"mg k\r\n");
        assert_eq!(
            parse_meta_get("HD s5 t-1 h0\r\n").unwrap(),
            MetaGet::Hit(vec![
                ('s', "5".into()),
                ('t', "-1".into()),
                ('h', "0".into())
            ])
        );
        assert_eq!(parse_meta_get("HD\r\n").unwrap(), MetaGet::Hit(vec![]));
        assert_eq!(parse_meta_get("EN\r\n").unwrap(), MetaGet::Miss);
        // Older servers answer unknown commands with a bare ERROR.
        assert!(matches!(
            parse_meta_get("ERROR\r\n"),
            Err(ProtocolError::Server(_))
        ));
        assert!(parse_meta_get("VALUE x").is_err());
    }

    #[test]
    fn parses_metadump_lines() {
        // 1.6 format, with the trailing `flags=` field and a trailing space.
        let l =
            "key=user%3A1%3Aprofile exp=-1 la=1792956136 cas=2 fetch=no cls=1 size=77 flags=0 \r\n";
        assert_eq!(
            parse_dump_line(l).unwrap(),
            DumpLine::Entry(DumpEntry {
                key: "user:1:profile".into(),
                expires_at: None,
                last_access: 1792956136,
                fetched: false,
                size: 77,
                slab_class: 1,
            })
        );
        // 1.5 format with a real expiry and a fetched item.
        match parse_dump_line("key=a exp=1792956251 la=1 cas=6 fetch=yes cls=3 size=66\r\n")
            .unwrap()
        {
            DumpLine::Entry(e) => assert_eq!(
                (e.expires_at, e.fetched, e.slab_class),
                (Some(1792956251), true, 3)
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(parse_dump_line("END\r\n").unwrap(), DumpLine::End);
        assert_eq!(parse_dump_line("OK\r\n").unwrap(), DumpLine::Ok);
        assert_eq!(
            parse_dump_line("CLIENT_ERROR lru crawler disabled\r\n"),
            Err(ProtocolError::Server(
                "CLIENT_ERROR lru crawler disabled".into()
            ))
        );
        assert!(parse_dump_line("key=a exp=x la=1 fetch=no cls=1 size=1").is_err());
        assert!(parse_dump_line("key=a la=1 fetch=no cls=1 size=1").is_err()); // missing exp
        assert!(parse_dump_line("garbage").is_err());
    }

    #[test]
    fn percent_decoding_handles_edges() {
        assert_eq!(percent_decode("a%3Ab%25c"), "a:b%c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%C3%A9"), "é");
        assert_eq!(percent_decode(""), "");
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
        assert!(parse_value_header("VALUE k 0 1 extra\r\n").is_err());
        assert!(parse_value_header("VALUE  0 1\r\n").is_err());
    }

    #[test]
    fn strict_dump_and_meta_parsing() {
        assert!(parse_dump_line("key= exp=-1 la=1 fetch=no cls=1 size=1").is_err());
        assert!(parse_dump_line("key=k exp=-2 la=1 fetch=no cls=1 size=1").is_err());
        assert!(parse_dump_line("key=k exp=-1 la=1 fetch=maybe cls=1 size=1").is_err());
        assert!(parse_dump_line("key=k exp=-1 exp=2 la=1 fetch=no cls=1 size=1").is_err());
        assert!(parse_meta_get("HD s5 s6").is_err());
        assert!(parse_stat_line("STAT  value\r\n").is_err());
    }
}
