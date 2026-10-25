//! Groups sampled keys by prefix, so "what is in this cache?" can be answered without listing
//! every key name.

use std::collections::BTreeMap;

use serde::Serialize;

/// Label for keys that contain no delimiter.
pub const NO_PREFIX: &str = "(no delimiter)";

#[derive(Debug, Clone, Copy)]
pub struct Item<'a> {
    pub key: &'a str,
    /// Total item size as the server reports it.
    pub size: u64,
    pub fetched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrefixStat {
    pub prefix: String,
    pub items: u64,
    pub bytes: u64,
    /// Items never read since they were stored.
    pub never_fetched: u64,
}

/// The part of `key` before the first `delim`, or [`NO_PREFIX`].
pub fn prefix_of(key: &str, delim: char) -> &str {
    match key.split_once(delim) {
        Some((p, _)) if !p.is_empty() => p,
        _ => NO_PREFIX,
    }
}

/// Most numerous prefixes first; on ties real prefixes come before [`NO_PREFIX`], then by name.
pub fn summarize<'a>(items: impl IntoIterator<Item = Item<'a>>, delim: char) -> Vec<PrefixStat> {
    let mut by: BTreeMap<&str, PrefixStat> = BTreeMap::new();
    for it in items {
        let p = prefix_of(it.key, delim);
        let s = by.entry(p).or_insert_with(|| PrefixStat {
            prefix: p.to_owned(),
            items: 0,
            bytes: 0,
            never_fetched: 0,
        });
        s.items += 1;
        s.bytes += it.size;
        s.never_fetched += u64::from(!it.fetched);
    }
    let mut out: Vec<_> = by.into_values().collect();
    // Ties: real prefixes before the catch-all bucket, then by name.
    out.sort_by(|a, b| {
        b.items
            .cmp(&a.items)
            .then_with(|| (a.prefix == NO_PREFIX).cmp(&(b.prefix == NO_PREFIX)))
            .then_with(|| a.prefix.cmp(&b.prefix))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(key: &str, size: u64, fetched: bool) -> Item<'_> {
        Item { key, size, fetched }
    }

    #[test]
    fn groups_by_first_segment() {
        let s = summarize(
            [
                item("user:1:profile", 80, true),
                item("user:2:profile", 90, false),
                item("sess:abc", 70, false),
                item("plain", 60, false),
                item(":odd", 10, true),
            ],
            ':',
        );
        assert_eq!(
            s,
            vec![
                PrefixStat {
                    prefix: "user".into(),
                    items: 2,
                    bytes: 170,
                    never_fetched: 1
                },
                PrefixStat {
                    prefix: NO_PREFIX.into(),
                    items: 2,
                    bytes: 70,
                    never_fetched: 1
                },
                PrefixStat {
                    prefix: "sess".into(),
                    items: 1,
                    bytes: 70,
                    never_fetched: 1
                },
            ]
        );
    }

    #[test]
    fn honours_the_delimiter_and_empty_input() {
        let s = summarize(
            [
                item("a/b", 1, true),
                item("a/c", 1, true),
                item("a:b", 1, true),
            ],
            '/',
        );
        assert_eq!((s[0].prefix.as_str(), s[0].items), ("a", 2));
        assert_eq!(s[1].prefix, NO_PREFIX);
        assert!(summarize([], ':').is_empty());
    }

    #[test]
    fn ties_sort_by_name() {
        let s = summarize([item("b:1", 1, true), item("a:1", 1, true)], ':');
        assert_eq!(
            s.iter().map(|p| p.prefix.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
    }
}
