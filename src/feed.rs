//! The OpenPhish community feed: parsing it and deciding how a scan matches it.
//! Pure code, unit tested natively; lib.rs does the fetching and D1 work.

use std::collections::HashSet;

use crate::policy::is_shared_host;
use crate::target::{self, Target};

/// Updated every 12 hours (around 00:00 and 12:00 UTC). Non-commercial use only.
pub const URL: &str = "https://openphish.com/feed.txt";

/// Entries are kept this long after they last appeared in the feed. Hosts are
/// matched as a whole, so this is kept short.
pub const RETAIN_SECS: i64 = 3 * 24 * 60 * 60;

/// Rows per INSERT: three bound parameters each, and D1 allows 100 per query.
pub const ROWS_PER_INSERT: usize = 33;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Normalised like [`Target::lookup_url`], so it matches what scans look up.
    pub url: String,
    pub host: String,
}

/// One entry per listed URL, normalised. Lines that aren't valid http(s) URLs
/// are skipped.
pub fn parse(text: &str) -> Vec<Entry> {
    let mut seen = HashSet::new();
    text.lines()
        .map(str::trim)
        .filter(|l| target::validate_url(l))
        .filter_map(|l| target::parse(l).ok())
        .filter(|t| seen.insert(t.lookup_url.clone()))
        .map(|t| Entry {
            url: t.lookup_url,
            host: t.host,
        })
        .collect()
}

/// An upsert of `rows` feed entries, bound as (url, host, last_seen) triples.
pub fn upsert_sql(rows: usize) -> String {
    let values: Vec<String> = (0..rows)
        .map(|i| format!("(?{}, ?{}, ?{})", 3 * i + 1, 3 * i + 2, 3 * i + 3))
        .collect();
    format!(
        "INSERT INTO feed_urls (url, host, last_seen) VALUES {} \
         ON CONFLICT(url) DO UPDATE SET last_seen = excluded.last_seen",
        values.join(", ")
    )
}

/// The host a scan may match on as a whole, besides its exact URL. A phishing
/// kit usually owns its host and serves many paths from it. On a shared host
/// (`*.pages.dev`, `sites.google.com`, an S3 bucket) other people's pages live
/// next to the listed one, so there only the exact URL counts.
pub fn host_to_match(t: &Target) -> Option<&str> {
    (!is_shared_host(t)).then_some(t.host.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_normalised_like_scans() {
        let entries = parse(
            "https://Login.Example-Bank.top/verify?id=1#x\n\
             https://login.example-bank.top/verify?id=2\n\
             \n\
             not a url\n\
             ftp://files.example/\n\
             http://198.51.100.7/paypal/\n",
        );
        assert_eq!(
            entries,
            vec![
                Entry {
                    url: "https://login.example-bank.top/verify".into(),
                    host: "login.example-bank.top".into(),
                },
                Entry {
                    url: "http://198.51.100.7/paypal/".into(),
                    host: "198.51.100.7".into(),
                },
            ]
        );
        let scanned = target::parse("https://login.example-bank.top/verify?token=abc").unwrap();
        assert_eq!(scanned.lookup_url, entries[0].url);
    }

    #[test]
    fn upsert_numbers_every_parameter() {
        assert_eq!(
            upsert_sql(2),
            "INSERT INTO feed_urls (url, host, last_seen) VALUES (?1, ?2, ?3), (?4, ?5, ?6) \
             ON CONFLICT(url) DO UPDATE SET last_seen = excluded.last_seen"
        );
        assert!(upsert_sql(ROWS_PER_INSERT).ends_with(
            "(?97, ?98, ?99) \
             ON CONFLICT(url) DO UPDATE SET last_seen = excluded.last_seen"
        ));
    }

    #[test]
    fn dedicated_hosts_match_as_a_whole() {
        let t = target::parse("https://login.example-bank.top/other/path").unwrap();
        assert_eq!(host_to_match(&t), Some("login.example-bank.top"));
        let ip = target::parse("http://198.51.100.7/").unwrap();
        assert_eq!(host_to_match(&ip), Some("198.51.100.7"));
    }

    #[test]
    fn shared_hosts_match_only_the_exact_url() {
        for url in [
            "https://evil.pages.dev/login",
            "https://sites.google.com/view/paypal-verify",
            "https://bucket.s3.eu-west-1.amazonaws.com/x.html",
        ] {
            assert_eq!(host_to_match(&target::parse(url).unwrap()), None, "{url}");
        }
    }
}
