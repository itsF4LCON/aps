//! Domain age from RDAP, the successor of WHOIS. Pure code, unit tested
//! natively; lib.rs does the fetching and caching.

use serde::Deserialize;

use crate::policy::is_shared_host;
use crate::target::Target;

/// IANA's list of which RDAP server answers for which TLD.
pub const BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

/// A domain registered less than this long ago gets the `new_domain` signal.
pub const NEW_DOMAIN_SECS: i64 = 30 * 24 * 60 * 60;
/// A known registration date is re-checked after this long, in case the
/// domain expired and was registered again.
pub const KNOWN_TTL_SECS: i64 = 30 * 24 * 60 * 60;
/// An unknown one (no RDAP server for the TLD, no such domain, no date) is
/// re-checked sooner.
pub const UNKNOWN_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Deserialize)]
pub struct Bootstrap {
    /// `[[tlds], [server URLs]]` pairs.
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Deserialize)]
pub struct Domain {
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
struct Event {
    #[serde(rename = "eventAction")]
    action: String,
    #[serde(rename = "eventDate")]
    date: String,
}

/// The registered domain to look up. IPs have none, and on a shared host the
/// platform's age says nothing about the page.
pub fn domain_to_check(t: &Target) -> Option<&str> {
    if t.is_ip || is_shared_host(t) {
        return None;
    }
    t.registrable.as_deref()
}

/// The RDAP query URL for `domain`, if its TLD has an HTTPS RDAP server.
pub fn query_url(bootstrap: &Bootstrap, domain: &str) -> Option<String> {
    let tld = domain.rsplit('.').next()?;
    let (_, servers) = bootstrap
        .services
        .iter()
        .find(|(tlds, _)| tlds.iter().any(|t| t.eq_ignore_ascii_case(tld)))?;
    let base = servers.iter().find(|s| s.starts_with("https://"))?;
    let slash = if base.ends_with('/') { "" } else { "/" };
    Some(format!("{base}{slash}domain/{domain}"))
}

/// Unix time of the `registration` event, if the registry reports one.
pub fn registered_at(d: &Domain) -> Option<i64> {
    d.events
        .iter()
        .find(|e| e.action.eq_ignore_ascii_case("registration"))
        .and_then(|e| parse_rfc3339(&e.date))
}

pub fn is_new(registered_at: i64, now: i64) -> bool {
    (0..NEW_DOMAIN_SECS).contains(&(now - registered_at))
}

/// Whether a cached lookup can still be used. `checked_at` and `now` are Unix seconds.
pub fn is_fresh(checked_at: i64, now: i64, known: bool) -> bool {
    let ttl = if known {
        KNOWN_TTL_SECS
    } else {
        UNKNOWN_TTL_SECS
    };
    (0..ttl).contains(&(now - checked_at))
}

/// `2026-09-30T23:00:03Z`, `2026-09-30T23:00:03.5+02:00` and the like, to Unix seconds.
fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hour, min, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        rest = frac.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && matches!(&rest[..1], "+" | "-") && &rest[3..4] == ":" => {
            let o = num(s.len() - 5, 2)? * 3600 + num(s.len() - 2, 2)? * 60;
            if rest.starts_with('-') {
                -o
            } else {
                o
            }
        }
        _ => return None,
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec - offset)
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::parse;

    const BOOTSTRAP: &str = r#"{
        "version": "1.0",
        "services": [
            [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
            [["top"], ["http://rdap.example-top.test/", "https://rdap.zdns.cn/top"]],
            [["kg"], ["http://rdap.cctld.kg/"]]
        ]
    }"#;

    fn bootstrap() -> Bootstrap {
        serde_json::from_str(BOOTSTRAP).unwrap()
    }

    #[test]
    fn picks_the_https_server_for_the_tld() {
        let b = bootstrap();
        assert_eq!(
            query_url(&b, "example.com").as_deref(),
            Some("https://rdap.verisign.com/com/v1/domain/example.com")
        );
        assert_eq!(
            query_url(&b, "phish.top").as_deref(),
            Some("https://rdap.zdns.cn/top/domain/phish.top")
        );
    }

    #[test]
    fn no_server_means_no_lookup() {
        let b = bootstrap();
        assert_eq!(query_url(&b, "example.de"), None, "TLD without RDAP");
        assert_eq!(query_url(&b, "example.kg"), None, "plain-HTTP server only");
    }

    #[test]
    fn reads_the_registration_event() {
        let d: Domain = serde_json::from_str(
            r#"{"objectClassName": "domain", "ldhName": "EXAMPLE.COM", "events": [
                {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:39Z"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(registered_at(&d), Some(808_372_800));

        let none: Domain = serde_json::from_str(r#"{"objectClassName": "domain"}"#).unwrap();
        assert_eq!(registered_at(&none), None);
    }

    #[test]
    fn parses_rfc3339_variants() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-09-30T23:00:03Z"), Some(1_790_809_203));
        assert_eq!(
            parse_rfc3339("2026-10-01T01:00:03.123+02:00"),
            Some(1_790_809_203)
        );
        assert_eq!(
            parse_rfc3339("2026-09-30T18:00:03-05:00"),
            Some(1_790_809_203)
        );
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-09-30"), None);
        assert_eq!(parse_rfc3339("garbage-and-more-garbage"), None);
    }

    #[test]
    fn new_means_under_thirty_days_old() {
        let now = 1_790_809_203;
        assert!(is_new(now - 86_400, now));
        assert!(!is_new(now - NEW_DOMAIN_SECS, now));
        assert!(
            !is_new(now + 86_400, now),
            "a date in the future is not trusted"
        );
    }

    #[test]
    fn only_registered_domains_are_looked_up() {
        let d = |u: &str| domain_to_check(&parse(u).unwrap()).map(str::to_string);
        assert_eq!(
            d("https://login.example.co.uk/x").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(d("https://evil.pages.dev/"), None);
        assert_eq!(d("https://sites.google.com/view/x"), None);
        assert_eq!(d("http://198.51.100.7/"), None);
    }

    #[test]
    fn unknown_dates_are_rechecked_sooner() {
        let now = 1_790_809_203;
        assert!(is_fresh(now - UNKNOWN_TTL_SECS - 1, now, true));
        assert!(!is_fresh(now - UNKNOWN_TTL_SECS, now, false));
        assert!(!is_fresh(now - KNOWN_TTL_SECS, now, true));
    }
}
