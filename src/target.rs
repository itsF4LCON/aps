//! Parsing and normalising the URL under test. Pure code, unit tested natively.

pub const MAX_URL_LENGTH: usize = 2048;

/// Cheap pre-checks before parsing: length, http(s) only, no script/data payloads.
pub fn validate_url(url: &str) -> bool {
    if url.is_empty() || url.len() > MAX_URL_LENGTH {
        return false;
    }
    let lower = url.to_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    if lower.contains("javascript:") || lower.contains("data:text") {
        return false;
    }
    true
}

/// The URL under test, normalised for analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Full hostname: lower-case, IDNA (punycode) form, no trailing dot.
    /// IPv6 literals keep their brackets.
    pub host: String,
    /// Registrable domain (eTLD+1) per the Public Suffix List, including its
    /// private section, so `evil.pages.dev` is its own site rather than
    /// `pages.dev`. `None` for IP literals and bare suffixes.
    pub registrable: Option<String>,
    pub is_ip: bool,
    pub path: String,
    /// Credentials before the host (`https://paypal.com@evil.example/`).
    pub has_userinfo: bool,
    pub has_query: bool,
    /// The query or path carries another URL (open-redirect pattern).
    pub embedded_url: bool,
    /// `scheme://host/path` without query or fragment. Used as the cache key
    /// and as the only form sent to third parties, since email links often
    /// carry tokens in the query string.
    pub lookup_url: String,
}

pub fn parse(raw: &str) -> Result<Target, &'static str> {
    let url = url::Url::parse(raw).map_err(|_| "Malformed URL")?;
    let (host, is_ip) = match url.host() {
        Some(url::Host::Domain(d)) => (d.trim_end_matches('.').to_ascii_lowercase(), false),
        Some(url::Host::Ipv4(ip)) => (ip.to_string(), true),
        Some(url::Host::Ipv6(ip)) => (format!("[{ip}]"), true),
        None => return Err("No host found in URL"),
    };
    if host.is_empty() {
        return Err("No host found in URL");
    }
    let registrable = if is_ip {
        None
    } else {
        psl::domain_str(&host).map(str::to_string)
    };
    let path = url.path().to_string();
    let lower_path = path.to_ascii_lowercase();
    let embedded_url = url.query_pairs().any(|(_, v)| looks_like_url(&v))
        || lower_path.contains("://")
        || lower_path.contains("%3a%2f%2f");
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Ok(Target {
        lookup_url: format!("{}://{host}{port}{path}", url.scheme()),
        host,
        registrable,
        is_ip,
        path,
        has_userinfo: !url.username().is_empty() || url.password().is_some(),
        has_query: url.query().is_some_and(|q| !q.is_empty()),
        embedded_url,
    })
}

/// Browsers accept `https:/x`, `https:\\x` and `\\\\x` as URLs too, so match
/// loosely: anything with a scheme separator or a leading double slash.
fn looks_like_url(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    v.contains("://")
        || v.contains(":\\")
        || v.starts_with("//")
        || v.starts_with("\\\\")
        || v.starts_with("http:")
        || v.starts_with("https:")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(url: &str) -> Target {
        parse(url).unwrap()
    }

    #[test]
    fn keeps_the_full_hostname() {
        let x = t("https://Sites.Google.com./view/login");
        assert_eq!(x.host, "sites.google.com");
        assert_eq!(x.registrable.as_deref(), Some("google.com"));
        assert_eq!(x.path, "/view/login");
    }

    #[test]
    fn private_suffixes_are_separate_sites() {
        assert_eq!(
            t("https://evil.pages.dev/").registrable.as_deref(),
            Some("evil.pages.dev")
        );
        assert_eq!(
            t("https://a.b.workers.dev/").registrable.as_deref(),
            Some("b.workers.dev")
        );
        assert_eq!(
            t("https://x.github.io/").registrable.as_deref(),
            Some("x.github.io")
        );
    }

    #[test]
    fn multi_label_public_suffixes() {
        assert_eq!(
            t("https://www.bbc.co.uk/").registrable.as_deref(),
            Some("bbc.co.uk")
        );
        // The old hand-rolled parser turned this into "com.au"-style garbage.
        assert_eq!(
            t("https://login.paypal.com.au/").registrable.as_deref(),
            Some("paypal.com.au")
        );
    }

    #[test]
    fn idn_hosts_are_punycode() {
        // Cyrillic "а" in "pаypal".
        let x = t("https://p\u{0430}ypal.com/");
        assert!(x.host.starts_with("xn--"), "{}", x.host);
    }

    #[test]
    fn ip_literals_have_no_registrable_domain() {
        let v4 = t("http://192.168.10.1/login");
        assert!(v4.is_ip);
        assert_eq!(v4.registrable, None);
        let v6 = t("http://[2001:db8::1]/");
        assert!(v6.is_ip);
        assert_eq!(v6.host, "[2001:db8::1]");
    }

    #[test]
    fn detects_userinfo_and_embedded_urls() {
        assert!(t("https://paypal.com@evil.example/").has_userinfo);
        assert!(!t("https://evil.example/").has_userinfo);
        assert!(t("https://www.google.com/url?q=https://evil.example").embedded_url);
        assert!(t("https://x.example/r?to=//evil.example").embedded_url);
        assert!(t("https://x.example/go/https%3A%2F%2Fevil.example").embedded_url);
        assert!(!t("https://x.example/search?q=phishing").embedded_url);
        assert!(t("https://x.example/r?u=https:/evil.example").embedded_url);
        assert!(t("https://x.example/r?u=https:%5C%5Cevil.example").embedded_url);
        assert!(t("https://x.example/r?u=%5C%5Cevil.example").embedded_url);
        assert!(t("https://x.example/?q=a").has_query);
        assert!(!t("https://x.example/?").has_query);
    }

    #[test]
    fn lookup_url_drops_query_and_fragment() {
        let x = t("https://Example.com:8443/reset?token=s3cret#frag");
        assert_eq!(x.lookup_url, "https://example.com:8443/reset");
    }

    #[test]
    fn rejects_hostless_urls() {
        assert!(parse("not a url").is_err());
    }

    #[test]
    fn accepts_http_and_https() {
        assert!(validate_url("https://example.com/login"));
        assert!(validate_url("HTTP://EXAMPLE.COM"));
    }

    #[test]
    fn rejects_other_schemes_and_payloads() {
        assert!(!validate_url(""));
        assert!(!validate_url("ftp://example.com"));
        assert!(!validate_url("javascript:alert(1)"));
        assert!(!validate_url("https://example.com/?x=javascript:alert(1)"));
        assert!(!validate_url("https://example.com/?x=data:text/html,hi"));
        assert!(!validate_url(&format!(
            "https://e.com/{}",
            "a".repeat(MAX_URL_LENGTH)
        )));
    }
}
