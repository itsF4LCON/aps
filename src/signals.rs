//! Deterministic phishing signals computed from the URL alone. Fast, explainable
//! and immune to prompt injection, unlike the language-model check.

use serde::Serialize;

use crate::policy::is_shared_host;
use crate::target::Target;

/// Score at or above which a URL is blocked.
pub const BLOCK_THRESHOLD: u32 = 60;

/// Brands worth impersonating. Kept to names of 5+ characters: shorter ones
/// match too many unrelated domains.
pub const BRANDS: &[&str] = &[
    "paypal",
    "google",
    "microsoft",
    "office365",
    "outlook",
    "apple",
    "icloud",
    "amazon",
    "github",
    "catawiki",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "dropbox",
    "docusign",
    "coinbase",
    "binance",
    "metamask",
];

/// Official registrable domains that contain a brand name plus extra words.
const OFFICIAL_BRAND_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "amazon-adsystem.com",
    "paypal-community.com",
    "paypal-objects.com",
];

/// Matched as prefixes of path words, and of adjacent word pairs so that
/// `log-in` and `sign_in` count too.
const CREDENTIAL_WORDS: &[&str] = &[
    "login",
    "signin",
    "logon",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "wallet",
    "unlock",
    "suspend",
    "confirm",
    "billing",
    "invoice",
    "secure",
    "update",
    "authenticate",
    "2fa",
    "otp",
    "recover",
];

const RISKY_TLDS: &[&str] = &[
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "rest", "cam",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    UserinfoInUrl,
    BrandLookalike,
    BrandInSubdomain,
    IpLiteralHost,
    PunycodeHost,
    BrandInPath,
    SharedHost,
    EmbeddedRedirect,
    CredentialPath,
    DeepSubdomain,
    RiskyTld,
}

impl Signal {
    pub fn weight(self) -> u32 {
        match self {
            Signal::BrandLookalike => 50,
            Signal::BrandInSubdomain => 50,
            Signal::UserinfoInUrl => 40,
            Signal::IpLiteralHost => 30,
            Signal::PunycodeHost => 25,
            Signal::BrandInPath => 15,
            Signal::SharedHost => 15,
            Signal::EmbeddedRedirect => 15,
            Signal::CredentialPath => 10,
            Signal::DeepSubdomain => 10,
            Signal::RiskyTld => 10,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Signal::BrandLookalike => "domain imitates a well-known brand",
            Signal::BrandInSubdomain => "brand name used as a subdomain of an unrelated site",
            Signal::UserinfoInUrl => "text before '@' disguises the real host",
            Signal::IpLiteralHost => "raw IP address instead of a domain",
            Signal::PunycodeHost => "internationalised (punycode) hostname",
            Signal::BrandInPath => "brand name in the path of an unrelated site",
            Signal::SharedHost => "hosted on a platform where anyone can publish",
            Signal::EmbeddedRedirect => "URL redirects to another URL",
            Signal::CredentialPath => "path asks for a login or account action",
            Signal::DeepSubdomain => "unusually deep subdomain chain",
            Signal::RiskyTld => "top-level domain heavily used for abuse",
        }
    }
}

/// All signals present in `target`, strongest first.
pub fn analyze(target: &Target) -> Vec<Signal> {
    let mut out = Vec::new();
    if target.has_userinfo {
        out.push(Signal::UserinfoInUrl);
    }
    if target.is_ip {
        out.push(Signal::IpLiteralHost);
    }
    if target.host.split('.').any(|l| l.starts_with("xn--")) {
        out.push(Signal::PunycodeHost);
    }
    if target.embedded_url {
        out.push(Signal::EmbeddedRedirect);
    }
    let shared = is_shared_host(target);
    if shared {
        out.push(Signal::SharedHost);
    }

    let (label, subdomains) = split_host(target);
    // On a shared host the "owner" is the platform, not the page author, so
    // sites.google.com/view/paypal-login is still checked for brands.
    let brand_owner = !shared
        && (label.as_deref().is_some_and(|l| BRANDS.contains(&l))
            || target
                .registrable
                .as_deref()
                .is_some_and(|r| OFFICIAL_BRAND_DOMAINS.contains(&r)));
    if !brand_owner {
        if label.as_deref().is_some_and(is_brand_lookalike) {
            out.push(Signal::BrandLookalike);
        }
        let in_sub = subdomains
            .iter()
            .flat_map(|s| s.split('-'))
            .any(|tok| BRANDS.contains(&tok));
        if in_sub {
            out.push(Signal::BrandInSubdomain);
        }
        let path = target.path.to_ascii_lowercase();
        if BRANDS.iter().any(|b| path.contains(b)) {
            out.push(Signal::BrandInPath);
        }
    }

    if has_credential_word(&target.path) {
        out.push(Signal::CredentialPath);
    }
    if subdomains.len() >= 4 {
        out.push(Signal::DeepSubdomain);
    }
    if !target.is_ip {
        let tld = target.host.rsplit('.').next().unwrap_or("");
        if RISKY_TLDS.contains(&tld) {
            out.push(Signal::RiskyTld);
        }
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.weight()));
    out
}

fn has_credential_word(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let words: Vec<&str> = path
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let pairs = words.windows(2).map(|p| format!("{}{}", p[0], p[1]));
    words
        .iter()
        .map(|w| w.to_string())
        .chain(pairs)
        .any(|w| CREDENTIAL_WORDS.iter().any(|c| w.starts_with(c)))
}

/// Sum of weights, capped at 100.
pub fn score(signals: &[Signal]) -> u32 {
    signals.iter().map(|s| s.weight()).sum::<u32>().min(100)
}

/// (label of the registrable domain, subdomain labels), e.g.
/// `a.b.paypal-login.co.uk` -> (`paypal-login`, [`a`, `b`]).
/// For shared hosts the registrable domain includes the platform suffix, so
/// `paypal-verify.pages.dev` -> (`paypal-verify`, []).
fn split_host(target: &Target) -> (Option<String>, Vec<String>) {
    let Some(registrable) = target.registrable.as_deref() else {
        return (None, Vec::new());
    };
    let suffix = psl::suffix_str(registrable).unwrap_or("");
    let label = registrable
        .strip_suffix(suffix)
        .and_then(|s| s.strip_suffix('.'))
        .unwrap_or(registrable)
        .to_string();
    let subdomains = target
        .host
        .strip_suffix(registrable)
        .and_then(|s| s.strip_suffix('.'))
        .map(|s| s.split('.').map(str::to_string).collect())
        .unwrap_or_default();
    (Some(label), subdomains)
}

/// `paypa1`, `paypal-secure`, `micros0ft`, `arnazon` -> true; `paypal` -> false.
fn is_brand_lookalike(label: &str) -> bool {
    if BRANDS.contains(&label) {
        return false;
    }
    let normalized = normalize_homoglyphs(label);
    let candidates = std::iter::once(normalized.as_str())
        .chain(normalized.split('-'))
        .chain(label.split('-'));
    for cand in candidates {
        for brand in BRANDS {
            if cand == *brand {
                return true;
            }
            let max_edits = if brand.len() >= 8 { 2 } else { 1 };
            // Avoid matching short unrelated words of a different length class.
            if cand.len().abs_diff(brand.len()) <= max_edits
                && damerau_levenshtein(cand, brand) <= max_edits
            {
                return true;
            }
        }
    }
    false
}

fn normalize_homoglyphs(s: &str) -> String {
    s.replace("rn", "m")
        .replace("vv", "w")
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' => 'l',
            '3' => 'e',
            '5' => 's',
            '4' => 'a',
            '7' => 't',
            _ => c,
        })
        .collect()
}

/// Optimal string alignment distance (Damerau-Levenshtein with adjacent swaps).
fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::parse;

    fn sig(url: &str) -> Vec<Signal> {
        analyze(&parse(url).unwrap())
    }

    fn blocked(url: &str) -> bool {
        score(&sig(url)) >= BLOCK_THRESHOLD
    }

    #[test]
    fn typosquats_and_combosquats() {
        assert!(sig("https://paypa1.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://micros0ft.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://arnazon.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://paypal-secure-login.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://catawlki.nl/").contains(&Signal::BrandLookalike));
        assert!(sig("https://paypal-verify.pages.dev/").contains(&Signal::BrandLookalike));
    }

    #[test]
    fn real_brand_domains_are_not_lookalikes() {
        for url in [
            "https://paypal.com/",
            "https://www.paypal.de/",
            "https://google.co.uk/",
            "https://www.google-analytics.com/",
            "https://applebees.com/",
            "https://example.com/",
            "https://pineapple.com/",
        ] {
            assert!(!sig(url).contains(&Signal::BrandLookalike), "{url}");
        }
    }

    #[test]
    fn brand_in_subdomain_of_unrelated_site() {
        let s = sig("https://paypal.com.account-check.example/login");
        assert!(s.contains(&Signal::BrandInSubdomain), "{s:?}");
        assert!(s.contains(&Signal::CredentialPath));
        assert!(!sig("https://www.paypal.com/").contains(&Signal::BrandInSubdomain));
    }

    #[test]
    fn host_tricks() {
        assert!(sig("http://192.0.2.10/login").contains(&Signal::IpLiteralHost));
        assert!(sig("https://p\u{0430}ypal.com/").contains(&Signal::PunycodeHost));
        assert!(sig("https://paypal.com@evil.example/").contains(&Signal::UserinfoInUrl));
        assert!(sig("https://a.b.c.d.evil.example/").contains(&Signal::DeepSubdomain));
        assert!(sig("https://invoice.zip/").contains(&Signal::RiskyTld));
    }

    #[test]
    fn shared_host_phishing_page_scores_but_platform_alone_does_not_block() {
        let page = sig("https://sites.google.com/view/paypal-login");
        assert!(page.contains(&Signal::SharedHost));
        assert!(page.contains(&Signal::BrandInPath));
        assert!(page.contains(&Signal::CredentialPath));
        assert!(!blocked("https://someone.github.io/blog/"));
    }

    #[test]
    fn verdicts_at_the_threshold() {
        assert!(blocked("https://paypa1.com/signin"));
        assert!(blocked("https://paypal.com.account-check.example/login"));
        assert!(blocked("https://paypal.com@192.0.2.10/"));
        assert!(!blocked("https://example.com/"));
        assert!(!blocked("https://www.bbc.co.uk/news"));
        assert!(!blocked("https://github.com/login"));
    }

    #[test]
    fn signals_are_sorted_strongest_first() {
        let s = sig("https://paypal.com@192.0.2.10/login");
        let weights: Vec<u32> = s.iter().map(|x| x.weight()).collect();
        let mut sorted = weights.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(weights, sorted);
    }

    #[test]
    fn credential_words_in_paths() {
        assert!(has_credential_word("/view/paypal-login"));
        assert!(has_credential_word("/log-in"));
        assert!(has_credential_word("/Account/Verify.php"));
        assert!(!has_credential_word("/blog/rust-tips"));
        assert!(!has_credential_word("/author/jane"));
    }

    #[test]
    fn edit_distance() {
        assert_eq!(damerau_levenshtein("paypal", "paypal"), 0);
        assert_eq!(damerau_levenshtein("paypla", "paypal"), 1);
        assert_eq!(damerau_levenshtein("payal", "paypal"), 1);
        assert_eq!(damerau_levenshtein("kitten", "sitting"), 3);
    }
}
