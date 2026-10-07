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

/// Registrable domains the brands really own. Ownership is decided by this
/// list, never by the label alone: `paypal.support` and `apple.xyz` are not
/// PayPal's or Apple's. Country domains are listed for the big brands; a
/// missing one shows up as a lookalike, which alone does not block.
const OFFICIAL_DOMAINS: &[&str] = &[
    // PayPal
    "paypal.com",
    "paypal.me",
    "paypalobjects.com",
    "paypal.de",
    "paypal.fr",
    "paypal.it",
    "paypal.es",
    "paypal.nl",
    "paypal.co.uk",
    "paypal.com.au",
    "paypal.ca",
    // Google
    "google.com",
    "google.co.uk",
    "google.de",
    "google.nl",
    "google.fr",
    "google.es",
    "google.it",
    "google.be",
    "google.ca",
    "google.com.au",
    "google.co.jp",
    "google.co.in",
    "google.com.br",
    "google.ch",
    "google.at",
    "google.pl",
    "google.se",
    "google-analytics.com",
    "googleapis.com",
    "googlevideo.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "googleusercontent.com",
    "googlesource.com",
    "google.org",
    // Microsoft
    "microsoft.com",
    "microsoftonline.com",
    "microsoft365.com",
    "office365.com",
    "outlook.com",
    "office.com",
    "live.com",
    // Apple
    "apple.com",
    "icloud.com",
    "cdn-apple.com",
    "apple.co",
    // Amazon
    "amazon.com",
    "amazon.co.uk",
    "amazon.de",
    "amazon.nl",
    "amazon.fr",
    "amazon.es",
    "amazon.it",
    "amazon.ca",
    "amazon.co.jp",
    "amazon.com.au",
    "amazon.in",
    "amazon.com.br",
    "amazon.se",
    "amazon.pl",
    "amazon.com.be",
    "amazon-adsystem.com",
    "amazonaws.com",
    // Others
    "github.com",
    "github.dev",
    "githubusercontent.com",
    "github.blog",
    "githubassets.com",
    "catawiki.com",
    "catawiki.nl",
    "catawiki.de",
    "catawiki.fr",
    "catawiki.be",
    "catawiki.it",
    "catawiki.es",
    "netflix.com",
    "netflix.net",
    "facebook.com",
    "facebook.net",
    "facebookmail.com",
    "instagram.com",
    "whatsapp.com",
    "whatsapp.net",
    "linkedin.com",
    "dropbox.com",
    "dropboxusercontent.com",
    "docusign.com",
    "docusign.net",
    "coinbase.com",
    "binance.com",
    "metamask.io",
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
    BrandCombosquat,
    BrandInSubdomain,
    CredentialHost,
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
            Signal::BrandCombosquat => 45,
            Signal::CredentialHost => 15,
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
            Signal::BrandCombosquat => "domain combines a brand name with other words",
            Signal::CredentialHost => "hostname contains login or account words",
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
    // Match on the decoded path: /%6cogin is /login.
    let path = percent_encoding::percent_decode_str(&target.path)
        .decode_utf8_lossy()
        .to_ascii_lowercase();
    // On a shared host the "owner" is the platform, not the page author, so
    // sites.google.com/view/paypal-login is still checked for brands.
    let owned = target
        .registrable
        .as_deref()
        .is_some_and(|r| OFFICIAL_DOMAINS.contains(&r));
    let brand_owner = !shared && owned;
    if !brand_owner {
        // On brand-owned user-content hosts (sites.google.com) the label is
        // the platform's own name, so only the subdomains and path can lie.
        if !owned {
            match label
                .as_deref()
                .and_then(|l| brand_match(&confusable_skeleton(l)))
            {
                Some(BrandMatch::Typo) => out.push(Signal::BrandLookalike),
                Some(BrandMatch::Combo) => out.push(Signal::BrandCombosquat),
                None => {}
            }
        }
        let in_sub = subdomains
            .iter()
            .any(|s| brand_match(&confusable_skeleton(s)).is_some());
        if in_sub {
            out.push(Signal::BrandInSubdomain);
        }
        if BRANDS.iter().any(|b| path.contains(b)) {
            out.push(Signal::BrandInPath);
        }
        let host_words = subdomains
            .iter()
            .map(String::as_str)
            .chain(label.as_deref());
        let credential_host = host_words
            .flat_map(|l| l.split('-'))
            .any(|w| CREDENTIAL_WORDS.iter().any(|c| w.starts_with(c)));
        if credential_host && !owned {
            out.push(Signal::CredentialHost);
        }
    }

    if has_credential_word(&path) {
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

#[derive(Debug, PartialEq, Eq)]
enum BrandMatch {
    /// The whole label is the brand or a near miss: `paypa1`, `arnazon`,
    /// `paypal` itself on a domain PayPal does not own.
    Typo,
    /// A word in the label starts with a brand: `paypal-verify`, `appleid-help`,
    /// `paypalsecure`, `microsoftonline-login`.
    Combo,
}

fn brand_match(label: &str) -> Option<BrandMatch> {
    let folded = normalize_homoglyphs(label);
    if BRANDS.iter().any(|b| folded == *b || near_miss(&folded, b)) {
        return Some(BrandMatch::Typo);
    }
    let combo = folded.split('-').chain(label.split('-')).any(|word| {
        BRANDS
            .iter()
            .any(|b| word.starts_with(b) || (word.len() >= 6 && near_miss(word, b)))
    });
    combo.then_some(BrandMatch::Combo)
}

/// One or two edits away from a brand of 6+ characters. Shorter brands only
/// match exactly (after homoglyph folding): `apply` is not `apple`.
fn near_miss(word: &str, brand: &str) -> bool {
    if brand.len() < 6 || word == brand {
        return false;
    }
    let max_edits = if brand.len() >= 8 { 2 } else { 1 };
    word.len().abs_diff(brand.len()) <= max_edits && damerau_levenshtein(word, brand) <= max_edits
}

/// Decodes a punycode label and maps characters that look like ASCII letters
/// to those letters: Cyrillic `аррӏе` -> `apple`, `pаypаl` -> `paypal`.
/// A small subset of Unicode's confusables (UTS #39) covering the scripts
/// actually used in IDN homograph attacks.
fn confusable_skeleton(label: &str) -> String {
    let (unicode, _) = idna::domain_to_unicode(label);
    unicode
        .chars()
        .map(|c| match c {
            'а' | 'α' | 'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' | 'ā' => 'a',
            'Ь' | 'ь' | 'Ꮟ' => 'b',
            'с' | 'ϲ' | 'ç' => 'c',
            'ԁ' => 'd',
            'е' | 'ё' | 'ε' | 'è' | 'é' | 'ê' | 'ë' | 'ē' => 'e',
            'ɡ' => 'g',
            'һ' => 'h',
            'і' | 'ї' | 'ı' | 'ɩ' | 'ι' | 'ì' | 'í' | 'î' | 'ï' => 'i',
            'ј' => 'j',
            'κ' | 'к' => 'k',
            'ӏ' | 'ⅼ' => 'l',
            'ո' | 'ñ' => 'n',
            'о' | 'ο' | 'ö' | 'ò' | 'ó' | 'ô' | 'õ' | 'ø' => 'o',
            'р' | 'ρ' => 'p',
            'ԛ' => 'q',
            'ѕ' => 's',
            'υ' | 'ü' | 'ù' | 'ú' | 'û' => 'u',
            'ν' => 'v',
            'ԝ' | 'ѡ' => 'w',
            'х' | 'χ' => 'x',
            'у' | 'ү' | 'ý' | 'ÿ' => 'y',
            other => other,
        })
        .collect()
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
    fn user_content_hosts_never_block_on_their_own() {
        for host in crate::policy::USER_CONTENT_HOSTS {
            let url = format!("https://{host}/a/b");
            assert!(!blocked(&url), "{url}: {:?}", sig(&url));
            let sub = format!("https://x.{host}/a/b");
            assert!(!blocked(&sub), "{sub}: {:?}", sig(&sub));
        }
        assert!(!blocked("https://lh3.googleusercontent.com/a/xyz"));
        assert!(!blocked("https://dl.dropboxusercontent.com/s/abc/file.pdf"));
    }

    #[test]
    fn microsoft_and_apple_service_domains() {
        assert!(!blocked("https://outlook.office.com/owa/auth/logon.aspx"));
        assert!(!blocked("https://outlook.live.com/owa/"));
        assert!(!blocked("https://appleid.cdn-apple.com/x"));
    }

    #[test]
    fn typosquats() {
        assert!(sig("https://paypa1.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://micros0ft.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://arnazon.com/").contains(&Signal::BrandLookalike));
        assert!(sig("https://catawlki.nl/").contains(&Signal::BrandLookalike));
    }

    #[test]
    fn combosquats() {
        for url in [
            "https://paypal-secure-login.com/",
            "https://paypal-verify.pages.dev/",
            "https://paypalsecure.com/",
            "https://appleid-verify.com/",
            "https://microsoftonline-login.com/",
        ] {
            assert!(sig(url).contains(&Signal::BrandCombosquat), "{url}");
        }
        // A combosquat with login words in the domain blocks on its own.
        assert!(blocked("https://paypal-secure-login.com/"));
        assert!(blocked("https://appleid-verify.com/"));
        assert!(blocked("https://microsoftonline-login.com/"));
    }

    #[test]
    fn brand_words_alone_do_not_block() {
        assert!(!blocked("https://apply-now.com/account"));
        assert!(!blocked("https://google-tips.blog/login"));
        assert!(!blocked("https://apples.com/"));
        assert!(!blocked("https://outlook-cafe.nl/"));
        assert!(!sig("https://apply.com/").contains(&Signal::BrandLookalike));
    }

    #[test]
    fn lookalikes_in_subdomains() {
        assert!(blocked("https://paypa1.evil.example/login"));
    }

    #[test]
    fn percent_encoded_paths_are_decoded() {
        let s = sig("https://evil.example/%6cogin/%70aypal");
        assert!(s.contains(&Signal::CredentialPath));
        assert!(s.contains(&Signal::BrandInPath));
    }

    #[test]
    fn brand_name_on_a_domain_the_brand_does_not_own() {
        assert!(blocked("https://paypal.support/login"));
        assert!(blocked("https://paypal.com.co/signin"));
        assert!(sig("https://apple.xyz/account/verify").contains(&Signal::BrandLookalike));
        // The review's pages.dev case: exact brand on a shared host.
        assert!(blocked("https://paypal.pages.dev/login"));
        assert!(blocked("https://microsoft.github.io/signin"));
    }

    #[test]
    fn idn_homographs_are_lookalikes() {
        // The well-known all-Cyrillic "аррӏе.com" proof of concept.
        assert!(blocked("https://xn--80ak6aa92e.com/login"));
        assert!(blocked("https://p\u{0430}yp\u{0430}l.com/login"));
        assert!(blocked("https://g\u{043e}\u{043e}gle.com/login"));
        assert_eq!(confusable_skeleton("xn--80ak6aa92e"), "apple");
        // A genuine non-Latin domain is not a lookalike of anything.
        assert!(
            !sig("https://\u{043f}\u{0440}\u{0438}\u{043c}\u{0435}\u{0440}.\u{0440}\u{0444}/")
                .contains(&Signal::BrandLookalike)
        );
    }

    #[test]
    fn real_brand_domains_are_not_lookalikes() {
        for url in [
            "https://paypal.com/",
            "https://www.paypal.de/",
            "https://www.paypalobjects.com/",
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
        assert!(!blocked("https://sites.google.com/view/team-wiki"));
        assert!(!blocked(
            "https://docs.google.com/forms/d/e/1FAIpQL/viewform"
        ));
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
