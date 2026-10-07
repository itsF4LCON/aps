//! Which hosts may skip analysis, and which hosts serve other people's content.

use crate::target::Target;

/// Exact hostnames that skip analysis. Matching is on the full hostname, never
/// on the registrable domain: `sites.google.com` must not inherit `google.com`.
pub const TRUSTED_HOSTS: &[&str] = &[
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "mail.google.com",
    "paypal.com",
    "www.paypal.com",
    "microsoft.com",
    "www.microsoft.com",
    "login.microsoftonline.com",
    "apple.com",
    "www.apple.com",
    "appleid.apple.com",
    "amazon.com",
    "www.amazon.com",
    "catawiki.com",
    "www.catawiki.com",
    "catawiki.nl",
    "www.catawiki.nl",
];

/// Hosts that serve user-generated pages but are not in the Public Suffix
/// List's private section (which already covers pages.dev, workers.dev,
/// github.io, netlify.app, web.app, blogspot.com and many more).
pub const USER_CONTENT_HOSTS: &[&str] = &[
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "script.google.com",
    "forms.gle",
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
    "googleusercontent.com",
    "forms.office.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "blob.core.windows.net",
    "web.core.windows.net",
    "dropboxusercontent.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "notion.site",
    "ipfs.io",
    "dweb.link",
    "trycloudflare.com",
];

/// Paths that bounce the visitor elsewhere on otherwise trusted hosts
/// (`www.google.com/url?q=`, `/amp/s/evil.example`).
const REDIRECT_PATH_PREFIXES: &[&str] = &[
    "/url",
    "/amp/",
    "/aclk",
    "/imgres",
    "/link",
    "/redirect",
    "/l/",
    "/r/",
    "/out",
];

/// `host` equals `suffix` or is a subdomain of it.
fn host_is_or_under(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Anyone can publish a page here, so the host's reputation says nothing
/// about the page.
pub fn is_shared_host(target: &Target) -> bool {
    if target.is_ip {
        return false;
    }
    let private_suffix =
        psl::suffix(target.host.as_bytes()).is_some_and(|s| s.typ() == Some(psl::Type::Private));
    private_suffix
        || USER_CONTENT_HOSTS
            .iter()
            .any(|h| host_is_or_under(&target.host, h))
}

/// Whether the scan may stop early with a "trusted" verdict. Deliberately
/// narrow: an exact trusted host, no query string (redirect parameters come in
/// too many encodings to enumerate) and no redirect-style path. Anything else
/// is simply analysed like any other URL.
pub fn is_trusted(target: &Target) -> bool {
    let path = target.path.to_ascii_lowercase();
    TRUSTED_HOSTS.contains(&target.host.as_str())
        && !target.has_query
        && !target.embedded_url
        && !target.has_userinfo
        && !REDIRECT_PATH_PREFIXES.iter().any(|p| path.starts_with(p))
        && !is_shared_host(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::parse;

    fn trusted(url: &str) -> bool {
        is_trusted(&parse(url).unwrap())
    }

    fn shared(url: &str) -> bool {
        is_shared_host(&parse(url).unwrap())
    }

    #[test]
    fn exact_trusted_hosts_pass() {
        assert!(trusted("https://accounts.google.com/signin"));
        assert!(trusted("https://www.paypal.com/myaccount"));
        assert!(trusted("https://www.google.com/"));
    }

    #[test]
    fn subdomains_of_trusted_domains_are_not_trusted() {
        assert!(!trusted("https://sites.google.com/view/paypal-verify"));
        assert!(!trusted(
            "https://docs.google.com/forms/d/e/1FAIpQL/viewform"
        ));
        assert!(!trusted("https://anything.paypal.com/"));
    }

    #[test]
    fn redirects_and_userinfo_break_trust() {
        assert!(!trusted(
            "https://www.google.com/url?q=https://evil.example"
        ));
        assert!(!trusted("https://www.google.com/url?q=evil.example"));
        assert!(!trusted("https://www.google.com/url?q=https:/evil.example"));
        assert!(!trusted(
            "https://www.google.com/url?q=https:%5C%5Cevil.example"
        ));
        assert!(!trusted("https://www.google.com/amp/s/evil.example/login"));
        assert!(!trusted("https://paypal.com@evil.example/"));
    }

    #[test]
    fn github_is_user_content_not_trusted() {
        assert!(!trusted(
            "https://github.com/x/y/releases/download/v1/setup.exe"
        ));
    }

    #[test]
    fn shared_hosts_from_the_psl_private_section() {
        assert!(shared("https://evil.pages.dev/"));
        assert!(shared("https://x.y.workers.dev/"));
        assert!(shared("https://someone.github.io/login"));
        assert!(shared("https://phish.netlify.app/"));
    }

    #[test]
    fn shared_hosts_from_the_explicit_list() {
        assert!(shared("https://sites.google.com/view/x"));
        assert!(shared("https://docs.google.com/forms/d/x"));
        assert!(shared("https://contoso.sharepoint.com/x"));
        assert!(shared("https://forms.gle/abc"));
    }

    #[test]
    fn ordinary_hosts_are_not_shared() {
        assert!(!shared("https://example.com/"));
        assert!(!shared("https://www.google.com/"));
        assert!(!shared("https://notsharepoint.com/"));
        assert!(!shared("http://10.0.0.1/"));
    }
}
