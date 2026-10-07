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

#[cfg(test)]
mod tests {
    use super::*;

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
