//! Freshness rules for cached remote checks (reputation feed and model).

/// A clean result is re-checked after 6 hours: domains are often registered
/// clean and weaponised later, and feeds list new phishing within hours.
pub const CLEAN_TTL_SECS: i64 = 6 * 60 * 60;
/// A flagged result is kept for a week.
pub const FLAGGED_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// `checked_at` and `now` are Unix seconds.
pub fn is_fresh(checked_at: i64, now: i64, flagged: bool) -> bool {
    let ttl = if flagged {
        FLAGGED_TTL_SECS
    } else {
        CLEAN_TTL_SECS
    };
    let age = now - checked_at;
    (0..ttl).contains(&age)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

    #[test]
    fn clean_results_expire_after_six_hours() {
        assert!(is_fresh(NOW - CLEAN_TTL_SECS + 1, NOW, false));
        assert!(!is_fresh(NOW - CLEAN_TTL_SECS, NOW, false));
    }

    #[test]
    fn flagged_results_last_a_week() {
        assert!(is_fresh(NOW - CLEAN_TTL_SECS * 4, NOW, true));
        assert!(!is_fresh(NOW - FLAGGED_TTL_SECS, NOW, true));
    }

    #[test]
    fn timestamps_in_the_future_are_not_trusted() {
        assert!(!is_fresh(NOW + 60, NOW, false));
    }
}
