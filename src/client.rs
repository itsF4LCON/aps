//! Who is calling, for rate limiting. Pure code, unit tested natively.

use std::net::IpAddr;

/// The key a client's requests are counted under. An IPv6 user usually gets a
/// whole /64 and can pick a fresh address per request, so IPv6 is limited per
/// /64 prefix rather than per address. IPv4 (including IPv4-mapped IPv6) stays
/// per address. Anything unparseable shares one bucket.
pub fn rate_limit_key(ip: &str) -> String {
    match ip.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        Err(_) => "unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_per_address() {
        assert_eq!(rate_limit_key("203.0.113.7"), "203.0.113.7");
        assert_ne!(rate_limit_key("203.0.113.7"), rate_limit_key("203.0.113.8"));
    }

    #[test]
    fn ipv6_is_per_64_prefix() {
        let a = rate_limit_key("2001:db8:1:2:aaaa::1");
        let b = rate_limit_key("2001:db8:1:2:ffff:ffff:ffff:ffff");
        assert_eq!(a, "2001:db8:1:2::/64");
        assert_eq!(a, b, "rotating the interface id must not reset the limit");
        assert_ne!(a, rate_limit_key("2001:db8:1:3::1"));
    }

    #[test]
    fn ipv6_spellings_share_a_key() {
        assert_eq!(
            rate_limit_key("2001:0DB8:0001:0002:0000:0000:0000:0001"),
            rate_limit_key("2001:db8:1:2::1")
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_the_ipv4_address() {
        assert_eq!(rate_limit_key("::ffff:203.0.113.7"), "203.0.113.7");
    }

    #[test]
    fn missing_or_garbage_falls_back_to_one_bucket() {
        assert_eq!(rate_limit_key("unknown"), "unknown");
        assert_eq!(rate_limit_key(""), "unknown");
        assert_eq!(rate_limit_key("not an ip"), "unknown");
    }
}
