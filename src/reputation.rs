//! Google Safe Browsing Lookup API (v4 `threatMatches:find`) types.
//!
//! Optional: enabled by the `SAFE_BROWSING_API_KEY` secret. Only the URL's
//! scheme, host and path are sent, never its query string. The Safe Browsing
//! API is for non-commercial use; a commercial deployment should switch to
//! Google's Web Risk API.

use serde::{Deserialize, Serialize};

pub const ENDPOINT: &str = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

const THREAT_TYPES: &[&str] = &[
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindRequest<'a> {
    client: Client,
    threat_info: ThreatInfo<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Client {
    client_id: &'static str,
    client_version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatInfo<'a> {
    threat_types: &'static [&'static str],
    platform_types: [&'static str; 1],
    threat_entry_types: [&'static str; 1],
    threat_entries: [Entry<'a>; 1],
}

#[derive(Serialize)]
struct Entry<'a> {
    url: &'a str,
}

pub fn request(url: &str) -> FindRequest<'_> {
    FindRequest {
        client: Client {
            client_id: "aps",
            client_version: env!("CARGO_PKG_VERSION"),
        },
        threat_info: ThreatInfo {
            threat_types: THREAT_TYPES,
            platform_types: ["ANY_PLATFORM"],
            threat_entry_types: ["URL"],
            threat_entries: [Entry { url }],
        },
    }
}

/// `{}` when the URL is not listed.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FindResponse {
    #[serde(default)]
    matches: Vec<Match>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Match {
    threat_type: String,
}

impl FindResponse {
    /// Human-readable label of the first match, if any.
    pub fn threat(&self) -> Option<String> {
        self.matches.first().map(|m| {
            match m.threat_type.as_str() {
                "SOCIAL_ENGINEERING" => "phishing / social engineering",
                "MALWARE" => "malware",
                "UNWANTED_SOFTWARE" => "unwanted software",
                "POTENTIALLY_HARMFUL_APPLICATION" => "potentially harmful application",
                _ => "a known threat",
            }
            .to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_the_documented_shape() {
        let body = serde_json::to_value(request("https://evil.example/login")).unwrap();
        assert_eq!(body["client"]["clientId"], "aps");
        assert_eq!(body["threatInfo"]["threatTypes"][0], "SOCIAL_ENGINEERING");
        assert_eq!(body["threatInfo"]["platformTypes"][0], "ANY_PLATFORM");
        assert_eq!(body["threatInfo"]["threatEntryTypes"][0], "URL");
        assert_eq!(
            body["threatInfo"]["threatEntries"][0]["url"],
            "https://evil.example/login"
        );
    }

    #[test]
    fn parses_listed_and_clean_responses() {
        let clean: FindResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(clean.threat(), None);
        let listed: FindResponse = serde_json::from_str(
            r#"{"matches":[{"threatType":"SOCIAL_ENGINEERING","platformType":"ANY_PLATFORM",
                "threat":{"url":"https://evil.example/login"},"cacheDuration":"300s",
                "threatEntryType":"URL"}]}"#,
        )
        .unwrap();
        assert_eq!(
            listed.threat().as_deref(),
            Some("phishing / social engineering")
        );
    }
}
