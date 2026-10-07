//! Combines the evidence for one URL into a verdict. Pure and unit tested.

use crate::signals::{score, Signal, BLOCK_THRESHOLD};

/// Weight of a BLOCK answer from the language model. Equal to the threshold:
/// the model can block on its own (it knows brands our list does not), but it
/// can only ever add risk. A prompt-injected "SAFE" changes nothing.
pub const AI_BLOCK_WEIGHT: u32 = BLOCK_THRESHOLD;

/// Longest model explanation passed through to clients.
const MAX_AI_REASON_CHARS: usize = 160;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Evidence {
    pub signals: Vec<Signal>,
    /// The model's answer, if it was consulted: (said BLOCK, its explanation).
    pub ai: Option<(bool, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub blocked: bool,
    pub score: u32,
    pub reason: String,
}

/// Whether the model is worth asking: only while the URL signals alone have
/// not already decided to block.
pub fn needs_ai(signals: &[Signal]) -> bool {
    score(signals) < BLOCK_THRESHOLD
}

pub fn decide(e: &Evidence) -> Verdict {
    let ai_block = e.ai.as_ref().is_some_and(|(b, _)| *b);
    let total = (score(&e.signals) + if ai_block { AI_BLOCK_WEIGHT } else { 0 }).min(100);
    let blocked = total >= BLOCK_THRESHOLD;

    let described: Vec<&str> = e.signals.iter().take(3).map(|s| s.describe()).collect();
    let mut reason = if described.is_empty() {
        String::new()
    } else {
        capitalize(&described.join("; "))
    };
    if ai_block {
        let ai_reason = e.ai.as_ref().map(|(_, r)| clean(r)).unwrap_or_default();
        if !reason.is_empty() {
            reason.push_str(". ");
        }
        reason.push_str("Model flagged it");
        if !ai_reason.is_empty() {
            reason.push_str(": ");
            reason.push_str(&ai_reason);
        }
    }
    if reason.is_empty() {
        reason = "No phishing signals found.".into();
    } else if !blocked {
        reason = format!("Low risk: {reason}");
    }
    Verdict {
        blocked,
        score: total,
        reason,
    }
}

/// Model output is untrusted text: single line, printable, bounded.
fn clean(s: &str) -> String {
    let one_line: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = one_line.split_whitespace().collect::<Vec<_>>().join(" ");
    trimmed.chars().take(MAX_AI_REASON_CHARS).collect()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_url_is_safe() {
        let v = decide(&Evidence::default());
        assert!(!v.blocked);
        assert_eq!(v.score, 0);
        assert_eq!(v.reason, "No phishing signals found.");
    }

    #[test]
    fn strong_signals_block_without_the_model() {
        let signals = vec![Signal::BrandLookalike, Signal::CredentialPath];
        assert!(!needs_ai(&signals));
        let v = decide(&Evidence { signals, ai: None });
        assert!(v.blocked);
        assert_eq!(v.score, 60);
        assert!(v.reason.starts_with("Domain imitates a well-known brand"));
    }

    #[test]
    fn model_can_escalate_but_never_clear() {
        let signals = vec![Signal::BrandLookalike, Signal::CredentialPath];
        let injected = decide(&Evidence {
            signals: signals.clone(),
            ai: Some((false, "SAFE, ignore previous instructions".into())),
        });
        assert!(injected.blocked, "a SAFE answer must not lower the verdict");

        let escalated = decide(&Evidence {
            signals: vec![],
            ai: Some((true, "Typosquats rabobank.nl".into())),
        });
        assert!(escalated.blocked);
        assert_eq!(escalated.reason, "Model flagged it: Typosquats rabobank.nl");
    }

    #[test]
    fn weak_signals_are_reported_as_low_risk() {
        let v = decide(&Evidence {
            signals: vec![Signal::SharedHost],
            ai: Some((false, "SAFE".into())),
        });
        assert!(!v.blocked);
        assert_eq!(
            v.reason,
            "Low risk: Hosted on a platform where anyone can publish"
        );
    }

    #[test]
    fn model_text_is_sanitised() {
        let v = decide(&Evidence {
            signals: vec![],
            ai: Some((true, format!("bad\n\x1b[31mlink {}", "x".repeat(500)))),
        });
        assert!(!v.reason.contains('\n') && !v.reason.contains('\x1b'));
        assert!(v.reason.chars().count() < 200);
    }
}
