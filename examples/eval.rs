//! Offline evaluation of the deterministic layer: trusted hosts plus URL
//! signals, exactly as `/scan` runs them, without Safe Browsing, the phishing
//! feed, domain age or the model.
//!
//!     eval/fetch.sh
//!     cargo run --release --example eval -- eval/data/phish.txt eval/data/benign.txt

use std::collections::{BTreeMap, HashSet};

use aps::{policy, signals, target, verdict};

/// The verdict `/scan` would give from the URL alone. `None` if `/scan` would
/// reject the URL as invalid.
fn judge(url: &str) -> Option<(String, bool, Vec<signals::Signal>)> {
    if !target::validate_url(url) {
        return None;
    }
    let t = target::parse(url).ok()?;
    if policy::is_trusted(&t) {
        return Some((t.host, false, Vec::new()));
    }
    let found = signals::analyze(&t);
    let v = verdict::decide(&verdict::Evidence {
        signals: found.clone(),
        ..verdict::Evidence::default()
    });
    Some((t.host, v.blocked, found))
}

#[derive(Default)]
struct Tally {
    total: usize,
    blocked: usize,
    hosts: usize,
    hosts_blocked: usize,
    skipped: usize,
    signals: BTreeMap<String, usize>,
    blocked_examples: Vec<String>,
}

impl Tally {
    fn run(urls: &[String]) -> Tally {
        let mut t = Tally::default();
        let mut seen_hosts = HashSet::new();
        for url in urls {
            let Some((host, blocked, found)) = judge(url) else {
                t.skipped += 1;
                continue;
            };
            t.total += 1;
            t.blocked += usize::from(blocked);
            // Phishing kits put hundreds of paths on one host; per host, only
            // the first URL in the list counts.
            if seen_hosts.insert(host) {
                t.hosts += 1;
                t.hosts_blocked += usize::from(blocked);
            }
            for s in &found {
                let name = serde_json::to_value(s).unwrap();
                *t.signals
                    .entry(name.as_str().unwrap().to_string())
                    .or_default() += 1;
            }
            if blocked {
                t.blocked_examples.push(url.clone());
            }
        }
        t
    }
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

fn read(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, phish_path, benign_path] = args.as_slice() else {
        eprintln!("usage: eval <phish.txt> <benign.txt>");
        std::process::exit(2);
    };
    let benign = read(benign_path);
    let benign_set: HashSet<&String> = benign.iter().collect();
    let all_phish = read(phish_path);
    let phish: Vec<String> = all_phish
        .iter()
        .filter(|u| !benign_set.contains(u))
        .cloned()
        .collect();

    let p = Tally::run(&phish);
    let b = Tally::run(&benign);
    let (tp, fp) = (p.blocked, b.blocked);
    println!("| | URLs | blocked | rate |");
    println!("|---|---:|---:|---:|");
    println!(
        "| phishing (OpenPhish) | {} | {} | {:.1}% detection |",
        p.total,
        tp,
        pct(tp, p.total)
    );
    println!(
        "| phishing, one URL per host | {} | {} | {:.1}% detection |",
        p.hosts,
        p.hosts_blocked,
        pct(p.hosts_blocked, p.hosts)
    );
    println!(
        "| legitimate (Tranco) | {} | {} | {:.2}% false positives |",
        b.total,
        fp,
        pct(fp, b.total)
    );
    println!();
    println!(
        "precision {:.1}% at this mix ({} phishing : {} legitimate)",
        pct(tp, tp + fp),
        p.total,
        b.total
    );
    println!(
        "removed {} phishing URLs that were also in the legitimate list; skipped {} + {} invalid",
        all_phish.len() - phish.len(),
        p.skipped,
        b.skipped
    );
    println!("\nsignal                  phishing  legitimate");
    let names: std::collections::BTreeSet<&String> =
        p.signals.keys().chain(b.signals.keys()).collect();
    for n in names {
        println!(
            "{n:<22} {:>9} {:>11}",
            p.signals.get(n).unwrap_or(&0),
            b.signals.get(n).unwrap_or(&0)
        );
    }
    println!("\nfalse positives:");
    for u in &b.blocked_examples {
        println!("  {u}");
    }
}
