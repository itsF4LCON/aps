pub mod policy;
pub mod signals;
pub mod target;
pub mod verdict;

use serde::{Deserialize, Serialize};
use target::validate_url;
use worker::*;

const SCAN_RATE_LIMIT_MAX: u64 = 30;
const SCAN_RATE_LIMIT_WINDOW_SECS: u64 = 60;

const DEMO_RATE_LIMIT_MAX: u64 = 5;
const DEMO_RATE_LIMIT_WINDOW_SECS: u64 = 60;

const KEYGEN_RATE_LIMIT_MAX: u64 = 3;
const KEYGEN_RATE_LIMIT_WINDOW_SECS: u64 = 60 * 60;

const CACHE_TTL_SECS: i64 = 60 * 60 * 24 * 7;

const EXTENSION_ORIGINS: &[&str] = &["moz-extension://e21d4d0c-ba42-4f63-adbe-442a4a17d6ad"];

const SITE_ORIGINS: &[&str] = &["https://xivlabs.tech", "https://aps.xivlabs.tech"];

#[derive(Deserialize)]
struct ScanRequest {
    url: String,
}

/// `blocked` and `reason` are what the extension and site read; `score` and
/// `signals` were added later and are safe for older clients to ignore.
#[derive(Serialize)]
struct ScanResponse {
    blocked: bool,
    reason: String,
    score: u32,
    signals: Vec<signals::Signal>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct AiBody {
    messages: Vec<ChatMessage>,
    max_tokens: u32,
}

#[derive(Deserialize)]
struct AiResponse {
    response: String,
}

#[derive(Deserialize)]
struct CachedRow {
    threat_score: i32,
    flagged_at: String,
}

#[derive(Serialize)]
struct KeygenResponse {
    key: String,
}

enum Caller {
    Extension(String),
    Site(String),
    Api,
    Unknown,
}

async fn identify_caller(req: &Request, env: &Env) -> Result<Caller> {
    let origin = req.headers().get("Origin").unwrap_or(None);
    if let Some(o) = origin {
        if EXTENSION_ORIGINS.contains(&o.as_str()) {
            return Ok(Caller::Extension(o));
        }
        if SITE_ORIGINS.contains(&o.as_str()) {
            return Ok(Caller::Site(o));
        }
    }
    if let Ok(Some(provided_key)) = req.headers().get("X-API-Key") {
        let db = env.d1("phishing_db")?;
        let key_hash = sha256_hex(&provided_key);
        let stmt = db.prepare("SELECT 1 FROM api_keys WHERE key_hash = ?1 AND active = 1");
        let found = stmt
            .bind(&[key_hash.into()])?
            .first::<i32>(Some("1"))
            .await?;
        if found.is_some() {
            return Ok(Caller::Api);
        }
    }
    Ok(Caller::Unknown)
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// 128 bits from the platform CSPRNG (`crypto.getRandomValues` on Workers).
/// `Math.random()` is not cryptographically secure, so keys made with it were guessable.
fn generate_api_key() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| Error::RustError(format!("rng: {e}")))?;
    let body: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("aps_{body}"))
}

fn add_cors_headers(response: &mut Response, caller: &Caller) -> Result<()> {
    let origin = match caller {
        Caller::Extension(o) | Caller::Site(o) => o.as_str(),
        Caller::Api | Caller::Unknown => "*",
    };
    let headers = response.headers_mut();
    headers.set("Access-Control-Allow-Origin", origin)?;
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")?;
    Ok(())
}

fn client_ip(req: &Request) -> String {
    req.headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".into())
}

async fn is_rate_limited(
    kv: &kv::KvStore,
    prefix: &str,
    ip: &str,
    max: u64,
    window_secs: u64,
) -> Result<bool> {
    let bucket = Date::now().as_millis() / 1000 / window_secs;
    let key = format!("rl:{}:{}:{}", prefix, ip, bucket);
    let count: u64 = match kv.get(&key).text().await? {
        Some(v) => v.parse().unwrap_or(0),
        None => 0,
    };
    if count >= max {
        return Ok(true);
    }
    kv.put(&key, (count + 1).to_string())?
        .expiration_ttl(window_secs * 2)
        .execute()
        .await?;
    Ok(false)
}

fn is_cache_stale(flagged_at: &str) -> bool {
    let now_secs = Date::now().as_millis() / 1000;
    let cutoff = now_secs as i64 - CACHE_TTL_SECS;
    let parts: Vec<&str> = flagged_at.split_whitespace().collect();
    if parts.len() != 2 {
        return true;
    }
    let d: Vec<i64> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
    let t: Vec<i64> = parts[1].split(':').filter_map(|s| s.parse().ok()).collect();
    if d.len() != 3 || t.len() != 3 {
        return true;
    }
    let approx = (d[0] - 1970) * 31_536_000
        + (d[1] - 1) * 2_592_000
        + (d[2] - 1) * 86_400
        + t[0] * 3_600
        + t[1] * 60
        + t[2];
    approx < cutoff
}

fn err(msg: &str, status: u16) -> Result<Response> {
    Response::error(msg, status)
}

fn bad_request(msg: &str, caller: &Caller) -> Result<Response> {
    let mut res = err(msg, 400)?;
    add_cors_headers(&mut res, caller)?;
    Ok(res)
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        let mut res = Response::empty()?;
        res.headers_mut().set("Access-Control-Allow-Origin", "*")?;
        res.headers_mut()
            .set("Access-Control-Allow-Methods", "POST, OPTIONS")?;
        res.headers_mut()
            .set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")?;
        return Ok(res);
    }

    let path = req.path();

    if path == "/keygen" && req.method() == Method::Post {
        let ip = client_ip(&req);
        let kv = env.kv("RATE_LIMIT_KV")?;
        if is_rate_limited(
            &kv,
            "keygen",
            &ip,
            KEYGEN_RATE_LIMIT_MAX,
            KEYGEN_RATE_LIMIT_WINDOW_SECS,
        )
        .await?
        {
            let mut res = err("Rate limit exceeded. Try again later.", 429)?;
            res.headers_mut().set("Retry-After", "3600")?;
            res.headers_mut().set("Access-Control-Allow-Origin", "*")?;
            return Ok(res);
        }

        let key = generate_api_key()?;
        let key_hash = sha256_hex(&key);
        let db = env.d1("phishing_db")?;
        let stmt = db.prepare(
            "INSERT INTO api_keys (key_hash, active, created_at) VALUES (?1, 1, CURRENT_TIMESTAMP)",
        );
        stmt.bind(&[key_hash.into()])?.run().await?;
        let body = KeygenResponse { key };
        let mut res = Response::from_json(&body)?;
        res.headers_mut().set("Access-Control-Allow-Origin", "*")?;
        return Ok(res);
    }

    if path != "/scan" || req.method() != Method::Post {
        return err("Not found", 404);
    }

    let caller = identify_caller(&req, &env).await?;
    if matches!(caller, Caller::Unknown) {
        let mut res = err("Unauthorized", 401)?;
        add_cors_headers(&mut res, &Caller::Unknown)?;
        return Ok(res);
    }

    let ip = client_ip(&req);
    let kv = env.kv("RATE_LIMIT_KV")?;
    let (rl_prefix, rl_max, rl_window) = match caller {
        Caller::Site(_) => ("demo", DEMO_RATE_LIMIT_MAX, DEMO_RATE_LIMIT_WINDOW_SECS),
        _ => ("scan", SCAN_RATE_LIMIT_MAX, SCAN_RATE_LIMIT_WINDOW_SECS),
    };
    if is_rate_limited(&kv, rl_prefix, &ip, rl_max, rl_window).await? {
        let mut res = err("Rate limit exceeded. Try again in 60 seconds.", 429)?;
        res.headers_mut().set("Retry-After", "60")?;
        add_cors_headers(&mut res, &caller)?;
        return Ok(res);
    }

    let mut req = req;
    let payload: ScanRequest = match req.json().await {
        Ok(p) => p,
        Err(_) => return bad_request("Invalid JSON payload", &caller),
    };
    if !validate_url(&payload.url) {
        return bad_request("Invalid or disallowed URL", &caller);
    }

    let target = match target::parse(&payload.url) {
        Ok(t) => t,
        Err(msg) => return bad_request(msg, &caller),
    };

    if policy::is_trusted(&target) {
        let mut res = Response::from_json(&ScanResponse {
            blocked: false,
            reason: "Verified trusted host.".into(),
            score: 0,
            signals: Vec::new(),
        })?;
        add_cors_headers(&mut res, &caller)?;
        return Ok(res);
    }

    let mut evidence = verdict::Evidence {
        signals: signals::analyze(&target),
        ai: None,
    };
    if verdict::needs_ai(&evidence.signals) {
        evidence.ai = Some(ai_opinion(&env, &target).await?);
    }

    let v = verdict::decide(&evidence);
    let mut res = Response::from_json(&ScanResponse {
        blocked: v.blocked,
        reason: v.reason,
        score: v.score,
        signals: evidence.signals,
    })?;
    add_cors_headers(&mut res, &caller)?;
    Ok(res)
}

/// The model's BLOCK/SAFE opinion on a hostname, cached per host in D1.
async fn ai_opinion(env: &Env, target: &target::Target) -> Result<(bool, String)> {
    let db = env.d1("phishing_db")?;
    let cached = db
        .prepare("SELECT threat_score, flagged_at FROM blocked_domains WHERE domain = ?1")
        .bind(&[target.host.clone().into()])?
        .first::<CachedRow>(None)
        .await?;
    if let Some(row) = cached {
        if !is_cache_stale(&row.flagged_at) {
            return Ok((row.threat_score > 80, String::new()));
        }
    }

    let ai = env.ai("AI")?;
    let input = AiBody {
        messages: vec![
            ChatMessage {
                role: "system".into(),
                content: "You are a phishing detector. Evaluate a hostname from an \
                           email link. ONLY output 'BLOCK' if the domain is clearly \
                           typosquatting or impersonating a known brand (e.g. paypa1.com, \
                           paypal.com.account-check.example) or is a known scam domain. \
                           Otherwise output 'SAFE'. Provide a max 15-word reason."
                    .into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!("Hostname: {}", target.host),
            },
        ],
        max_tokens: 60,
    };

    let ai_result: AiResponse = ai
        .run("@cf/meta/llama-3.1-8b-instruct-fast", &input)
        .await?;
    let is_malicious = ai_result.response.to_uppercase().contains("BLOCK");
    let score: i32 = if is_malicious { 90 } else { 0 };

    db.prepare(
        "INSERT INTO blocked_domains (domain, threat_score, flagged_at) \
         VALUES (?1, ?2, CURRENT_TIMESTAMP) \
         ON CONFLICT(domain) DO UPDATE SET \
           threat_score = excluded.threat_score, \
           flagged_at   = CURRENT_TIMESTAMP",
    )
    .bind(&[target.host.clone().into(), score.into()])?
    .run()
    .await?;

    Ok((is_malicious, ai_result.response))
}
