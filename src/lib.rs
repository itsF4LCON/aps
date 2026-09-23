use serde::{Deserialize, Serialize};
use worker::*;

const MAX_URL_LENGTH: usize = 2048;

const SCAN_RATE_LIMIT_MAX: u64 = 30;
const SCAN_RATE_LIMIT_WINDOW_SECS: u64 = 60;

const KEYGEN_RATE_LIMIT_MAX: u64 = 3;
const KEYGEN_RATE_LIMIT_WINDOW_SECS: u64 = 60 * 60;

const CACHE_TTL_SECS: i64 = 60 * 60 * 24 * 7;

const EXTENSION_ORIGINS: &[&str] = &[
    "chrome-extension://EXTENSION_ID_NOT_SET",
    "moz-extension://e21d4d0c-ba42-4f63-adbe-442a4a17d6ad",
];

#[derive(Deserialize)]
struct ScanRequest {
    url: String,
}

#[derive(Serialize)]
struct ScanResponse {
    blocked: bool,
    reason: String,
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
    Api,
    Unknown,
}

async fn identify_caller(req: &Request, env: &Env) -> Result<Caller> {
    let origin = req.headers().get("Origin").unwrap_or(None);
    if let Some(o) = origin {
        if EXTENSION_ORIGINS.contains(&o.as_str()) {
            return Ok(Caller::Extension(o));
        }
    }
    if let Ok(Some(provided_key)) = req.headers().get("X-API-Key") {
        let db = env.d1("phishing_db")?;
        let key_hash = sha256_hex(&provided_key);
        let stmt = db.prepare("SELECT 1 FROM api_keys WHERE key_hash = ?1 AND active = 1");
        let found = stmt.bind(&[key_hash.into()])?.first::<i32>(Some("1")).await?;
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

fn generate_api_key() -> String {
    use js_sys::Math;
    let part = || {
        let r = (Math::random() * 4_294_967_295.0) as u32;
        format!("{:08x}", r)
    };
    let key_body: String = (0..4).map(|_| part()).collect();
    format!("aps_{}", key_body)
}

fn add_cors_headers(response: &mut Response, caller: &Caller) -> Result<()> {
    let origin = match caller {
        Caller::Extension(o) => o.as_str(),
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

fn validate_url(url: &str) -> bool {
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

fn extract_base_domain(full_domain: &str) -> String {
    let parts: Vec<&str> = full_domain.split('.').collect();
    if parts.len() > 2 {
        let sld = parts[parts.len() - 2];
        if matches!(sld, "co" | "com" | "net" | "org") {
            return parts[parts.len().saturating_sub(3)..].join(".");
        }
        return parts[parts.len().saturating_sub(2)..].join(".");
    }
    full_domain.to_string()
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

const TRUSTED_DOMAINS: &[&str] = &[
    "google.com",
    "github.com",
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "catawiki.com",
    "catawiki.nl",
];

fn err(msg: &str, status: u16) -> Result<Response> {
    Response::error(msg, status)
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

        let key = generate_api_key();
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
    if is_rate_limited(&kv, "scan", &ip, SCAN_RATE_LIMIT_MAX, SCAN_RATE_LIMIT_WINDOW_SECS).await? {
        let mut res = err("Rate limit exceeded. Try again in 60 seconds.", 429)?;
        res.headers_mut().set("Retry-After", "60")?;
        add_cors_headers(&mut res, &caller)?;
        return Ok(res);
    }

    let mut req = req;
    let payload: ScanRequest = match req.json().await {
        Ok(p) => p,
        Err(_) => return err("Invalid JSON payload", 400),
    };
    if !validate_url(&payload.url) {
        return err("Invalid or disallowed URL", 400);
    }

    let parsed_url = match url::Url::parse(&payload.url) {
        Ok(u) => u,
        Err(_) => return err("Malformed URL", 400),
    };
    let full_domain = match parsed_url.domain() {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => return err("No domain found in URL", 400),
    };
    let base_domain = extract_base_domain(&full_domain);

    if TRUSTED_DOMAINS.iter().any(|&td| base_domain == td) {
        let mut res = Response::from_json(&ScanResponse {
            blocked: false,
            reason: "Verified trusted domain.".into(),
        })?;
        add_cors_headers(&mut res, &caller)?;
        return Ok(res);
    }

    let db = env.d1("phishing_db")?;
    let cached = db
        .prepare("SELECT threat_score, flagged_at FROM blocked_domains WHERE domain = ?1")
        .bind(&[base_domain.clone().into()])?
        .first::<CachedRow>(None)
        .await?;

    if let Some(row) = cached {
        if !is_cache_stale(&row.flagged_at) {
            let blocked = row.threat_score > 80;
            let mut res = Response::from_json(&ScanResponse {
                blocked,
                reason: if blocked {
                    "Base domain found in known threat database.".into()
                } else {
                    "Base domain verified as safe in cache.".into()
                },
            })?;
            add_cors_headers(&mut res, &caller)?;
            return Ok(res);
        }
    }

    let ai = env.ai("AI")?;
    let input = AiBody {
        messages: vec![
            ChatMessage {
                role: "system".into(),
                content: "You are a phishing detector. Evaluate a parsed base domain from an \
                           email link. ONLY output 'BLOCK' if the domain is clearly \
                           typosquatting a known brand (e.g. paypa1.com) or is a known scam \
                           domain. Otherwise output 'SAFE'. Provide a max 15-word reason."
                    .into(),
            },
            ChatMessage {
                role: "user".into(),
                content: format!("Base Domain: {}", base_domain),
            },
        ],
        max_tokens: 60,
    };

    let ai_result: AiResponse = ai.run("@cf/meta/llama-3.1-8b-instruct-fast", &input).await?;
    let is_malicious = ai_result.response.to_uppercase().contains("BLOCK");
    let score: i32 = if is_malicious { 90 } else { 0 };

    db.prepare(
        "INSERT INTO blocked_domains (domain, threat_score, flagged_at) \
         VALUES (?1, ?2, CURRENT_TIMESTAMP) \
         ON CONFLICT(domain) DO UPDATE SET \
           threat_score = excluded.threat_score, \
           flagged_at   = CURRENT_TIMESTAMP",
    )
    .bind(&[base_domain.into(), score.into()])?
    .run()
    .await?;

    let mut res = Response::from_json(&ScanResponse {
        blocked: is_malicious,
        reason: ai_result.response.trim().to_string(),
    })?;
    add_cors_headers(&mut res, &caller)?;
    Ok(res)
}
