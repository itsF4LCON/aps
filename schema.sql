CREATE TABLE IF NOT EXISTS verdict_cache (
    url        TEXT    PRIMARY KEY,  -- scheme://host/path, no query string
    reputation TEXT,                 -- Safe Browsing threat label, NULL if not listed
    ai_block   INTEGER,              -- 1 BLOCK, 0 SAFE, NULL if the model was not asked
    ai_reason  TEXT,
    checked_at INTEGER NOT NULL      -- Unix seconds
);

CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash   TEXT    NOT NULL UNIQUE,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_key_hash ON api_keys(key_hash);
CREATE TABLE IF NOT EXISTS feed_urls (
    url       TEXT    PRIMARY KEY,  -- scheme://host/path, normalised like a scan's lookup URL
    host      TEXT    NOT NULL,
    last_seen INTEGER NOT NULL      -- Unix seconds of the last refresh that listed it
);
CREATE INDEX IF NOT EXISTS idx_feed_urls_host ON feed_urls(host);

CREATE TABLE IF NOT EXISTS domain_age (
    domain        TEXT    PRIMARY KEY,  -- registrable domain, e.g. example.co.uk
    registered_at INTEGER,              -- Unix seconds; NULL if the registry didn't say
    checked_at    INTEGER NOT NULL      -- Unix seconds
);
