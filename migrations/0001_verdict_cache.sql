-- Per-URL cache of the remote checks (reputation feed and model), with Unix
-- timestamps. Replaces blocked_domains, which cached one verdict per base
-- domain with a 7-day TTL for every result.
CREATE TABLE IF NOT EXISTS verdict_cache (
    url        TEXT    PRIMARY KEY,  -- scheme://host/path, no query string
    reputation TEXT,                 -- Safe Browsing threat label, NULL if not listed
    ai_block   INTEGER,              -- 1 BLOCK, 0 SAFE, NULL if the model was not asked
    ai_reason  TEXT,
    checked_at INTEGER NOT NULL      -- Unix seconds
);

-- The old cache is no longer read. Its rows are disposable; drop it once the
-- new Worker is deployed:
-- DROP TABLE IF EXISTS blocked_domains;
