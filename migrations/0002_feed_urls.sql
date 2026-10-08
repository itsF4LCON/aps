-- URLs from the OpenPhish community feed, refreshed by the cron trigger.
CREATE TABLE IF NOT EXISTS feed_urls (
    url       TEXT    PRIMARY KEY,  -- scheme://host/path, normalised like a scan's lookup URL
    host      TEXT    NOT NULL,
    last_seen INTEGER NOT NULL      -- Unix seconds of the last refresh that listed it
);
CREATE INDEX IF NOT EXISTS idx_feed_urls_host ON feed_urls(host);
