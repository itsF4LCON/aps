-- Registration dates from RDAP, per registered domain.
CREATE TABLE IF NOT EXISTS domain_age (
    domain        TEXT    PRIMARY KEY,  -- registrable domain, e.g. example.co.uk
    registered_at INTEGER,              -- Unix seconds; NULL if the registry didn't say
    checked_at    INTEGER NOT NULL      -- Unix seconds
);
