-- Index for "latest check" queries (overview's lastCheckAt, now derived
-- from ip_pool but other paths may still need it). Without this, ORDER BY
-- checked_at DESC LIMIT 1 does a full table scan on ip_checks (134k+ rows).
CREATE INDEX idx_ip_checks_checked_at ON ip_checks(checked_at DESC, id DESC);

-- Index for "most recently checked IP" query in the rewritten overview()
-- (MAX(last_checked_at) + scan_mode of that row from ip_pool). Without
-- this, ORDER BY last_checked_at DESC LIMIT 1 scans all of ip_pool.
CREATE INDEX idx_ip_pool_last_checked_at ON ip_pool(last_checked_at DESC);
