-- Index for topIPsForPublish's filter+sort (src/store.ts): WHERE is_ipv6=?
-- AND last_check_ok=1 AND last_rtt_ms IS NOT NULL ORDER BY times_seen DESC,
-- last_rtt_ms ASC LIMIT n. Without a covering index this sorts the full
-- filtered set every call (syncPublish runs it twice per ingest, and
-- functions/check.ts per on-demand probe) — ~6.6k rows read per call.
CREATE INDEX idx_ip_pool_publish ON ip_pool(is_ipv6, last_check_ok, times_seen DESC, last_rtt_ms ASC);

-- Index for listKnownIPs's default ordering (ORDER BY last_seen DESC) --
-- the home page's full-pool listing, 7.7k rows per call without it.
CREATE INDEX idx_ip_pool_last_seen ON ip_pool(last_seen DESC);
