-- Migration number: 0019 	 2026-09-08T00:00:00.000Z
--
-- Generalize the probe rate limiter for the query page. Counters are now
-- per (kind, client_ip, window): kind "probe" is the on-demand probe button
-- (functions/check.ts, per-UTC-minute) and kind "query" is the query page's
-- live DNS lookups (functions/query.ts, per-UTC-hour). Separate kinds so the
-- probe button's tight per-minute budget and the query page's generous
-- hourly budget don't pollute each other's counters.
--
-- Why an hourly query limiter: a single enumeration crawl through /query
-- (one pass over every known IP plus every cached hostname) rewrote ~25k
-- ptr_cache/host_cache/ip_pool rows in under four hours -- TTL-driven cache
-- refills only write when someone reads, but nothing bounded the readers.
--
-- Rebuild rather than ALTER TABLE because the PK gains a column. Rows are
-- ephemeral per-minute counters pruned lazily, so dropping them at most
-- resets the current window -- no backfill needed.
DROP TABLE check_rate_limit;
CREATE TABLE check_rate_limit (
	kind       TEXT NOT NULL,
	client_ip  TEXT NOT NULL,
	window     TEXT NOT NULL,  -- ISO UTC bucket start: 'YYYY-MM-DDTHH:MM' (probe) / 'YYYY-MM-DDTHH:00' (query)
	count      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (kind, client_ip, window)
);
