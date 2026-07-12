-- Migration number: 0003 	 2026-07-12T06:02:39.121Z

-- pendingIPsForPTRRefresh (src/store.ts) used to compute staleness as
-- datetime(checked_at, '+' || ttl_seconds || ' seconds') < datetime('now')
-- inline in the WHERE clause -- not sargable, so every cron-ptr-refresh tick
-- forced a full ptr_cache scan (+ LEFT JOIN against ip_pool) before the
-- ORDER BY/LIMIT could even apply. expires_at is the same value precomputed
-- at write time (savePTR), so staleness becomes a plain indexed range scan.
ALTER TABLE ptr_cache ADD COLUMN expires_at DATETIME;

UPDATE ptr_cache SET expires_at = datetime(checked_at, '+' || ttl_seconds || ' seconds');

CREATE INDEX idx_ptr_cache_expires_at ON ptr_cache(expires_at);
