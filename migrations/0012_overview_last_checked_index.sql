-- Migration number: 0012 	2026-08-22

-- Index for overview()'s last-check query (src/store.ts): ORDER BY
-- last_checked_at DESC LIMIT 1 was a full ip_pool scan + top-1 sort
-- (~7.8k rows read) on every /api/pool and /api/pool/changes cache miss.
-- With this index it's a 1-row seek, so lastCheckAt/scanMode can stay
-- live-fresh (unlike the COUNT/SUM aggregates, which are TTL-cached --
-- see overview's comment). DESC to match the query's direction, same
-- style as 0009's idx_ip_pool_last_seen.
-- IF NOT EXISTS: this index was hotfixed onto prod by hand before the
-- migration landed, so the plain CREATE failed with "index already exists"
-- and d1_migrations never recorded 0012 -- idempotent form lets the
-- migration bookkeeping catch up without touching the live index.
CREATE INDEX IF NOT EXISTS idx_ip_pool_last_checked_at ON ip_pool(last_checked_at DESC);
