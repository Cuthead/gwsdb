-- Migration number: 0005 	 2026-07-12T11:23:39.000Z

-- pendingIPsForPTRRefresh dropped TTL-based staleness for a straight
-- round-robin (oldest-checked-first, full pool cycled roughly daily) --
-- see src/store.ts's module comment. That needs a per-pool-member "when did
-- we last refresh this IP's PTR" cursor that ORDER BY ... LIMIT can seek on
-- directly. ptr_cache.checked_at can't serve that: ptr_cache is a general
-- IP->PTR cache keyed by any IP ever queried (functions/query.ts's ad-hoc
-- /query?ip= path caches misses there too), not just current ip_pool
-- members, and it isn't cleaned up when an IP falls out of ip_pool -- a
-- LEFT JOIN to it for ordering would force a full-pool scan+sort every
-- tick, the same cost this migration exists to avoid. ptr_checked_at is a
-- deliberate denormalization: savePTR now writes both this column and
-- ptr_cache.checked_at in the same db.batch(), so the round-robin cursor
-- stays index-backed while ptr_cache keeps serving the general cache role.
ALTER TABLE ip_pool ADD COLUMN ptr_checked_at DATETIME;

UPDATE ip_pool SET ptr_checked_at = (
	SELECT checked_at FROM ptr_cache WHERE ptr_cache.ip = ip_pool.ip
);

-- NULL (never PTR-checked) sorts first in SQLite's default ASC ordering,
-- so this index also gives "unchecked IPs first" for free without a
-- separate missing-IP query.
CREATE INDEX idx_ip_pool_ptr_checked_at ON ip_pool(ptr_checked_at);

-- expires_at (added by migration 0003) was the old TTL-staleness scheduling
-- optimization; the round-robin scheduler above replaces the query it
-- existed for. ttl_seconds/checked_at stay on ptr_cache -- getPTR still
-- uses them for the ad-hoc /query?ip= freshness check, which is unrelated
-- to background refresh scheduling.
DROP INDEX idx_ptr_cache_expires_at;

ALTER TABLE ptr_cache DROP COLUMN expires_at;
