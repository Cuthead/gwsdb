-- Migration number: 0017 	 2026-09-04T00:00:00.000Z
--
-- overview()'s lastCheckAt was the only consumer of idx_ip_pool_last_checked_at
-- (migration 0012). It now reads the newest ip_checks row instead (ORDER BY id
-- DESC LIMIT 1 -- a 1-row rowid seek, same cost as the index top-1), so the
-- index only added cost: every ip_pool mutation changes last_checked_at and
-- therefore rewrote this index entry -- ~12.5k rows written/day, ~11% of the
-- daily write budget, for one cached-adjacent top-1 query.
DROP INDEX idx_ip_pool_last_checked_at;
