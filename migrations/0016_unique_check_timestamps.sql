-- Retried flushes re-insert identical checks. The scanner requeues a whole
-- buffer when /ingest fails partway (e.g. daily quota exhausted during
-- updatePoolBatch after insertCheckRows already committed), and each retry
-- inserted the same rows again -- one IP accumulated 285 duplicate rows of
-- 15 real probes. Enforce (ip, checked_at) uniqueness so re-submission is a
-- no-op instead.

-- Keep the first insert of each duplicated (ip, checked_at) pair.
DELETE FROM ip_checks
WHERE id NOT IN (
	SELECT MIN(id) FROM ip_checks GROUP BY ip, checked_at
);

-- Same columns as the old non-unique idx_ip_checks_ip (0001), so write cost
-- is unchanged; only the uniqueness constraint is new.
DROP INDEX idx_ip_checks_ip;
CREATE UNIQUE INDEX idx_ip_checks_ip ON ip_checks(ip, checked_at);

-- Dedup shrank retained histories; resync the maintained counts.
UPDATE ip_pool
SET history_count = (SELECT COUNT(*) FROM ip_checks WHERE ip_checks.ip = ip_pool.ip);
