-- Migration number: 0002 	 2026-07-11T20:01:27.961Z

-- ip_pool was a VIEW recomputed live (window functions over all of
-- ip_checks) on every reference, regardless of selectivity -- even a
-- single-IP lookup or a COUNT(*) had to materialize the whole windowed
-- result first. D1 Query Insights showed this dominating daily rows-read.
-- Converts it to a real table, maintained incrementally by
-- refreshPoolForIPs (src/store.ts) after every ip_checks write, scoped to
-- just the IPs that write touched.
DROP VIEW ip_pool;

CREATE TABLE ip_pool (
	ip              TEXT PRIMARY KEY,
	is_ipv6         INTEGER NOT NULL,
	scan_mode       TEXT,
	first_seen      DATETIME,
	last_seen       DATETIME,
	last_scan_id    INTEGER,
	last_rtt_ms     INTEGER,
	times_seen      INTEGER NOT NULL,
	last_checked_at DATETIME,
	last_check_ok   INTEGER
);

-- One-time backfill using the exact aggregation the old view had, unscoped,
-- to populate every IP already in ip_checks.
INSERT INTO ip_pool (ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok)
WITH ranked AS (
	SELECT
		ip, ok, rtt_ms, scan_id, scan_mode, checked_at,
		ROW_NUMBER() OVER (PARTITION BY ip ORDER BY checked_at DESC, id DESC) AS rn_any,
		ROW_NUMBER() OVER (PARTITION BY ip, ok ORDER BY checked_at DESC, id DESC) AS rn_ok_desc,
		ROW_NUMBER() OVER (PARTITION BY ip, ok ORDER BY checked_at ASC, id ASC) AS rn_ok_asc
	FROM ip_checks
),
counts AS (
	SELECT
		ip,
		CASE WHEN instr(ip, ':') > 0 THEN 1 ELSE 0 END AS is_ipv6,
		COUNT(CASE WHEN ok = 1 THEN 1 END) AS times_seen
	FROM ip_checks
	GROUP BY ip
	HAVING times_seen > 0
)
SELECT
	counts.ip            AS ip,
	counts.is_ipv6       AS is_ipv6,
	last_ok.scan_mode    AS scan_mode,
	first_ok.checked_at  AS first_seen,
	last_ok.checked_at   AS last_seen,
	last_ok.scan_id      AS last_scan_id,
	last_ok.rtt_ms       AS last_rtt_ms,
	counts.times_seen    AS times_seen,
	last_any.checked_at  AS last_checked_at,
	last_any.ok          AS last_check_ok
FROM counts
JOIN ranked last_ok  ON last_ok.ip = counts.ip  AND last_ok.ok = 1 AND last_ok.rn_ok_desc = 1
JOIN ranked first_ok ON first_ok.ip = counts.ip AND first_ok.ok = 1 AND first_ok.rn_ok_asc = 1
JOIN ranked last_any ON last_any.ip = counts.ip AND last_any.rn_any = 1;
