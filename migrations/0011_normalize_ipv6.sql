-- Normalize historical IPv6 text keys so equivalent spellings share one
-- ip_checks history and one ip_pool row. New writes are normalized by
-- src/ipAddr.ts before reaching D1.

CREATE TABLE ipv6_normalization (
	old_ip TEXT PRIMARY KEY,
	new_ip TEXT NOT NULL
);

INSERT INTO ipv6_normalization (old_ip, new_ip)
WITH sources AS (
	SELECT DISTINCT ip AS old_ip, instr(ip, '::') AS compression_at
	FROM ip_checks
	WHERE instr(ip, ':') > 0
),
halves AS (
	SELECT old_ip,
		CASE WHEN compression_at = 0 THEN old_ip ELSE substr(old_ip, 1, compression_at - 1) END AS head,
		CASE WHEN compression_at = 0 THEN '' ELSE substr(old_ip, compression_at + 2) END AS tail
	FROM sources
),
arrays AS (
	SELECT old_ip,
		CASE WHEN head = '' THEN '[]' ELSE '["' || replace(head, ':', '","') || '"]' END AS head_json,
		CASE WHEN tail = '' THEN '[]' ELSE '["' || replace(tail, ':', '","') || '"]' END AS tail_json
	FROM halves
),
array_sizes AS (
	SELECT old_ip, head_json, tail_json,
		json_array_length(head_json) AS head_count,
		json_array_length(tail_json) AS tail_count
	FROM arrays
),
indices(i) AS (VALUES (0), (1), (2), (3), (4), (5), (6), (7)),
expanded_groups AS (
	SELECT old_ip, i,
		CASE
			WHEN i < head_count THEN json_extract(head_json, '$[' || i || ']')
			WHEN i >= 8 - tail_count THEN json_extract(tail_json, '$[' || (i - (8 - tail_count)) || ']')
			ELSE '0'
		END AS raw_group
	FROM array_sizes CROSS JOIN indices
),
normalized_groups AS (
	SELECT sizes.old_ip, (
		SELECT group_concat(part, ':') FROM (
			SELECT i, CASE WHEN ltrim(raw_group, '0') = '' THEN '0' ELSE lower(ltrim(raw_group, '0')) END AS part
			FROM expanded_groups
			WHERE old_ip = sizes.old_ip
			ORDER BY i
		)
	) AS base
	FROM array_sizes AS sizes
),
runs(groups, pattern) AS (
	VALUES
		(8, ':0:0:0:0:0:0:0:0:'),
		(7, ':0:0:0:0:0:0:0:'),
		(6, ':0:0:0:0:0:0:'),
		(5, ':0:0:0:0:0:'),
		(4, ':0:0:0:0:'),
		(3, ':0:0:0:'),
		(2, ':0:0:')
),
chosen AS (
	SELECT old_ip, base, ':' || base || ':' AS padded,
		COALESCE((
			SELECT pattern FROM runs
			WHERE instr(':' || base || ':', pattern) > 0
			ORDER BY groups DESC
			LIMIT 1
		), '') AS pattern
	FROM normalized_groups
)
SELECT old_ip,
	CASE WHEN pattern = '' THEN base ELSE
		CASE WHEN instr(padded, pattern) = 1 THEN '' ELSE substr(padded, 2, instr(padded, pattern) - 2) END
		|| '::' ||
		CASE
			WHEN instr(padded, pattern) + length(pattern) > length(padded) THEN ''
			ELSE substr(
				padded,
				instr(padded, pattern) + length(pattern),
				length(padded) - instr(padded, pattern) - length(pattern)
			)
		END
	END AS new_ip
FROM chosen;

UPDATE ip_checks
SET ip = (SELECT new_ip FROM ipv6_normalization WHERE old_ip = ip_checks.ip)
WHERE ip IN (SELECT old_ip FROM ipv6_normalization);

-- PTR rows are disposable cache entries and may collide after normalization.
DELETE FROM ptr_cache WHERE instr(ip, ':') > 0;

-- Rebuild IPv6 pool aggregates after aliases have merged in ip_checks.
UPDATE pool_revision SET version = version + 1 WHERE singleton = 1;
DELETE FROM ip_pool WHERE is_ipv6 = 1;

INSERT INTO ip_pool (
	ip, is_ipv6, scan_mode, first_seen, last_seen, last_rtt_ms,
	times_seen, last_checked_at, last_check_ok, revision
)
WITH ranked AS (
	SELECT ip, ok, rtt_ms, scan_mode, checked_at,
		ROW_NUMBER() OVER (PARTITION BY ip ORDER BY checked_at DESC, id DESC) AS rn_any,
		ROW_NUMBER() OVER (PARTITION BY ip, ok ORDER BY checked_at DESC, id DESC) AS rn_ok_desc,
		ROW_NUMBER() OVER (PARTITION BY ip, ok ORDER BY checked_at ASC, id ASC) AS rn_ok_asc
	FROM ip_checks
	WHERE instr(ip, ':') > 0
),
counts AS (
	SELECT ip, COUNT(CASE WHEN ok = 1 THEN 1 END) AS times_seen
	FROM ip_checks
	WHERE instr(ip, ':') > 0
	GROUP BY ip
	HAVING times_seen > 0
)
SELECT counts.ip, 1, last_ok.scan_mode, first_ok.checked_at,
	last_ok.checked_at, last_ok.rtt_ms, counts.times_seen,
	last_any.checked_at, last_any.ok,
	(SELECT version FROM pool_revision WHERE singleton = 1)
FROM counts
JOIN ranked last_ok ON last_ok.ip = counts.ip AND last_ok.ok = 1 AND last_ok.rn_ok_desc = 1
JOIN ranked first_ok ON first_ok.ip = counts.ip AND first_ok.ok = 1 AND first_ok.rn_ok_asc = 1
JOIN ranked last_any ON last_any.ip = counts.ip AND last_any.rn_any = 1;

DROP TABLE ipv6_normalization;
