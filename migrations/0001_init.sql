-- Migration number: 0001 	 2026-07-11T16:12:53.168Z
--
-- Ported from internal/store/store.go's `schema` + `ipPoolViewSQL` (Go/SQLite
-- version, git history has the full evolution). This is a fresh D1 database
-- with no prior rows, so none of the old ALTER-TABLE/backfill migrations
-- that store.go's migrate() carries for pre-existing SQLite files are
-- needed here -- the schema starts directly at its current shape.

CREATE TABLE scans (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_mode          TEXT NOT NULL,
	server_name        TEXT,
	verify_common_name TEXT,
	http_path          TEXT,
	http_method        TEXT,
	http_verify_hosts  TEXT,
	valid_status_code  INTEGER,
	input_file         TEXT,
	output_file        TEXT,
	level              INTEGER,
	config_json        TEXT,
	log_text           TEXT,
	started_at         DATETIME,
	finished_at        DATETIME,
	scanned_count      INTEGER,
	found_count        INTEGER,
	created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ip_checks is the append-only availability history: every pass/fail probe,
-- scan-driven or report-triggered recheck. The tracked "pool" of known-good
-- IPs and their aggregates (first/last seen, times seen, etc.) are never
-- stored -- they're derived live from this table by the ip_pool view below,
-- so deleting or editing history here can never leave a stale aggregate
-- behind.
CREATE TABLE ip_checks (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id        INTEGER REFERENCES scans(id), -- NULL for report-triggered rechecks (no owning scan)
	config_scan_id INTEGER REFERENCES scans(id), -- for rechecks: the scan whose config the probe ran with
	ip             TEXT NOT NULL,
	ok             INTEGER NOT NULL,
	rtt_ms         INTEGER,
	reason         TEXT, -- e.g. dial/handshake/cn/http/status/ping; NULL for successes
	detail         TEXT, -- e.g. "error=..." / "got_cn=..." / "got_code=..."
	checked_at     DATETIME NOT NULL,
	scan_mode      TEXT -- the scan mode in effect for this probe (e.g. "SNI")
);
CREATE INDEX idx_ip_checks_ip ON ip_checks(ip, checked_at);
CREATE INDEX idx_ip_checks_ip_ok ON ip_checks(ip, ok, checked_at);
CREATE INDEX idx_ip_checks_scan_id ON ip_checks(scan_id);

-- ttl_seconds on the three *_cache tables is the DNS TTL observed at
-- checked_at (DoH wire-format responses carry it per record; the minimum
-- across a lookup's records should be stored, floored so a 0/near-0 TTL
-- doesn't force a fresh DoH round trip on every request). A row is stale
-- once checked_at + ttl_seconds has passed, rather than any fixed cache
-- lifetime.
CREATE TABLE ptr_cache (
	ip            TEXT PRIMARY KEY,
	ptr_hostname  TEXT,
	lookup_ok     INTEGER NOT NULL DEFAULT 1,
	ttl_seconds   INTEGER NOT NULL DEFAULT 0,
	checked_at    DATETIME NOT NULL
);

CREATE TABLE asn_cache (
	ip            TEXT PRIMARY KEY,
	asn           INTEGER,
	as_name       TEXT,
	prefix        TEXT,
	country       TEXT,
	lookup_ok     INTEGER NOT NULL DEFAULT 1,
	ttl_seconds   INTEGER NOT NULL DEFAULT 0,
	checked_at    DATETIME NOT NULL
);

-- host_cache is the forward-lookup counterpart to ptr_cache: A/AAAA records
-- for a 1e100.net hostname queried directly (see the query page's
-- hostname-mode). ipv4/ipv6 are "; "-joined lists, same packing as
-- ptr_cache.ptr_hostname.
CREATE TABLE host_cache (
	hostname      TEXT PRIMARY KEY,
	ipv4          TEXT,
	ipv6          TEXT,
	lookup_ok     INTEGER NOT NULL DEFAULT 1,
	ttl_seconds   INTEGER NOT NULL DEFAULT 0,
	checked_at    DATETIME NOT NULL
);

CREATE TABLE ip_reports (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	ip                TEXT NOT NULL,
	verdict           INTEGER NOT NULL,
	comment           TEXT,
	reporter_prefix   TEXT,
	reporter_asn      INTEGER,
	reporter_as_name  TEXT,
	created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ip_reports_ip ON ip_reports(ip, created_at);

-- recheck_queue holds one pending re-scan per user report that disagreed
-- with our last known status for that IP (and postdated it). A report is
-- enqueued at most once -- UNIQUE(report_id) plus the fact that enqueueing
-- only happens once, right after the report is saved, is what makes "one
-- check per report" hold even though the worker may run long after.
CREATE TABLE recheck_queue (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id    INTEGER NOT NULL REFERENCES ip_reports(id),
	ip           TEXT NOT NULL,
	created_at   DATETIME NOT NULL,
	scheduled_at DATETIME, -- earliest time the worker may pick this up; NULL means immediately
	processed_at DATETIME,
	ok           INTEGER,
	UNIQUE(report_id)
);
CREATE INDEX idx_recheck_queue_pending ON recheck_queue(processed_at);

-- ip_pool is the tracked pool of "ever seen reachable" IPs and their
-- aggregates, computed live from ip_checks rather than maintained
-- incrementally. An IP appears here only while at least one ok=1 row for it
-- survives in ip_checks -- delete the checks and the IP falls back out of
-- the pool on its own, no cleanup pass required.
CREATE VIEW ip_pool AS
WITH ranked AS (
	-- rn_* columns rank each ip_checks row within its group so the
	-- earliest/latest row can be picked by plain column reference below.
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
