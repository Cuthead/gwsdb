// Package store provides the SQLite-backed persistence layer for gwsdb.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS scans (
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

CREATE TABLE IF NOT EXISTS scan_results (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id  INTEGER NOT NULL REFERENCES scans(id),
	ip       TEXT NOT NULL,
	rtt_ms   INTEGER,
	rank     INTEGER,
	UNIQUE(scan_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip);

CREATE TABLE IF NOT EXISTS ip_status (
	ip              TEXT PRIMARY KEY,
	is_ipv6         INTEGER NOT NULL DEFAULT 0,
	scan_mode       TEXT NOT NULL,
	first_seen      DATETIME NOT NULL,
	last_seen       DATETIME NOT NULL,
	last_scan_id    INTEGER,
	last_rtt_ms     INTEGER,
	times_seen      INTEGER NOT NULL DEFAULT 1,
	last_checked_at DATETIME,
	last_check_ok   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ip_status_last_seen ON ip_status(last_seen);

CREATE TABLE IF NOT EXISTS ip_checks (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id    INTEGER NOT NULL REFERENCES scans(id),
	ip         TEXT NOT NULL,
	ok         INTEGER NOT NULL,
	rtt_ms     INTEGER,
	reason     TEXT, -- e.g. dial/handshake/cn/status/ping; NULL for successes
	detail     TEXT, -- e.g. "sni=g.cn host=www.google.com.hk got_code=403"
	checked_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_checks_ip ON ip_checks(ip, checked_at);
CREATE INDEX IF NOT EXISTS idx_ip_checks_scan_id ON ip_checks(scan_id);

CREATE TABLE IF NOT EXISTS ptr_cache (
	ip            TEXT PRIMARY KEY,
	ptr_hostname  TEXT,
	airport_code  TEXT,
	geo_city      TEXT,
	geo_country   TEXT,
	lookup_ok     INTEGER NOT NULL DEFAULT 1,
	checked_at    DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS asn_cache (
	ip            TEXT PRIMARY KEY,
	asn           INTEGER,
	as_name       TEXT,
	prefix        TEXT,
	country       TEXT,
	lookup_ok     INTEGER NOT NULL DEFAULT 1,
	checked_at    DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_reports (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	ip                TEXT NOT NULL,
	verdict           INTEGER NOT NULL,
	comment           TEXT,
	reporter_ip       TEXT NOT NULL,
	reporter_prefix   TEXT,
	reporter_asn      INTEGER,
	reporter_as_name  TEXT,
	created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ip_reports_ip ON ip_reports(ip, created_at);

-- recheck_queue holds one pending re-scan per user report that disagreed
-- with our last known status for that IP (and postdated it). A report is
-- enqueued at most once -- UNIQUE(report_id) plus the fact that enqueueing
-- only happens once, right after the report is saved, is what makes "one
-- check per report" hold even though the worker may run long after.
CREATE TABLE IF NOT EXISTS recheck_queue (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id    INTEGER NOT NULL REFERENCES ip_reports(id),
	ip           TEXT NOT NULL,
	created_at   DATETIME NOT NULL,
	scheduled_at DATETIME, -- earliest time the worker may pick this up; NULL means immediately
	processed_at DATETIME,
	ok           INTEGER,
	UNIQUE(report_id)
);
CREATE INDEX IF NOT EXISTS idx_recheck_queue_pending ON recheck_queue(processed_at);
`

// Store wraps a SQLite database handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // sqlite3 driver is not safe for concurrent writers
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate adds columns introduced after a database's tables were first
// created. CREATE TABLE IF NOT EXISTS above doesn't touch existing tables,
// so new columns need an explicit, idempotent ALTER TABLE here.
func migrate(db *sql.DB) error {
	if err := addColumnsIfMissing(db, "ip_status", map[string]string{
		"last_checked_at": `ALTER TABLE ip_status ADD COLUMN last_checked_at DATETIME`,
		"last_check_ok":   `ALTER TABLE ip_status ADD COLUMN last_check_ok INTEGER`,
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(db, "ip_checks", map[string]string{
		"reason": `ALTER TABLE ip_checks ADD COLUMN reason TEXT`,
		"detail": `ALTER TABLE ip_checks ADD COLUMN detail TEXT`,
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(db, "scans", map[string]string{
		"http_method": `ALTER TABLE scans ADD COLUMN http_method TEXT`,
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(db, "recheck_queue", map[string]string{
		"scheduled_at": `ALTER TABLE recheck_queue ADD COLUMN scheduled_at DATETIME`,
	}); err != nil {
		return err
	}
	return nil
}

func addColumnsIfMissing(db *sql.DB, table string, colDDL map[string]string) error {
	cols := map[string]bool{}
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for col, ddl := range colDDL {
		if !cols[col] {
			if _, err := db.Exec(ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
