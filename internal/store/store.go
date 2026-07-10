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
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id        INTEGER REFERENCES scans(id), -- NULL for report-triggered rechecks (no owning scan)
	config_scan_id INTEGER REFERENCES scans(id), -- for rechecks: the scan whose config the probe ran with
	ip             TEXT NOT NULL,
	ok             INTEGER NOT NULL,
	rtt_ms         INTEGER,
	reason         TEXT, -- e.g. dial/handshake/cn/status/ping; NULL for successes
	detail         TEXT, -- e.g. "sni=g.cn host=www.google.com.hk got_code=403"
	checked_at     DATETIME NOT NULL
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
		"reason":         `ALTER TABLE ip_checks ADD COLUMN reason TEXT`,
		"detail":         `ALTER TABLE ip_checks ADD COLUMN detail TEXT`,
		"config_scan_id": `ALTER TABLE ip_checks ADD COLUMN config_scan_id INTEGER REFERENCES scans(id)`,
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
	if err := mergeScanResultsIntoChecks(db); err != nil {
		return err
	}
	if err := makeIPChecksScanIDNullable(db); err != nil {
		return err
	}
	// Reporter addresses are no longer stored at all -- the announced
	// prefix/AS is enough. Dropping the column also purges every full IP
	// previously saved.
	if err := dropColumnIfPresent(db, "ip_reports", "reporter_ip"); err != nil {
		return err
	}
	return nil
}

func dropColumnIfPresent(db *sql.DB, table, col string) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	present := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == col {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if !present {
		return nil
	}
	if _, err := db.Exec(`ALTER TABLE ` + table + ` DROP COLUMN ` + col); err != nil {
		return fmt.Errorf("drop %s.%s: %w", table, col, err)
	}
	// The dropped values can survive in freelist pages; rewrite the file so
	// they're actually gone. Only runs the one time the column is dropped.
	if _, err := db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("vacuum after dropping %s.%s: %w", table, col, err)
	}
	return nil
}

// makeIPChecksScanIDNullable rebuilds ip_checks on databases created when
// scan_id was still NOT NULL. Rechecks triggered by community reports record
// their outcome as an ip_checks row with no owning scan, so the column must
// accept NULL. SQLite can't drop a NOT NULL constraint in place, hence the
// create/copy/rename dance. Runs after addColumnsIfMissing so reason/detail
// are guaranteed to exist.
func makeIPChecksScanIDNullable(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(ip_checks)`)
	if err != nil {
		return err
	}
	scanIDNotNull := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "scan_id" && notnull != 0 {
			scanIDNotNull = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if !scanIDNotNull {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		CREATE TABLE ip_checks_new (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id        INTEGER REFERENCES scans(id),
			config_scan_id INTEGER REFERENCES scans(id),
			ip             TEXT NOT NULL,
			ok             INTEGER NOT NULL,
			rtt_ms         INTEGER,
			reason         TEXT,
			detail         TEXT,
			checked_at     DATETIME NOT NULL
		)`); err != nil {
		return fmt.Errorf("create ip_checks_new: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO ip_checks_new (id, scan_id, config_scan_id, ip, ok, rtt_ms, reason, detail, checked_at)
		SELECT id, scan_id, config_scan_id, ip, ok, rtt_ms, reason, detail, checked_at FROM ip_checks`); err != nil {
		return fmt.Errorf("copy ip_checks: %w", err)
	}
	if _, err := tx.Exec(`DROP TABLE ip_checks`); err != nil {
		return fmt.Errorf("drop old ip_checks: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE ip_checks_new RENAME TO ip_checks`); err != nil {
		return fmt.Errorf("rename ip_checks_new: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_ip_checks_ip ON ip_checks(ip, checked_at)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_ip_checks_scan_id ON ip_checks(scan_id)`); err != nil {
		return err
	}
	return tx.Commit()
}

// mergeScanResultsIntoChecks folds the legacy scan_results table into
// ip_checks and drops it. scan_results rows were per-scan success snapshots;
// most predate complete log ingestion, so many have no matching ok row in
// ip_checks. scan_results had no per-row timestamp -- backfilled rows borrow
// the scan's finish time. The rank column is dropped: nothing ever read it.
func mergeScanResultsIntoChecks(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'scan_results'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`
		INSERT INTO ip_checks (scan_id, ip, ok, rtt_ms, checked_at)
		SELECT sr.scan_id, sr.ip, 1, sr.rtt_ms,
		       COALESCE(s.finished_at, s.started_at, s.created_at)
		FROM scan_results sr
		JOIN scans s ON s.id = sr.scan_id
		WHERE NOT EXISTS (
			SELECT 1 FROM ip_checks c
			WHERE c.scan_id = sr.scan_id AND c.ip = sr.ip AND c.ok = 1
		)`); err != nil {
		return fmt.Errorf("backfill ip_checks from scan_results: %w", err)
	}
	if _, err := tx.Exec(`DROP TABLE scan_results`); err != nil {
		return fmt.Errorf("drop scan_results: %w", err)
	}
	return tx.Commit()
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
