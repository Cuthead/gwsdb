package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestMigrateDropsReporterIP verifies that opening a database created before
// reporter_ip was removed drops the column (purging the stored addresses)
// while keeping the rest of each report row.
func TestMigrateDropsReporterIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE ip_reports (
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
		INSERT INTO ip_reports (ip, verdict, comment, reporter_ip, reporter_prefix, reporter_asn, reporter_as_name)
		VALUES ('8.8.8.8', 1, 'works', '203.0.113.7', '203.0.113.0/24', 64500, 'EXAMPLE-AS');
	`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	rows, err := st.db.Query(`PRAGMA table_info(ip_reports)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "reporter_ip" {
			t.Fatal("reporter_ip column still present after migration")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	reps, err := st.ListReports("8.8.8.8", 10)
	if err != nil {
		t.Fatalf("ListReports: %v", err)
	}
	if len(reps) != 1 {
		t.Fatalf("got %d reports, want 1", len(reps))
	}
	if reps[0].ReporterPrefix != "203.0.113.0/24" || reps[0].ReporterASN != 64500 {
		t.Fatalf("report data lost: %+v", reps[0])
	}
}

// TestMigrateDropsIPStatus verifies that opening a database created before
// ip_status was replaced by the ip_pool view drops the old table, backfills
// ip_checks.scan_mode from the owning scan, and that ip_pool reports the same
// IP the old ip_status row did.
func TestMigrateDropsIPStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_mode TEXT NOT NULL,
			started_at DATETIME, finished_at DATETIME,
			scanned_count INTEGER, found_count INTEGER,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE ip_status (
			ip TEXT PRIMARY KEY,
			is_ipv6 INTEGER NOT NULL DEFAULT 0,
			scan_mode TEXT NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			last_scan_id INTEGER,
			last_rtt_ms INTEGER,
			times_seen INTEGER NOT NULL DEFAULT 1,
			last_checked_at DATETIME,
			last_check_ok INTEGER
		);
		CREATE TABLE ip_checks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER REFERENCES scans(id),
			ip TEXT NOT NULL,
			ok INTEGER NOT NULL,
			rtt_ms INTEGER,
			checked_at DATETIME NOT NULL
		);
		INSERT INTO scans (id, scan_mode, started_at, finished_at, scanned_count, found_count)
			VALUES (1, 'http', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 1, 1);
		INSERT INTO ip_checks (scan_id, ip, ok, rtt_ms, checked_at)
			VALUES (1, '8.8.8.8', 1, 50, '2026-01-01T00:00:00Z');
		INSERT INTO ip_status (ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok)
			VALUES ('8.8.8.8', 0, 'http', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 1, 50, 1, '2026-01-01T00:00:00Z', 1);
	`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ip_status'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("ip_status table still present after migration")
	}

	status, err := st.IPStatusFor("8.8.8.8")
	if err != nil {
		t.Fatalf("IPStatusFor: %v", err)
	}
	if status == nil {
		t.Fatal("8.8.8.8 missing from ip_pool after migration")
	}
	if status.ScanMode != "http" {
		t.Fatalf("scan_mode = %q, want backfilled %q", status.ScanMode, "http")
	}
	if status.TimesSeen != 1 {
		t.Fatalf("times_seen = %d, want 1", status.TimesSeen)
	}
}
