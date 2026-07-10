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
