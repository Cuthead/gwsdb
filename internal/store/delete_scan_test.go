package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestDeleteScanIPPoolDerivation verifies that ip_pool, computed live from
// ip_checks, reflects a scan deletion immediately -- there's no maintained
// aggregate that can be left stale.
func TestDeleteScanIPPoolDerivation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	const ip = "2404:6800:4002:80b::a7"
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	var scanIDs []int64
	for i := range 3 {
		ts := base.Add(time.Duration(i) * time.Hour)
		id, err := st.SaveScan(
			&Scan{ScanMode: "http", StartedAt: ts, FinishedAt: ts, ScannedCount: 1, FoundCount: 1},
			[]ScanResult{{IP: ip, RTTMs: 100 + i}},
			[]IPCheck{{IP: ip, OK: true, RTTMs: 100 + i, CheckedAt: ts}},
		)
		if err != nil {
			t.Fatalf("SaveScan %d: %v", i, err)
		}
		scanIDs = append(scanIDs, id)
	}

	status, err := st.IPStatusFor(ip)
	if err != nil {
		t.Fatalf("IPStatusFor: %v", err)
	}
	if status == nil || status.TimesSeen != 3 || status.ScanMode != "http" {
		t.Fatalf("got %+v, want times_seen=3 scan_mode=http", status)
	}

	// Delete the most recent scan; times_seen should drop to 2 and last_seen
	// should fall back to the second scan's timestamp, not stay stale.
	if err := st.DeleteScan(scanIDs[2]); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	status, err = st.IPStatusFor(ip)
	if err != nil {
		t.Fatalf("IPStatusFor after delete: %v", err)
	}
	if status == nil {
		t.Fatal("ip disappeared from ip_pool after partial delete")
	}
	if status.TimesSeen != 2 {
		t.Fatalf("times_seen = %d, want 2", status.TimesSeen)
	}
	wantLastSeen := base.Add(1 * time.Hour)
	if !status.LastSeen.Equal(wantLastSeen) {
		t.Fatalf("last_seen = %v, want %v", status.LastSeen, wantLastSeen)
	}
	if status.LastScanID != scanIDs[1] {
		t.Fatalf("last_scan_id = %d, want %d", status.LastScanID, scanIDs[1])
	}

	// Delete the remaining two scans; the IP has no surviving evidence of
	// ever being reachable, so it should fully revert out of ip_pool.
	if err := st.DeleteScan(scanIDs[1]); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	if err := st.DeleteScan(scanIDs[0]); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	status, err = st.IPStatusFor(ip)
	if err != nil {
		t.Fatalf("IPStatusFor after full delete: %v", err)
	}
	if status != nil {
		t.Fatalf("ip survived in ip_pool after deletion of all scans: %+v", status)
	}
}
