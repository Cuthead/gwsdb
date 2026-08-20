package ingest

import (
	"testing"
	"time"

	"github.com/cuthead/gwsdb/internal/store"
)

func TestFilterChecksPreservesReasonForSuccessAndFailure(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	results := []store.ScanResult{
		{IP: "192.0.2.1", RTTMs: 50},
	}
	checks := []store.IPCheck{
		{IP: "192.0.2.1", OK: true, RTTMs: 50, Reason: "scan:ok", Detail: "got_code=200", CheckedAt: now},
		{IP: "192.0.2.2", OK: false, Reason: "recheck:ping", Detail: "ping timeout", CheckedAt: now},
		{IP: "192.0.2.3", OK: false, Reason: "scan:dial", Detail: "dial timeout", CheckedAt: now}, // unknown failure, should be dropped
	}
	knownGood := map[string]bool{
		"192.0.2.1": true,
		"192.0.2.2": true,
	}

	filtered := FilterChecks(results, checks, knownGood, now)
	if len(filtered) != 2 {
		t.Fatalf("filtered count = %d, want 2", len(filtered))
	}
	if filtered[0].Reason != "scan:ok" {
		t.Errorf("filtered[0].Reason = %q, want %q", filtered[0].Reason, "scan:ok")
	}
	if filtered[1].Reason != "recheck:ping" {
		t.Errorf("filtered[1].Reason = %q, want %q", filtered[1].Reason, "recheck:ping")
	}
}
