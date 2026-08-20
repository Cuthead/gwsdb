package ingest

import (
	"time"

	"github.com/cuthead/gwsdb/internal/store"
)

// FilterChecks replicates internal/store/queries.go's SaveScan gating logic
// (recorded-dedup for successes, known-good gate for failures) as a pure
// function, for callers that must apply the same filter *before* submitting
// to a remote store rather than inline in a local transaction -- the China
// box calls this after Parse and before client.go's Submit, using a
// known-good set fetched once per run (GET /ingest) instead of a DB lookup
// per row. Returns the exact set of ip_checks rows SaveScan would have
// written: every result (deduped), every log-only success not already
// covered by a result, and every failure whose IP is in knownGood
// ("never seen reachable before -- not part of the tracked pool" is
// dropped, same as SaveScan).
func FilterChecks(results []store.ScanResult, checks []store.IPCheck, knownGood map[string]bool, now time.Time) []store.IPCheck {
	recorded := make(map[string]bool, len(results))
	out := make([]store.IPCheck, 0, len(results)+len(checks))

	// Prefer the log's own per-line timestamp for "when was this actually
	// seen" over now, when we have one -- mirrors SaveScan's seenAt map.
	seenAt := make(map[string]time.Time, len(checks))
	detailByIP := make(map[string]string, len(checks))
	reasonByIP := make(map[string]string, len(checks))
	for _, c := range checks {
		if c.OK && !c.CheckedAt.IsZero() {
			seenAt[c.IP] = c.CheckedAt
			if c.Detail != "" {
				detailByIP[c.IP] = c.Detail
			}
			if c.Reason != "" {
				reasonByIP[c.IP] = c.Reason
			}
		}
	}

	// The output file may repeat an IP; the old scan_results table absorbed
	// that with UNIQUE(scan_id, ip), ip_checks has no such constraint.
	for _, r := range results {
		if recorded[r.IP] {
			continue
		}
		recorded[r.IP] = true
		ts, ok := seenAt[r.IP]
		if !ok {
			ts = now
		}
		out = append(out, store.IPCheck{IP: r.IP, OK: true, RTTMs: r.RTTMs, Reason: reasonByIP[r.IP], Detail: detailByIP[r.IP], CheckedAt: ts})
	}

	for _, c := range checks {
		checkedAt := c.CheckedAt
		if checkedAt.IsZero() {
			checkedAt = now
		}
		if c.OK {
			// Successes covered by a result row are already recorded; only
			// keep log-only successes (e.g. output file truncated). The
			// reason carries the scanner's "scan:ok"/"recheck:ok" origin tag.
			if recorded[c.IP] {
				continue
			}
			recorded[c.IP] = true
			out = append(out, store.IPCheck{IP: c.IP, OK: true, RTTMs: c.RTTMs, Reason: c.Reason, Detail: c.Detail, CheckedAt: checkedAt})
			continue
		}
		// SaveScan's live DB check sees this run's own already-inserted
		// successes too (same transaction), not just pre-existing history --
		// an IP that succeeds earlier in this same log and fails later
		// still counts as known-good for that later failure.
		if !recorded[c.IP] && !knownGood[c.IP] {
			continue
		}
		out = append(out, store.IPCheck{IP: c.IP, OK: false, Reason: c.Reason, Detail: c.Detail, CheckedAt: checkedAt})
	}

	return out
}
