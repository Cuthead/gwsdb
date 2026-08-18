package scan

import (
	"context"
	"log"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/store"
)

// runFlusher submits accumulated checks to the Cloudflare-hosted API on
// a fixed cadence. Checks are written directly to ip_checks (no per-flush
// Scan row — the scans table is gone). On ctx cancellation it runs one
// final flush under a detached context so the last window's checks aren't lost.
//
// The known-good set (which IPs may have failure rows submitted) is kept
// in memory and refreshed hourly rather than fetched per flush: the only
// consumer of GET /ingest is this flusher, and each flush's own POST
// bumps poolVersion, so any caching on the server side could never hit —
// the memory copy replaces 144 full-pool fetches/day with ~24.
func (s *Scanner) runFlusher(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flush(context.Background())
			return
		case <-ticker.C:
			s.flush(ctx)
		}
	}
}

// knownGoodRefreshInterval is how often the scanner re-fetches the full
// known-good set from the API. Between refreshes the set is extended
// locally with each flush's newly-discovered reachable IPs; the only drift
// is deletions (IPs pruned server-side after their history rolls out of
// the retention window), which self-corrects on the next refresh and is
// harmless in between — a failure row for a since-pruned IP is written to
// ip_checks but updatePoolBatch's UPDATE is a no-op for a non-pool IP.
const knownGoodRefreshInterval = time.Hour

// flush drains the check buffer and submits it. If the submit fails, the
// checks are requeued for the next window rather than dropped. Safe to
// call with a cancelled ctx only when passing context.Background() (final
// flush). Only runFlusher's goroutine calls this, so s.knownGood needs no
// locking.
func (s *Scanner) flush(ctx context.Context) {
	s.mu.Lock()
	checks := s.checks
	s.checks = nil
	scanned := s.scannedCount
	s.scannedCount = 0
	s.mu.Unlock()

	if len(checks) == 0 {
		log.Printf("scan: flush: nothing to flush")
		return
	}

	// Deduped successes become the "results" (authoritative hit list for
	// this flush window). Failures stay in checks; FilterChecks keeps only
	// the known-good ones.
	seen := make(map[string]bool, len(checks))
	var results []store.ScanResult
	for _, c := range checks {
		if c.OK && !seen[c.IP] {
			seen[c.IP] = true
			results = append(results, store.ScanResult{IP: c.IP, RTTMs: c.RTTMs})
		}
	}

	flushCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if s.knownGood == nil || time.Since(s.knownGoodFetchedAt) > knownGoodRefreshInterval {
		fresh, err := ingest.FetchKnownGood(flushCtx, s.cfg.APIBase, s.cfg.Token)
		if err != nil {
			if s.knownGood == nil {
				log.Printf("scan: flush: fetch known-good: %v — retaining %d checks for next flush", err, len(checks))
				s.requeue(checks, scanned)
				return
			}
			// Stale set is still serviceable; retry the fetch next flush.
			log.Printf("scan: flush: fetch known-good: %v — using stale set (age %s)", err, time.Since(s.knownGoodFetchedAt).Round(time.Minute))
		} else {
			s.knownGood = fresh
			s.knownGoodFetchedAt = time.Now()
		}
	}

	filtered := ingest.FilterChecks(results, checks, s.knownGood, time.Now().UTC())
	// FilterChecks rebuilds IPChecks without ScanMode; re-apply it so the
	// ip_checks rows carry the mode the scanner probed with.
	for i := range filtered {
		filtered[i].ScanMode = s.cfg.ScanMode
	}

	if err := ingest.Submit(flushCtx, s.cfg.APIBase, s.cfg.Token, filtered); err != nil {
		log.Printf("scan: flush: submit: %v — retaining %d checks for next flush", err, len(checks))
		s.requeue(checks, scanned)
		return
	}
	// Extend the in-memory set with this window's discoveries so failures
	// for them pass the filter in later windows without waiting for the
	// hourly refresh.
	for _, r := range results {
		s.knownGood[r.IP] = true
	}
	log.Printf("scan: flushed: %d probes, %d checks, %d found (known-good %d, refreshed %s ago)",
		scanned, len(filtered), len(results), len(s.knownGood), time.Since(s.knownGoodFetchedAt).Round(time.Minute))
}

// requeue puts checks back at the front of the buffer if a flush failed,
// so they're retried next window instead of being lost. scanned is
// restored too so the next flush's probe count reflects the full window.
func (s *Scanner) requeue(checks []store.IPCheck, scanned int) {
	s.mu.Lock()
	s.checks = append(checks, s.checks...)
	s.scannedCount += scanned
	s.mu.Unlock()
}
