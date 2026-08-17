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

// flush drains the check buffer and submits it. If either the known-good
// fetch or the submit fails, the checks are requeued for the next window
// rather than dropped. Safe to call with a cancelled ctx only when passing
// context.Background() (final flush).
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

	knownGood, err := ingest.FetchKnownGood(flushCtx, s.cfg.APIBase, s.cfg.Token)
	if err != nil {
		log.Printf("scan: flush: fetch known-good: %v — retaining %d checks for next flush", err, len(checks))
		s.requeue(checks, scanned)
		return
	}

	filtered := ingest.FilterChecks(results, checks, knownGood, time.Now().UTC())
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
	log.Printf("scan: flushed: %d probes, %d checks, %d found", scanned, len(filtered), len(results))
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
