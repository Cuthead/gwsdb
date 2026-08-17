package scan

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/store"
)

// runFlusher submits accumulated checks to the Cloudflare-hosted API on
// a fixed cadence. One flush window becomes one store.Scan row (with
// StartedAt/FinishedAt bracketing the window and ScannedCount/FoundCount
// summarizing it), which is exactly the shape functions/ingest.ts
// expects — so no Cloudflare-side change is needed. On ctx cancellation
// it runs one final flush under a detached context so the last window's
// checks aren't lost.
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

// flush drains the check buffer and submits it as one Scan. If either
// the known-good fetch or the submit fails, the checks are requeued for
// the next window rather than dropped. Safe to call with a cancelled
// ctx only when passing context.Background() (final flush) — the fetch
// and submit honor the ctx deadline.
func (s *Scanner) flush(ctx context.Context) {
	s.mu.Lock()
	checks := s.checks
	s.checks = nil
	scanned := s.scannedCount
	s.scannedCount = 0
	startedAt := s.flushStart
	s.flushStart = time.Now().UTC()
	s.mu.Unlock()

	if len(checks) == 0 {
		log.Printf("scan: flush: nothing to flush")
		return
	}

	// Deduped successes become the Scan's "results" (the authoritative
	// hit list for this flush window), mirroring how ingest.Parse
	// produces ScanResult from gscan_quic's output file. Failures stay
	// in checks; FilterChecks will keep only the known-good ones.
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

	configJSON, err := store.MarshalConfig(s.cfg.ProbeConfig)
	if err != nil {
		log.Printf("scan: flush: marshal config: %v — retaining %d checks", err, len(checks))
		s.requeue(checks, scanned)
		return
	}

	scan := &store.Scan{
		ScanMode:         strings.ToUpper(s.cfg.ScanMode),
		ServerName:       strings.Join(s.cfg.ProbeConfig.ServerName, ","),
		VerifyCommonName: s.cfg.ProbeConfig.VerifyCommonName,
		HTTPPath:         s.cfg.ProbeConfig.HTTPPath,
		HTTPMethod:       s.cfg.ProbeConfig.HTTPMethod,
		HTTPVerifyHosts:  strings.Join(s.cfg.ProbeConfig.HTTPVerifyHosts, ","),
		ValidStatusCode:  s.cfg.ProbeConfig.ValidStatusCode,
		InputFile:        s.cfg.InputFile,
		OutputFile:       "", // no output file — scanner submits directly
		Level:            s.cfg.ProbeConfig.Level,
		ConfigJSON:       configJSON,
		StartedAt:        startedAt,
		FinishedAt:       time.Now().UTC(),
		ScannedCount:     scanned,
		FoundCount:       len(results),
	}

	scanID, err := ingest.Submit(flushCtx, s.cfg.APIBase, s.cfg.Token, scan, filtered)
	if err != nil {
		log.Printf("scan: flush: submit: %v — retaining %d checks for next flush", err, len(checks))
		s.requeue(checks, scanned)
		return
	}
	log.Printf("scan: flushed scan #%d: %d probes, %d checks, %d found", scanID, scanned, len(filtered), len(results))
}

// requeue puts checks back at the front of the buffer if a flush failed,
// so they're retried next window instead of being lost. scanned is
// restored too so the Scan row's ScannedCount reflects the full window.
func (s *Scanner) requeue(checks []store.IPCheck, scanned int) {
	s.mu.Lock()
	s.checks = append(checks, s.checks...)
	s.scannedCount += scanned
	s.mu.Unlock()
}
