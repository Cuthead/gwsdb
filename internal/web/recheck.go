package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/store"
)

// recheckScanMode is the only scan mode the recheck queue re-tests --
// gscan_quic's SNI probe (~/gscan_quic/sni.go) is what recheck.CheckSNI ports.
const recheckScanMode = "SNI"

// recheckProbeTimeout bounds one recheck attempt so a stuck dial/handshake
// can't wedge the worker loop.
const recheckProbeTimeout = 10 * time.Second

// StartRecheckWorker processes one pending recheck_queue item per interval
// tick: it re-runs the SNI probe against the reported IP using the most
// recent SNI scan's config, then records the outcome exactly as a one-IP
// scan would (via SaveScan), updating ip_status/ip_checks history. Intended
// to run in its own goroutine for the lifetime of the server.
func (s *Server) StartRecheckWorker(interval time.Duration) {
	for {
		if err := s.processNextRecheck(); err != nil {
			log.Printf("recheck: %v", err)
		}
		time.Sleep(interval)
	}
}

func (s *Server) processNextRecheck() error {
	item, err := s.st.NextPendingRecheck()
	if err != nil {
		return fmt.Errorf("NextPendingRecheck: %w", err)
	}
	if item == nil {
		return nil
	}

	configJSON, err := s.st.LatestScanConfigJSON(recheckScanMode)
	if err != nil {
		return fmt.Errorf("LatestScanConfigJSON: %w", err)
	}
	if configJSON == "" {
		log.Printf("recheck: no %s scan on file yet, skipping recheck #%d for %s", recheckScanMode, item.ID, item.IP)
		return s.st.MarkRecheckProcessed(item.ID, false, time.Now().UTC())
	}
	var cfg ingest.ScanConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("unmarshal latest %s scan config: %w", recheckScanMode, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), recheckProbeTimeout)
	result := recheck.CheckSNI(ctx, item.IP, &cfg)
	cancel()

	now := time.Now().UTC()
	scan := &store.Scan{
		ScanMode:         recheckScanMode,
		ServerName:       strings.Join(cfg.ServerName, ","),
		VerifyCommonName: cfg.VerifyCommonName,
		HTTPPath:         cfg.HTTPPath,
		HTTPMethod:       cfg.HTTPMethod,
		HTTPVerifyHosts:  strings.Join(cfg.HTTPVerifyHosts, ","),
		ValidStatusCode:  cfg.ValidStatusCode,
		Level:            cfg.Level,
		StartedAt:        now,
		FinishedAt:       now,
		ScannedCount:     1,
	}
	var results []store.ScanResult
	if result.OK {
		scan.FoundCount = 1
		results = []store.ScanResult{{IP: item.IP, RTTMs: result.RTTMs, Rank: 1}}
	}
	checks := []store.IPCheck{{
		IP:        item.IP,
		OK:        result.OK,
		RTTMs:     result.RTTMs,
		Reason:    result.Reason,
		Detail:    result.Detail,
		CheckedAt: now,
	}}

	if _, err := s.st.SaveScan(scan, results, checks); err != nil {
		return fmt.Errorf("SaveScan: %w", err)
	}
	return s.st.MarkRecheckProcessed(item.ID, result.OK, now)
}
