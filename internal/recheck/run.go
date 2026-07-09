package recheck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/store"
)

// DefaultScanMode is the only scan mode RunAndSave currently knows how to
// probe -- CheckSNI ports gscan_quic's SNI-specific logic.
const DefaultScanMode = "SNI"

// RunAndSave re-tests ip using the config of the most recent scanMode scan on
// file, then records the outcome exactly as a one-IP scan would: a new scans
// row plus matching ip_checks/ip_status updates via SaveScan. Shared by the
// recheck_queue background worker and the "gwsdb recheck" CLI command.
//
// The returned error is only for infrastructure failures (no scan config on
// file, corrupt config JSON, DB write failure) -- a failed probe is a normal
// Result (OK: false), not an error.
func RunAndSave(st *store.Store, ip, scanMode string, probeTimeout time.Duration) (Result, error) {
	scanMode = strings.ToUpper(scanMode)

	configJSON, err := st.LatestScanConfigJSON(scanMode)
	if err != nil {
		return Result{}, fmt.Errorf("LatestScanConfigJSON: %w", err)
	}
	if configJSON == "" {
		return Result{}, fmt.Errorf("no %s scan on file yet", scanMode)
	}
	var cfg ingest.ScanConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return Result{}, fmt.Errorf("unmarshal latest %s scan config: %w", scanMode, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	result := CheckSNI(ctx, ip, &cfg)

	now := time.Now().UTC()
	scan := &store.Scan{
		ScanMode:         scanMode,
		ServerName:       strings.Join(cfg.ServerName, ","),
		VerifyCommonName: cfg.VerifyCommonName,
		HTTPPath:         cfg.HTTPPath,
		HTTPMethod:       cfg.HTTPMethod,
		HTTPVerifyHosts:  strings.Join(cfg.HTTPVerifyHosts, ","),
		ValidStatusCode:  cfg.ValidStatusCode,
		ConfigJSON:       configJSON,
		Level:            cfg.Level,
		StartedAt:        now,
		FinishedAt:       now,
		ScannedCount:     1,
	}
	var results []store.ScanResult
	if result.OK {
		scan.FoundCount = 1
		results = []store.ScanResult{{IP: ip, RTTMs: result.RTTMs}}
	}
	checks := []store.IPCheck{{
		IP:        ip,
		OK:        result.OK,
		RTTMs:     result.RTTMs,
		Reason:    result.Reason,
		Detail:    result.Detail,
		CheckedAt: now,
	}}

	if _, err := st.SaveScan(scan, results, checks); err != nil {
		return Result{}, fmt.Errorf("SaveScan: %w", err)
	}
	return result, nil
}
