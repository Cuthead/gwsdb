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
// file, then records the outcome via SaveRecheck: an ip_checks history row
// with no owning scan. No scans row is created -- the scans table only
// records real scanner runs ingested via the CLI.
// Shared by the recheck_queue background worker and the "gwsdb recheck" CLI
// command.
//
// The returned error is only for infrastructure failures (no scan config on
// file, corrupt config JSON, DB write failure) -- a failed probe is a normal
// Result (OK: false), not an error.
func RunAndSave(st *store.Store, ip, scanMode string, probeTimeout time.Duration) (Result, error) {
	scanMode = strings.ToUpper(scanMode)

	configScanID, configJSON, err := st.LatestScanConfig(scanMode)
	if err != nil {
		return Result{}, fmt.Errorf("LatestScanConfig: %w", err)
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

	check := store.IPCheck{
		IP:           ip,
		OK:           result.OK,
		RTTMs:        result.RTTMs,
		Reason:       result.Reason,
		Detail:       result.Detail,
		CheckedAt:    time.Now().UTC(),
		ScanMode:     scanMode,
		ConfigScanID: configScanID,
	}
	if err := st.SaveRecheck(check); err != nil {
		return Result{}, fmt.Errorf("SaveRecheck: %w", err)
	}
	return result, nil
}
