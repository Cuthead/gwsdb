package recheck

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
)

// DefaultScanMode is the only scan mode the pull-model worker currently
// knows how to probe -- CheckSNI ports gscan_quic's SNI-specific logic. Must
// match the Cloudflare side's functions/recheck/next.ts DEFAULT_SCAN_MODE.
const DefaultScanMode = "SNI"

// PullAndRun fetches the next due recheck_queue item from the
// Cloudflare-hosted API (GET /recheck/next), probes it with the unchanged
// CheckSNI (the part that must physically run on real China-based network
// infrastructure -- Cloudflare's edge doesn't sit behind the GFW and can't
// produce a meaningful result), and reports the outcome back
// (POST /recheck/result). Storage now lives entirely in Cloudflare D1 --
// there is no local *store.Store on the China box to read/write directly,
// unlike the pre-migration in-process worker this replaces.
//
// drained is true when there was nothing due to pull, so the caller's
// drain-the-backlog loop knows to stop. err is only for infrastructure
// failures (network/API errors, corrupt config JSON) -- a failed probe is a
// normal Result (OK: false), not an error.
func PullAndRun(ctx context.Context, apiBase, token string, probeTimeout time.Duration) (drained bool, result Result, err error) {
	item, err := FetchNext(ctx, apiBase, token)
	if err != nil {
		return false, Result{}, fmt.Errorf("FetchNext: %w", err)
	}
	if item == nil {
		return true, Result{}, nil
	}

	var cfg ingest.ScanConfig
	if err := json.Unmarshal([]byte(item.ConfigJSON), &cfg); err != nil {
		return false, Result{}, fmt.Errorf("unmarshal scan config for #%d %s: %w", item.ID, item.IP, err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	result = CheckSNI(probeCtx, item.IP, &cfg)
	cancel()

	if err := Submit(ctx, apiBase, token, SubmitResult{
		ID:           item.ID,
		IP:           item.IP,
		OK:           result.OK,
		RTTMs:        result.RTTMs,
		Reason:       result.Reason,
		Detail:       result.Detail,
		ScanMode:     item.ScanMode,
		ConfigScanID: item.ConfigScanID,
		CheckedAt:    time.Now().UTC(),
	}); err != nil {
		return false, Result{}, fmt.Errorf("Submit #%d %s: %w", item.ID, item.IP, err)
	}
	return false, result, nil
}
