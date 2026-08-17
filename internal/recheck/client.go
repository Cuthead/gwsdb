package recheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SubmitResult is the body POSTed to /recheck/result after probing a
// NextItem -- mirrors store.IPCheck's recheck-relevant fields.
type SubmitResult struct {
	ID           int64     `json:"id"`
	IP           string    `json:"ip"`
	OK           bool      `json:"ok"`
	RTTMs        int       `json:"rttMs"`
	Reason       string    `json:"reason"`
	Detail       string    `json:"detail"`
	ScanMode     string    `json:"scanMode"`
	ConfigScanID int64     `json:"configScanId"`
	CheckedAt    time.Time `json:"checkedAt"`
}

// FetchLatestScanID asks the Cloudflare-hosted API for the id of the most
// recent SNI scan on file, or 0 if none exists yet -- gwsdb recheck -ip
// (ad-hoc mode) uses this so its submission's config_scan_id points at a
// real scans row (same as the pull-model worker's item does), which is what
// the query page's "Probe Request" column joins against to show the
// request context (sni=/method=/path=/... -- see ipHistory in src/store.ts).
func FetchLatestScanID(ctx context.Context, apiBase, token string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/recheck/latest-scan-id", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("GET /recheck/latest-scan-id: %s: %s", resp.Status, body)
	}

	var out struct {
		ScanID *int64 `json:"scanId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode /recheck/latest-scan-id response: %w", err)
	}
	if out.ScanID == nil {
		return 0, nil
	}
	return *out.ScanID, nil
}

// SubmitResult reports a probe outcome back to the Cloudflare-hosted API,
// which records the ip_checks row and marks the recheck_queue entry
// processed.
func Submit(ctx context.Context, apiBase, token string, result SubmitResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/recheck/result", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST /recheck/result: %s: %s", resp.Status, respBody)
	}
	return nil
}
