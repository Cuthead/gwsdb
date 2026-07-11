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

// NextItem is what GET /recheck/next returns: the target IP plus the scan
// config to probe it with, straight off the corresponding row in
// Cloudflare D1's scans table.
type NextItem struct {
	ID           int64  `json:"id"`
	IP           string `json:"ip"`
	ScanMode     string `json:"scanMode"`
	ConfigScanID int64  `json:"configScanId"`
	ConfigJSON   string `json:"configJson"`
}

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

// FetchNext asks the Cloudflare-hosted API for the next due recheck_queue
// item, or nil if none are ready yet (204). Bearer-authed with the same
// token scan_and_ingest.sh uses for /ingest -- one China box, one trust
// boundary, no separate secret.
func FetchNext(ctx context.Context, apiBase, token string) (*NextItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/recheck/next", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET /recheck/next: %s: %s", resp.Status, body)
	}

	var item NextItem
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("decode /recheck/next response: %w", err)
	}
	return &item, nil
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
