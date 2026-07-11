package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cuthead/gwsdb/internal/store"
)

// FetchKnownGood asks the Cloudflare-hosted API for every IP in the tracked
// pool, so FilterChecks can gate this run's failures without a DB round
// trip per distinct failing IP. Bearer-authed with the same token
// scan_and_ingest.sh/recheck -worker use for /ingest and /recheck/*.
func FetchKnownGood(ctx context.Context, apiBase, token string) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/ingest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET /ingest: %s: %s", resp.Status, body)
	}

	var out struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode /ingest response: %w", err)
	}

	knownGood := make(map[string]bool, len(out.IPs))
	for _, ip := range out.IPs {
		knownGood[ip] = true
	}
	return knownGood, nil
}

// submitPayload is the POST /ingest body -- scan/checks marshal with their
// native store.Scan/store.IPCheck field names (PascalCase, no json tags),
// which functions/ingest.ts consumes directly. Fields it doesn't need
// (Scan.ID, Scan.LogText, IPCheck.Recheck/ConfigScanID) are harmlessly
// ignored on the TS side.
type submitPayload struct {
	Scan   *store.Scan     `json:"scan"`
	Checks []store.IPCheck `json:"checks"`
}

// Submit posts one already-parsed-and-filtered scan (see Parse, FilterChecks)
// to the Cloudflare-hosted API, returning the new scan's id.
func Submit(ctx context.Context, apiBase, token string, scan *store.Scan, checks []store.IPCheck) (int64, error) {
	body, err := json.Marshal(submitPayload{Scan: scan, Checks: checks})
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/ingest", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("POST /ingest: %s: %s", resp.Status, respBody)
	}

	var out struct {
		ScanID int64 `json:"scanId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode /ingest response: %w", err)
	}
	return out.ScanID, nil
}
