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
// trip per distinct failing IP. Bearer-authed with the same token the
// scanner uses for /ingest.
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

// submitPayload is the POST /ingest body -- just checks (no Scan row; the
// scans table is gone, checks are written directly to ip_checks).
type submitPayload struct {
	Checks []store.IPCheck `json:"checks"`
}

// Submit posts already-parsed-and-filtered checks to the Cloudflare-hosted
// API (functions/ingest.ts), which writes them to ip_checks via
// insertCheckRows.
func Submit(ctx context.Context, apiBase, token string, checks []store.IPCheck) error {
	body, err := json.Marshal(submitPayload{Checks: checks})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/ingest", bytes.NewReader(body))
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
		return fmt.Errorf("POST /ingest: %s: %s", resp.Status, respBody)
	}
	return nil
}
