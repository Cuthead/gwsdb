package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

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

// poolResponse is the /api/pool payload. Only ip + lastSeen + status are
// needed — the recheck feeder sorts by lastSeen ascending so the oldest-
// checked IPs are rechecked first (mirrors XX-Net's get_ip_sni_host
// pointer walking the handshake-sorted ip_list from the front). Only
// Reachable IPs are returned: re-checking a known-dead IP just burns a
// 2s ping timeout per IP with no useful outcome (it's already marked
// Unreachable in the pool, and re-probing it won't restore it).
type poolResponse struct {
	IPs []struct {
		IP       string `json:"ip"`
		LastSeen string `json:"lastSeen"` // "YYYY-MM-DD HH:MM:SS" or "-"
		Status   string `json:"status"`   // "Reachable" / "Unreachable" / "-"
	} `json:"ips"`
}

// FetchPool returns every currently-reachable IP in the tracked pool,
// sorted by lastSeen ascending (oldest first). No auth — /api/pool is
// the same public endpoint the home page fetches. The response is
// edge-cached keyed by poolVersion, so a fetch right after a flush sees
// fresh data.
func FetchPool(ctx context.Context, apiBase string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/pool", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET /api/pool: %s: %s", resp.Status, body)
	}
	var out poolResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode /api/pool: %w", err)
	}
	reachable := make([]struct {
		IP       string
		LastSeen string
	}, 0, len(out.IPs))
	for _, r := range out.IPs {
		if r.Status == "Reachable" {
			reachable = append(reachable, struct {
				IP       string
				LastSeen string
			}{r.IP, r.LastSeen})
		}
	}
	sort.SliceStable(reachable, func(i, j int) bool {
		return reachable[i].LastSeen < reachable[j].LastSeen
	})
	ips := make([]string, len(reachable))
	for i, r := range reachable {
		ips[i] = r.IP
	}
	return ips, nil
}

// submitPayload is the POST /ingest body -- just checks (no Scan row; the
// scans table is gone, checks are written directly to ip_checks).
type submitPayload struct {
	Checks      []store.IPCheck `json:"checks"`
	Maintenance bool            `json:"maintenance"`
}

// Submit posts already-parsed-and-filtered checks to the Cloudflare-hosted
// API (functions/ingest.ts), which writes them to ip_checks via
// insertCheckRows.
func Submit(ctx context.Context, apiBase, token string, checks []store.IPCheck, maintenance bool) error {
	body, err := json.Marshal(submitPayload{Checks: checks, Maintenance: maintenance})
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
	// Reading to EOF lets http.Transport reuse HTTP/1.1 connections; HTTP/2
	// already multiplexes streams. A 200 means D1 committed, so a drain error
	// must not cause a retry that would duplicate accepted checks.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
