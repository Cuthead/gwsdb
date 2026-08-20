package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

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
	decodeErr := json.NewDecoder(resp.Body).Decode(&out)
	_, _ = io.Copy(io.Discard, resp.Body)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode /ingest response: %w", decodeErr)
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

type PoolTarget struct {
	IP       string
	LastSeen time.Time
}

const poolTimeLayout = "2006-01-02 15:04:05"

// FetchPool returns every currently-reachable IP of family 4 or 6 in the
// tracked pool, sorted by lastSeen ascending (oldest first). No auth —
// /api/pool is the same public endpoint the home page fetches. The response
// is edge-cached keyed by poolVersion, so a fetch right after a flush sees
// fresh data.
func FetchPool(ctx context.Context, apiBase string, family int) ([]PoolTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/pool?family=%d", apiBase, family), nil)
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
	reachable := make([]PoolTarget, 0, len(out.IPs))
	for _, r := range out.IPs {
		if r.Status != "Reachable" {
			continue
		}
		var lastSeen time.Time
		if r.LastSeen != "-" {
			lastSeen, err = time.ParseInLocation(poolTimeLayout, r.LastSeen, time.UTC)
			if err != nil {
				return nil, fmt.Errorf("parse lastSeen for %s: %w", r.IP, err)
			}
		}
		reachable = append(reachable, PoolTarget{IP: r.IP, LastSeen: lastSeen})
	}
	sort.SliceStable(reachable, func(i, j int) bool {
		return reachable[i].LastSeen.Before(reachable[j].LastSeen)
	})
	return reachable, nil
}

// submitPayload is the POST /ingest body -- just checks (no Scan row; the
// scans table is gone, checks are written directly to ip_checks).
type submitPayload struct {
	Checks      []store.IPCheck `json:"checks"`
	Maintenance bool            `json:"maintenance"`
	PruneIPs    []string        `json:"pruneIPs"`
}

// Submit posts already-parsed-and-filtered checks to the Cloudflare-hosted
// API (functions/ingest.ts), which writes them to ip_checks via
// insertCheckRows.
func Submit(ctx context.Context, apiBase, token string, checks []store.IPCheck, maintenance bool, pruneIPs []string) (bool, error) {
	if pruneIPs == nil {
		pruneIPs = []string{}
	}
	body, err := json.Marshal(submitPayload{Checks: checks, Maintenance: maintenance, PruneIPs: pruneIPs})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/ingest", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("POST /ingest: %s: %s", resp.Status, respBody)
	}
	var out struct {
		PruneOK *bool `json:"pruneOk"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&out)
	_, _ = io.Copy(io.Discard, resp.Body)
	if decodeErr != nil {
		// A 200 means D1 committed. Never retry accepted checks because the
		// response body was truncated, but retain prune candidates because its
		// outcome is unknown. Old servers return valid JSON without pruneOk.
		return false, nil
	}
	return out.PruneOK == nil || *out.PruneOK, nil
}
