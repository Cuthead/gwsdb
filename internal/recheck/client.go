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

// SubmitResult is the body POSTed to /recheck/result after probing an IP
// ad-hoc (gwsdb recheck -ip) -- mirrors store.IPCheck's recheck-relevant
// fields.
type SubmitResult struct {
	IP        string    `json:"ip"`
	OK        bool      `json:"ok"`
	RTTMs     int       `json:"rttMs"`
	Reason    string    `json:"reason"`
	Detail    string    `json:"detail"`
	ScanMode  string    `json:"scanMode"`
	CheckedAt time.Time `json:"checkedAt"`
}

// Submit reports a probe outcome back to the Cloudflare-hosted API
// (functions/recheck/result.ts), which records the ip_checks row.
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
