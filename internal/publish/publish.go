// Package publish maintains a small set of DNS records on Cloudflare that
// point at the currently best-known GWS IPs. It reads the top IPs per address
// family from the store, diffs them against the records already on file for
// the target name, and applies only the difference -- so an unchanged top set
// makes no write calls. Triggered off user-driven rechecks (see the recheck
// worker), not a timer.
package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// apiBase is the default Cloudflare API v4 root. Publisher.base holds the
// value actually used, so a test can point it at a stub server.
const apiBase = "https://api.cloudflare.com/client/v4"

// IPSource is the slice of the store the publisher needs: the ranked IPs to
// publish for an address family (4 or 6).
type IPSource interface {
	TopIPsForPublish(family, limit int) ([]string, error)
}

// Config holds the Cloudflare target and publish policy.
type Config struct {
	APIToken string // Cloudflare API token with DNS edit on the zone
	ZoneID   string // zone the Name lives in
	Name     string // record name, e.g. "google.com.ip6arpa.uk"
	TTL      int    // record TTL in seconds; keep low (e.g. 300) so stale records expire fast
	Limit    int    // max records per family; keep small (4-8) -- more gives no benefit
}

// Publisher syncs Config.Name's A/AAAA records to the store's top IPs.
type Publisher struct {
	src  IPSource
	cfg  Config
	http *http.Client
	base string
}

// New builds a Publisher. Returns an error if required config is missing.
func New(src IPSource, cfg Config) (*Publisher, error) {
	if cfg.APIToken == "" || cfg.ZoneID == "" || cfg.Name == "" {
		return nil, fmt.Errorf("publish: APIToken, ZoneID and Name are required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 300
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 4
	}
	return &Publisher{
		src:  src,
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
		base: apiBase,
	}, nil
}

// Sync reconciles both A and AAAA records for the configured name. Errors from
// one family don't abort the other; the first error seen is returned.
func (p *Publisher) Sync(ctx context.Context) error {
	var firstErr error
	for _, f := range []struct {
		family  int
		dnsType string
	}{{4, "A"}, {6, "AAAA"}} {
		if err := p.syncFamily(ctx, f.family, f.dnsType); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("publish %s: %w", f.dnsType, err)
		}
	}
	return firstErr
}

// syncFamily reconciles one record type: fetch the desired top IPs, fetch the
// records already on file, then add the missing ones and delete the extras.
func (p *Publisher) syncFamily(ctx context.Context, family int, dnsType string) error {
	want, err := p.src.TopIPsForPublish(family, p.cfg.Limit)
	if err != nil {
		return fmt.Errorf("TopIPsForPublish: %w", err)
	}
	wantSet := make(map[string]bool, len(want))
	for _, ip := range want {
		wantSet[ip] = true
	}

	have, err := p.listRecords(ctx, dnsType)
	if err != nil {
		return err
	}
	haveSet := make(map[string]string, len(have)) // content -> record id
	for _, r := range have {
		haveSet[r.Content] = r.ID
	}

	for ip := range wantSet {
		if _, ok := haveSet[ip]; !ok {
			if err := p.createRecord(ctx, dnsType, ip); err != nil {
				return err
			}
		}
	}
	for content, id := range haveSet {
		if !wantSet[content] {
			if err := p.deleteRecord(ctx, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// dnsRecord is the subset of a Cloudflare DNS record we read back.
type dnsRecord struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

func (p *Publisher) listRecords(ctx context.Context, dnsType string) ([]dnsRecord, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records?type=%s&name=%s",
		p.base, p.cfg.ZoneID, dnsType, p.cfg.Name)
	var body struct {
		Success bool        `json:"success"`
		Errors  []cfError   `json:"errors"`
		Result  []dnsRecord `json:"result"`
	}
	if err := p.do(ctx, http.MethodGet, url, nil, &body); err != nil {
		return nil, err
	}
	if !body.Success {
		return nil, cfErr("list", body.Errors)
	}
	return body.Result, nil
}

func (p *Publisher) createRecord(ctx context.Context, dnsType, content string) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records", p.base, p.cfg.ZoneID)
	req := map[string]any{
		"type":    dnsType,
		"name":    p.cfg.Name,
		"content": content,
		"ttl":     p.cfg.TTL,
		"proxied": false, // must resolve to the real Google IP, not a CF proxy
	}
	var body struct {
		Success bool      `json:"success"`
		Errors  []cfError `json:"errors"`
	}
	if err := p.do(ctx, http.MethodPost, url, req, &body); err != nil {
		return err
	}
	if !body.Success {
		return cfErr("create", body.Errors)
	}
	return nil
}

func (p *Publisher) deleteRecord(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", p.base, p.cfg.ZoneID, id)
	var body struct {
		Success bool      `json:"success"`
		Errors  []cfError `json:"errors"`
	}
	if err := p.do(ctx, http.MethodDelete, url, nil, &body); err != nil {
		return err
	}
	if !body.Success {
		return cfErr("delete", body.Errors)
	}
	return nil
}

// do issues one Cloudflare API request, encoding reqBody as JSON if non-nil
// and decoding the response into out.
func (p *Publisher) do(ctx context.Context, method, url string, reqBody, out any) error {
	var rdr *bytes.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s %d: %w", method, resp.StatusCode, err)
	}
	return nil
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func cfErr(op string, errs []cfError) error {
	if len(errs) == 0 {
		return fmt.Errorf("%s: cloudflare reported failure with no error detail", op)
	}
	return fmt.Errorf("%s: cloudflare error %d: %s", op, errs[0].Code, errs[0].Message)
}
