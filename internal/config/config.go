// Package config loads gwsdb's own application config from a single JSON file
// (config.json), which holds the Cloudflare secrets and is gitignored. This is
// gwsdb's config, distinct from the gscan_quic scanner config that ingest reads.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Config is gwsdb's application config.
type Config struct {
	DNS DNS `json:"dns"`
}

// DNS configures the Cloudflare DNS publisher. Publishing stays off unless
// Name is set.
type DNS struct {
	Name               string `json:"name"`               // record name, e.g. "google.com.ip6arpa.uk"
	TTL                int    `json:"ttl"`                // record TTL in seconds (default 300 if <= 0)
	Limit              int    `json:"limit"`              // max records per address family (default 4 if <= 0)
	CloudflareZoneID   string `json:"cloudflareZoneId"`   // zone the name lives in
	CloudflareAPIToken string `json:"cloudflareApiToken"` // token with DNS edit permission
}

// Load reads config from path. A missing file is not an error: it yields the
// zero Config, so publishing stays off unless DNS.Name is set.
func Load(path string) (*Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}
