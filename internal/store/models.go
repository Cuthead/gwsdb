// Package store holds the data-shape types shared between the ingest/recheck
// CLI (cmd/gwsdb) and the Cloudflare-hosted API it submits to -- there is no
// local database here anymore, all persistence lives in D1 behind
// functions/. See AGENTS.md.
package store

import (
	"strings"
	"time"
)

// listSep joins multiple values into a single TEXT column -- ptr_cache's
// ptr_hostname (a hostname can have more than one PTR) and host_cache's
// ipv4/ipv6 (a hostname can have more than one A/AAAA record). "; " can't
// appear in a 1e100.net hostname or an IP address, so splitting is
// unambiguous.
const listSep = "; "

// JoinStrings packs multiple values for storage in a single "; "-joined
// TEXT column (PTRCacheEntry.PTRHostname, HostCacheEntry.IPv4/IPv6).
func JoinStrings(values []string) string {
	return strings.Join(values, listSep)
}

// SplitStrings unpacks a "; "-joined column (PTRCacheEntry.PTRHostname,
// IPStatus.PTRHostname, HostCacheEntry.IPv4/IPv6) back into individual
// values. Returns nil for "".
func SplitStrings(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, listSep)
}

// ScanResult is a single IP found reachable during a scan, taken from the
// scanner's output file. Persisted as an ok row in ip_checks.
type ScanResult struct {
	IP    string
	RTTMs int // 0 if unknown
}

// IPStatus is the rolling reachability record for one IP across all checks.
type IPStatus struct {
	IP            string
	IsIPv6        bool
	ScanMode      string
	FirstSeen     time.Time
	LastSeen      time.Time // last time this IP was confirmed reachable
	LastRTTMs     int
	TimesSeen     int
	LastCheckedAt time.Time // last time this IP was tested at all (pass or fail)
	LastCheckOK   bool
	HasCheck      bool   // whether LastCheckedAt/LastCheckOK are populated
	PTRHostname   string // cached PTR hostname, "" if never resolved; only populated by ListKnownIPs
}

// IPCheck is a single pass/fail observation of one IP -- the raw material
// for per-IP availability history. Unlike ScanResult (which only exists for
// successful hits), IPCheck also records attempts that were tested and
// failed, so absence can be told apart from "wasn't tested".
type IPCheck struct {
	IP        string
	OK        bool
	RTTMs     int
	Reason    string // e.g. "dial", "handshake", "cn", "http", "status", "ping"; empty for successes
	Detail    string // e.g. "got_code=403"; empty if unavailable
	CheckedAt time.Time
	ScanMode  string
}

// PTRCacheEntry is a cached reverse-DNS lookup result for one IP. Geo/airport
// decoding is derived from PTRHostname at read time via geo.Decode, not
// stored here, so it always reflects the current airports.go tables. TTL is
// the DNS TTL observed when it was looked up -- the row is stale once
// CheckedAt+TTL has passed, not after any fixed cache lifetime.
type PTRCacheEntry struct {
	IP          string
	PTRHostname string
	LookupOK    bool
	TTL         time.Duration
	CheckedAt   time.Time
}

// ASNCacheEntry is a cached ASN/prefix lookup result for one IP, used to
// avoid re-querying Team Cymru's DNS whois for repeat reporters. TTL is the
// DNS TTL observed when it was looked up (see PTRCacheEntry.TTL).
type ASNCacheEntry struct {
	IP        string
	ASN       int
	ASName    string
	Prefix    string
	Country   string
	LookupOK  bool
	TTL       time.Duration
	CheckedAt time.Time
}

// HostCacheEntry is a cached forward A/AAAA lookup result for one 1e100.net
// hostname (the query page's hostname-mode). TTL is the DNS TTL observed
// when it was looked up (see PTRCacheEntry.TTL).
type HostCacheEntry struct {
	Hostname  string
	IPv4      []string
	IPv6      []string
	LookupOK  bool
	TTL       time.Duration
	CheckedAt time.Time
}
