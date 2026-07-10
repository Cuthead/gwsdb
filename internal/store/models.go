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

// Scan represents one execution of the gscan_quic scanner for a given scan mode.
type Scan struct {
	ID               int64
	ScanMode         string
	ServerName       string
	VerifyCommonName string
	HTTPPath         string
	HTTPMethod       string
	HTTPVerifyHosts  string
	ValidStatusCode  int
	InputFile        string
	OutputFile       string
	Level            int
	ConfigJSON       string
	LogText          string
	StartedAt        time.Time
	FinishedAt       time.Time
	ScannedCount     int
	FoundCount       int
}

// ScanResult is a single IP found reachable during a Scan, taken from the
// scanner's output file. Persisted as an ok row in ip_checks.
type ScanResult struct {
	IP    string
	RTTMs int // 0 if unknown
}

// IPStatus is the rolling reachability record for one IP across all scans.
type IPStatus struct {
	IP            string
	IsIPv6        bool
	ScanMode      string
	FirstSeen     time.Time
	LastSeen      time.Time // last time this IP was confirmed reachable
	LastScanID    int64
	LastRTTMs     int
	TimesSeen     int
	LastCheckedAt time.Time // last time this IP was tested at all (pass or fail)
	LastCheckOK   bool
	HasCheck      bool   // whether LastCheckedAt/LastCheckOK are populated
	PTRHostname   string // cached PTR hostname, "" if never resolved; only populated by ListKnownIPs
}

// IPCheck is a single pass/fail observation of one IP during one scan --
// the raw material for per-IP availability history. Unlike ScanResult (which
// only exists for successful hits), IPCheck also records attempts that were
// tested and failed, so absence can be told apart from "wasn't tested".
type IPCheck struct {
	IP        string
	OK        bool
	RTTMs     int
	Reason    string // e.g. "dial", "handshake", "cn", "http", "status", "ping"; empty for successes
	Detail    string // e.g. "got_code=403"; empty if unavailable
	CheckedAt time.Time
	Recheck   bool // true for report-triggered/CLI rechecks, which have no owning scan

	// ConfigScanID is the scan whose config a recheck probe ran with (rechecks
	// reuse the latest scan's config). 0 for regular scan checks -- their
	// config is the owning scan's -- and for rechecks whose source scan was
	// since deleted.
	ConfigScanID int64

	// Request context in effect for this specific check, from the scan it
	// belongs to (or, for rechecks, the ConfigScanID scan) -- config can
	// change between scans, so this is joined per-row rather than assumed to
	// match the current config.
	ScanMode         string
	ServerName       string
	HTTPPath         string
	HTTPMethod       string
	HTTPVerifyHosts  string
	VerifyCommonName string
	ValidStatusCode  int
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

// IPReport is a community-submitted "usable"/"unusable" report for one IP,
// similar in spirit to AbuseIPDB's report feature. The reporter's full IP is
// never stored -- only the announced prefix and AS it resolved to at
// submission time.
type IPReport struct {
	ID             int64
	IP             string // the IP being reported on
	Verdict        bool   // true = usable, false = unusable
	Comment        string
	ReporterPrefix string // BGP-announced prefix containing the reporter's address
	ReporterASN    int
	ReporterASName string
	CreatedAt      time.Time
}

// RecheckQueueItem is one pending (or processed) re-scan triggered by a user
// report that disagreed with our last known status for its IP.
type RecheckQueueItem struct {
	ID          int64
	ReportID    int64
	IP          string
	CreatedAt   time.Time
	ScheduledAt time.Time // zero if eligible immediately (pre-delay rows)
	ProcessedAt time.Time // zero if still pending
}
