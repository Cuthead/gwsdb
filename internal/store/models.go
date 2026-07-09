package store

import "time"

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
	Reason    string // e.g. "dial", "handshake", "cn", "status", "ping"; empty for successes
	Detail    string // e.g. "sni=g.cn host=www.google.com.hk got_code=403"; empty if unavailable
	CheckedAt time.Time

	// Request context in effect for this specific check, from the scan it
	// belongs to -- config can change between scans, so this is joined
	// per-row rather than assumed to match the current config.
	ScanMode         string
	ServerName       string
	HTTPPath         string
	HTTPMethod       string
	HTTPVerifyHosts  string
	VerifyCommonName string
	ValidStatusCode  int
}

// PTRCacheEntry is a cached reverse-DNS + geo decode result for one IP.
type PTRCacheEntry struct {
	IP          string
	PTRHostname string
	AirportCode string
	GeoCity     string
	GeoCountry  string
	LookupOK    bool
	CheckedAt   time.Time
}

// ASNCacheEntry is a cached ASN/prefix lookup result for one IP, used to
// avoid re-querying Team Cymru's DNS whois for repeat reporters.
type ASNCacheEntry struct {
	IP        string
	ASN       int
	ASName    string
	Prefix    string
	Country   string
	LookupOK  bool
	CheckedAt time.Time
}

// IPReport is a community-submitted "usable"/"unusable" report for one IP,
// similar in spirit to AbuseIPDB's report feature. The reporter's full IP is
// retained (ReporterIP) for abuse mitigation, but only their announced
// prefix and AS are meant to be shown publicly.
type IPReport struct {
	ID             int64
	IP             string // the IP being reported on
	Verdict        bool   // true = usable, false = unusable
	Comment        string
	ReporterIP     string // full reporter address; not for public display
	ReporterPrefix string // BGP-announced prefix containing ReporterIP
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
