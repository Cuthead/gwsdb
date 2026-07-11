// Ports internal/store/models.go's types, added incrementally as each
// phase starts reading/writing the corresponding table.

export interface Scan {
	ScanMode: string;
	ServerName: string;
	VerifyCommonName: string;
	HTTPPath: string;
	HTTPMethod: string;
	HTTPVerifyHosts: string;
	ValidStatusCode: number;
	InputFile: string;
	OutputFile: string;
	Level: number;
	ConfigJSON: string;
	StartedAt: Date | null;
	FinishedAt: Date | null;
	ScannedCount: number;
	FoundCount: number;
}

// ScanRow is the read-path shape of a scans row (mirrors Scan plus its id),
// used by listScans/latestScan.
export interface ScanRow extends Scan {
	id: number;
}

// IPStatus mirrors internal/store/models.go's IPStatus: the rolling
// reachability record for one IP, derived live from the ip_pool view.
export interface IPStatus {
	ip: string;
	isIPv6: boolean;
	scanMode: string;
	firstSeen: Date | null;
	lastSeen: Date | null; // last time this IP was confirmed reachable
	lastScanId: number | null;
	lastRttMs: number;
	timesSeen: number;
	lastCheckedAt: Date | null; // last time this IP was tested at all (pass or fail)
	lastCheckOk: boolean;
	hasCheck: boolean; // whether lastCheckedAt/lastCheckOk are populated
	ptrHostname: string[]; // cached PTR hostname(s), [] if never looked up; only populated by listKnownIPs
}

// Stats holds simple aggregate counters shown on the home page.
export interface Stats {
	totalKnownIPs: number;
	totalScans: number;
	lastScanAt: Date | null;
}

// PTRCacheEntry is a cached reverse-DNS lookup result for one IP.
export interface PTRCacheEntry {
	ip: string;
	ptrHostnames: string[];
	lookupOk: boolean;
	ttlSeconds: number;
	checkedAt: Date;
}

// HostCacheEntry is a cached forward A/AAAA lookup result for one 1e100.net
// hostname (the query page's hostname-mode).
export interface HostCacheEntry {
	hostname: string;
	ipv4: string[];
	ipv6: string[];
	lookupOk: boolean;
	ttlSeconds: number;
	checkedAt: Date;
}

// ASNCacheEntry is a cached ASN/prefix lookup result for one IP.
export interface ASNCacheEntry {
	ip: string;
	asn: number;
	asName: string;
	prefix: string;
	country: string;
	lookupOk: boolean;
	ttlSeconds: number;
	checkedAt: Date;
}

// IPReport is a community-submitted usable/unusable report for one IP. The
// reporter's full IP is never stored -- only the announced prefix/AS.
export interface IPReport {
	id: number;
	ip: string;
	verdict: boolean;
	comment: string;
	reporterPrefix: string;
	reporterASN: number;
	reporterASName: string;
	createdAt: Date;
}

// IPCheckHistoryRow is one row from IPHistory: a pass/fail observation plus
// the request context (from its owning/config scan) in effect at the time.
export interface IPCheckHistoryRow {
	ip: string;
	ok: boolean;
	rttMs: number;
	reason: string;
	detail: string;
	checkedAt: Date | null;
	recheck: boolean; // true when this check has no owning scan (scan_id IS NULL)
	scanMode: string;
	serverName: string;
	httpPath: string;
	httpMethod: string;
	httpVerifyHosts: string;
	verifyCommonName: string;
	validStatusCode: number;
}

// RecheckQueueItem is a pending recheck_queue row, returned by
// nextPendingRecheck to the China box's pull-model worker.
export interface RecheckQueueItem {
	id: number;
	reportId: number;
	ip: string;
	createdAt: Date;
	scheduledAt: Date | null;
}
