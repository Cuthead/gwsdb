// Ports internal/store/models.go's types, added incrementally as each
// phase starts reading/writing the corresponding table.

// IPStatus mirrors internal/store/models.go's IPStatus: the rolling
// reachability record for one IP, derived live from the ip_pool view.
export interface IPStatus {
	ip: string;
	revision: number;
	isIPv6: boolean;
	scanMode: string;
	firstSeen: Date | null;
	lastSeen: Date | null; // last time this IP was confirmed reachable
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
	totalChecks: number;
	lastCheckAt: Date | null;
	scanMode: string;
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

// IPCheckHistoryRow is one row from IPHistory: a pass/fail observation plus
// the request context (from its owning/config scan) in effect at the time.
export interface IPCheckHistoryRow {
	ip: string;
	ok: boolean;
	rttMs: number;
	reason: string;
	detail: string;
	checkedAt: Date | null;
	scanMode: string;
}

