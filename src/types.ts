// Subset of internal/store/models.go needed by the ingest + home/scans read
// paths. Other tables (ip_reports, recheck_queue, asn_cache, host_cache)
// have no TS types yet -- those land with the phase that reads/writes them
// (query/report pages, still on internal/asn + internal/resolver).

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
