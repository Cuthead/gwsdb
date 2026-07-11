// Subset of internal/store/models.go needed by the ingest path (phase 1).
// Other tables (ip_reports, recheck_queue, ptr_cache, ...) exist in the D1
// schema already (migrations/0001_init.sql) but have no TS types yet --
// those land with the phase that writes to them.

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
