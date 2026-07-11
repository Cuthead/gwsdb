// Mirrors internal/ingest/config.go: the gscan_quic config.json/config.user.json
// shape, and internal/recheck's ScanConfig (same shape, per-mode block).

export interface ScanConfig {
	ScanCountPerIP: number;
	ServerName: string[];
	HTTPVerifyHosts: string[];
	VerifyCommonName: string;
	HTTPPath: string;
	HTTPMethod: string;
	ValidStatusCode: number;
	HandshakeTimeout: number;
	ScanMinRTT: number;
	ScanMaxRTT: number;
	RecordLimit: number;
	InputFile: string;
	OutputFile: string;
	OutputSeparator: string;
	Level: number;
}

export interface GScannerConfig {
	ScanWorker: number;
	ScanMode: string;
	LogLevel: number; // gwsdb needs 5 (all failure categories) to build ip_checks history
	VerifyPing: boolean;
	ScanMinPingRTT: number;
	ScanMaxPingRTT: number;
	PING: ScanConfig;
	QUIC: ScanConfig;
	TLS: ScanConfig;
	SNI: ScanConfig;
}

function normalizeMode(mode: string): string {
	return mode.toLowerCase();
}

// forMode returns the ScanConfig block for the given (case-insensitive) scan mode.
export function forMode(cfg: GScannerConfig, mode: string): ScanConfig | null {
	switch (normalizeMode(mode)) {
		case "quic":
			return cfg.QUIC;
		case "tls":
			return cfg.TLS;
		case "sni":
			return cfg.SNI;
		case "ping":
			return cfg.PING;
		default:
			return null;
	}
}
