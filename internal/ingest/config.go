package ingest

// ScanConfig mirrors the per-mode config block used by gscan_quic
// (see config.user.json / gscan.go's ScanConfig).
type ScanConfig struct {
	ScanCountPerIP   int
	ServerName       []string
	HTTPVerifyHosts  []string
	VerifyCommonName string
	HTTPPath         string
	ValidStatusCode  int
	HandshakeTimeout int
	ScanMinRTT       int
	ScanMaxRTT       int
	RecordLimit      int
	InputFile        string
	OutputFile       string
	OutputSeparator  string
	Level            int
}

// GScannerConfig mirrors the top-level config.json / config.user.json shape
// produced by gscan_quic.
type GScannerConfig struct {
	ScanWorker     int
	ScanMode       string
	LogLevel       int // gwsdb needs 5 (all failure categories) to build ip_checks history
	VerifyPing     bool
	ScanMinPingRTT int
	ScanMaxPingRTT int
	PING           ScanConfig
	QUIC           ScanConfig
	TLS            ScanConfig
	SNI            ScanConfig
}

// ForMode returns the ScanConfig block for the given (case-insensitive) scan mode.
func (c *GScannerConfig) ForMode(mode string) *ScanConfig {
	switch normalizeMode(mode) {
	case "quic":
		return &c.QUIC
	case "tls":
		return &c.TLS
	case "sni":
		return &c.SNI
	case "ping":
		return &c.PING
	default:
		return nil
	}
}

func normalizeMode(mode string) string {
	out := make([]byte, len(mode))
	for i := 0; i < len(mode); i++ {
		b := mode[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		out[i] = b
	}
	return string(out)
}
