// Package recheck re-runs a single IP through the same SNI probe logic
// gscan_quic uses (~/gscan_quic/sni.go, testSni/testip), for the background
// worker that follows up on user reports which disagree with our last known
// status. It doesn't import gscan_quic (a separate module whose probe is an
// unexported function in package main) -- the logic below is a port, kept in
// sync by hand.
package recheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
)

// DefaultScanMode is the only scan mode CheckSNI currently knows how to
// probe -- it ports gscan_quic's SNI-specific testSni logic. Must match the
// Cloudflare side's DEFAULT_SCAN_MODE (functions/recheck/latest-scan-id.ts,
// functions/check.ts).
const DefaultScanMode = "SNI"

// Result is the outcome of one SNI recheck attempt.
type Result struct {
	OK     bool
	RTTMs  int
	Reason string // e.g. "dial", "handshake", "cn", "http", "status"; empty on success
	Detail string
	// Mixed marks a split outcome across ScanCountPerIP attempts: some
	// passed, some failed. Callers must not record mixed results
	// (ip_checks, pool state) -- the IP is flapping and neither verdict
	// would be trustworthy.
	Mixed bool
}

// CheckSNI re-tests ip against cfg, repeating cfg.ScanCountPerIP times and
// averaging RTT across the attempts, mirroring gscan_quic's testip loop
// around testSni. cfg is typically parsed from the most recent SNI scan's
// stored config, so the recheck uses the same target server names, TLS CN,
// and HTTP verification the last real scan used.
//
// Unlike gscan_quic (which fails fast on the first failed attempt), every
// attempt runs and the outcome requires consensus: OK only when all
// attempts pass, fail only when all attempts fail with the same reason.
// Any other outcome (some attempts passed, or failures disagree on the
// reason -- both typical GFW random packet loss) returns Mixed=true,
// which callers treat as "record nothing": neither a transient success
// nor a transient failure is allowed to become the IP's recorded state.
func CheckSNI(ctx context.Context, ip string, cfg *ingest.ScanConfig) Result {
	return checkSNIMulti(ctx, ip, "443", cfg)
}

// checkSNIMulti is CheckSNI with an explicit port so tests can target a
// local listener; production always passes 443.
func checkSNIMulti(ctx context.Context, ip, port string, cfg *ingest.ScanConfig) Result {
	count := max(cfg.ScanCountPerIP, 1)
	var totalRTT time.Duration
	var lastDetail string
	var failures []Result
	for range count {
		res := checkSNIOnce(ctx, ip, port, cfg)
		if !res.OK {
			failures = append(failures, res)
			continue
		}
		totalRTT += time.Duration(res.RTTMs) * time.Millisecond
		lastDetail = res.Detail
	}
	if len(failures) > 0 {
		return mergeFailures(failures, count)
	}
	return Result{OK: true, RTTMs: int((totalRTT / time.Duration(count)).Milliseconds()), Detail: lastDetail}
}

// mergeFailures folds the failed attempts into one Result. Consensus
// requires the failures to agree on a reason: all-fail with the same
// reason is a trustworthy failure, but disagreeing reasons (e.g. an EOF
// on one attempt and a dial timeout on the next -- GFW random packet
// loss throwing a different failure mode each time) means the outcome is
// not reproducible, so Result.Mixed is set and callers drop the result.
// Split pass/fail outcomes are Mixed for the same reason.
func mergeFailures(failures []Result, total int) Result {
	reason := failures[0].Reason
	disagree := false
	details := make([]string, 0, len(failures))
	for _, f := range failures {
		if f.Reason != reason {
			reason = "mixed"
			disagree = true
		}
		details = append(details, f.Detail)
	}
	detail := strings.Join(details, "; ")
	if len(failures) < total {
		detail = fmt.Sprintf("%d/%d attempts failed: %s", len(failures), total, detail)
	}
	return Result{Reason: reason, Detail: detail, Mixed: len(failures) < total || disagree}
}

// ProbeParams returns a string summarizing cfg's target request and
// expectation parameters.
func ProbeParams(cfg *ingest.ScanConfig) string {
	serverName := ""
	if len(cfg.ServerName) > 0 {
		serverName = cfg.ServerName[0]
	}
	host := ""
	if len(cfg.HTTPVerifyHosts) > 0 {
		host = cfg.HTTPVerifyHosts[0]
	}
	method := cfg.HTTPMethod
	if method == "" {
		method = "HEAD"
	}
	return probeParams(serverName, host, method, cfg)
}

func probeParams(serverName, host, method string, cfg *ingest.ScanConfig) string {
	var parts []string
	if serverName != "" {
		parts = append(parts, "sni="+serverName)
	}
	if host != "" && cfg.Level > 2 {
		parts = append(parts, "host="+host)
	}
	if method != "" && cfg.Level > 2 {
		parts = append(parts, "method="+method)
	}
	if cfg.HTTPPath != "" && cfg.Level > 2 {
		parts = append(parts, "path="+cfg.HTTPPath)
	}
	if cfg.VerifyCommonName != "" && cfg.Level > 1 {
		parts = append(parts, "want_cn="+cfg.VerifyCommonName)
	}
	if cfg.ValidStatusCode != 0 && cfg.Level > 2 {
		parts = append(parts, fmt.Sprintf("want_code=%d", cfg.ValidStatusCode))
	}
	return strings.Join(parts, " ")
}

// checkSNIOnce mirrors gscan_quic's testSni for a single pass over
// cfg.ServerName, summing RTT across every server name tested. port is
// always 443 in production; tests pass their listener's port.
func checkSNIOnce(ctx context.Context, ip, port string, cfg *ingest.ScanConfig) Result {
	handshakeTimeout := time.Duration(cfg.HandshakeTimeout) * time.Millisecond
	scanMinRTT := time.Duration(cfg.ScanMinRTT) * time.Millisecond
	scanMaxRTT := time.Duration(cfg.ScanMaxRTT) * time.Millisecond

	tlscfg := &tls.Config{InsecureSkipVerify: true}

	host := randomHost()
	if len(cfg.HTTPVerifyHosts) > 0 {
		host = cfg.HTTPVerifyHosts[rand.Intn(len(cfg.HTTPVerifyHosts))]
	}
	method := cfg.HTTPMethod
	if method == "" {
		method = "HEAD"
	}

	var totalRTT time.Duration
	var details []string
	for _, serverName := range cfg.ServerName {
		params := probeParams(serverName, host, method, cfg)
		start := time.Now()

		dialCtx, cancel := context.WithTimeout(ctx, scanMaxRTT)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip, port))
		cancel()
		if err != nil {
			return Result{Reason: "dial", Detail: fmt.Sprintf("%s error=%s", params, ingest.SanitizeNetErr(err.Error()))}
		}

		tlscfg.ServerName = serverName
		tlsconn := tls.Client(conn, tlscfg)
		tlsconn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tlsconn.Handshake(); err != nil {
			tlsconn.Close()
			return Result{Reason: "handshake", Detail: fmt.Sprintf("%s error=%s", params, ingest.SanitizeNetErr(err.Error()))}
		}

		if cfg.Level > 1 {
			pcs := tlsconn.ConnectionState().PeerCertificates
			gotCN := ""
			if len(pcs) > 0 {
				gotCN = pcs[0].Subject.CommonName
			}
			if len(pcs) == 0 || gotCN != cfg.VerifyCommonName {
				tlsconn.Close()
				return Result{Reason: "cn", Detail: fmt.Sprintf("%s got_cn=%s", params, gotCN)}
			}
		}

		if cfg.Level > 2 {
			req, err := http.NewRequest(method, "https://"+net.JoinHostPort(ip, port)+cfg.HTTPPath, nil)
			if err != nil {
				tlsconn.Close()
				return Result{Reason: "http", Detail: fmt.Sprintf("%s error=%s", params, err.Error())}
			}
			req.Host = host
			tlsconn.SetDeadline(time.Now().Add(scanMaxRTT - time.Since(start)))
			httpconn := &http.Client{
				Transport: &http.Transport{
					DialTLS: func(network, addr string) (net.Conn, error) { return tlsconn, nil },
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Timeout: scanMaxRTT - time.Since(start),
			}
			resp, err := httpconn.Do(req)
			if err != nil {
				tlsconn.Close()
				return Result{Reason: "http", Detail: fmt.Sprintf("%s error=%s", params, ingest.SanitizeNetErr(err.Error()))}
			}
			if resp.StatusCode != cfg.ValidStatusCode {
				tlsconn.Close()
				return Result{Reason: "status", Detail: fmt.Sprintf("%s got_code=%d", params, resp.StatusCode)}
			}
		}

		tlsconn.Close()

		// RTT gate, same as gscan_quic's testSni: a pass slower than
		// ScanMaxRTT (or suspiciously faster than ScanMinRTT — GFW forged
		// replies) is a failed probe, never a success with an out-of-range
		// RTT. Without this, edge-case passes (dial nearly timing out but
		// succeeding) recorded OK=true with RTT far above ScanMaxRTT.
		rtt := time.Since(start)
		if rtt < scanMinRTT || rtt > scanMaxRTT {
			return Result{Reason: "rtt", Detail: fmt.Sprintf("%s rtt=%dms (want %d-%dms)", params, rtt.Milliseconds(), scanMinRTT.Milliseconds(), scanMaxRTT.Milliseconds())}
		}
		totalRTT += rtt
		details = append(details, params)
	}

	return Result{OK: true, RTTMs: int(totalRTT.Milliseconds()), Detail: strings.Join(details, " ")}
}

// randomHost mirrors gscan_quic's util.go randomHost: a fake 2-3 segment
// hostname used as the HTTP Host header when no HTTPVerifyHosts is configured.
func randomHost() string {
	n := randInt(2, 4)
	parts := make([]string, n)
	for i := range parts {
		m := randInt(3, 7)
		b := make([]byte, m)
		for j := range b {
			b[j] = byte(randInt(97, 122))
		}
		parts[i] = string(b)
	}
	return strings.Join(parts, ".")
}

func randInt(l, u int) int {
	return rand.Intn(u-l) + l
}
