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

// Result is the outcome of one SNI recheck attempt.
type Result struct {
	OK     bool
	RTTMs  int
	Reason string // e.g. "dial", "handshake", "cn", "http", "status"; empty on success
	Detail string
}

// CheckSNI re-tests ip against cfg, repeating cfg.ScanCountPerIP times and
// averaging RTT across the attempts, mirroring gscan_quic's testip loop
// around testSni. cfg is typically parsed from the most recent SNI scan's
// stored config, so the recheck uses the same target server names, TLS CN,
// and HTTP verification the last real scan used.
func CheckSNI(ctx context.Context, ip string, cfg *ingest.ScanConfig) Result {
	count := max(cfg.ScanCountPerIP, 1)
	var totalRTT time.Duration
	for range count {
		res := checkSNIOnce(ctx, ip, cfg)
		if !res.OK {
			return res
		}
		totalRTT += time.Duration(res.RTTMs) * time.Millisecond
	}
	return Result{OK: true, RTTMs: int((totalRTT / time.Duration(count)).Milliseconds())}
}

// checkSNIOnce mirrors gscan_quic's testSni for a single pass over
// cfg.ServerName, summing RTT across every server name tested.
func checkSNIOnce(ctx context.Context, ip string, cfg *ingest.ScanConfig) Result {
	handshakeTimeout := time.Duration(cfg.HandshakeTimeout) * time.Millisecond
	scanMaxRTT := time.Duration(cfg.ScanMaxRTT) * time.Millisecond

	tlscfg := &tls.Config{InsecureSkipVerify: true}
	tr := &http.Transport{TLSClientConfig: tlscfg, ResponseHeaderTimeout: scanMaxRTT}
	httpconn := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}
	defer httpconn.CloseIdleConnections()

	host := randomHost()
	if len(cfg.HTTPVerifyHosts) > 0 {
		host = cfg.HTTPVerifyHosts[rand.Intn(len(cfg.HTTPVerifyHosts))]
	}
	method := cfg.HTTPMethod
	if method == "" {
		method = "HEAD"
	}

	var totalRTT time.Duration
	for _, serverName := range cfg.ServerName {
		start := time.Now()

		dialCtx, cancel := context.WithTimeout(ctx, scanMaxRTT)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip, "443"))
		cancel()
		if err != nil {
			return Result{Reason: "dial", Detail: fmt.Sprintf("error=%s", ingest.SanitizeNetErr(err.Error()))}
		}

		tlscfg.ServerName = serverName
		tlsconn := tls.Client(conn, tlscfg)
		tlsconn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tlsconn.Handshake(); err != nil {
			tlsconn.Close()
			return Result{Reason: "handshake", Detail: fmt.Sprintf("error=%s", ingest.SanitizeNetErr(err.Error()))}
		}

		if cfg.Level > 1 {
			pcs := tlsconn.ConnectionState().PeerCertificates
			gotCN := ""
			if len(pcs) > 0 {
				gotCN = pcs[0].Subject.CommonName
			}
			if len(pcs) == 0 || gotCN != cfg.VerifyCommonName {
				tlsconn.Close()
				return Result{Reason: "cn", Detail: fmt.Sprintf("got_cn=%s", gotCN)}
			}
		}

		if cfg.Level > 2 {
			req, err := http.NewRequest(method, "https://"+net.JoinHostPort(ip, "443")+cfg.HTTPPath, nil)
			if err != nil {
				tlsconn.Close()
				return Result{Reason: "http", Detail: fmt.Sprintf("error=build request: %s", err.Error())}
			}
			req.Host = host
			tlsconn.SetDeadline(time.Now().Add(scanMaxRTT - time.Since(start)))
			resp, err := httpconn.Do(req)
			if err != nil {
				tlsconn.Close()
				return Result{Reason: "http", Detail: fmt.Sprintf("error=%s", ingest.SanitizeNetErr(err.Error()))}
			}
			if resp.StatusCode != cfg.ValidStatusCode {
				tlsconn.Close()
				return Result{Reason: "status", Detail: fmt.Sprintf("got_code=%d", resp.StatusCode)}
			}
		}

		tlsconn.Close()

		totalRTT += time.Since(start)
	}

	return Result{OK: true, RTTMs: int(totalRTT.Milliseconds())}
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
