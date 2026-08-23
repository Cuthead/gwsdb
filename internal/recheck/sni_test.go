package recheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
)

// delayedConn sleeps once before its first Read, letting a test TLS server
// stretch the client's handshake past a configured ScanMaxRTT.
type delayedConn struct {
	net.Conn
	delay   time.Duration
	delayed atomic.Bool
}

func (c *delayedConn) Read(b []byte) (int, error) {
	if !c.delayed.Swap(true) {
		time.Sleep(c.delay)
	}
	return c.Conn.Read(b)
}

// selfSignedCert generates a throwaway cert so the TLS handshake can complete
// (the client uses InsecureSkipVerify, so its contents don't matter).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestCheckSNIRTTGateSlowPassFails verifies the ported gscan_quic RTT gate:
// a servername pass slower than ScanMaxRTT must fail the probe (reason
// "rtt") instead of returning OK with an out-of-range RTT.
func TestCheckSNIRTTGateSlowPassFails(t *testing.T) {
	cert := selfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			// Delay the first read (client hello) so the client's measured
			// pass RTT (~150ms) exceeds ScanMaxRTT (50ms) while the
			// HandshakeTimeout (1s) still lets the handshake finish.
			_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
			go func() {
				defer tlsConn.Close()
				delayed := &delayedConn{Conn: tlsConn, delay: 150 * time.Millisecond}
				raw := tls.Server(delayed, &tls.Config{Certificates: []tls.Certificate{cert}})
				_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
				_ = raw.Handshake()
			}()
		}
	}()

	cfg := &ingest.ScanConfig{
		ScanCountPerIP:   1,
		ServerName:       []string{"g.cn"},
		HandshakeTimeout: 1000,
		ScanMinRTT:       0,
		ScanMaxRTT:       50,
		Level:            0,
	}
	addr := listener.Addr().(*net.TCPAddr)
	res := checkSNIOnce(context.Background(), addr.IP.String(), fmt.Sprint(addr.Port), cfg)
	if res.OK {
		t.Fatalf("slow pass = OK with rtt=%dms, want failure", res.RTTMs)
	}
	if res.Reason != "rtt" {
		t.Fatalf("reason = %q, want %q (detail: %s)", res.Reason, "rtt", res.Detail)
	}
}

// TestCheckSNIRTTGateFastPassOK verifies a pass within [ScanMinRTT,
// ScanMaxRTT] still succeeds and reports its RTT.
func TestCheckSNIRTTGateFastPassOK(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("timing-sensitive on loaded CI runners")
	}
	cert := selfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	cfg := &ingest.ScanConfig{
		ScanCountPerIP:   1,
		ServerName:       []string{"g.cn"},
		HandshakeTimeout: 2000,
		ScanMinRTT:       0,
		ScanMaxRTT:       2000,
		Level:            0,
	}
	addr := listener.Addr().(*net.TCPAddr)
	res := checkSNIOnce(context.Background(), addr.IP.String(), fmt.Sprint(addr.Port), cfg)
	if !res.OK {
		t.Fatalf("fast pass failed: reason=%s detail=%s", res.Reason, res.Detail)
	}
	if res.RTTMs <= 0 || res.RTTMs > 2000 {
		t.Fatalf("rtt = %dms, want within (0, 2000]", res.RTTMs)
	}
}

// startTLSServer serves handshakes controlled by allow: each Accept consults
// allow(attempt) -- true completes the handshake, false closes immediately.
// It returns the listener's host:port for probing.
func startTLSServer(t *testing.T, cert tls.Certificate, allow func(attempt int32) bool) (string, string) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	var attempt int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			n := atomic.AddInt32(&attempt, 1)
			go func() {
				defer conn.Close()
				if !allow(n) {
					return // drop: client handshake fails
				}
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), fmt.Sprint(addr.Port)
}

// multiCfg returns a ScanConfig for checkSNIMulti tests: count attempts,
// generous RTT bounds, Level 0 (TLS handshake only).
func multiCfg(count int) *ingest.ScanConfig {
	return &ingest.ScanConfig{
		ScanCountPerIP:   count,
		ServerName:       []string{"g.cn"},
		HandshakeTimeout: 2000,
		ScanMinRTT:       0,
		ScanMaxRTT:       2000,
		Level:            0,
	}
}

// TestCheckSNIConsensusAllPassOK: every attempt passes -> OK with averaged RTT.
func TestCheckSNIConsensusAllPassOK(t *testing.T) {
	cert := selfSignedCert(t)
	ip, port := startTLSServer(t, cert, func(int32) bool { return true })
	res := checkSNIMulti(context.Background(), ip, port, multiCfg(2))
	if !res.OK {
		t.Fatalf("all-pass = failure: reason=%s detail=%s", res.Reason, res.Detail)
	}
	if res.RTTMs <= 0 || res.RTTMs > 2000 {
		t.Fatalf("rtt = %dms, want within (0, 2000]", res.RTTMs)
	}
}

// TestCheckSNIConsensusAllFailFails: every attempt fails the same way ->
// failure with no Mixed flag (recorded).
func TestCheckSNIConsensusAllFailFails(t *testing.T) {
	cert := selfSignedCert(t)
	ip, port := startTLSServer(t, cert, func(int32) bool { return false })
	res := checkSNIMulti(context.Background(), ip, port, multiCfg(2))
	if res.OK {
		t.Fatal("all-fail = OK, want failure")
	}
	if res.Mixed {
		t.Fatal("all-fail = Mixed, want plain failure")
	}
	if res.Reason != "handshake" {
		t.Fatalf("reason = %q, want %q", res.Reason, "handshake")
	}
}

// TestMergeFailuresDisagreeingReasonsMixed: all attempts fail but with
// different reasons (EOF on one, dial timeout on the other -- GFW random
// packet loss) -> Mixed=true, nothing gets recorded.
func TestMergeFailuresDisagreeingReasonsMixed(t *testing.T) {
	res := mergeFailures([]Result{
		{Reason: "http", Detail: "error=EOF"},
		{Reason: "dial", Detail: "error=i/o timeout"},
	}, 2)
	if res.OK || !res.Mixed {
		t.Fatalf("disagreeing all-fail: ok=%t mixed=%t, want failure with Mixed=true", res.OK, res.Mixed)
	}
	if res.Reason != "mixed" {
		t.Fatalf("reason = %q, want %q", res.Reason, "mixed")
	}
}

// TestMergeFailuresSameReasonRecorded: all attempts fail with the same
// reason -> plain failure (recorded), no Mixed flag.
func TestMergeFailuresSameReasonRecorded(t *testing.T) {
	res := mergeFailures([]Result{
		{Reason: "dial", Detail: "error=i/o timeout"},
		{Reason: "dial", Detail: "error=i/o timeout"},
	}, 2)
	if res.OK || res.Mixed {
		t.Fatalf("agreeing all-fail: ok=%t mixed=%t, want plain failure", res.OK, res.Mixed)
	}
	if res.Reason != "dial" {
		t.Fatalf("reason = %q, want %q", res.Reason, "dial")
	}
}

// TestCheckSNIConsensusFlapMixed: attempts disagree (1 pass, 1 fail) ->
// Mixed=true (caller drops it, nothing recorded), detail explains the split,
// and both attempts ran (no fail-fast short-circuit).
func TestCheckSNIConsensusFlapMixed(t *testing.T) {
	cert := selfSignedCert(t)
	ip, port := startTLSServer(t, cert, func(n int32) bool { return n%2 == 1 })
	res := checkSNIMulti(context.Background(), ip, port, multiCfg(2))
	if res.OK {
		t.Fatal("flap (1/2 pass) = OK, want failure")
	}
	if !res.Mixed {
		t.Fatal("flap = plain failure, want Mixed=true")
	}
	if !strings.Contains(res.Detail, "1/2 attempts failed") {
		t.Fatalf("detail missing split summary: %s", res.Detail)
	}
}
