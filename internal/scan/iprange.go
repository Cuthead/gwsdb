// Package scan implements the always-on GWS IP scanner — a long-running
// process that continuously probes candidate Google IPs from real
// China-based network infrastructure, mirroring XX-Net's IpManager model:
// N worker goroutines each sleeping then probing a random IP drawn from
// a CIDR range file, with a periodic flush that submits accumulated
// results to the Cloudflare-hosted API. It replaces the old cron-driven
// scan_and_ingest.sh + external gscan_quic one-shot model.
//
// The probe itself reuses internal/recheck.CheckSNI (already a Go port of
// gscan_quic's testSni); submission reuses internal/ingest.Submit /
// FilterChecks / FetchKnownGood. Nothing here touches a local database —
// all persistence lives in D1 behind functions/, same as the rest of the
// China-box CLI.
package scan

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"sync"
)

// IPRangeSource holds a set of CIDR prefixes loaded from one or more
// range files (gscan_quic's iprange/iprange_gws_a.txt format: one CIDR
// per line, v4 or v6). GetIP picks a random prefix, then a random
// address within it — the same shape as XX-Net's Ipv4RangeSource but
// CIDR-based (gscan_quic's format) rather than begin-end-based, and
// v4/v6 agnostic (a single source can hold both; netip handles the
// address-family distinction, and recheck.CheckSNI dials both the same
// way via net.JoinHostPort).
type IPRangeSource struct {
	mu       sync.Mutex
	prefixes []netip.Prefix
}

// LoadIPRanges reads CIDR prefixes from the given files (one per line,
// blank lines and # comments ignored, unparseable lines skipped). Files
// may mix v4 and v6 CIDRs freely. Returns an error only if no valid
// prefix is loaded from any file.
func LoadIPRanges(paths []string) (*IPRangeSource, error) {
	var prefixes []netip.Prefix
	for _, p := range paths {
		if err := func() error {
			f, err := os.Open(p)
			if err != nil {
				return fmt.Errorf("open %s: %w", p, err)
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				prefix, err := netip.ParsePrefix(line)
				if err != nil {
					continue
				}
				prefixes = append(prefixes, prefix.Masked())
			}
			return sc.Err()
		}(); err != nil {
			return nil, err
		}
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no valid CIDR prefixes loaded from %v", paths)
	}
	return &IPRangeSource{prefixes: prefixes}, nil
}

// GetIP returns a uniformly random address within a randomly chosen
// prefix. Caller doesn't need to know whether it's v4 or v6 —
// recheck.CheckSNI dials via net.JoinHostPort which handles both.
func (s *IPRangeSource) GetIP() string {
	s.mu.Lock()
	prefix := s.prefixes[rand.Intn(len(s.prefixes))]
	s.mu.Unlock()
	return randomAddrInPrefix(prefix).String()
}

// Len returns the number of loaded prefixes (for startup logging).
func (s *IPRangeSource) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.prefixes)
}

// randomAddrInPrefix returns a random address within prefix. The prefix
// is assumed already Masked (network bits fixed, host bits zero) —
// LoadIPRanges calls Masked on load. Host bytes are filled with random
// data; the partial byte straddling the network/host boundary keeps its
// high network bits and randomizes only the low host bits. v4 and v6
// use the same logic since AsSlice gives the raw 4- or 16-byte form.
func randomAddrInPrefix(prefix netip.Prefix) netip.Addr {
	bits := prefix.Bits()
	b := prefix.Addr().AsSlice()

	// Fill whole host bytes (those entirely past the network prefix).
	firstFullHostByte := (bits + 7) / 8
	for i := firstFullHostByte; i < len(b); i++ {
		b[i] = byte(rand.Intn(256))
	}
	// Fill the partial byte's low host bits if the prefix isn't
	// byte-aligned (e.g. a /20 keeps the high 4 bits of byte 2).
	if rem := bits % 8; rem != 0 {
		partial := bits / 8
		mask := byte(0xFF << (8 - rem)) // high `rem` bits = network, keep
		b[partial] = (b[partial] & mask) | (byte(rand.Intn(256)) & ^mask)
	}

	if len(b) == 4 {
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	}
	var arr [16]byte
	copy(arr[:], b)
	return netip.AddrFrom16(arr)
}
