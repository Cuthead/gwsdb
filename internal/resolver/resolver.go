// Package resolver performs DNS lookups (PTR and forward A/AAAA), either via
// the host's system resolver or via a DNS-over-HTTPS (RFC 8484 wire format)
// endpoint when configured. DoH avoids depending on what a given
// deployment's local/ISP resolver happens to return -- some silently drop
// one of two PTR records Google publishes for the same IP, or steer
// geo-sensitive replies toward their own resolver's location.
package resolver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var httpClient = &http.Client{}

// LookupPTR resolves every PTR record for ip, deduped and sorted for
// deterministic ordering. Google sometimes publishes more than one PTR per
// IP (e.g. an f-numeric and an x-hex form of the same host), so callers
// that need a single hostname must pick one explicitly rather than assume
// there's only ever one. ok is false with a nil err when the record
// definitively does not exist (NXDOMAIN / no records); a non-nil err means
// the lookup failed transiently (timeout, HTTP error, malformed response)
// and says nothing about whether a PTR record exists.
//
// dohURL is an RFC 8484 DoH endpoint, e.g. "https://dns.google/dns-query".
// Empty uses the host's system resolver instead.
func LookupPTR(ip string, timeout time.Duration, dohURL string) (hostnames []string, ok bool, err error) {
	if dohURL == "" {
		return lookupPTRSystem(ip, timeout)
	}
	name, err := reverseName(ip)
	if err != nil {
		return nil, false, err
	}
	reply, err := doHQuery(name, dnsmessage.TypePTR, timeout, dohURL)
	if err != nil {
		return nil, false, err
	}
	if reply == nil {
		return nil, false, nil
	}
	for _, a := range reply.Answers {
		ptr, isPTR := a.Body.(*dnsmessage.PTRResource)
		if !isPTR {
			continue
		}
		if h := strings.TrimSuffix(ptr.PTR.String(), "."); h != "" {
			hostnames = append(hostnames, h)
		}
	}
	if len(hostnames) == 0 {
		return nil, false, nil
	}
	return dedupeSorted(hostnames), true, nil
}

// LookupHost forward-resolves host's A and AAAA records, each deduped and
// sorted. Both are empty (with ok=false, err=nil) if the host has neither --
// NXDOMAIN or an empty answer for both record types.
//
// dohURL is an RFC 8484 DoH endpoint; empty uses the host's system resolver.
func LookupHost(host string, timeout time.Duration, dohURL string) (ipv4, ipv6 []string, ok bool, err error) {
	if dohURL == "" {
		return lookupHostSystem(host, timeout)
	}
	replyA, errA := doHQuery(host, dnsmessage.TypeA, timeout, dohURL)
	if errA != nil {
		return nil, nil, false, errA
	}
	replyAAAA, errAAAA := doHQuery(host, dnsmessage.TypeAAAA, timeout, dohURL)
	if errAAAA != nil {
		return nil, nil, false, errAAAA
	}
	if replyA != nil {
		for _, a := range replyA.Answers {
			if rec, isA := a.Body.(*dnsmessage.AResource); isA {
				ipv4 = append(ipv4, net.IP(rec.A[:]).String())
			}
		}
	}
	if replyAAAA != nil {
		for _, a := range replyAAAA.Answers {
			if rec, isAAAA := a.Body.(*dnsmessage.AAAAResource); isAAAA {
				ipv6 = append(ipv6, net.IP(rec.AAAA[:]).String())
			}
		}
	}
	ipv4, ipv6 = dedupeSorted(ipv4), dedupeSorted(ipv6)
	return ipv4, ipv6, len(ipv4)+len(ipv6) > 0, nil
}

// lookupPTRSystem resolves via the host's system resolver (getaddrinfo/cgo
// or Go's pure-Go resolver, whichever net.DefaultResolver picks).
func lookupPTRSystem(ip string, timeout time.Duration) (hostnames []string, ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(names) == 0 {
		return nil, false, nil
	}
	return dedupeSorted(names), true, nil
}

// lookupHostSystem resolves via the host's system resolver.
func lookupHostSystem(host string, timeout time.Duration) (ipv4, ipv6 []string, ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	var v4, v6 []string
	for _, a := range addrs {
		if v4addr := a.IP.To4(); v4addr != nil {
			v4 = append(v4, v4addr.String())
		} else {
			v6 = append(v6, a.IP.String())
		}
	}
	v4, v6 = dedupeSorted(v4), dedupeSorted(v6)
	return v4, v6, len(v4)+len(v6) > 0, nil
}

// doHQuery sends a single RFC 8484 wire-format DoH question for name/qtype
// to dohURL and returns the parsed reply. A definitive NXDOMAIN/no-such-name
// answer is reported as a nil message with a nil error; any other failure
// (transport, non-success RCode, malformed response) is a non-nil error.
func doHQuery(name string, qtype dnsmessage.Type, timeout time.Duration, dohURL string) (*dnsmessage.Message, error) {
	fqdn, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, fmt.Errorf("doh: build query name: %w", err)
	}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  fqdn,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("doh: pack query: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// RFC 8484 GET form: base64url (no padding) of the wire-format query in
	// the "dns" parameter.
	u := dohURL + "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s: unexpected status %s", dohURL, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh %s: read response: %w", dohURL, err)
	}

	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("doh %s: unpack response: %w", dohURL, err)
	}
	if reply.RCode == dnsmessage.RCodeNameError {
		return nil, nil
	}
	if reply.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("doh %s: rcode %s", dohURL, reply.RCode)
	}
	return &reply, nil
}

// dedupeSorted trims trailing dots, dedupes, and sorts names/addresses for
// deterministic output regardless of the order a resolver returned them in.
func dedupeSorted(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// reverseName builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6) query name
// for ip, the same name a PTR query would use over classic DNS.
func reverseName(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP: %q", ip)
	}
	if v4 := parsed.To4(); v4 != nil && strings.Contains(ip, ".") {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v6 := parsed.To16()
	var sb strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", v6[i]&0xf, v6[i]>>4)
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}
