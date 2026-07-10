// Package resolver performs reverse-DNS (PTR) lookups, either via the host's
// system resolver or via a DNS-over-HTTPS (RFC 8484 wire format) endpoint
// when configured. DoH avoids depending on what a given deployment's
// local/ISP resolver happens to return -- some silently drop one of two PTR
// records Google publishes for the same IP, or steer geo-sensitive replies
// toward their own resolver's location.
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
	return lookupPTRDoH(ip, timeout, dohURL)
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

// lookupPTRDoH resolves via an RFC 8484 DoH endpoint using the standard wire
// format (application/dns-message), not any provider's proprietary JSON API.
func lookupPTRDoH(ip string, timeout time.Duration, dohURL string) (hostnames []string, ok bool, err error) {
	name, err := reverseName(ip)
	if err != nil {
		return nil, false, err
	}
	fqdn, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, false, fmt.Errorf("doh: build query name: %w", err)
	}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  fqdn,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := query.Pack()
	if err != nil {
		return nil, false, fmt.Errorf("doh: pack query: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// RFC 8484 GET form: base64url (no padding) of the wire-format query in
	// the "dns" parameter.
	u := dohURL + "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("doh %s: unexpected status %s", dohURL, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("doh %s: read response: %w", dohURL, err)
	}

	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return nil, false, fmt.Errorf("doh %s: unpack response: %w", dohURL, err)
	}
	if reply.RCode == dnsmessage.RCodeNameError {
		return nil, false, nil
	}
	if reply.RCode != dnsmessage.RCodeSuccess {
		return nil, false, fmt.Errorf("doh %s: rcode %s", dohURL, reply.RCode)
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

// dedupeSorted trims trailing dots, dedupes, and sorts hostnames for
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
