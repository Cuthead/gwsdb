// Package resolver performs DNS lookups (PTR, forward A/AAAA, and TXT) over
// DNS-over-HTTPS (RFC 8484 wire format), not the host's system resolver, so
// results don't depend on what a given deployment's local/ISP resolver
// happens to return -- some silently drop one of two PTR records Google
// publishes for the same IP, or steer geo-sensitive replies toward their own
// resolver's location. It also has no way to report the record's DNS TTL,
// which callers need to cache results correctly; the wire-format DoH
// response carries it directly.
package resolver

import (
	"context"
	"encoding/base64"
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
// deterministic ordering, plus the minimum TTL across the matched records
// (how long the result may be cached). Google sometimes publishes more than
// one PTR per IP (e.g. an f-numeric and an x-hex form of the same host), so
// callers that need a single hostname must pick one explicitly rather than
// assume there's only ever one. ok is false with a nil err when the record
// definitively does not exist (NXDOMAIN / no records); a non-nil err means
// the lookup failed transiently (timeout, HTTP error, malformed response)
// and says nothing about whether a PTR record exists.
//
// dohURL is an RFC 8484 DoH endpoint, e.g. "https://dns.google/dns-query",
// and is required.
func LookupPTR(ip string, timeout time.Duration, dohURL string) (hostnames []string, ttl time.Duration, ok bool, err error) {
	name, err := reverseName(ip)
	if err != nil {
		return nil, 0, false, err
	}
	reply, err := doHQuery(name, dnsmessage.TypePTR, timeout, dohURL)
	if err != nil {
		return nil, 0, false, err
	}
	if reply == nil {
		return nil, 0, false, nil
	}
	var minSeconds uint32
	for _, a := range reply.Answers {
		ptr, isPTR := a.Body.(*dnsmessage.PTRResource)
		if !isPTR {
			continue
		}
		if h := strings.TrimSuffix(ptr.PTR.String(), "."); h != "" {
			hostnames = append(hostnames, h)
			if minSeconds == 0 || a.Header.TTL < minSeconds {
				minSeconds = a.Header.TTL
			}
		}
	}
	if len(hostnames) == 0 {
		return nil, 0, false, nil
	}
	return dedupeSorted(hostnames), time.Duration(minSeconds) * time.Second, true, nil
}

// LookupHost forward-resolves host's A and AAAA records, each deduped and
// sorted, plus the minimum TTL across every matched record. Both address
// lists are empty (with ok=false, err=nil, ttl=0) if the host has neither --
// NXDOMAIN or an empty answer for both record types.
//
// dohURL is an RFC 8484 DoH endpoint and is required.
func LookupHost(host string, timeout time.Duration, dohURL string) (ipv4, ipv6 []string, ttl time.Duration, ok bool, err error) {
	replyA, errA := doHQuery(host, dnsmessage.TypeA, timeout, dohURL)
	if errA != nil {
		return nil, nil, 0, false, errA
	}
	replyAAAA, errAAAA := doHQuery(host, dnsmessage.TypeAAAA, timeout, dohURL)
	if errAAAA != nil {
		return nil, nil, 0, false, errAAAA
	}
	var minSeconds uint32
	observe := func(s uint32) {
		if minSeconds == 0 || s < minSeconds {
			minSeconds = s
		}
	}
	if replyA != nil {
		for _, a := range replyA.Answers {
			if rec, isA := a.Body.(*dnsmessage.AResource); isA {
				ipv4 = append(ipv4, net.IP(rec.A[:]).String())
				observe(a.Header.TTL)
			}
		}
	}
	if replyAAAA != nil {
		for _, a := range replyAAAA.Answers {
			if rec, isAAAA := a.Body.(*dnsmessage.AAAAResource); isAAAA {
				ipv6 = append(ipv6, net.IP(rec.AAAA[:]).String())
				observe(a.Header.TTL)
			}
		}
	}
	ipv4, ipv6 = dedupeSorted(ipv4), dedupeSorted(ipv6)
	return ipv4, ipv6, time.Duration(minSeconds) * time.Second, len(ipv4)+len(ipv6) > 0, nil
}

// LookupTXT resolves every TXT record for name, in answer order (not
// deduped -- unlike hostnames/addresses, repeated identical TXT strings can
// be meaningful), plus the minimum TTL across them.
//
// dohURL is an RFC 8484 DoH endpoint and is required.
func LookupTXT(name string, timeout time.Duration, dohURL string) (txts []string, ttl time.Duration, ok bool, err error) {
	reply, err := doHQuery(name, dnsmessage.TypeTXT, timeout, dohURL)
	if err != nil {
		return nil, 0, false, err
	}
	if reply == nil {
		return nil, 0, false, nil
	}
	var minSeconds uint32
	for _, a := range reply.Answers {
		txt, isTXT := a.Body.(*dnsmessage.TXTResource)
		if !isTXT {
			continue
		}
		txts = append(txts, strings.Join(txt.TXT, ""))
		if minSeconds == 0 || a.Header.TTL < minSeconds {
			minSeconds = a.Header.TTL
		}
	}
	if len(txts) == 0 {
		return nil, 0, false, nil
	}
	return txts, time.Duration(minSeconds) * time.Second, true, nil
}

// doHQuery sends a single RFC 8484 wire-format DoH question for name/qtype
// to dohURL and returns the parsed reply. A definitive NXDOMAIN/no-such-name
// answer is reported as a nil message with a nil error; any other failure
// (transport, non-success RCode, malformed response) is a non-nil error.
func doHQuery(name string, qtype dnsmessage.Type, timeout time.Duration, dohURL string) (*dnsmessage.Message, error) {
	if dohURL == "" {
		return nil, fmt.Errorf("doh: no endpoint configured")
	}
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
