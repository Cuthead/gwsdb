// Package asn resolves an IP address to its announcing AS number, AS name,
// and BGP-announced prefix via Team Cymru's DNS whois service. No local
// GeoIP/ASN database file is required -- it's two DNS TXT lookups.
package asn

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Info is the result of an ASN lookup for one IP.
type Info struct {
	ASN     int
	ASName  string
	Prefix  string // BGP-announced prefix containing the IP, e.g. "1.1.1.0/24"
	Country string
}

// Lookup resolves ip's origin AS and announced prefix. ok is false if ip is
// invalid or the lookup failed/timed out.
func Lookup(ip string, timeout time.Duration) (Info, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Info{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var query string
	if v4 := parsed.To4(); v4 != nil {
		query = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	} else {
		query = reverseNibbles(parsed) + ".origin6.asn.cymru.com"
	}

	txts, err := net.DefaultResolver.LookupTXT(ctx, query)
	if err != nil || len(txts) == 0 {
		return Info{}, false
	}
	// "13335 | 1.1.1.0/24 | US | apnic | 2011-08-11" -- multiple origin ASNs
	// are newline-joined within the record; take the first.
	fields := strings.Split(strings.Split(txts[0], "\n")[0], "|")
	if len(fields) < 3 {
		return Info{}, false
	}
	asnField := strings.Fields(strings.TrimSpace(fields[0]))
	if len(asnField) == 0 {
		return Info{}, false
	}
	asnNum, err := strconv.Atoi(asnField[0])
	if err != nil {
		return Info{}, false
	}

	info := Info{
		ASN:     asnNum,
		Prefix:  strings.TrimSpace(fields[1]),
		Country: strings.TrimSpace(fields[2]),
	}

	if nameTxts, err := net.DefaultResolver.LookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asnNum)); err == nil && len(nameTxts) > 0 {
		// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
		nf := strings.Split(nameTxts[0], "|")
		if len(nf) >= 5 {
			info.ASName = strings.TrimSpace(nf[4])
		}
	}

	return info, true
}

// reverseNibbles renders ip (IPv6) as the dot-separated, reversed hex nibble
// string origin6.asn.cymru.com expects (the same scheme as ip6.arpa PTRs).
func reverseNibbles(ip net.IP) string {
	h := hex.EncodeToString(ip.To16())
	parts := make([]string, len(h))
	for i, n := 0, len(h); i < n; i++ {
		parts[i] = string(h[n-1-i])
	}
	return strings.Join(parts, ".")
}
