// Package resolver performs reverse-DNS (PTR) lookups with a bounded timeout.
package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// LookupPTR resolves the PTR record(s) for ip, returning the first hostname
// found. ok is false with a nil err when the record definitively does not
// exist (NXDOMAIN / no records); a non-nil err means the lookup failed
// transiently (timeout, SERVFAIL, network error) and says nothing about
// whether a PTR record exists.
func LookupPTR(ip string, timeout time.Duration) (hostname string, ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	if len(names) == 0 {
		return "", false, nil
	}
	return strings.TrimSuffix(names[0], "."), true, nil
}
