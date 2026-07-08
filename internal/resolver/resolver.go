// Package resolver performs reverse-DNS (PTR) lookups with a bounded timeout.
package resolver

import (
	"context"
	"net"
	"strings"
	"time"
)

// LookupPTR resolves the PTR record(s) for ip, returning the first hostname
// found. ok is false if the lookup failed or returned no records within timeout.
func LookupPTR(ip string, timeout time.Duration) (hostname string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "", false
	}
	return strings.TrimSuffix(names[0], "."), true
}
