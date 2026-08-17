package scan

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// networkMonitor periodically checks whether the local network can reach
// the outside world, mirroring XX-Net's check_local_network module
// (gae_proxy/local/check_local_network.py). When the network is down,
// probe workers sleep instead of burning through dial attempts that will
// all fail — a GFW-induced outage shouldn't generate a flood of failure
// checks or wasted probe work. Uses bing.com as the reachability target
// (XX-Net's choice), which is reliably reachable from China when the
// network is up and doesn't touch Google infrastructure.
type networkMonitor struct {
	ok   atomic.Bool
	prev atomic.Bool
}

// Run blocks until ctx is cancelled, probing reachability every
// interval. Assumes up at startup; the first tick corrects if not.
// Logs state transitions only — a steady "up" every 30s would be noise;
// a change (up→down or down→up) is what the operator needs to see.
func (n *networkMonitor) Run(ctx context.Context, interval time.Duration) {
	n.ok.Store(true)
	n.prev.Store(true)
	client := &http.Client{Timeout: 5 * time.Second}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := checkReachable(ctx, client)
			n.ok.Store(now)
			if now != n.prev.Swap(now) {
				if now {
					log.Printf("scan: network up")
				} else {
					log.Printf("scan: network down — pausing probe workers")
				}
			}
		}
	}
}

// OK reports whether the last probe succeeded.
func (n *networkMonitor) OK() bool { return n.ok.Load() }

// checkReachable returns true if a HEAD request to bing.com completes
// without transport error — any HTTP response (even 4xx/5xx) means the
// network path is up; a transport error means it's down.
func checkReachable(ctx context.Context, client *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://www.bing.com/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}
