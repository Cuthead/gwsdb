package scan

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
)

// runRecheckFeeder periodically fetches one address family's tracked pool
// from /api/pool (sorted oldest-first by lastSeen) and pushes it into jobs. It
// blocks on jobs when workers are slow, so a full pool cycle naturally
// takes pool_size / recheck_workers * interval — the feeder doesn't
// re-fetch until the previous batch has been consumed and one recheck
// interval has passed, preventing rapid repeats of a small pool.
// Stops on ctx cancellation.
//
// This mirrors XX-Net's IpManager scan_ip_worker recheck mode: when the
// pool is full, the scan worker stops scanning new IPs and instead
// pulls from get_ip_sni_host (the sorted ip_list) to re-verify existing
// IPs. IPv4 and IPv6 use independent feeders so a large pool in one family
// cannot delay the next cycle of the other family.
func (s *Scanner) runRecheckFeeder(ctx context.Context, jobs chan<- string, ipv6Only bool) {
	family := "IPv4"
	if ipv6Only {
		family = "IPv6"
	}
	familyNumber := 4
	if ipv6Only {
		familyNumber = 6
	}
	for {
		if ctx.Err() != nil {
			return
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		pool, err := ingest.FetchPool(fetchCtx, s.cfg.APIBase, familyNumber)
		cancel()
		if err != nil {
			log.Printf("scan: %s recheck feeder: fetch pool: %v — retrying in 30s", family, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		ipv4, ipv6 := splitPoolByFamily(pool)
		matching := ipv4
		if ipv6Only {
			matching = ipv6
		}
		if len(matching) == 0 {
			log.Printf("scan: %s recheck feeder: pool empty — waiting 60s", family)
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second):
			}
			continue
		}
		log.Printf("scan: %s recheck feeder: queued %d IPs (oldest first)", family, len(matching))
		feedRecheckJobs(ctx, jobs, matching)
		log.Printf("scan: %s recheck feeder: cycle consumed — waiting %s before next cycle", family, s.cfg.RecheckInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.RecheckInterval):
		}
	}
}

func splitPoolByFamily(pool []string) (ipv4, ipv6 []string) {
	for _, ip := range pool {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			log.Printf("scan: recheck feeder: invalid IP %q: %v", ip, err)
			continue
		}
		if addr.Is4() {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}
	return ipv4, ipv6
}

func feedRecheckJobs(ctx context.Context, jobs chan<- string, ips []string) {
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return
		case jobs <- ip:
		}
	}
}

// runRecheckWorker consumes IPs from jobs (fed by runRecheckFeeder),
// runs the same ping gate + CheckSNI probe as the scan worker, and
// records the result for the flusher to submit. The recorded checks
// flow through the same flush path as scan results, so a recheck failure
// writes an ok=0 ip_checks row and refreshPoolForIPs updates the pool's
// last_check_ok / last_checked_at accordingly — no special "tombstone"
// or removal logic, matching the existing behavior for scan failures.
//
// Stops on ctx cancellation. Same Interval sleep between probes as scan
// workers, so the two populations share the probe-rate budget cleanly.
func (s *Scanner) runRecheckWorker(ctx context.Context, jobs <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.Interval):
		}
		if !s.netMon.OK() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case ip := <-jobs:
			// Ping gate — same as runWorker: skip the TCP/SNI probe if
			// ICMP echo gets no reply, recording reason=ping so the
			// failure reason is distinguishable from a dial failure.
			pingCtx, pingCancel := context.WithTimeout(ctx, recheck.PingTimeout)
			ping := recheck.Ping(pingCtx, ip)
			pingCancel()
			if !ping.OK {
				s.record(ip, recheck.Result{
					Reason: "ping",
					Detail: fmt.Sprintf("%s error=%s", recheck.ProbeParams(s.cfg.ProbeConfig), ping.Err),
				})
				continue
			}
			probeCtx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
			result := recheck.CheckSNI(probeCtx, ip, s.cfg.ProbeConfig)
			cancel()
			s.record(ip, result)
		}
	}
}
