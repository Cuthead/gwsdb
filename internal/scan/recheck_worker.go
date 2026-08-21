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
func (s *Scanner) runRecheckFeeder(ctx context.Context, jobs chan<- ingest.PoolTarget, ipv6Only bool) {
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
		s.seedRecheckStates(pool)
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

func splitPoolByFamily(pool []ingest.PoolTarget) (ipv4, ipv6 []ingest.PoolTarget) {
	for _, target := range pool {
		addr, err := netip.ParseAddr(target.IP)
		if err != nil {
			log.Printf("scan: recheck feeder: invalid IP %q: %v", target.IP, err)
			continue
		}
		if addr.Is4() {
			ipv4 = append(ipv4, target)
		} else {
			ipv6 = append(ipv6, target)
		}
	}
	return ipv4, ipv6
}

func feedRecheckJobs(ctx context.Context, jobs chan<- ingest.PoolTarget, targets []ingest.PoolTarget) {
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return
		case jobs <- target:
		}
	}
}

// runRecheckWorker consumes IPs from jobs (fed by runRecheckFeeder),
// runs the ping gate + CheckSNI probe, and records the result for the
// flusher to submit. With PingCount=3 any-reply semantics the gate
// fails only on genuinely ICMP-dead targets, saving the TCP dial
// timeout those would otherwise burn. Stops on ctx cancellation. Same
// Interval sleep between probes as scan workers, so the two
// populations share the probe-rate budget.
func (s *Scanner) runRecheckWorker(ctx context.Context, jobs <-chan ingest.PoolTarget) {
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
		case target := <-jobs:
			// Ping gate: PingCount=3 with any-reply-passes cuts the
			// per-datagram ~25% GFW path loss to ~1.6%, so a gate failure
			// now means the target is genuinely ICMP-dead — skip the TCP
			// probe and record reason=ping. (The old single-shot gate
			// misfired a quarter of the time on healthy pool IPs.)
			pingCtx, pingCancel := context.WithTimeout(ctx, recheck.PingBudget)
			ping := recheck.Ping(pingCtx, target.IP)
			pingCancel()
			if !ping.OK {
				s.recordRecheck(target, recheck.Result{
					Reason: "ping",
					Detail: fmt.Sprintf("%s error=%s", recheck.ProbeParams(s.cfg.ProbeConfig), ping.Err),
				})
				continue
			}
			probeCtx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
			result := recheck.CheckSNI(probeCtx, target.IP, s.cfg.ProbeConfig)
			cancel()
			s.recordRecheck(target, result)
		}
	}
}
