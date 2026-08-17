package scan

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
)

// runRecheckFeeder periodically fetches the tracked pool from /api/pool
// (sorted oldest-first by lastSeen) and pushes each IP into jobs. It
// blocks on jobs when workers are slow, so a full pool cycle naturally
// takes pool_size / recheck_workers * interval — the feeder doesn't
// re-fetch until the previous batch has been consumed, preventing
// double-queueing. Stops on ctx cancellation.
//
// This mirrors XX-Net's IpManager scan_ip_worker recheck mode: when the
// pool is full, the scan worker stops scanning new IPs and instead
// pulls from get_ip_sni_host (the sorted ip_list) to re-verify existing
// IPs. Here the feeder is split into its own goroutine so N recheck
// workers can consume in parallel without contending for a single
// shared pointer.
func (s *Scanner) runRecheckFeeder(ctx context.Context, jobs chan<- string) {
	for {
		if ctx.Err() != nil {
			return
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		pool, err := ingest.FetchPool(fetchCtx, s.cfg.APIBase)
		cancel()
		if err != nil {
			log.Printf("scan: recheck feeder: fetch pool: %v — retrying in 30s", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		if len(pool) == 0 {
			log.Printf("scan: recheck feeder: pool empty — waiting 60s")
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second):
			}
			continue
		}
		log.Printf("scan: recheck feeder: queued %d IPs (oldest first)", len(pool))
		for _, ip := range pool {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
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
