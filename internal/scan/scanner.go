package scan

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/store"
)

// Config configures one always-on scanner process.
type Config struct {
	// ProbeConfig is the per-mode scan config (gscan_quic's
	// config.user.json SNI block) that recheck.CheckSNI probes with.
	ProbeConfig *ingest.ScanConfig
	// ScanMode is the mode name recorded on each flushed Scan row
	// ("SNI"). Must match recheck.DefaultScanMode since the probe is
	// SNI-specific.
	ScanMode string
	// IPRange is the source of candidate IPs. It may be nil when both scan
	// worker counts are zero and the process only rechecks known IPs.
	IPRange *IPRangeSource
	// InputFile is recorded on the Scan row for provenance (the
	// config's InputFile plus any extra -ip-range files, comma-joined).
	InputFile string

	IPv4Workers        int                // random IPv4 scan goroutines
	IPv6Workers        int                // random IPv6 scan goroutines
	IPv4RecheckWorkers int                // known IPv4 recheck goroutines
	IPv6RecheckWorkers int                // known IPv6 recheck goroutines
	Interval           time.Duration      // per-worker sleep between probes
	ProbeTimeout       time.Duration      // per-probe deadline (bounds CheckSNI)
	FlushInterval      time.Duration      // maximum age before submitting accumulated checks
	FlushSize          int                // submit early when this many checks are buffered
	RecheckInterval    time.Duration      // delay between completed recheck cycles per address family
	PingConfig         recheck.PingConfig // VerifyPing gate settings (top-level config block)

	// ProbeAddr is the address the on-demand probe HTTP server listens
	// on (e.g. "0.0.0.0:8787"), reached by the gwsdb-probe Worker (worker/)
	// over Cloudflare Mesh. Empty disables the probe server (scan-only mode).
	ProbeAddr string
	// ProbeToken authenticates probe requests (X-Probe-Token header,
	// crypto/subtle.ConstantTimeCompare). Must match the Cloudflare side's
	// PROBE_TOKEN.
	ProbeToken string

	APIBase string
	Token   string
}

// ipState is the scanner's in-memory view of one discovered IP. Not the
// source of truth (D1 is) — used only for diagnostics and to carry
// lastSeen/RTT across flush windows for the query-page freshness signal.
type ipState struct {
	lastRTT   int
	lastSeen  time.Time
	failTimes int
}

type recheckState struct {
	lastOK       bool
	lastSuccess  time.Time
	lastResultAt time.Time
}

// Scanner is the long-running process: N probe workers + a flush ticker
// + a recheck-queue puller + a network monitor, all sharing one
// in-memory check buffer that the flusher periodically drains to the
// Cloudflare-hosted API.
type Scanner struct {
	cfg Config

	mu                sync.Mutex
	checks            []store.IPCheck
	inFlightChecks    []store.IPCheck
	pool              map[string]*ipState
	scannedCount      int
	lastMaintenanceAt time.Time
	nextPruneRetryAt  time.Time
	flushReady        chan struct{}
	pruneIPs          map[string]struct{}
	recheckStates     map[string]recheckState

	// known-good set for FilterChecks' failure gate, owned by runFlusher's
	// goroutine (no locking needed). Refreshed hourly, extended locally
	// with each flush's discoveries — see flush.go.
	knownGood          map[string]bool
	knownGoodFetchedAt time.Time

	// Cumulative source counters for the periodic status log. Suppressed
	// rechecks succeeded but were inside the 24-hour heartbeat window.
	scanProbes        atomic.Int64
	scanFound         atomic.Int64
	recheckProbes     atomic.Int64
	recheckFound      atomic.Int64
	recheckSuppressed atomic.Int64

	netMon networkMonitor
}

// New returns a Scanner with defaults applied for zero/invalid durations.
func New(cfg Config) *Scanner {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 10 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.FlushSize <= 0 {
		cfg.FlushSize = 100
	}
	if cfg.RecheckInterval <= 0 {
		cfg.RecheckInterval = 10 * time.Minute
	}
	return &Scanner{
		cfg:           cfg,
		pool:          make(map[string]*ipState),
		flushReady:    make(chan struct{}, 1),
		pruneIPs:      make(map[string]struct{}),
		recheckStates: make(map[string]recheckState),
	}
}

// Run blocks until ctx is cancelled, running all subsystems in parallel
// goroutines. On cancellation it waits for every producer to stop, then does
// one final bounded-retry flush so no late check can miss the drain.
func (s *Scanner) Run(ctx context.Context) error {
	counts := []int{s.cfg.IPv4Workers, s.cfg.IPv6Workers, s.cfg.IPv4RecheckWorkers, s.cfg.IPv6RecheckWorkers}
	for _, count := range counts {
		if count < 0 {
			return fmt.Errorf("worker counts must not be negative")
		}
	}
	ipv4ScanN, ipv6ScanN := s.cfg.IPv4Workers, s.cfg.IPv6Workers
	v4, v6, prefixCount := 0, 0, 0
	if s.cfg.IPRange != nil {
		v4, v6 = s.cfg.IPRange.Counts()
		prefixCount = s.cfg.IPRange.Len()
	}
	if ipv4ScanN > 0 && v4 == 0 {
		log.Printf("scan: no IPv4 prefixes loaded; disabling %d IPv4 scan workers", ipv4ScanN)
		ipv4ScanN = 0
	}
	if ipv6ScanN > 0 && v6 == 0 {
		log.Printf("scan: no IPv6 prefixes loaded; disabling %d IPv6 scan workers", ipv6ScanN)
		ipv6ScanN = 0
	}
	totalWorkers := ipv4ScanN + ipv6ScanN + s.cfg.IPv4RecheckWorkers + s.cfg.IPv6RecheckWorkers
	log.Printf("scan: starting: %d workers (IPv4 scan=%d recheck=%d, IPv6 scan=%d recheck=%d), interval=%s, flush=%s/%d checks, probe=%s, %d CIDR prefixes (v4=%d, v6=%d)",
		totalWorkers, ipv4ScanN, s.cfg.IPv4RecheckWorkers, ipv6ScanN, s.cfg.IPv6RecheckWorkers,
		s.cfg.Interval, s.cfg.FlushInterval, s.cfg.FlushSize, s.cfg.ProbeAddr, prefixCount, v4, v6)
	log.Printf("scan: probe config: level=%d %s",
		s.cfg.ProbeConfig.Level,
		recheck.ProbeParams(s.cfg.ProbeConfig))

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.netMon.Run(ctx, 30*time.Second)
	}()

	if s.cfg.ProbeAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.runProbeServer(ctx, s.cfg.ProbeAddr, s.cfg.ProbeToken); err != nil {
				log.Printf("scan: probe server: %v", err)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runStatusLogger(ctx, 60*time.Second)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runFlusher(ctx)
	}()

	// Recheck workers: each address family independently fetches and consumes
	// its tracked pool, so a large IPv6 cycle cannot block a small IPv4 cycle.
	startRecheck := func(workerN int, ipv6 bool) {
		if workerN == 0 {
			return
		}
		jobs := make(chan ingest.PoolTarget)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runRecheckFeeder(ctx, jobs, ipv6)
		}()
		for range workerN {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.runRecheckWorker(ctx, jobs)
			}()
		}
	}
	startRecheck(s.cfg.IPv4RecheckWorkers, false)
	startRecheck(s.cfg.IPv6RecheckWorkers, true)

	for range ipv4ScanN {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runWorker(ctx, false)
		}()
	}
	for range ipv6ScanN {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runWorker(ctx, true)
		}()
	}

	<-ctx.Done()
	log.Printf("scan: shutting down, waiting for workers...")
	wg.Wait()
	log.Printf("scan: workers stopped, flushing remaining checks...")
	s.flushFinal()
	log.Printf("scan: stopped")
	return ctx.Err()
}

// runWorker is the XX-Net scan_ip_worker equivalent: loop forever
// sleeping then probing a random IP, recording each result for the
// flusher to submit. Stops on ctx.Done.
func (s *Scanner) runWorker(ctx context.Context, ipv6 bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.Interval):
		}
		if !s.netMon.OK() {
			// Network looks down — sleep and retry rather than hammering
			// dead dial attempts (mirrors XX-Net's check_local_network
			// gate in scan_ip_worker).
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		ip, ok := s.cfg.IPRange.GetIPv4()
		if ipv6 {
			ip, ok = s.cfg.IPRange.GetIPv6()
		}
		if !ok {
			return
		}

		// Ping gate, same as gscan_quic's VerifyPing: skip the TCP/SNI probe
		// entirely if ICMP echo gets no reply — most unreachable IPs fail
		// ping too, so this saves a ~10s dial timeout per dead IP.
		pingCtx, pingCancel := context.WithTimeout(ctx, s.cfg.PingConfig.PingBudget())
		ping := recheck.Ping(pingCtx, ip, s.cfg.PingConfig)
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

// /api/pool formats lastSeen to whole seconds, so the extra second prevents
// persisting a heartbeat up to 999ms before the true 24-hour boundary.
const recheckSuccessInterval = 24*time.Hour + time.Second

// record handles random scan results. Every scan result remains eligible for
// FilterChecks; only repeat successful rechecks are heartbeat-suppressed.
// Mixed (flapping) results are dropped entirely -- no check, no state update.
func (s *Scanner) record(ip string, result recheck.Result) {
	s.scanProbes.Add(1)
	if result.Mixed {
		log.Printf("scan: MIXED %s detail=%s (not recorded)", ip, result.Detail)
		return
	}
	if result.OK {
		s.scanFound.Add(1)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.recordResultLocked(ip, result, true, now, "scan")
	state, tracked := s.recheckStates[ip]
	if result.OK {
		s.recheckStates[ip] = recheckState{lastOK: true, lastSuccess: now, lastResultAt: now}
	} else if tracked {
		state.lastOK = false
		state.lastResultAt = now
		s.recheckStates[ip] = state
	}
	s.mu.Unlock()
}

// seedRecheckStates captures the server state when a feeder loads its queue.
// Existing entries win because they reflect probes completed after that
// potentially stale snapshot was fetched.
func (s *Scanner) seedRecheckStates(targets []ingest.PoolTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := make(map[string]store.IPCheck, len(s.checks)+len(s.inFlightChecks))
	for _, check := range append(s.checks, s.inFlightChecks...) {
		if previous, exists := pending[check.IP]; !exists || check.CheckedAt.After(previous.CheckedAt) {
			pending[check.IP] = check
		}
	}
	for _, target := range targets {
		state, exists := s.recheckStates[target.IP]
		if !exists {
			state = recheckState{lastOK: true, lastSuccess: target.LastSeen, lastResultAt: target.LastSeen}
		} else {
			if target.LastSeen.After(state.lastSuccess) {
				state.lastSuccess = target.LastSeen
			}
			if target.LastSeen.After(state.lastResultAt) {
				state.lastOK = true
				state.lastResultAt = target.LastSeen
			}
		}
		if check, exists := pending[target.IP]; exists && check.CheckedAt.After(state.lastResultAt) {
			state.lastOK = check.OK
			state.lastResultAt = check.CheckedAt
			if check.OK {
				state.lastSuccess = check.CheckedAt
			}
		}
		s.recheckStates[target.IP] = state
	}
}

// mergeSubmittedStates records only checks the server accepted (after
// FilterChecks removed unknown failures), then clears the in-flight snapshot.
// This closes the gap where a feeder fetched stale state before submission
// but did not seed its queue until after the request completed.
func (s *Scanner) mergeSubmittedStates(checks []store.IPCheck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, check := range checks {
		state, exists := s.recheckStates[check.IP]
		if !exists {
			state = recheckState{}
		}
		if check.CheckedAt.After(state.lastResultAt) {
			state.lastOK = check.OK
			state.lastResultAt = check.CheckedAt
		}
		if check.OK && check.CheckedAt.After(state.lastSuccess) {
			state.lastSuccess = check.CheckedAt
		}
		s.recheckStates[check.IP] = state
	}
	s.inFlightChecks = nil
}

// recordRecheck persists failures immediately and successful heartbeats only
// when the server's last successful check is at least 24 hours old.
func (s *Scanner) recordRecheck(target ingest.PoolTarget, result recheck.Result) {
	s.recheckProbes.Add(1)
	if result.Mixed {
		log.Printf("scan: recheck MIXED %s detail=%s (not recorded)", target.IP, result.Detail)
		return
	}
	if result.OK {
		s.recheckFound.Add(1)
	} else {
		log.Printf("scan: recheck FAIL %s reason=%s detail=%s", target.IP, result.Reason, result.Detail)
	}
	now := time.Now().UTC()
	s.mu.Lock()
	state, tracked := s.recheckStates[target.IP]
	if !tracked {
		state = recheckState{lastOK: true, lastSuccess: target.LastSeen, lastResultAt: target.LastSeen}
	}
	// Failures always persist. A success persists on recovery or once the
	// latest locally/server-observed successful heartbeat reaches 24 hours.
	persist := !result.OK || !state.lastOK || state.lastSuccess.IsZero() || now.Sub(state.lastSuccess) >= recheckSuccessInterval
	if !persist {
		s.recheckSuppressed.Add(1)
	}
	s.recordResultLocked(target.IP, result, persist, now, "recheck")
	state.lastOK = result.OK
	state.lastResultAt = now
	if result.OK && persist {
		state.lastSuccess = now
	}
	s.recheckStates[target.IP] = state
	s.mu.Unlock()
}

// sourcePrefix tags a check's reason with its probe origin. Failures keep
// their cause ("recheck:ping"); successes carry a bare origin ("scan:ok") so
// the query page can attribute reachable rows too.
func sourcePrefix(ok bool, source, reason string) string {
	if ok {
		return source + ":ok"
	}
	return source + ":" + reason
}

// recordResultLocked updates diagnostics and conditionally appends a check.
// Caller holds s.mu so heartbeat decisions and state updates stay atomic.
func (s *Scanner) recordResultLocked(ip string, result recheck.Result, persist bool, now time.Time, source string) {
	s.scannedCount++
	if persist {
		s.checks = append(s.checks, store.IPCheck{
			IP:    ip,
			OK:    result.OK,
			RTTMs: result.RTTMs,
			// Prefix the failure reason with the probe origin ("scan:" /
			// "recheck:") so the query page's history can attribute each
			// failed check without a dedicated source column. Successes keep
			// an empty reason.
			Reason:    sourcePrefix(result.OK, source, result.Reason),
			Detail:    result.Detail,
			CheckedAt: now,
			ScanMode:  s.cfg.ScanMode,
		})
		if len(s.checks) >= s.cfg.FlushSize {
			select {
			case s.flushReady <- struct{}{}:
			default:
			}
		}
	}
	if result.OK {
		if persist {
			log.Printf("scan: %s OK %s rtt=%dms", source, ip, result.RTTMs)
		}
		st := s.pool[ip]
		if st == nil {
			st = &ipState{}
			s.pool[ip] = st
		}
		st.lastRTT = result.RTTMs
		st.lastSeen = now
		st.failTimes = 0
	} else if st, ok := s.pool[ip]; ok {
		st.failTimes++
	}
}

// runStatusLogger prints a periodic one-line summary so the operator can
// tell the scanner is alive and making progress between flushes — without
// it, a healthy scanner with no hits is silent for the whole flush window.
func (s *Scanner) runStatusLogger(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		poolSize := len(s.pool)
		pending := len(s.checks)
		s.mu.Unlock()
		net := "down"
		if s.netMon.OK() {
			net = "up"
		}
		log.Printf("scan: status: scan=%d probes/%d found, recheck=%d probes/%d found/%d suppressed, pool=%d, pending=%d, net=%s",
			s.scanProbes.Load(), s.scanFound.Load(),
			s.recheckProbes.Load(), s.recheckFound.Load(), s.recheckSuppressed.Load(),
			poolSize, pending, net)
	}
}
