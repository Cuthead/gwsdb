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
	// IPRange is the source of candidate IPs.
	IPRange *IPRangeSource
	// InputFile is recorded on the Scan row for provenance (the
	// config's InputFile plus any extra -ip-range files, comma-joined).
	InputFile string

	Workers        int           // probe goroutine count (scan + recheck combined)
	RecheckWorkers int           // recheck goroutines carve-out; -1 = Workers/3, 0 = disable
	Interval       time.Duration // per-worker sleep between probes
	ProbeTimeout   time.Duration // per-probe deadline (bounds CheckSNI)
	FlushInterval  time.Duration // how often to submit accumulated checks

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

// Scanner is the long-running process: N probe workers + a flush ticker
// + a recheck-queue puller + a network monitor, all sharing one
// in-memory check buffer that the flusher periodically drains to the
// Cloudflare-hosted API.
type Scanner struct {
	cfg Config

	mu           sync.Mutex
	checks       []store.IPCheck
	pool         map[string]*ipState
	scannedCount int
	flushStart   time.Time

	// known-good set for FilterChecks' failure gate, owned by runFlusher's
	// goroutine (no locking needed). Refreshed hourly, extended locally
	// with each flush's discoveries — see flush.go.
	knownGood          map[string]bool
	knownGoodFetchedAt time.Time

	// Cumulative counters across flush windows, for the periodic status
	// log — scannedCount in flush.go resets each window.
	totalScanned atomic.Int64
	totalFound   atomic.Int64

	netMon networkMonitor
}

// New returns a Scanner with defaults applied for any zero/invalid
// Config field.
func New(cfg Config) *Scanner {
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 10 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Minute
	}
	return &Scanner{
		cfg:        cfg,
		pool:       make(map[string]*ipState),
		flushStart: time.Now().UTC(),
	}
}

// Run blocks until ctx is cancelled, running all subsystems in parallel
// goroutines. On cancellation it does one final flush so accumulated-
// but-unflushed checks aren't lost (the flusher's ctx.Done case runs a
// detached-context flush before returning).
func (s *Scanner) Run(ctx context.Context) error {
	recheckN := s.cfg.RecheckWorkers
	if recheckN < 0 {
		recheckN = s.cfg.Workers / 3
	}
	if recheckN > s.cfg.Workers {
		recheckN = s.cfg.Workers
	}
	scanN := s.cfg.Workers - recheckN

	v4, v6 := s.cfg.IPRange.Counts()
	log.Printf("scan: starting: %d workers (%d scan + %d recheck), interval=%s, flush=%s, probe=%s, %d CIDR prefixes (v4=%d, v6=%d)",
		s.cfg.Workers, scanN, recheckN, s.cfg.Interval, s.cfg.FlushInterval, s.cfg.ProbeAddr, s.cfg.IPRange.Len(), v4, v6)
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

	// Recheck workers: a feeder fetches the tracked pool from /api/pool
	// (oldest-first by lastSeen) and feeds IPs through an unbuffered
	// channel to N recheck workers, which re-probe each with the same
	// ping gate + CheckSNI as scan workers. The unbuffered channel means
	// the feeder blocks until a worker takes each IP, so it doesn't
	// re-fetch until the previous full cycle has been consumed — natural
	// backpressure, no double-queueing. See recheck_worker.go.
	if recheckN > 0 {
		jobs := make(chan string)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runRecheckFeeder(ctx, jobs)
		}()
		for range recheckN {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.runRecheckWorker(ctx, jobs)
			}()
		}
	}

	for range scanN {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runWorker(ctx)
		}()
	}

	<-ctx.Done()
	log.Printf("scan: shutting down, waiting for workers + final flush...")
	wg.Wait()
	log.Printf("scan: stopped")
	return ctx.Err()
}

// runWorker is the XX-Net scan_ip_worker equivalent: loop forever
// sleeping then probing a random IP, recording each result for the
// flusher to submit. Stops on ctx.Done.
func (s *Scanner) runWorker(ctx context.Context) {
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

		ip := s.cfg.IPRange.GetIP()

		// Ping gate: skip the TCP/SNI probe entirely if ICMP echo gets
		// no reply — most unreachable IPs fail ping too, so this saves a
		// ~10s dial timeout per dead IP and lets workers move on faster.
		// Ping uses unprivileged ICMP (udp4/udp6 datagram), no root needed.
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

// record appends one check to the buffer and updates the in-memory pool.
// Called from multiple worker goroutines — guarded by s.mu.
func (s *Scanner) record(ip string, result recheck.Result) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scannedCount++
	s.totalScanned.Add(1)
	s.checks = append(s.checks, store.IPCheck{
		IP:        ip,
		OK:        result.OK,
		RTTMs:     result.RTTMs,
		Reason:    result.Reason,
		Detail:    result.Detail,
		CheckedAt: now,
		ScanMode:  s.cfg.ScanMode,
	})
	if result.OK {
		s.totalFound.Add(1)
		// Log every hit so the operator can see the scanner is finding IPs
		// without waiting for a flush. Failures aren't logged here — they'd
		// flood (the vast majority of probes fail).
		log.Printf("scan: OK %s rtt=%dms", ip, result.RTTMs)
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
		log.Printf("scan: status: %d probes, %d found, pool=%d, pending=%d, net=%s",
			s.totalScanned.Load(), s.totalFound.Load(), poolSize, pending, net)
	}
}
