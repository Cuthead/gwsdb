package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/store"
)

func TestSplitPoolByFamily(t *testing.T) {
	ipv4, ipv6 := splitPoolByFamily([]ingest.PoolTarget{
		{IP: "2001:db8::1"},
		{IP: "192.0.2.1"},
		{IP: "invalid"},
		{IP: "198.51.100.2"},
		{IP: "2001:db8::2"},
	})
	if want := []ingest.PoolTarget{{IP: "192.0.2.1"}, {IP: "198.51.100.2"}}; !reflect.DeepEqual(ipv4, want) {
		t.Fatalf("IPv4 = %v, want %v", ipv4, want)
	}
	if want := []ingest.PoolTarget{{IP: "2001:db8::1"}, {IP: "2001:db8::2"}}; !reflect.DeepEqual(ipv6, want) {
		t.Fatalf("IPv6 = %v, want %v", ipv6, want)
	}
}

func TestFeedRecheckJobsStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		feedRecheckJobs(ctx, make(chan ingest.PoolTarget), []ingest.PoolTarget{{IP: "192.0.2.1"}})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("feedRecheckJobs did not stop after cancellation")
	}
}

func TestRecheckFeederWaitsForRecheckInterval(t *testing.T) {
	requests := make(chan time.Time, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("family"); got != "4" {
			t.Errorf("family = %q, want 4", got)
		}
		requests <- time.Now()
		_, _ = w.Write([]byte(`{"ips":[{"ip":"192.0.2.1","lastSeen":"2026-08-19 11:00:00","status":"Reachable"}]}`))
	}))
	defer server.Close()

	const recheckInterval = 200 * time.Millisecond
	s := New(Config{APIBase: server.URL, RecheckInterval: recheckInterval})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobs := make(chan ingest.PoolTarget)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-jobs:
			}
		}
	}()
	go s.runRecheckFeeder(ctx, jobs, false)

	first := <-requests
	select {
	case second := <-requests:
		if elapsed := second.Sub(first); elapsed < recheckInterval {
			t.Fatalf("pool refetched after %s, before recheck interval %s", elapsed, recheckInterval)
		}
	case <-time.After(recheckInterval + time.Second):
		t.Fatal("pool was not refetched after recheck interval")
	}
}

func TestRecheckFamiliesRunIndependentCycles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ips":[{"ip":"192.0.2.1","lastSeen":"2026-08-20 03:00:00","status":"Reachable"},{"ip":"2001:db8::1","lastSeen":"2026-08-20 03:00:00","status":"Reachable"}]}`))
	}))
	defer server.Close()

	s := New(Config{APIBase: server.URL, RecheckInterval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ipv4Jobs := make(chan ingest.PoolTarget)
	ipv6Jobs := make(chan ingest.PoolTarget) // Deliberately never consumed.
	ipv4Checks := make(chan string, 2)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case target := <-ipv4Jobs:
				select {
				case ipv4Checks <- target.IP:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go s.runRecheckFeeder(ctx, ipv4Jobs, false)
	go s.runRecheckFeeder(ctx, ipv6Jobs, true)

	for range 2 {
		select {
		case ip := <-ipv4Checks:
			if ip != "192.0.2.1" {
				t.Fatalf("IPv4 feeder returned %q", ip)
			}
		case <-time.After(time.Second):
			t.Fatal("IPv4 feeder was blocked by unfinished IPv6 cycle")
		}
	}
}

func TestRecheckSuccessHeartbeatAndFailurePersistence(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	recent := ingest.PoolTarget{IP: "192.0.2.1", LastSeen: time.Now().UTC().Add(-time.Hour)}
	s.recordRecheck(recent, recheck.Result{OK: true, RTTMs: 10})
	if len(s.checks) != 0 {
		t.Fatalf("recent successful recheck buffered %d checks, want 0", len(s.checks))
	}
	if got := s.recheckSuppressed.Load(); got != 1 {
		t.Fatalf("suppressed = %d, want 1", got)
	}

	s.recordRecheck(recent, recheck.Result{Reason: "ping"})
	if len(s.checks) != 1 || s.checks[0].OK {
		t.Fatalf("failure checks = %+v, want one failed check", s.checks)
	}
	s.recordRecheck(recent, recheck.Result{OK: true, RTTMs: 15})
	if len(s.checks) != 2 || !s.checks[1].OK {
		t.Fatalf("recovery checks = %+v, want immediate successful transition", s.checks)
	}

	old := ingest.PoolTarget{IP: "192.0.2.2", LastSeen: time.Now().UTC().Add(-25 * time.Hour)}
	s.recordRecheck(old, recheck.Result{OK: true, RTTMs: 20})
	if len(s.checks) != 3 || !s.checks[2].OK {
		t.Fatalf("old success checks = %+v, want persisted heartbeat", s.checks)
	}
	// The same stale feeder snapshot must not persist a second heartbeat.
	s.recordRecheck(old, recheck.Result{OK: true, RTTMs: 21})
	if len(s.checks) != 3 {
		t.Fatalf("duplicate old heartbeat buffered %d checks, want 3", len(s.checks))
	}
	if got := s.recheckProbes.Load(); got != 5 {
		t.Fatalf("recheck probes = %d, want 5", got)
	}
	if got := s.recheckFound.Load(); got != 4 {
		t.Fatalf("recheck found = %d, want 4", got)
	}
	if got := s.recheckSuppressed.Load(); got != 2 {
		t.Fatalf("recheck suppressed = %d, want 2", got)
	}
}

func TestFailureReasonCarriesSourcePrefix(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	target := ingest.PoolTarget{IP: "192.0.2.9", LastSeen: time.Now().UTC().Add(-time.Hour)}

	s.record(target.IP, recheck.Result{Reason: "ping", Detail: "scan probe"})
	if got := s.checks[0].Reason; got != "scan:ping" {
		t.Fatalf("scan failure reason = %q, want %q", got, "scan:ping")
	}

	s.recordRecheck(target, recheck.Result{Reason: "ping", Detail: "recheck probe"})
	if got := s.checks[1].Reason; got != "recheck:ping" {
		t.Fatalf("recheck failure reason = %q, want %q", got, "recheck:ping")
	}

	s.record(target.IP, recheck.Result{OK: true, RTTMs: 5})
	if got := s.checks[2].Reason; got != "scan:ok" {
		t.Fatalf("scan success reason = %q, want %q", got, "scan:ok")
	}

	oldTarget := ingest.PoolTarget{IP: "192.0.2.10", LastSeen: time.Now().UTC().Add(-25 * time.Hour)}
	s.recordRecheck(oldTarget, recheck.Result{OK: true, RTTMs: 5})
	if got := s.checks[3].Reason; got != "recheck:ok" {
		t.Fatalf("recheck heartbeat success reason = %q, want %q", got, "recheck:ok")
	}
}

func TestScanFailureBeforeRecheckForcesRecoveryPersistence(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	target := ingest.PoolTarget{IP: "192.0.2.1", LastSeen: time.Now().UTC().Add(-time.Hour)}
	s.seedRecheckStates([]ingest.PoolTarget{target})

	// Random scan failure arrives while target waits in the feeder queue.
	s.record(target.IP, recheck.Result{Reason: "ping"})
	s.recordRecheck(target, recheck.Result{OK: true, RTTMs: 10})

	if len(s.checks) != 2 || s.checks[0].OK || !s.checks[1].OK {
		t.Fatalf("checks = %+v, want failure followed by persisted recovery", s.checks)
	}
}

func TestBufferedFailureBeforeFeederSeedForcesRecoveryPersistence(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	target := ingest.PoolTarget{IP: "192.0.2.1", LastSeen: time.Now().UTC().Add(-time.Hour)}

	s.record(target.IP, recheck.Result{Reason: "ping"})
	s.seedRecheckStates([]ingest.PoolTarget{target})
	s.recordRecheck(target, recheck.Result{OK: true, RTTMs: 10})

	if len(s.checks) != 2 || s.checks[0].OK || !s.checks[1].OK {
		t.Fatalf("checks = %+v, want buffered failure followed by persisted recovery", s.checks)
	}
}

func TestNewerPoolSnapshotAdvancesHeartbeatCursor(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	ip := "192.0.2.1"
	old := ingest.PoolTarget{IP: ip, LastSeen: time.Now().UTC().Add(-2 * time.Hour)}
	newer := ingest.PoolTarget{IP: ip, LastSeen: time.Now().UTC().Add(-time.Hour)}
	s.seedRecheckStates([]ingest.PoolTarget{old})
	s.recordRecheck(old, recheck.Result{OK: true, RTTMs: 9}) // suppressed, but advances lastResultAt locally
	s.seedRecheckStates([]ingest.PoolTarget{newer})

	if got := s.recheckStates[ip].lastSuccess; !got.Equal(newer.LastSeen) {
		t.Fatalf("lastSuccess = %s, want newer server cursor %s", got, newer.LastSeen)
	}
	s.recordRecheck(newer, recheck.Result{OK: true, RTTMs: 10})
	if len(s.checks) != 0 {
		t.Fatalf("newer external heartbeat buffered %d checks, want 0", len(s.checks))
	}
}

func TestInFlightFailureBeforeFeederSeedForcesRecoveryPersistence(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	target := ingest.PoolTarget{IP: "192.0.2.1", LastSeen: time.Now().UTC().Add(-time.Hour)}
	s.inFlightChecks = []store.IPCheck{{IP: target.IP, OK: false, CheckedAt: time.Now().UTC()}}
	s.seedRecheckStates([]ingest.PoolTarget{target})
	s.recordRecheck(target, recheck.Result{OK: true, RTTMs: 10})

	if len(s.checks) != 1 || !s.checks[0].OK {
		t.Fatalf("checks = %+v, want persisted recovery after in-flight failure", s.checks)
	}
}

func TestSubmittedFailureBeforeDelayedFeederSeedForcesRecoveryPersistence(t *testing.T) {
	s := New(Config{ScanMode: "SNI"})
	target := ingest.PoolTarget{IP: "192.0.2.1", LastSeen: time.Now().UTC().Add(-time.Hour)}
	failure := store.IPCheck{IP: target.IP, OK: false, CheckedAt: time.Now().UTC()}

	// Feeder has fetched target but has not seeded it when submission finishes.
	s.inFlightChecks = []store.IPCheck{failure}
	s.mergeSubmittedStates([]store.IPCheck{failure})
	s.seedRecheckStates([]ingest.PoolTarget{target})
	s.recordRecheck(target, recheck.Result{OK: true, RTTMs: 10})

	if len(s.checks) != 1 || !s.checks[0].OK {
		t.Fatalf("checks = %+v, want persisted recovery after submitted failure", s.checks)
	}
}
