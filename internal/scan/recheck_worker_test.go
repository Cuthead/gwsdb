package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestSplitPoolByFamily(t *testing.T) {
	ipv4, ipv6 := splitPoolByFamily([]string{
		"2001:db8::1",
		"192.0.2.1",
		"invalid",
		"198.51.100.2",
		"2001:db8::2",
	})
	if want := []string{"192.0.2.1", "198.51.100.2"}; !reflect.DeepEqual(ipv4, want) {
		t.Fatalf("IPv4 = %v, want %v", ipv4, want)
	}
	if want := []string{"2001:db8::1", "2001:db8::2"}; !reflect.DeepEqual(ipv6, want) {
		t.Fatalf("IPv6 = %v, want %v", ipv6, want)
	}
}

func TestFeedRecheckJobsStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		feedRecheckJobs(ctx, make(chan string), []string{"192.0.2.1"})
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
	jobs := make(chan string)
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
	ipv4Jobs := make(chan string)
	ipv6Jobs := make(chan string) // Deliberately never consumed.
	ipv4Checks := make(chan string, 2)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ip := <-ipv4Jobs:
				select {
				case ipv4Checks <- ip:
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
