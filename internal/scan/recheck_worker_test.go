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

func TestRecheckFeederWaitsForFlushInterval(t *testing.T) {
	requests := make(chan time.Time, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- time.Now()
		_, _ = w.Write([]byte(`{"ips":[{"ip":"192.0.2.1","lastSeen":"2026-08-19 11:00:00","status":"Reachable"}]}`))
	}))
	defer server.Close()

	const flushInterval = 200 * time.Millisecond
	s := New(Config{APIBase: server.URL, FlushInterval: flushInterval})
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
	go s.runRecheckFeeder(ctx, jobs, nil)

	first := <-requests
	select {
	case second := <-requests:
		if elapsed := second.Sub(first); elapsed < flushInterval {
			t.Fatalf("pool refetched after %s, before flush interval %s", elapsed, flushInterval)
		}
	case <-time.After(flushInterval + time.Second):
		t.Fatal("pool was not refetched after flush interval")
	}
}
