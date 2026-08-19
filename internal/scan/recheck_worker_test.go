package scan

import (
	"context"
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
