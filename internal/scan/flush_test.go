package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cuthead/gwsdb/internal/recheck"
)

func TestFlusherSubmitsAtSizeThreshold(t *testing.T) {
	maintenance := make(chan bool, 2)
	server := ingestServer(t, maintenance)
	defer server.Close()

	s := New(Config{
		APIBase:       server.URL,
		Token:         "token",
		ScanMode:      "SNI",
		FlushInterval: time.Hour,
		FlushSize:     2,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runFlusher(ctx)
		close(done)
	}()

	s.record("192.0.2.1", recheck.Result{OK: true, RTTMs: 10})
	s.record("192.0.2.2", recheck.Result{OK: true, RTTMs: 20})

	select {
	case first := <-maintenance:
		if !first {
			t.Fatal("first micro-batch did not request maintenance")
		}
	case <-time.After(time.Second):
		t.Fatal("size threshold did not trigger flush")
	}

	s.record("192.0.2.3", recheck.Result{OK: true, RTTMs: 30})
	s.record("192.0.2.4", recheck.Result{OK: true, RTTMs: 40})
	select {
	case second := <-maintenance:
		if second {
			t.Fatal("second micro-batch requested maintenance before interval elapsed")
		}
	case <-time.After(time.Second):
		t.Fatal("second size threshold did not trigger flush")
	}

	cancel()
	<-done
}

func TestFlusherSubmitsAtTimeThreshold(t *testing.T) {
	maintenance := make(chan bool, 1)
	server := ingestServer(t, maintenance)
	defer server.Close()

	s := New(Config{
		APIBase:       server.URL,
		Token:         "token",
		ScanMode:      "SNI",
		FlushInterval: 20 * time.Millisecond,
		FlushSize:     100,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runFlusher(ctx)
		close(done)
	}()

	s.record("192.0.2.1", recheck.Result{OK: true, RTTMs: 10})
	select {
	case <-maintenance:
	case <-time.After(time.Second):
		t.Fatal("time threshold did not trigger flush")
	}

	cancel()
	<-done
}

func TestFlusherRetriesFailedBatch(t *testing.T) {
	var posts atomic.Int32
	submitted := make(chan int, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"ips":[]}`))
			return
		}
		var body struct {
			Checks []json.RawMessage `json:"checks"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if posts.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		submitted <- len(body.Checks)
		_, _ = w.Write([]byte(`{"checks":1}`))
	}))
	defer server.Close()

	s := New(Config{
		APIBase:       server.URL,
		Token:         "token",
		ScanMode:      "SNI",
		FlushInterval: 10 * time.Millisecond,
		FlushSize:     1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runFlusher(ctx)
		close(done)
	}()

	s.record("192.0.2.1", recheck.Result{OK: true, RTTMs: 10})
	select {
	case got := <-submitted:
		if got != 1 {
			t.Fatalf("retried checks = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("failed batch was not retried")
	}
	cancel()
	<-done
}

func ingestServer(t *testing.T, maintenance chan<- bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ips":[]}`))
			return
		}
		var body struct {
			Maintenance bool `json:"maintenance"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		maintenance <- body.Maintenance
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"checks":1}`))
	}))
}
