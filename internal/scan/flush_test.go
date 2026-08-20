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
	"github.com/cuthead/gwsdb/internal/store"
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

func TestPruneCandidatesAccumulateUntilMaintenanceSuccess(t *testing.T) {
	s := New(Config{})
	first := []store.IPCheck{{IP: "192.0.2.2"}, {IP: "192.0.2.1"}, {IP: "192.0.2.2"}}
	s.recordPruneCandidates(first, false)

	current := []store.IPCheck{{IP: "192.0.2.3"}, {IP: "192.0.2.1"}}
	got := s.pruneCandidates(current, true)
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if len(got) != len(want) {
		t.Fatalf("prune candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prune candidates = %v, want %v", got, want)
		}
	}

	// Building a maintenance request does not clear state; only a successful
	// Submit followed by recordPruneCandidates does.
	if retry := s.pruneCandidates(current, true); len(retry) != len(want) {
		t.Fatalf("retry candidates = %v, want %v", retry, want)
	}
	s.recordPruneCandidates(current, true)
	if got := s.pruneCandidates(nil, true); len(got) != 0 {
		t.Fatalf("candidates after maintenance success = %v, want empty", got)
	}
}

func TestFinalFlushSendsPendingPruneCandidatesWithoutChecks(t *testing.T) {
	type requestBody struct {
		Checks      []json.RawMessage `json:"checks"`
		Maintenance bool              `json:"maintenance"`
		PruneIPs    []string          `json:"pruneIPs"`
	}
	received := make(chan requestBody, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body requestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- body
		_, _ = w.Write([]byte(`{"checks":0}`))
	}))
	defer server.Close()

	s := New(Config{APIBase: server.URL, Token: "token", ScanMode: "SNI"})
	s.knownGood = map[string]bool{}
	s.knownGoodFetchedAt = time.Now()
	s.lastMaintenanceAt = time.Now()
	s.pruneIPs["192.0.2.1"] = struct{}{}
	s.flushFinal()

	select {
	case body := <-received:
		if !body.Maintenance || len(body.Checks) != 0 || len(body.PruneIPs) != 1 || body.PruneIPs[0] != "192.0.2.1" {
			t.Fatalf("final flush body = %+v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("final flush did not submit pending prune candidates")
	}
}

func TestPruneFailureRetainsCandidatesWithoutRequeueingChecks(t *testing.T) {
	maintenance := make(chan bool, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
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
		_, _ = w.Write([]byte(`{"checks":1,"pruneOk":false}`))
	}))
	defer server.Close()

	s := New(Config{APIBase: server.URL, Token: "token", ScanMode: "SNI"})
	s.record("192.0.2.1", recheck.Result{OK: true, RTTMs: 10})
	if ok := s.flush(context.Background()); !ok {
		t.Fatal("flush reported failure after checks were accepted")
	}
	if len(s.checks) != 0 {
		t.Fatalf("buffered checks = %d, want 0", len(s.checks))
	}
	if _, retained := s.pruneIPs["192.0.2.1"]; !retained {
		t.Fatal("failed prune candidate was not retained")
	}
	if !s.lastMaintenanceAt.IsZero() {
		t.Fatal("failed prune advanced maintenance deadline")
	}
	if !s.nextPruneRetryAt.After(time.Now()) {
		t.Fatal("failed prune did not schedule retry cooldown")
	}
	if first := <-maintenance; !first {
		t.Fatal("first flush maintenance = false, want true")
	}

	s.record("192.0.2.2", recheck.Result{OK: true, RTTMs: 20})
	if ok := s.flush(context.Background()); !ok {
		t.Fatal("flush during prune cooldown failed")
	}
	if second := <-maintenance; second {
		t.Fatal("flush retried maintenance before prune cooldown elapsed")
	}
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
