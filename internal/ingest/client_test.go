package ingest

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cuthead/gwsdb/internal/store"
)

func TestSubmitReusesHTTPConnection(t *testing.T) {
	var connections atomic.Int32
	pruneLengths := make(chan int, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body submitPayload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pruneLengths <- len(body.PruneIPs)
		_, _ = w.Write([]byte(`{"checks":1}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	checks := []store.IPCheck{{IP: "192.0.2.1", OK: true}}
	if _, err := Submit(context.Background(), server.URL, "token", checks, false, nil); err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	if _, err := Submit(context.Background(), server.URL, "token", checks, false, nil); err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want 1", got)
	}
	if first, second := <-pruneLengths, <-pruneLengths; first != 0 || second != 0 {
		t.Fatalf("nil pruneIPs encoded with lengths %d and %d, want explicit empty arrays", first, second)
	}
}

func TestSubmitSendsMaintenancePruneIPs(t *testing.T) {
	received := make(chan submitPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body submitPayload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- body
		_, _ = w.Write([]byte(`{"checks":1,"pruneOk":false}`))
	}))
	defer server.Close()

	checks := []store.IPCheck{{IP: "192.0.2.1", OK: true}}
	pruneIPs := []string{"192.0.2.1", "192.0.2.2"}
	pruneOK, err := Submit(context.Background(), server.URL, "token", checks, true, pruneIPs)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if pruneOK {
		t.Fatal("pruneOK = true, want false")
	}
	body := <-received
	if !body.Maintenance {
		t.Fatal("maintenance = false, want true")
	}
	if len(body.PruneIPs) != 2 || body.PruneIPs[0] != pruneIPs[0] || body.PruneIPs[1] != pruneIPs[1] {
		t.Fatalf("pruneIPs = %v, want %v", body.PruneIPs, pruneIPs)
	}
}

func TestSubmitRetainsPruneCandidatesOnTruncatedSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pruneOk":`))
	}))
	defer server.Close()

	pruneOK, err := Submit(context.Background(), server.URL, "token", []store.IPCheck{}, true, []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if pruneOK {
		t.Fatal("pruneOK = true after truncated response, want false")
	}
}
