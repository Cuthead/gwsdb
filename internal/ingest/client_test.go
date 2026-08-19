package ingest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cuthead/gwsdb/internal/store"
)

func TestSubmitReusesHTTPConnection(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	if err := Submit(context.Background(), server.URL, "token", checks, false); err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	if err := Submit(context.Background(), server.URL, "token", checks, false); err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want 1", got)
	}
}
