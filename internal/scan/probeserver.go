package scan

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/cuthead/gwsdb/internal/recheck"
)

// probeRequest is the JSON body POSTed to the probe server by the
// gwsdb-probe Worker (worker/), relayed from functions/check.ts.
type probeRequest struct {
	IP string `json:"ip"`
}

// probeResponse is what the probe server returns — mirrors
// recheck.Result's user-facing fields.
type probeResponse struct {
	OK     bool   `json:"ok"`
	RTTMs  int    `json:"rttMs"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// runProbeServer serves POST /probe on addr, probing each requested IP
// with recheck.CheckSNI using the scanner's ProbeConfig. This is the
// endpoint the gwsdb-probe Worker (worker/) VPC-fetches for the query
// page's on-demand probe button — reachable over Cloudflare Mesh without
// opening a public port on the China box. Authenticates each request with
// X-Probe-Token (crypto/subtle.ConstantTimeCompare against token), so the
// Mesh address alone isn't enough to drive probes. Blocks until ctx is
// cancelled (graceful shutdown), so it's meant to run in its own goroutine.
func (s *Scanner) runProbeServer(ctx context.Context, addr, token string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Probe-Token")), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req probeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "missing ip", http.StatusBadRequest)
			return
		}
		probeCtx, cancel := context.WithTimeout(r.Context(), s.cfg.ProbeTimeout)
		result := recheck.CheckSNI(probeCtx, req.IP, s.cfg.ProbeConfig)
		cancel()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(probeResponse{
			OK:     result.OK,
			RTTMs:  result.RTTMs,
			Reason: result.Reason,
			Detail: result.Detail,
		})
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Printf("scan: probe server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
