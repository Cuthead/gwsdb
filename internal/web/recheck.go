package web

import (
	"log"
	"time"

	"github.com/cuthead/gwsdb/internal/recheck"
)

// recheckProbeTimeout bounds one recheck attempt so a stuck dial/handshake
// can't wedge the worker loop.
const recheckProbeTimeout = 10 * time.Second

// StartRecheckWorker processes one pending recheck_queue item per interval
// tick, re-testing the reported IP via recheck.RunAndSave. Intended to run in
// its own goroutine for the lifetime of the server.
func (s *Server) StartRecheckWorker(interval time.Duration) {
	for {
		if err := s.processNextRecheck(); err != nil {
			log.Printf("recheck: %v", err)
		}
		time.Sleep(interval)
	}
}

func (s *Server) processNextRecheck() error {
	item, err := s.st.NextPendingRecheck()
	if err != nil {
		return err
	}
	if item == nil {
		return nil
	}

	now := time.Now().UTC()
	result, err := recheck.RunAndSave(s.st, item.IP, recheck.DefaultScanMode, recheckProbeTimeout)
	if err != nil {
		log.Printf("recheck: #%d %s: %v", item.ID, item.IP, err)
		return s.st.MarkRecheckProcessed(item.ID, false, now)
	}
	return s.st.MarkRecheckProcessed(item.ID, result.OK, now)
}
