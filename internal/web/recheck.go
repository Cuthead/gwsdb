package web

import (
	"log"
	"time"

	"github.com/cuthead/gwsdb/internal/recheck"
)

// recheckProbeTimeout bounds one recheck attempt so a stuck dial/handshake
// can't wedge the worker loop.
const recheckProbeTimeout = 10 * time.Second

// recheckQueueRetention is how long a processed recheck_queue row is kept
// around (for debugging/audit) before StartRecheckWorker prunes it.
const recheckQueueRetention = 30 * 24 * time.Hour

// StartRecheckWorker processes one pending recheck_queue item per interval
// tick, re-testing the reported IP via recheck.RunAndSave, and prunes
// processed entries older than recheckQueueRetention so the table doesn't
// grow unboundedly. Intended to run in its own goroutine for the lifetime of
// the server.
func (s *Server) StartRecheckWorker(interval time.Duration) {
	for {
		if err := s.processNextRecheck(); err != nil {
			log.Printf("recheck: %v", err)
		}
		if n, err := s.st.PruneRecheckQueue(recheckQueueRetention); err != nil {
			log.Printf("recheck: PruneRecheckQueue: %v", err)
		} else if n > 0 {
			log.Printf("recheck: pruned %d processed queue entries older than %s", n, recheckQueueRetention)
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
