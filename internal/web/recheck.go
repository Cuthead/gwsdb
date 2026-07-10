package web

import (
	"context"
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

// publishTimeout bounds one DNS-publish reconcile so a slow Cloudflare API
// call can't wedge the recheck worker loop.
const publishTimeout = 15 * time.Second

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
	if err := s.st.MarkRecheckProcessed(item.ID, result.OK, now); err != nil {
		return err
	}
	s.publishAfterRecheck()
	return nil
}

// publishAfterRecheck reconciles the published DNS records with the store's
// current top IPs, if a publisher is configured. A recheck just changed an
// IP's status, so the top set may have shifted. Runs synchronously but is
// diff-only, so an unchanged set makes no write calls; publish failures are
// logged, not propagated -- they must not fail the recheck.
func (s *Server) publishAfterRecheck() {
	if s.pub == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	if err := s.pub.Sync(ctx); err != nil {
		log.Printf("recheck: publish: %v", err)
	}
}
