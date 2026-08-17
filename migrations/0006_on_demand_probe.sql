-- Drop community reports and the report-triggered recheck queue. The
-- query page now has an on-demand "probe" button that synchronously
-- calls the China box through the gwsdb-probe Worker (see functions/check.ts
-- + worker/ + internal/scan/probeserver.go), so there's no deferred queue and no
-- report table. ip_checks rows from on-demand probes are written directly
-- by functions/check.ts via saveRecheckResult, same shape as ad-hoc
-- `gwsdb recheck -ip`.
DROP TABLE IF EXISTS recheck_queue;
DROP TABLE IF EXISTS ip_reports;

-- Per-client-IP rate limit for the on-demand probe button. One row per
-- (client_ip, UTC minute window); count is incremented per probe request.
-- Old windows are pruned lazily on each request (see store.ts
-- checkRateLimit). D1 rather than KV so the limit is strongly consistent
-- (a same-second double-click shouldn't both pass).
CREATE TABLE check_rate_limit (
	client_ip  TEXT NOT NULL,
	window     TEXT NOT NULL,  -- 'YYYY-MM-DDTHH:MM' (UTC minute)
	count      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (client_ip, window)
);
