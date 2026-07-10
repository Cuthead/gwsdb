package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// SaveScan persists a completed scan, its successful results, and every
// pass/fail check observed in its log. Both roll into ip_checks (the
// availability history timeline): each result becomes an ok row (so
// successes are recorded even when the log is incomplete), and log successes
// are added only for IPs not already covered by a result. Results also roll
// into the per-IP ip_status registry (the "ever found reachable" pool);
// failure checks are kept only for IPs already in that pool -- a scan can
// probe thousands of never-seen-good IPs and we don't want to keep permanent
// history for every one of them. Everything happens in one transaction.
func (s *Store) SaveScan(scan *Scan, results []ScanResult, checks []IPCheck) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT INTO scans (
			scan_mode, server_name, verify_common_name, http_path, http_method, http_verify_hosts,
			valid_status_code, input_file, output_file, level, config_json, log_text,
			started_at, finished_at, scanned_count, found_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scan.ScanMode, scan.ServerName, scan.VerifyCommonName, scan.HTTPPath, scan.HTTPMethod, scan.HTTPVerifyHosts,
		scan.ValidStatusCode, scan.InputFile, scan.OutputFile, scan.Level, scan.ConfigJSON, scan.LogText,
		nullTime(scan.StartedAt), nullTime(scan.FinishedAt), scan.ScannedCount, scan.FoundCount,
	)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	insertCheck, err := tx.Prepare(`
		INSERT INTO ip_checks (scan_id, ip, ok, rtt_ms, reason, detail, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer insertCheck.Close()

	upsertStatus, err := tx.Prepare(`
		INSERT INTO ip_status (ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1)
		ON CONFLICT(ip) DO UPDATE SET
			last_seen       = excluded.last_seen,
			last_scan_id    = excluded.last_scan_id,
			last_rtt_ms     = excluded.last_rtt_ms,
			scan_mode       = excluded.scan_mode,
			times_seen      = times_seen + 1,
			last_checked_at = excluded.last_checked_at,
			last_check_ok   = 1`)
	if err != nil {
		return 0, err
	}
	defer upsertStatus.Close()

	now := time.Now().UTC()

	// Prefer the log's own per-line timestamp for "when was this actually seen"
	// over the ingest wall-clock time, when we have one.
	seenAt := make(map[string]time.Time, len(checks))
	for _, c := range checks {
		if c.OK && !c.CheckedAt.IsZero() {
			seenAt[c.IP] = c.CheckedAt
		}
	}

	// The output file may repeat an IP; the old scan_results table absorbed
	// that with UNIQUE(scan_id, ip), ip_checks has no such constraint.
	recorded := make(map[string]bool, len(results))
	for _, r := range results {
		if recorded[r.IP] {
			continue
		}
		recorded[r.IP] = true
		ts, ok := seenAt[r.IP]
		if !ok {
			ts = now
		}
		if _, err := insertCheck.Exec(scanID, r.IP, 1, nullInt(r.RTTMs), nil, nil, ts); err != nil {
			return 0, fmt.Errorf("insert ip_check %s: %w", r.IP, err)
		}
		isIPv6 := strings.Contains(r.IP, ":")
		if _, err := upsertStatus.Exec(r.IP, boolToInt(isIPv6), scan.ScanMode, ts, ts, scanID, nullInt(r.RTTMs), ts); err != nil {
			return 0, fmt.Errorf("upsert ip_status %s: %w", r.IP, err)
		}
	}

	markFailed, err := tx.Prepare(`
		UPDATE ip_status SET last_checked_at = ?, last_check_ok = 0 WHERE ip = ?`)
	if err != nil {
		return 0, err
	}
	defer markFailed.Close()

	for _, c := range checks {
		checkedAt := c.CheckedAt
		if checkedAt.IsZero() {
			checkedAt = now
		}
		if c.OK {
			// Successes covered by a result row are already in ip_checks;
			// only record log-only successes (e.g. output file truncated).
			if recorded[c.IP] {
				continue
			}
			recorded[c.IP] = true
			if _, err := insertCheck.Exec(scanID, c.IP, 1, nullInt(c.RTTMs), nil, nil, checkedAt); err != nil {
				return 0, fmt.Errorf("insert ip_check %s: %w", c.IP, err)
			}
			continue
		}
		res, err := markFailed.Exec(checkedAt, c.IP)
		if err != nil {
			return 0, fmt.Errorf("mark failed %s: %w", c.IP, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if affected == 0 {
			// Never seen reachable before -- not part of the tracked pool.
			continue
		}
		if _, err := insertCheck.Exec(scanID, c.IP, 0, nil, nullString(c.Reason), nullString(c.Detail), checkedAt); err != nil {
			return 0, fmt.Errorf("insert ip_check %s: %w", c.IP, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return scanID, nil
}

// SaveRecheck records the outcome of a single report-triggered (or CLI)
// recheck probe: an ip_checks row with no owning scan (scan_id NULL, with
// config_scan_id pointing at the scan whose config the probe ran with) plus
// the same ip_status bookkeeping SaveScan does per IP. Rechecks deliberately do
// not create a scans row -- the scans table only records real scanner runs
// ingested via the CLI. Failure semantics match SaveScan: an IP never seen
// reachable gets its ip_status/history untouched, so probing arbitrary
// reported IPs can't grow permanent state.
func (s *Store) SaveRecheck(c IPCheck) error {
	checkedAt := c.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	configScanID := nullInt64(c.ConfigScanID)

	if c.OK {
		if _, err := tx.Exec(`
			INSERT INTO ip_checks (scan_id, config_scan_id, ip, ok, rtt_ms, reason, detail, checked_at)
			VALUES (NULL, ?, ?, 1, ?, NULL, NULL, ?)`,
			configScanID, c.IP, nullInt(c.RTTMs), checkedAt); err != nil {
			return fmt.Errorf("insert ip_check %s: %w", c.IP, err)
		}
		isIPv6 := strings.Contains(c.IP, ":")
		if _, err := tx.Exec(`
			INSERT INTO ip_status (ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok)
			VALUES (?, ?, ?, ?, ?, NULL, ?, 1, ?, 1)
			ON CONFLICT(ip) DO UPDATE SET
				last_seen       = excluded.last_seen,
				last_rtt_ms     = excluded.last_rtt_ms,
				times_seen      = times_seen + 1,
				last_checked_at = excluded.last_checked_at,
				last_check_ok   = 1`,
			c.IP, boolToInt(isIPv6), c.ScanMode, checkedAt, checkedAt, nullInt(c.RTTMs), checkedAt); err != nil {
			return fmt.Errorf("upsert ip_status %s: %w", c.IP, err)
		}
		return tx.Commit()
	}

	res, err := tx.Exec(`
		UPDATE ip_status SET last_checked_at = ?, last_check_ok = 0 WHERE ip = ?`, checkedAt, c.IP)
	if err != nil {
		return fmt.Errorf("mark failed %s: %w", c.IP, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		if _, err := tx.Exec(`
			INSERT INTO ip_checks (scan_id, config_scan_id, ip, ok, rtt_ms, reason, detail, checked_at)
			VALUES (NULL, ?, ?, 0, NULL, ?, ?, ?)`,
			configScanID, c.IP, nullString(c.Reason), nullString(c.Detail), checkedAt); err != nil {
			return fmt.Errorf("insert ip_check %s: %w", c.IP, err)
		}
	}
	return tx.Commit()
}

// DeleteScan removes a scan and its checks. ip_status rows pointing
// at it via last_scan_id are unlinked (set to NULL) rather than recomputed --
// their last_seen/times_seen/last_rtt_ms aggregates are left as-is.
func (s *Store) DeleteScan(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM ip_checks WHERE scan_id = ?`, id); err != nil {
		return fmt.Errorf("delete ip_checks: %w", err)
	}
	// Recheck rows referencing this scan's config survive; they just lose
	// their probe-request context.
	if _, err := tx.Exec(`UPDATE ip_checks SET config_scan_id = NULL WHERE config_scan_id = ?`, id); err != nil {
		return fmt.Errorf("clear ip_checks.config_scan_id: %w", err)
	}
	if _, err := tx.Exec(`UPDATE ip_status SET last_scan_id = NULL WHERE last_scan_id = ?`, id); err != nil {
		return fmt.Errorf("clear ip_status.last_scan_id: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM scans WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("scan %d not found", id)
	}
	return tx.Commit()
}

// LatestScan returns metadata about the most recent scan, if any.
func (s *Store) LatestScan(scanMode string) (*Scan, error) {
	var row *sql.Row
	if scanMode != "" {
		row = s.db.QueryRow(`SELECT id, scan_mode, started_at, finished_at, scanned_count, found_count FROM scans WHERE scan_mode = ? ORDER BY started_at DESC, id DESC LIMIT 1`, scanMode)
	} else {
		row = s.db.QueryRow(`SELECT id, scan_mode, started_at, finished_at, scanned_count, found_count FROM scans ORDER BY started_at DESC, id DESC LIMIT 1`)
	}
	sc := &Scan{}
	var started, finished sql.NullTime
	if err := row.Scan(&sc.ID, &sc.ScanMode, &started, &finished, &sc.ScannedCount, &sc.FoundCount); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	sc.StartedAt = started.Time
	sc.FinishedAt = finished.Time
	return sc, nil
}

// IPStatusFor returns the rolling reachability record for a single IP, if known.
func (s *Store) IPStatusFor(ip string) (*IPStatus, error) {
	st := &IPStatus{}
	var isIPv6 int
	var first, last, lastChecked sql.NullTime
	var lastScanID, lastRTT, lastCheckOK sql.NullInt64
	err := s.db.QueryRow(`
		SELECT ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok
		FROM ip_status WHERE ip = ?`, ip).Scan(
		&st.IP, &isIPv6, &st.ScanMode, &first, &last, &lastScanID, &lastRTT, &st.TimesSeen, &lastChecked, &lastCheckOK)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	st.IsIPv6 = isIPv6 != 0
	st.FirstSeen = first.Time
	st.LastSeen = last.Time
	st.LastScanID = lastScanID.Int64
	st.LastCheckedAt = lastChecked.Time
	st.HasCheck = lastCheckOK.Valid
	st.LastCheckOK = lastCheckOK.Int64 != 0
	st.LastRTTMs = int(lastRTT.Int64)
	return st, nil
}

// Stats holds simple aggregate counters shown on the home page.
type Stats struct {
	TotalKnownIPs int
	TotalScans    int
	LastScanAt    time.Time
}

// Overview returns aggregate stats for the home page.
func (s *Store) Overview() (Stats, error) {
	var st Stats
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ip_status`).Scan(&st.TotalKnownIPs); err != nil {
		return st, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&st.TotalScans); err != nil {
		return st, err
	}
	// Plain column references (rather than MAX()/COALESCE()) keep sqlite3's
	// declared-type detection intact so the driver hands back a time.Time.
	var started, created sql.NullTime
	err := s.db.QueryRow(`SELECT started_at, created_at FROM scans ORDER BY started_at DESC, created_at DESC LIMIT 1`).Scan(&started, &created)
	if err != nil && err != sql.ErrNoRows {
		return st, err
	}
	if started.Valid {
		st.LastScanAt = started.Time
	} else {
		st.LastScanAt = created.Time
	}
	return st, nil
}

// GetPTR returns a cached PTR/geo lookup for ip if present and not older than maxAge.
func (s *Store) GetPTR(ip string, maxAge time.Duration) (*PTRCacheEntry, error) {
	e := &PTRCacheEntry{}
	var ptr, code, city, country sql.NullString
	var lookupOK int
	var checkedAt time.Time
	err := s.db.QueryRow(`
		SELECT ip, ptr_hostname, airport_code, geo_city, geo_country, lookup_ok, checked_at
		FROM ptr_cache WHERE ip = ?`, ip).Scan(&e.IP, &ptr, &code, &city, &country, &lookupOK, &checkedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && time.Since(checkedAt) > maxAge {
		return nil, nil
	}
	e.PTRHostname, e.AirportCode, e.GeoCity, e.GeoCountry = ptr.String, code.String, city.String, country.String
	e.LookupOK = lookupOK != 0
	e.CheckedAt = checkedAt
	return e, nil
}

// SavePTR upserts a PTR/geo lookup result into the cache.
func (s *Store) SavePTR(e PTRCacheEntry) error {
	_, err := s.db.Exec(`
		INSERT INTO ptr_cache (ip, ptr_hostname, airport_code, geo_city, geo_country, lookup_ok, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			ptr_hostname = excluded.ptr_hostname,
			airport_code = excluded.airport_code,
			geo_city     = excluded.geo_city,
			geo_country  = excluded.geo_country,
			lookup_ok    = excluded.lookup_ok,
			checked_at   = excluded.checked_at`,
		e.IP, e.PTRHostname, e.AirportCode, e.GeoCity, e.GeoCountry, boolToInt(e.LookupOK), e.CheckedAt)
	return err
}

// NextIPForPTRRefresh returns one IP from ip_status whose ptr_cache entry is
// missing or older than maxAge, preferring never-checked IPs first, then the
// stalest. Returns "" if every known IP has a fresh cache entry.
func (s *Store) NextIPForPTRRefresh(maxAge time.Duration) (string, error) {
	var ip string
	err := s.db.QueryRow(`
		SELECT i.ip
		FROM ip_status i
		LEFT JOIN ptr_cache p ON p.ip = i.ip
		WHERE p.ip IS NULL OR p.checked_at < ?
		ORDER BY (p.checked_at IS NULL) DESC, p.checked_at ASC
		LIMIT 1`, time.Now().UTC().Add(-maxAge)).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ip, err
}

// RecentScans returns the most recent scans across all modes, newest first.
func (s *Store) RecentScans(limit int) ([]Scan, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_mode, started_at, finished_at, scanned_count, found_count
		FROM scans ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		var sc Scan
		var started, finished sql.NullTime
		if err := rows.Scan(&sc.ID, &sc.ScanMode, &started, &finished, &sc.ScannedCount, &sc.FoundCount); err != nil {
			return nil, err
		}
		sc.StartedAt = started.Time
		sc.FinishedAt = finished.Time
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ListScans returns full scan records (including config fields), newest
// first, up to limit rows.
func (s *Store) ListScans(limit int) ([]Scan, error) {
	rows, err := s.db.Query(`
		SELECT id, scan_mode, server_name, verify_common_name, http_path, http_method, http_verify_hosts,
			valid_status_code, input_file, output_file, level, config_json,
			started_at, finished_at, scanned_count, found_count
		FROM scans ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		var sc Scan
		var serverName, verifyCN, httpPath, httpMethod, httpHosts, inputFile, outputFile, configJSON sql.NullString
		var validStatusCode, level, scannedCount, foundCount sql.NullInt64
		var started, finished sql.NullTime
		if err := rows.Scan(
			&sc.ID, &sc.ScanMode, &serverName, &verifyCN, &httpPath, &httpMethod, &httpHosts,
			&validStatusCode, &inputFile, &outputFile, &level, &configJSON,
			&started, &finished, &scannedCount, &foundCount,
		); err != nil {
			return nil, err
		}
		sc.ServerName = serverName.String
		sc.VerifyCommonName = verifyCN.String
		sc.HTTPPath = httpPath.String
		sc.HTTPMethod = httpMethod.String
		sc.HTTPVerifyHosts = httpHosts.String
		sc.ValidStatusCode = int(validStatusCode.Int64)
		sc.InputFile = inputFile.String
		sc.OutputFile = outputFile.String
		sc.Level = int(level.Int64)
		sc.ConfigJSON = configJSON.String
		sc.StartedAt = started.Time
		sc.FinishedAt = finished.Time
		sc.ScannedCount = int(scannedCount.Int64)
		sc.FoundCount = int(foundCount.Int64)
		out = append(out, sc)
	}
	return out, rows.Err()
}

// listKnownIPsSortColumns whitelists the columns ListKnownIPs may sort by,
// mapping the caller-facing key to the actual SQL expression -- SortBy is
// caller-controlled (it comes from a query param), so it must never be
// interpolated into the query directly.
var listKnownIPsSortColumns = map[string]string{
	"ip":         "ip_status.ip",
	"ptr":        "ptr_cache.ptr_hostname",
	"status":     "last_check_ok",
	"first_seen": "first_seen",
	"last_seen":  "last_seen",
	"rtt":        "last_rtt_ms",
}

// ListKnownIPsOptions controls filtering and ordering for ListKnownIPs.
type ListKnownIPsOptions struct {
	OnlyUp bool

	// Family, if 4 or 6, restricts results to that IP address family;
	// any other value (including 0) returns both.
	Family int

	// Search, if non-empty, restricts results to IPs whose address or
	// cached PTR hostname contains it (case-insensitive).
	Search string

	// SortBy is one of the keys in listKnownIPsSortColumns; any other
	// value (including "") falls back to "last_seen".
	SortBy   string
	SortDesc bool

	// Limit caps the number of rows returned; 0 or negative means no cap.
	Limit int
}

// ListKnownIPs returns IPs from the tracked pool (ip_status), along with
// each IP's cached PTR hostname (empty if never resolved). If OnlyUp is
// true, only IPs whose most recent check succeeded (or that have never
// failed a check) are returned.
func (s *Store) ListKnownIPs(opts ListKnownIPsOptions) ([]IPStatus, error) {
	col, ok := listKnownIPsSortColumns[opts.SortBy]
	if !ok {
		col = "last_seen"
	}
	dir := "ASC"
	if opts.SortDesc {
		dir = "DESC"
	}

	q := `
		SELECT ip_status.ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok, COALESCE(ptr_cache.ptr_hostname, '')
		FROM ip_status
		LEFT JOIN ptr_cache ON ptr_cache.ip = ip_status.ip`

	var where []string
	var args []any
	if opts.OnlyUp {
		where = append(where, `(last_check_ok IS NULL OR last_check_ok = 1)`)
	}
	switch opts.Family {
	case 4:
		where = append(where, `is_ipv6 = 0`)
	case 6:
		where = append(where, `is_ipv6 = 1`)
	}
	if opts.Search != "" {
		where = append(where, `(ip_status.ip LIKE ? OR ptr_cache.ptr_hostname LIKE ?)`)
		pattern := "%" + opts.Search + "%"
		args = append(args, pattern, pattern)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY %s %s, last_seen DESC", col, dir)
	if opts.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPStatus
	for rows.Next() {
		var st IPStatus
		var isIPv6 int
		var first, last, lastChecked sql.NullTime
		var lastScanID, lastRTT, lastCheckOK sql.NullInt64
		if err := rows.Scan(&st.IP, &isIPv6, &st.ScanMode, &first, &last, &lastScanID, &lastRTT, &st.TimesSeen, &lastChecked, &lastCheckOK, &st.PTRHostname); err != nil {
			return nil, err
		}
		st.IsIPv6 = isIPv6 != 0
		st.FirstSeen = first.Time
		st.LastSeen = last.Time
		st.LastScanID = lastScanID.Int64
		st.LastRTTMs = int(lastRTT.Int64)
		st.LastCheckedAt = lastChecked.Time
		st.HasCheck = lastCheckOK.Valid
		st.LastCheckOK = lastCheckOK.Int64 != 0
		out = append(out, st)
	}
	return out, rows.Err()
}

// TopIPsForPublish returns up to limit IPs of the given address family
// (4 or 6) to publish as DNS records, most-seen first with lowest RTT
// breaking ties. Only IPs whose most recent check succeeded and that have a
// measured RTT are returned, so a known-dead or unmeasured IP is never
// published; times_seen/RTT are read as-is (no freshness window, since
// recheck timing is user-driven, not scheduled).
func (s *Store) TopIPsForPublish(family, limit int) ([]string, error) {
	isIPv6 := 0
	if family == 6 {
		isIPv6 = 1
	}
	rows, err := s.db.Query(`
		SELECT ip FROM ip_status
		WHERE is_ipv6 = ? AND last_check_ok = 1 AND last_rtt_ms IS NOT NULL
		ORDER BY times_seen DESC, last_rtt_ms ASC
		LIMIT ?`, isIPv6, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

// IPHistory returns the most recent availability checks for ip, newest first.
func (s *Store) IPHistory(ip string, limit int) ([]IPCheck, error) {
	rows, err := s.db.Query(`
		SELECT
			c.ip, c.ok, c.rtt_ms, c.reason, c.detail, c.checked_at, c.scan_id, c.config_scan_id,
			s.scan_mode, s.server_name, s.http_path, s.http_method, s.http_verify_hosts, s.verify_common_name, s.valid_status_code
		FROM ip_checks c
		LEFT JOIN scans s ON s.id = COALESCE(c.scan_id, c.config_scan_id)
		WHERE c.ip = ?
		ORDER BY c.checked_at DESC LIMIT ?`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPCheck
	for rows.Next() {
		var c IPCheck
		var ok int
		var rtt, validStatusCode, scanID, configScanID sql.NullInt64
		var reason, detail, scanMode, serverName, httpPath, httpMethod, httpVerifyHosts, verifyCN sql.NullString
		if err := rows.Scan(
			&c.IP, &ok, &rtt, &reason, &detail, &c.CheckedAt, &scanID, &configScanID,
			&scanMode, &serverName, &httpPath, &httpMethod, &httpVerifyHosts, &verifyCN, &validStatusCode,
		); err != nil {
			return nil, err
		}
		c.OK = ok != 0
		c.RTTMs = int(rtt.Int64)
		c.Reason = reason.String
		c.Detail = detail.String
		c.Recheck = !scanID.Valid
		c.ConfigScanID = configScanID.Int64
		c.ScanMode = scanMode.String
		c.ServerName = serverName.String
		c.HTTPPath = httpPath.String
		c.HTTPMethod = httpMethod.String
		c.HTTPVerifyHosts = httpVerifyHosts.String
		c.VerifyCommonName = verifyCN.String
		c.ValidStatusCode = int(validStatusCode.Int64)
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetASN returns a cached ASN/prefix lookup for ip if present and not older than maxAge.
func (s *Store) GetASN(ip string, maxAge time.Duration) (*ASNCacheEntry, error) {
	e := &ASNCacheEntry{}
	var asName, prefix, country sql.NullString
	var asNum sql.NullInt64
	var lookupOK int
	var checkedAt time.Time
	err := s.db.QueryRow(`
		SELECT ip, asn, as_name, prefix, country, lookup_ok, checked_at
		FROM asn_cache WHERE ip = ?`, ip).Scan(&e.IP, &asNum, &asName, &prefix, &country, &lookupOK, &checkedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && time.Since(checkedAt) > maxAge {
		return nil, nil
	}
	e.ASN = int(asNum.Int64)
	e.ASName, e.Prefix, e.Country = asName.String, prefix.String, country.String
	e.LookupOK = lookupOK != 0
	e.CheckedAt = checkedAt
	return e, nil
}

// SaveASN upserts an ASN/prefix lookup result into the cache.
func (s *Store) SaveASN(e ASNCacheEntry) error {
	_, err := s.db.Exec(`
		INSERT INTO asn_cache (ip, asn, as_name, prefix, country, lookup_ok, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			asn        = excluded.asn,
			as_name    = excluded.as_name,
			prefix     = excluded.prefix,
			country    = excluded.country,
			lookup_ok  = excluded.lookup_ok,
			checked_at = excluded.checked_at`,
		e.IP, nullInt(e.ASN), nullString(e.ASName), nullString(e.Prefix), nullString(e.Country), boolToInt(e.LookupOK), e.CheckedAt)
	return err
}

// SaveReport records one community report for an IP and returns its id.
func (s *Store) SaveReport(rep IPReport) (int64, error) {
	res, err := s.db.Exec(`
		INSERT INTO ip_reports (ip, verdict, comment, reporter_ip, reporter_prefix, reporter_asn, reporter_as_name, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rep.IP, boolToInt(rep.Verdict), nullString(rep.Comment), rep.ReporterIP,
		nullString(rep.ReporterPrefix), nullInt(rep.ReporterASN), nullString(rep.ReporterASName), rep.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListReports returns the most recent reports for ip, newest first. The
// reporter's full IP is intentionally not selected here -- callers should
// only surface ReporterPrefix/ReporterASN/ReporterASName publicly.
func (s *Store) ListReports(ip string, limit int) ([]IPReport, error) {
	rows, err := s.db.Query(`
		SELECT id, ip, verdict, COALESCE(comment, ''), COALESCE(reporter_prefix, ''), COALESCE(reporter_asn, 0), COALESCE(reporter_as_name, ''), created_at
		FROM ip_reports WHERE ip = ? ORDER BY created_at DESC LIMIT ?`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IPReport
	for rows.Next() {
		var rep IPReport
		var verdict int
		if err := rows.Scan(&rep.ID, &rep.IP, &verdict, &rep.Comment, &rep.ReporterPrefix, &rep.ReporterASN, &rep.ReporterASName, &rep.CreatedAt); err != nil {
			return nil, err
		}
		rep.Verdict = verdict != 0
		out = append(out, rep)
	}
	return out, rows.Err()
}

// recheckMinDelay/recheckMaxDelay bound the random delay applied before a
// queued recheck becomes eligible for the worker to pick up -- spreads out
// probes triggered by a burst of reports instead of firing them all at once.
const recheckMinDelay = 1 * time.Minute
const recheckMaxDelay = 1 * time.Hour

// EnqueueRecheck schedules a re-scan of ip for report reportID, eligible to
// run at a random time 1 minute to 1 hour from now. A no-op if that report
// was already enqueued (UNIQUE(report_id)), so callers can call it at most
// once per report without a separate existence check.
func (s *Store) EnqueueRecheck(reportID int64, ip string, createdAt time.Time) error {
	delay := recheckMinDelay + time.Duration(rand.Int63n(int64(recheckMaxDelay-recheckMinDelay)))
	scheduledAt := time.Now().UTC().Add(delay)
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO recheck_queue (report_id, ip, created_at, scheduled_at) VALUES (?, ?, ?, ?)`,
		reportID, ip, createdAt, scheduledAt)
	return err
}

// NextPendingRecheck returns the oldest not-yet-processed recheck_queue entry
// whose scheduled_at has arrived, or nil if none are ready yet.
func (s *Store) NextPendingRecheck() (*RecheckQueueItem, error) {
	item := &RecheckQueueItem{}
	var scheduledAt sql.NullTime
	err := s.db.QueryRow(`
		SELECT id, report_id, ip, created_at, scheduled_at FROM recheck_queue
		WHERE processed_at IS NULL AND (scheduled_at IS NULL OR scheduled_at <= ?)
		ORDER BY created_at ASC LIMIT 1`, time.Now().UTC()).Scan(
		&item.ID, &item.ReportID, &item.IP, &item.CreatedAt, &scheduledAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.ScheduledAt = scheduledAt.Time
	return item, nil
}

// MarkRecheckProcessed records the outcome of a recheck attempt so it is not
// picked up again.
func (s *Store) MarkRecheckProcessed(id int64, ok bool, processedAt time.Time) error {
	_, err := s.db.Exec(`UPDATE recheck_queue SET processed_at = ?, ok = ? WHERE id = ?`,
		processedAt, boolToInt(ok), id)
	return err
}

// PruneRecheckQueue deletes processed recheck_queue rows older than
// olderThan, so the table doesn't grow unboundedly with completed work.
// Pending (unprocessed) rows are never touched. Returns how many rows were
// removed.
func (s *Store) PruneRecheckQueue(olderThan time.Duration) (int64, error) {
	res, err := s.db.Exec(`
		DELETE FROM recheck_queue WHERE processed_at IS NOT NULL AND processed_at < ?`,
		time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LatestScanConfig returns the id and config_json of the most recent scan
// for scanMode, or (0, "") if none exists yet.
func (s *Store) LatestScanConfig(scanMode string) (int64, string, error) {
	var id int64
	var configJSON sql.NullString
	err := s.db.QueryRow(`
		SELECT id, config_json FROM scans WHERE scan_mode = ? ORDER BY started_at DESC, id DESC LIMIT 1`, scanMode).Scan(&id, &configJSON)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	return id, configJSON.String, nil
}

func nullInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// MarshalConfig is a small helper used by the ingest package to stash the raw
// scan config as JSON on the Scan record.
func MarshalConfig(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
