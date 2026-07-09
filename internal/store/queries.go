package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SaveScan persists a completed scan, its successful results, and every
// pass/fail check observed in its log. Results roll into the per-IP
// ip_status registry (the "ever found reachable" pool); checks roll into
// ip_checks (the availability history timeline) but, for failures, only for
// IPs already in that pool -- a scan can probe thousands of never-seen-good
// IPs and we don't want to keep permanent history for every one of them.
// Everything happens in one transaction.
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

	insertResult, err := tx.Prepare(`
		INSERT OR IGNORE INTO scan_results (scan_id, ip, rtt_ms, rank) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer insertResult.Close()

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

	for _, r := range results {
		if _, err := insertResult.Exec(scanID, r.IP, nullInt(r.RTTMs), nullInt(r.Rank)); err != nil {
			return 0, fmt.Errorf("insert scan_result %s: %w", r.IP, err)
		}
		ts, ok := seenAt[r.IP]
		if !ok {
			ts = now
		}
		isIPv6 := strings.Contains(r.IP, ":")
		if _, err := upsertStatus.Exec(r.IP, boolToInt(isIPv6), scan.ScanMode, ts, ts, scanID, nullInt(r.RTTMs), ts); err != nil {
			return 0, fmt.Errorf("upsert ip_status %s: %w", r.IP, err)
		}
	}

	insertCheck, err := tx.Prepare(`
		INSERT INTO ip_checks (scan_id, ip, ok, rtt_ms, reason, detail, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer insertCheck.Close()

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
			// Already recorded via the results/upsertStatus loop above; still
			// log the check itself for a complete timeline.
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

// DeleteScan removes a scan and its results/checks. ip_status rows pointing
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
	if _, err := tx.Exec(`DELETE FROM scan_results WHERE scan_id = ?`, id); err != nil {
		return fmt.Errorf("delete scan_results: %w", err)
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

	// Search, if non-empty, restricts results to IPs whose address or
	// cached PTR hostname contains it (case-insensitive).
	Search string

	// SortBy is one of the keys in listKnownIPsSortColumns; any other
	// value (including "") falls back to "last_seen".
	SortBy   string
	SortDesc bool

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
	if opts.Search != "" {
		where = append(where, `(ip_status.ip LIKE ? OR ptr_cache.ptr_hostname LIKE ?)`)
		pattern := "%" + opts.Search + "%"
		args = append(args, pattern, pattern)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY %s %s, last_seen DESC LIMIT ?", col, dir)
	args = append(args, opts.Limit)

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

// IPHistory returns the most recent availability checks for ip, newest first.
func (s *Store) IPHistory(ip string, limit int) ([]IPCheck, error) {
	rows, err := s.db.Query(`
		SELECT
			c.ip, c.ok, c.rtt_ms, c.reason, c.detail, c.checked_at,
			s.scan_mode, s.server_name, s.http_path, s.http_method, s.http_verify_hosts, s.verify_common_name, s.valid_status_code
		FROM ip_checks c
		JOIN scans s ON s.id = c.scan_id
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
		var rtt, validStatusCode sql.NullInt64
		var reason, detail, httpMethod sql.NullString
		if err := rows.Scan(
			&c.IP, &ok, &rtt, &reason, &detail, &c.CheckedAt,
			&c.ScanMode, &c.ServerName, &c.HTTPPath, &httpMethod, &c.HTTPVerifyHosts, &c.VerifyCommonName, &validStatusCode,
		); err != nil {
			return nil, err
		}
		c.OK = ok != 0
		c.RTTMs = int(rtt.Int64)
		c.Reason = reason.String
		c.Detail = detail.String
		c.HTTPMethod = httpMethod.String
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

// SaveReport records one community report for an IP.
func (s *Store) SaveReport(rep IPReport) error {
	_, err := s.db.Exec(`
		INSERT INTO ip_reports (ip, verdict, comment, reporter_ip, reporter_prefix, reporter_asn, reporter_as_name, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rep.IP, boolToInt(rep.Verdict), nullString(rep.Comment), rep.ReporterIP,
		nullString(rep.ReporterPrefix), nullInt(rep.ReporterASN), nullString(rep.ReporterASName), rep.CreatedAt)
	return err
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

func nullInt(v int) any {
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
