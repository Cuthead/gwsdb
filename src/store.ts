// D1-facing primitives used by the streaming ingest path (src/index.ts).
// Unlike internal/store/queries.go's SaveScan, this isn't one function
// wrapping everything in a single transaction -- D1's atomicity primitive
// (env.DB.batch()) requires every statement to be bound upfront in one call,
// which doesn't fit a pipeline that streams a ~100MB log through two passes.
// See src/logParser.ts's module comment for why two passes are needed, and
// src/index.ts for how these pieces are wired together. The trade-off: a
// crash partway through can leave a scans row with fewer ip_checks rows
// than a fully-succeeded run would have, rather than Go's all-or-nothing
// guarantee -- acceptable for phase 1, revisit if it bites in practice.
import type {
	ASNCacheEntry,
	HostCacheEntry,
	IPCheckHistoryRow,
	IPReport,
	IPStatus,
	PTRCacheEntry,
	RecheckQueueItem,
	Scan,
	ScanRow,
	Stats,
} from "./types";

// joinStrings packs multiple values for storage in a single "; "-joined
// TEXT column (ptr_cache.ptr_hostname, host_cache.ipv4/ipv6) -- mirrors
// store.JoinStrings.
function joinStrings(values: string[]): string {
	return values.join("; ");
}

const MAX_BATCH = 500; // comfortably under D1's 1,000/batch free-tier cap

function toSQLiteDateTime(d: Date | null): string | null {
	return d ? d.toISOString() : null;
}

export async function insertScan(db: D1Database, scan: Scan): Promise<number> {
	const res = await db
		.prepare(
			`INSERT INTO scans (
				scan_mode, server_name, verify_common_name, http_path, http_method, http_verify_hosts,
				valid_status_code, input_file, output_file, level, config_json, log_text,
				started_at, finished_at, scanned_count, found_count
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		.bind(
			scan.ScanMode,
			scan.ServerName,
			scan.VerifyCommonName,
			scan.HTTPPath,
			scan.HTTPMethod,
			scan.HTTPVerifyHosts,
			scan.ValidStatusCode,
			scan.InputFile,
			scan.OutputFile,
			scan.Level,
			scan.ConfigJSON,
			null, // log_text: the raw log is uploaded/decoded on the fly, never held whole, so it isn't persisted verbatim
			toSQLiteDateTime(scan.StartedAt),
			toSQLiteDateTime(scan.FinishedAt),
			scan.ScannedCount,
			scan.FoundCount,
		)
		.run();
	return res.meta.last_row_id;
}

export interface CheckRow {
	scanId: number;
	ip: string;
	ok: boolean;
	rttMs: number | null;
	reason: string | null;
	detail: string | null;
	checkedAt: Date;
	scanMode: string;
}

const insertCheckSQL = `INSERT INTO ip_checks (scan_id, ip, ok, rtt_ms, reason, detail, checked_at, scan_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

// insertCheckRows writes rows in chunks of MAX_BATCH, each chunk atomic via
// db.batch() but not atomic across chunks -- see the module comment.
export async function insertCheckRows(db: D1Database, rows: CheckRow[]): Promise<void> {
	for (let i = 0; i < rows.length; i += MAX_BATCH) {
		const chunk = rows.slice(i, i + MAX_BATCH);
		await db.batch(
			chunk.map((row) =>
				db
					.prepare(insertCheckSQL)
					.bind(
						row.scanId,
						row.ip,
						row.ok ? 1 : 0,
						row.rttMs,
						row.reason,
						row.detail,
						toSQLiteDateTime(row.checkedAt),
						row.scanMode,
					),
			),
		);
	}
}

// isKnownGood reports whether ip has ever had a successful check recorded --
// mirrors Go's live "EXISTS(SELECT 1 FROM ip_checks WHERE ip = ? AND ok = 1)"
// query in SaveScan. Callers should memoize per ingest run (see
// index.ts's makeKnownGoodChecker) rather than re-querying per log line.
export async function isKnownGood(db: D1Database, ip: string): Promise<boolean> {
	const row = await db.prepare(`SELECT EXISTS(SELECT 1 FROM ip_checks WHERE ip = ? AND ok = 1) AS e`).bind(ip).first<{ e: number }>();
	return row?.e === 1;
}

// topIPsForPublish returns up to limit IPs of the given address family
// (4 or 6) to publish as DNS records, most-seen first with lowest RTT
// breaking ties -- ports internal/store/queries.go's TopIPsForPublish. Only
// IPs whose most recent check succeeded and that have a measured RTT are
// returned, so a known-dead or unmeasured IP is never published.
export async function topIPsForPublish(db: D1Database, family: 4 | 6, limit: number): Promise<string[]> {
	const isIPv6 = family === 6 ? 1 : 0;
	const { results } = await db
		.prepare(
			`SELECT ip FROM ip_pool
			WHERE is_ipv6 = ? AND last_check_ok = 1 AND last_rtt_ms IS NOT NULL
			ORDER BY times_seen DESC, last_rtt_ms ASC
			LIMIT ?`,
		)
		.bind(isIPv6, limit)
		.all<{ ip: string }>();
	return results.map((r) => r.ip);
}

// --- Read-path queries for the home/scans pages (ports of the matching
// functions in internal/store/queries.go). ---

function fromSQLiteDateTime(s: string | null): Date | null {
	return s ? new Date(s) : null;
}

// splitStrings unpacks a "; "-joined column (ptr_cache.ptr_hostname) back
// into individual values -- mirrors store.SplitStrings. [] for "".
function splitStrings(joined: string): string[] {
	return joined ? joined.split("; ") : [];
}

interface IPPoolRow {
	ip: string;
	is_ipv6: number;
	scan_mode: string | null;
	first_seen: string | null;
	last_seen: string | null;
	last_scan_id: number | null;
	last_rtt_ms: number | null;
	times_seen: number;
	last_checked_at: string | null;
	last_check_ok: number | null;
	ptr_hostname?: string | null;
}

function rowToIPStatus(row: IPPoolRow): IPStatus {
	return {
		ip: row.ip,
		isIPv6: row.is_ipv6 !== 0,
		scanMode: row.scan_mode ?? "",
		firstSeen: fromSQLiteDateTime(row.first_seen),
		lastSeen: fromSQLiteDateTime(row.last_seen),
		lastScanId: row.last_scan_id,
		lastRttMs: row.last_rtt_ms ?? 0,
		timesSeen: row.times_seen,
		lastCheckedAt: fromSQLiteDateTime(row.last_checked_at),
		hasCheck: row.last_check_ok !== null,
		lastCheckOk: row.last_check_ok === 1,
		ptrHostname: splitStrings(row.ptr_hostname ?? ""),
	};
}

// IPStatusFor returns the rolling reachability record for a single IP, if known.
export async function ipStatusFor(db: D1Database, ip: string): Promise<IPStatus | null> {
	const row = await db
		.prepare(
			`SELECT ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok
			FROM ip_pool WHERE ip = ?`,
		)
		.bind(ip)
		.first<IPPoolRow>();
	return row ? rowToIPStatus(row) : null;
}

// overview returns aggregate stats for the home page.
export async function overview(db: D1Database): Promise<Stats> {
	const [poolCount, scanCount, lastScan] = await Promise.all([
		db.prepare(`SELECT COUNT(*) AS n FROM ip_pool`).first<{ n: number }>(),
		db.prepare(`SELECT COUNT(*) AS n FROM scans`).first<{ n: number }>(),
		db
			.prepare(`SELECT started_at, created_at FROM scans ORDER BY started_at DESC, created_at DESC LIMIT 1`)
			.first<{ started_at: string | null; created_at: string }>(),
	]);
	return {
		totalKnownIPs: poolCount?.n ?? 0,
		totalScans: scanCount?.n ?? 0,
		lastScanAt: lastScan ? fromSQLiteDateTime(lastScan.started_at ?? lastScan.created_at) : null,
	};
}

// poolVersion returns ip_checks' highest row id, a cheap (rowid-indexed)
// signal that changes whenever ingest or recheck writes a new check. The
// home page's client-side cache polls this to decide whether ip_pool needs
// refetching, instead of recomputing the view on every visit.
export async function poolVersion(db: D1Database): Promise<number> {
	const row = await db.prepare(`SELECT COALESCE(MAX(id), 0) AS v FROM ip_checks`).first<{ v: number }>();
	return row?.v ?? 0;
}

// listKnownIPsSortColumns whitelists the columns listKnownIPs may sort by,
// mapping the caller-facing key to the actual SQL expression -- sortBy is
// caller-controlled (query param), so it must never be interpolated directly.
const listKnownIPsSortColumns: Record<string, string> = {
	ip: "ip_pool.ip",
	ptr: "ptr_cache.ptr_hostname",
	status: "last_check_ok",
	first_seen: "first_seen",
	last_seen: "last_seen",
	rtt: "last_rtt_ms",
};

export interface ListKnownIPsOptions {
	onlyUp?: boolean;
	// family, if 4 or 6, restricts results to that IP address family; any
	// other value (including undefined) returns both.
	family?: number;
	// search, if non-empty, restricts results to IPs whose address or
	// cached PTR hostname contains it (case-insensitive via LIKE).
	search?: string;
	sortBy?: string;
	sortDesc?: boolean;
	limit?: number;
}

// listKnownIPs returns IPs from the tracked pool (ip_pool), along with each
// IP's cached PTR hostname(s) (empty if never resolved).
export async function listKnownIPs(db: D1Database, opts: ListKnownIPsOptions): Promise<IPStatus[]> {
	const col = listKnownIPsSortColumns[opts.sortBy ?? ""] ?? "last_seen";
	const dir = opts.sortDesc ? "DESC" : "ASC";

	let q = `SELECT ip_pool.ip, is_ipv6, scan_mode, first_seen, last_seen, last_scan_id, last_rtt_ms, times_seen, last_checked_at, last_check_ok, COALESCE(ptr_cache.ptr_hostname, '') AS ptr_hostname
		FROM ip_pool
		LEFT JOIN ptr_cache ON ptr_cache.ip = ip_pool.ip`;

	const where: string[] = [];
	const args: unknown[] = [];
	if (opts.onlyUp) where.push(`(last_check_ok IS NULL OR last_check_ok = 1)`);
	if (opts.family === 4) where.push(`is_ipv6 = 0`);
	else if (opts.family === 6) where.push(`is_ipv6 = 1`);
	if (opts.search) {
		where.push(`(ip_pool.ip LIKE ? OR ptr_cache.ptr_hostname LIKE ?)`);
		const pattern = `%${opts.search}%`;
		args.push(pattern, pattern);
	}
	if (where.length > 0) q += ` WHERE ${where.join(" AND ")}`;
	q += ` ORDER BY ${col} ${dir}, last_seen DESC`;
	if (opts.limit && opts.limit > 0) {
		q += ` LIMIT ?`;
		args.push(opts.limit);
	}

	const { results } = await db.prepare(q).bind(...args).all<IPPoolRow>();
	return results.map(rowToIPStatus);
}

interface ScanQueryRow {
	id: number;
	scan_mode: string;
	server_name: string | null;
	verify_common_name: string | null;
	http_path: string | null;
	http_method: string | null;
	http_verify_hosts: string | null;
	valid_status_code: number | null;
	input_file: string | null;
	output_file: string | null;
	level: number | null;
	config_json: string | null;
	started_at: string | null;
	finished_at: string | null;
	scanned_count: number | null;
	found_count: number | null;
}

function rowToScan(row: ScanQueryRow): ScanRow {
	return {
		id: row.id,
		ScanMode: row.scan_mode,
		ServerName: row.server_name ?? "",
		VerifyCommonName: row.verify_common_name ?? "",
		HTTPPath: row.http_path ?? "",
		HTTPMethod: row.http_method ?? "",
		HTTPVerifyHosts: row.http_verify_hosts ?? "",
		ValidStatusCode: row.valid_status_code ?? 0,
		InputFile: row.input_file ?? "",
		OutputFile: row.output_file ?? "",
		Level: row.level ?? 0,
		ConfigJSON: row.config_json ?? "",
		StartedAt: fromSQLiteDateTime(row.started_at),
		FinishedAt: fromSQLiteDateTime(row.finished_at),
		ScannedCount: row.scanned_count ?? 0,
		FoundCount: row.found_count ?? 0,
	};
}

// latestScan returns the most recent scan, optionally restricted to
// scanMode, or null if none exist yet.
export async function latestScan(db: D1Database, scanMode: string): Promise<ScanRow | null> {
	const q = scanMode
		? `SELECT id, scan_mode, started_at, finished_at, scanned_count, found_count FROM scans WHERE scan_mode = ? ORDER BY started_at DESC, id DESC LIMIT 1`
		: `SELECT id, scan_mode, started_at, finished_at, scanned_count, found_count FROM scans ORDER BY started_at DESC, id DESC LIMIT 1`;
	const stmt = scanMode ? db.prepare(q).bind(scanMode) : db.prepare(q);
	const row = await stmt.first<Pick<ScanQueryRow, "id" | "scan_mode" | "started_at" | "finished_at" | "scanned_count" | "found_count">>();
	if (!row) return null;
	return rowToScan({
		...row,
		server_name: null,
		verify_common_name: null,
		http_path: null,
		http_method: null,
		http_verify_hosts: null,
		valid_status_code: null,
		input_file: null,
		output_file: null,
		level: null,
		config_json: null,
	});
}

// listScans returns full scan records (including config fields), newest
// first, up to limit rows.
export async function listScans(db: D1Database, limit: number): Promise<ScanRow[]> {
	const { results } = await db
		.prepare(
			`SELECT id, scan_mode, server_name, verify_common_name, http_path, http_method, http_verify_hosts,
				valid_status_code, input_file, output_file, level, config_json,
				started_at, finished_at, scanned_count, found_count
			FROM scans ORDER BY started_at DESC, id DESC LIMIT ?`,
		)
		.bind(limit)
		.all<ScanQueryRow>();
	return results.map(rowToScan);
}

// --- PTR / host / ASN caches, IP history, community reports, recheck
// queue -- ports of the matching functions in internal/store/queries.go,
// used by functions/query.ts, functions/report.ts, and (PTR only)
// cron-ptr-refresh/index.ts. ---

interface PTRCacheRow {
	ip: string;
	ptr_hostname: string | null;
	lookup_ok: number;
	ttl_seconds: number;
	checked_at: string;
}

// getPTR returns a cached PTR/geo lookup for ip if present and not past its
// observed DNS TTL (checked_at + ttl_seconds).
export async function getPTR(db: D1Database, ip: string): Promise<PTRCacheEntry | null> {
	const row = await db
		.prepare(`SELECT ip, ptr_hostname, lookup_ok, ttl_seconds, checked_at FROM ptr_cache WHERE ip = ?`)
		.bind(ip)
		.first<PTRCacheRow>();
	if (!row) return null;
	const checkedAt = fromSQLiteDateTime(row.checked_at)!;
	if (Date.now() - checkedAt.getTime() > row.ttl_seconds * 1000) return null;
	return {
		ip: row.ip,
		ptrHostnames: splitStrings(row.ptr_hostname ?? ""),
		lookupOk: row.lookup_ok !== 0,
		ttlSeconds: row.ttl_seconds,
		checkedAt,
	};
}

// savePTR upserts a PTR lookup result into the cache.
export async function savePTR(db: D1Database, e: PTRCacheEntry): Promise<void> {
	await db
		.prepare(
			`INSERT INTO ptr_cache (ip, ptr_hostname, lookup_ok, ttl_seconds, checked_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				ptr_hostname = excluded.ptr_hostname,
				lookup_ok    = excluded.lookup_ok,
				ttl_seconds  = excluded.ttl_seconds,
				checked_at   = excluded.checked_at`,
		)
		.bind(e.ip, joinStrings(e.ptrHostnames), e.lookupOk ? 1 : 0, e.ttlSeconds, toSQLiteDateTime(e.checkedAt))
		.run();
}

// nextIPForPTRRefresh returns one IP from ip_pool whose ptr_cache entry is
// missing or past its observed DNS TTL, preferring never-checked IPs first,
// then the stalest. Returns null if every known IP has a fresh cache entry.
//
// Both sides of the staleness comparison go through SQLite's own datetime()
// (rather than binding a JS-formatted "now" string) so their TEXT output is
// guaranteed to be in the same format -- datetime() always normalizes to
// "YYYY-MM-DD HH:MM:SS" (space-separated, no fractional seconds), while
// Date#toISOString() produces "YYYY-MM-DDTHH:MM:SS.sssZ". Comparing those
// two formats as plain strings is a footgun: since ' ' (0x20) sorts before
// 'T' (0x54), "<datetime() output> < <toISOString() output>" is true for
// any same-day pair regardless of the actual times, making every row look
// perpetually stale.
export async function nextIPForPTRRefresh(db: D1Database): Promise<string | null> {
	const row = await db
		.prepare(
			`SELECT i.ip
			FROM ip_pool i
			LEFT JOIN ptr_cache p ON p.ip = i.ip
			WHERE p.ip IS NULL OR datetime(p.checked_at, '+' || p.ttl_seconds || ' seconds') < datetime('now')
			ORDER BY (p.checked_at IS NULL) DESC, p.checked_at ASC
			LIMIT 1`,
		)
		.first<{ ip: string }>();
	return row?.ip ?? null;
}

interface HostCacheRow {
	hostname: string;
	ipv4: string | null;
	ipv6: string | null;
	lookup_ok: number;
	ttl_seconds: number;
	checked_at: string;
}

// getHost returns a cached forward A/AAAA lookup for hostname if present
// and not past its observed DNS TTL (see getPTR).
export async function getHost(db: D1Database, hostname: string): Promise<HostCacheEntry | null> {
	const row = await db
		.prepare(`SELECT hostname, ipv4, ipv6, lookup_ok, ttl_seconds, checked_at FROM host_cache WHERE hostname = ?`)
		.bind(hostname)
		.first<HostCacheRow>();
	if (!row) return null;
	const checkedAt = fromSQLiteDateTime(row.checked_at)!;
	if (Date.now() - checkedAt.getTime() > row.ttl_seconds * 1000) return null;
	return {
		hostname: row.hostname,
		ipv4: splitStrings(row.ipv4 ?? ""),
		ipv6: splitStrings(row.ipv6 ?? ""),
		lookupOk: row.lookup_ok !== 0,
		ttlSeconds: row.ttl_seconds,
		checkedAt,
	};
}

// saveHost upserts a forward A/AAAA lookup result into the cache.
export async function saveHost(db: D1Database, e: HostCacheEntry): Promise<void> {
	await db
		.prepare(
			`INSERT INTO host_cache (hostname, ipv4, ipv6, lookup_ok, ttl_seconds, checked_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(hostname) DO UPDATE SET
				ipv4        = excluded.ipv4,
				ipv6        = excluded.ipv6,
				lookup_ok   = excluded.lookup_ok,
				ttl_seconds = excluded.ttl_seconds,
				checked_at  = excluded.checked_at`,
		)
		.bind(
			e.hostname,
			joinStrings(e.ipv4),
			joinStrings(e.ipv6),
			e.lookupOk ? 1 : 0,
			e.ttlSeconds,
			toSQLiteDateTime(e.checkedAt),
		)
		.run();
}

interface ASNCacheRow {
	ip: string;
	asn: number | null;
	as_name: string | null;
	prefix: string | null;
	country: string | null;
	lookup_ok: number;
	ttl_seconds: number;
	checked_at: string;
}

// getASN returns a cached ASN/prefix lookup for ip if present and not past
// its observed DNS TTL (see getPTR).
export async function getASN(db: D1Database, ip: string): Promise<ASNCacheEntry | null> {
	const row = await db
		.prepare(`SELECT ip, asn, as_name, prefix, country, lookup_ok, ttl_seconds, checked_at FROM asn_cache WHERE ip = ?`)
		.bind(ip)
		.first<ASNCacheRow>();
	if (!row) return null;
	const checkedAt = fromSQLiteDateTime(row.checked_at)!;
	if (Date.now() - checkedAt.getTime() > row.ttl_seconds * 1000) return null;
	return {
		ip: row.ip,
		asn: row.asn ?? 0,
		asName: row.as_name ?? "",
		prefix: row.prefix ?? "",
		country: row.country ?? "",
		lookupOk: row.lookup_ok !== 0,
		ttlSeconds: row.ttl_seconds,
		checkedAt,
	};
}

// saveASN upserts an ASN/prefix lookup result into the cache.
export async function saveASN(db: D1Database, e: ASNCacheEntry): Promise<void> {
	await db
		.prepare(
			`INSERT INTO asn_cache (ip, asn, as_name, prefix, country, lookup_ok, ttl_seconds, checked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				asn         = excluded.asn,
				as_name     = excluded.as_name,
				prefix      = excluded.prefix,
				country     = excluded.country,
				lookup_ok   = excluded.lookup_ok,
				ttl_seconds = excluded.ttl_seconds,
				checked_at  = excluded.checked_at`,
		)
		.bind(
			e.ip,
			e.asn || null,
			e.asName || null,
			e.prefix || null,
			e.country || null,
			e.lookupOk ? 1 : 0,
			e.ttlSeconds,
			toSQLiteDateTime(e.checkedAt),
		)
		.run();
}

interface IPHistoryRow {
	ip: string;
	ok: number;
	rtt_ms: number | null;
	reason: string | null;
	detail: string | null;
	checked_at: string | null;
	scan_id: number | null;
	config_scan_id: number | null;
	scan_mode: string | null;
	server_name: string | null;
	http_path: string | null;
	http_method: string | null;
	http_verify_hosts: string | null;
	verify_common_name: string | null;
	valid_status_code: number | null;
}

// ipHistory returns ip's most recent pass/fail checks, newest first, each
// joined against its owning (or, for rechecks, config) scan for the
// request-context columns.
export async function ipHistory(db: D1Database, ip: string, limit: number): Promise<IPCheckHistoryRow[]> {
	const { results } = await db
		.prepare(
			`SELECT
				c.ip, c.ok, c.rtt_ms, c.reason, c.detail, c.checked_at, c.scan_id, c.config_scan_id,
				s.scan_mode, s.server_name, s.http_path, s.http_method, s.http_verify_hosts, s.verify_common_name, s.valid_status_code
			FROM ip_checks c
			LEFT JOIN scans s ON s.id = COALESCE(c.scan_id, c.config_scan_id)
			WHERE c.ip = ?
			ORDER BY c.checked_at DESC LIMIT ?`,
		)
		.bind(ip, limit)
		.all<IPHistoryRow>();
	return results.map((row) => ({
		ip: row.ip,
		ok: row.ok !== 0,
		rttMs: row.rtt_ms ?? 0,
		reason: row.reason ?? "",
		detail: row.detail ?? "",
		checkedAt: fromSQLiteDateTime(row.checked_at),
		recheck: row.scan_id === null,
		scanMode: row.scan_mode ?? "",
		serverName: row.server_name ?? "",
		httpPath: row.http_path ?? "",
		httpMethod: row.http_method ?? "",
		httpVerifyHosts: row.http_verify_hosts ?? "",
		verifyCommonName: row.verify_common_name ?? "",
		validStatusCode: row.valid_status_code ?? 0,
	}));
}

// saveReport records one community report for an IP and returns its id.
export async function saveReport(db: D1Database, rep: Omit<IPReport, "id">): Promise<number> {
	const res = await db
		.prepare(
			`INSERT INTO ip_reports (ip, verdict, comment, reporter_prefix, reporter_asn, reporter_as_name, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
		)
		.bind(
			rep.ip,
			rep.verdict ? 1 : 0,
			rep.comment || null,
			rep.reporterPrefix || null,
			rep.reporterASN || null,
			rep.reporterASName || null,
			toSQLiteDateTime(rep.createdAt),
		)
		.run();
	return res.meta.last_row_id;
}

interface IPReportRow {
	id: number;
	ip: string;
	verdict: number;
	comment: string;
	reporter_prefix: string;
	reporter_asn: number;
	reporter_as_name: string;
	created_at: string;
}

// listReports returns the most recent reports for ip, newest first. The
// reporter's full IP is intentionally never selected -- callers should
// only surface reporterPrefix/reporterASN/reporterASName publicly.
export async function listReports(db: D1Database, ip: string, limit: number): Promise<IPReport[]> {
	const { results } = await db
		.prepare(
			`SELECT id, ip, verdict, COALESCE(comment, '') AS comment, COALESCE(reporter_prefix, '') AS reporter_prefix,
				COALESCE(reporter_asn, 0) AS reporter_asn, COALESCE(reporter_as_name, '') AS reporter_as_name, created_at
			FROM ip_reports WHERE ip = ? ORDER BY created_at DESC LIMIT ?`,
		)
		.bind(ip, limit)
		.all<IPReportRow>();
	return results.map((row) => ({
		id: row.id,
		ip: row.ip,
		verdict: row.verdict !== 0,
		comment: row.comment,
		reporterPrefix: row.reporter_prefix,
		reporterASN: row.reporter_asn,
		reporterASName: row.reporter_as_name,
		createdAt: fromSQLiteDateTime(row.created_at)!,
	}));
}

// recheckMinDelayMs/recheckMaxDelayMs bound the random delay applied before
// a queued recheck becomes eligible for the (deferred, pull-model) worker
// to pick up -- spreads out probes triggered by a burst of reports instead
// of firing them all at once.
const RECHECK_MIN_DELAY_MS = 60_000;
const RECHECK_MAX_DELAY_MS = 60 * 60_000;

// enqueueRecheck schedules a re-scan of ip for report reportId, eligible to
// run at a random time 1 minute to 1 hour from now. A no-op if that report
// was already enqueued (UNIQUE(report_id)), so callers can call it at most
// once per report without a separate existence check. Only *writes* the
// queue -- processing it is a later, deferred phase (the recheck
// pull-model rework).
export async function enqueueRecheck(db: D1Database, reportId: number, ip: string, createdAt: Date): Promise<void> {
	const delayMs = RECHECK_MIN_DELAY_MS + Math.random() * (RECHECK_MAX_DELAY_MS - RECHECK_MIN_DELAY_MS);
	const scheduledAt = new Date(Date.now() + delayMs);
	await db
		.prepare(`INSERT OR IGNORE INTO recheck_queue (report_id, ip, created_at, scheduled_at) VALUES (?, ?, ?, ?)`)
		.bind(reportId, ip, toSQLiteDateTime(createdAt), toSQLiteDateTime(scheduledAt))
		.run();
}

// --- Recheck pull-model: the China box's worker fetches its next probe
// target here and reports the outcome back through saveRecheckResult --
// ports internal/store/queries.go's NextPendingRecheck/MarkRecheckProcessed/
// PruneRecheckQueue/LatestScanConfig/SaveRecheck. ---

interface RecheckQueueRow {
	id: number;
	report_id: number;
	ip: string;
	created_at: string;
	scheduled_at: string | null;
}

// nextPendingRecheck returns the oldest not-yet-processed recheck_queue entry
// whose scheduled_at has arrived, or null if none are ready yet.
//
// scheduled_at is compared via SQLite's own datetime() on both sides (rather
// than a bound JS-formatted "now" string) for the same reason
// nextIPForPTRRefresh does: stored values here are ISO strings
// (toISOString(), "YYYY-MM-DDTHH:MM:SS.sssZ") but datetime('now') normalizes
// to "YYYY-MM-DD HH:MM:SS" (space-separated) -- comparing those as raw
// strings puts the ISO value (with 'T', 0x54) after the datetime() value
// (with ' ', 0x20) regardless of actual times, so scheduled_at would almost
// never look due. Wrapping scheduled_at in datetime() too normalizes both
// sides to the same format before comparing.
export async function nextPendingRecheck(db: D1Database): Promise<RecheckQueueItem | null> {
	const row = await db
		.prepare(
			`SELECT id, report_id, ip, created_at, scheduled_at FROM recheck_queue
			WHERE processed_at IS NULL AND (scheduled_at IS NULL OR datetime(scheduled_at) <= datetime('now'))
			ORDER BY created_at ASC LIMIT 1`,
		)
		.first<RecheckQueueRow>();
	if (!row) return null;
	return {
		id: row.id,
		reportId: row.report_id,
		ip: row.ip,
		createdAt: fromSQLiteDateTime(row.created_at)!,
		scheduledAt: fromSQLiteDateTime(row.scheduled_at),
	};
}

// markRecheckProcessed records the outcome of a recheck attempt so it is not
// picked up again.
export async function markRecheckProcessed(db: D1Database, id: number, ok: boolean, processedAt: Date): Promise<void> {
	await db
		.prepare(`UPDATE recheck_queue SET processed_at = ?, ok = ? WHERE id = ?`)
		.bind(toSQLiteDateTime(processedAt), ok ? 1 : 0, id)
		.run();
}

// pruneRecheckQueue deletes processed recheck_queue rows older than
// retentionDays, so the table doesn't grow unboundedly with completed work.
// Pending (unprocessed) rows are never touched.
export async function pruneRecheckQueue(db: D1Database, retentionDays: number): Promise<void> {
	await db
		.prepare(`DELETE FROM recheck_queue WHERE processed_at IS NOT NULL AND processed_at < datetime('now', '-' || ? || ' days')`)
		.bind(retentionDays)
		.run();
}

// latestScanConfig returns the id and config_json of the most recent scan
// for scanMode, or null if none exists yet.
export async function latestScanConfig(db: D1Database, scanMode: string): Promise<{ scanId: number; configJSON: string } | null> {
	const row = await db
		.prepare(`SELECT id, config_json FROM scans WHERE scan_mode = ? ORDER BY started_at DESC, id DESC LIMIT 1`)
		.bind(scanMode)
		.first<{ id: number; config_json: string | null }>();
	if (!row || !row.config_json) return null;
	return { scanId: row.id, configJSON: row.config_json };
}

export interface RecheckResult {
	ip: string;
	ok: boolean;
	rttMs: number | null;
	reason: string | null;
	detail: string | null;
	checkedAt: Date;
	scanMode: string;
	configScanId: number | null;
}

// saveRecheckResult records the outcome of a single report-triggered recheck
// probe: an ip_checks row with no owning scan (scan_id NULL, config_scan_id
// pointing at the scan whose config the probe used) -- ports
// internal/store/queries.go's SaveRecheck exactly, including its asymmetric
// branches. A failure is only recorded if the IP has some prior ok=1
// history (isKnownGood) -- probing arbitrary reported IPs can't grow
// permanent state for IPs nobody has ever seen reachable.
export async function saveRecheckResult(db: D1Database, r: RecheckResult): Promise<void> {
	if (r.ok) {
		await db
			.prepare(
				`INSERT INTO ip_checks (scan_id, config_scan_id, ip, ok, rtt_ms, reason, detail, checked_at, scan_mode)
				VALUES (NULL, ?, ?, 1, ?, NULL, NULL, ?, ?)`,
			)
			.bind(r.configScanId, r.ip, r.rttMs, toSQLiteDateTime(r.checkedAt), r.scanMode)
			.run();
		return;
	}

	if (!(await isKnownGood(db, r.ip))) return;

	await db
		.prepare(
			`INSERT INTO ip_checks (scan_id, config_scan_id, ip, ok, rtt_ms, reason, detail, checked_at, scan_mode)
			VALUES (NULL, ?, ?, 0, NULL, ?, ?, ?, ?)`,
		)
		.bind(r.configScanId, r.ip, r.reason, r.detail, toSQLiteDateTime(r.checkedAt), r.scanMode)
		.run();
}
