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
import type { IPStatus, Scan, ScanRow, Stats } from "./types";

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
