// D1-facing primitives used by functions/ingest.ts. Unlike
// internal/store/queries.go's SaveScan, insertScan/insertCheckRows aren't
// one function wrapping everything in a single transaction -- D1's
// atomicity primitive (env.DB.batch()) requires every statement to be bound
// upfront in one call, and a scan's check rows are chunked across multiple
// batch() calls (MAX_BATCH). The trade-off: a crash partway through can
// leave a scans row with fewer ip_checks rows than a fully-succeeded run
// would have, rather than Go's all-or-nothing guarantee -- acceptable so
// far, revisit if it bites in practice.
import { ipToHex, prefixToRange } from "./ipAddr";
import type {
	ASNCacheEntry,
	HostCacheEntry,
	IPCheckHistoryRow,
	IPStatus,
	PTRCacheEntry,
	Stats,
} from "./types";

// joinStrings packs multiple values for storage in a single "; "-joined
// TEXT column (ptr_cache.ptr_hostname, host_cache.ipv4/ipv6) -- mirrors
// store.JoinStrings.
function joinStrings(values: string[]): string {
	return values.join("; ");
}

const MAX_BATCH = 500; // comfortably under D1's 1,000/batch free-tier cap

function bumpPoolRevision(db: D1Database): D1PreparedStatement {
	return db.prepare(`UPDATE pool_revision SET version = version + 1 WHERE singleton = 1`);
}

function toSQLiteDateTime(d: Date | null): string | null {
	return d ? d.toISOString() : null;
}

export interface CheckRow {
	ip: string;
	ok: boolean;
	rttMs: number | null;
	reason: string | null;
	detail: string | null;
	checkedAt: Date;
	scanMode: string;
}

const insertCheckSQL = `INSERT INTO ip_checks (ip, ok, rtt_ms, reason, detail, checked_at, scan_mode) VALUES (?, ?, ?, ?, ?, ?, ?)`;

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

// POOL_UPSERT_CHUNK caps how many statements one updatePoolBatch db.batch()
// call covers. D1 Free caps db.batch() at 1,000 statements; 400 is safely under.
const POOL_UPSERT_CHUNK = 400;

// updatePoolBatch incrementally updates ip_pool directly from the incoming
// batch of checks. Unlike the old refreshPoolForIPs (which re-scanned all
// historical ip_checks rows for every touched IP with 3 window functions —
// executing 169 complex queries and reading 12M rows per ingest), this executes
// direct PK upserts/updates on ip_pool using db.batch():
// - ok = 1 checks: INSERT INTO ip_pool ... ON CONFLICT(ip) DO UPDATE
// - ok = 0 checks: UPDATE ip_pool SET last_checked_at=?, last_check_ok=0 WHERE ip=?
// Total queries per ingest drops from ~700 to ~19, reading 0 rows from ip_checks!
export async function updatePoolBatch(db: D1Database, rows: CheckRow[]): Promise<void> {
	// Deduplicate per IP within this batch, keeping the latest check.
	const latestByIP = new Map<string, CheckRow>();
	for (const r of rows) {
		const existing = latestByIP.get(r.ip);
		if (!existing || r.checkedAt >= existing.checkedAt) {
			latestByIP.set(r.ip, r);
		}
	}

	const uniqueRows = Array.from(latestByIP.values());
	if (uniqueRows.length === 0) return;

	for (let i = 0; i < uniqueRows.length; i += POOL_UPSERT_CHUNK) {
		const chunk = uniqueRows.slice(i, i + POOL_UPSERT_CHUNK);
		const statements = chunk.map((r) => {
			const isIPv6 = r.ip.includes(":") ? 1 : 0;
			const ts = toSQLiteDateTime(r.checkedAt);
			if (r.ok) {
				return db
					.prepare(
						`INSERT INTO ip_pool (ip, is_ipv6, scan_mode, first_seen, last_seen, last_rtt_ms, times_seen, last_checked_at, last_check_ok, revision)
						 VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1, (SELECT version FROM pool_revision WHERE singleton = 1))
						 ON CONFLICT(ip) DO UPDATE SET
							scan_mode = excluded.scan_mode,
							last_seen = excluded.last_seen,
							last_rtt_ms = excluded.last_rtt_ms,
							times_seen = ip_pool.times_seen + 1,
							last_checked_at = excluded.last_checked_at,
							last_check_ok = 1,
							revision = excluded.revision`,
					)
					.bind(r.ip, isIPv6, r.scanMode, ts, ts, r.rttMs ?? 0, ts);
			}
			return db
				.prepare(
					`UPDATE ip_pool SET
						last_checked_at = ?,
						last_check_ok = 0,
						revision = (SELECT version FROM pool_revision WHERE singleton = 1)
					 WHERE ip = ?`,
				)
				.bind(ts, r.ip);
		});
		await db.batch([bumpPoolRevision(db), ...statements]);
	}
}

// CHECK_HISTORY_RETENTION caps how many ip_checks rows survive per IP.
// functions/query.ts's history view only ever shows the most recent 30
// (MAX_HISTORY_ROWS), and ip_pool's first_seen/times_seen are allowed to
// drift to "within the retained window" rather than true lifetime values.
const CHECK_HISTORY_RETENTION = 300;

// pruneCheckHistory deletes ip_checks rows beyond CHECK_HISTORY_RETENTION
// per IP (oldest first) for the given ips. Run asynchronously via waitUntil.
export async function pruneCheckHistory(db: D1Database, ips: string[]): Promise<void> {
	const unique = [...new Set(ips)];
	for (let i = 0; i < unique.length; i += 100) {
		const chunk = unique.slice(i, i + 100);
		const placeholders = chunk.map(() => "?").join(",");
		await db
			.prepare(
				`DELETE FROM ip_checks
				 WHERE id IN (
					SELECT id FROM (
						SELECT id, ROW_NUMBER() OVER (PARTITION BY ip ORDER BY checked_at DESC, id DESC) AS rn
						FROM ip_checks
						WHERE ip IN (${placeholders})
					)
					WHERE rn > ?
				 )`,
			)
			.bind(...chunk, CHECK_HISTORY_RETENTION)
			.run();
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

// allKnownGoodIPs returns every IP in the tracked pool -- the China box's
// ingest flow fetches this once per run to filter a scan's failures down to
// only IPs already known reachable (mirroring Go's old inline SaveScan gate)
// before ever sending them to Cloudflare, rather than paying for a D1 lookup
// per distinct failing IP in the log (which, at gscan_quic's LogLevel: 5,
// can be tens of thousands per scan).
export async function allKnownGoodIPs(db: D1Database): Promise<string[]> {
	const { results } = await db.prepare(`SELECT ip FROM ip_pool`).all<{ ip: string }>();
	return results.map((r) => r.ip);
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
	revision: number;
	is_ipv6: number;
	scan_mode: string | null;
	first_seen: string | null;
	last_seen: string | null;
	last_rtt_ms: number | null;
	times_seen: number;
	last_checked_at: string | null;
	last_check_ok: number | null;
	ptr_hostname?: string | null;
}

function rowToIPStatus(row: IPPoolRow): IPStatus {
	return {
		ip: row.ip,
		revision: row.revision,
		isIPv6: row.is_ipv6 !== 0,
		scanMode: row.scan_mode ?? "",
		firstSeen: fromSQLiteDateTime(row.first_seen),
		lastSeen: fromSQLiteDateTime(row.last_seen),
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
			`SELECT ip, revision, is_ipv6, scan_mode, first_seen, last_seen, last_rtt_ms, times_seen, last_checked_at, last_check_ok
			FROM ip_pool WHERE ip = ?`,
		)
		.bind(ip)
		.first<IPPoolRow>();
	return row ? rowToIPStatus(row) : null;
}

// overview returns aggregate stats for the home page — now check-based
// overview computes the home page's summary stats. All three values come
// from ip_pool (the maintained table, ~7600 rows) rather than ip_checks
// (the append-only history, 134k+ rows and growing) — a single full scan
// of ip_pool is ~18x cheaper than a single COUNT(*) on ip_checks.
//
// totalChecks is SUM(times_seen), i.e. total successful checks across all
// IPs — semantically "how many times have we confirmed IPs reachable"
// rather than "how many probe results exist" (which includes failures).
// This is more meaningful for visitors and avoids the ip_checks scan.
export async function overview(db: D1Database): Promise<Stats> {
	const [agg, lastCheck] = await Promise.all([
		db
			.prepare(`SELECT COUNT(*) AS totalKnownIPs, COALESCE(SUM(times_seen), 0) AS totalChecks FROM ip_pool`)
			.first<{ totalKnownIPs: number; totalChecks: number }>(),
		db
			.prepare(`SELECT last_checked_at, scan_mode FROM ip_pool ORDER BY last_checked_at DESC LIMIT 1`)
			.first<{ last_checked_at: string | null; scan_mode: string | null }>(),
	]);
	return {
		totalKnownIPs: agg?.totalKnownIPs ?? 0,
		totalChecks: agg?.totalChecks ?? 0,
		lastCheckAt: lastCheck ? fromSQLiteDateTime(lastCheck.last_checked_at) : null,
		scanMode: lastCheck?.scan_mode ?? "",
	};
}

// poolVersion returns the latest published ip_pool revision. Check and PTR
// writers allocate one revision per logical batch, allowing clients to query
// rows changed after a prior snapshot.
export async function poolVersion(db: D1Database): Promise<number> {
	const row = await db.prepare(`SELECT version AS v FROM pool_revision WHERE singleton = 1`).first<{ v: number }>();
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

	let q = `SELECT ip_pool.ip, revision, is_ipv6, scan_mode, first_seen, last_seen, last_rtt_ms, times_seen, last_checked_at, last_check_ok, COALESCE(ptr_cache.ptr_hostname, '') AS ptr_hostname
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

// listKnownIPsChanged returns the current representation of rows touched in
// (afterRevision, throughRevision]. Repeated mutations collapse naturally to
// one row, so no retained change-log table is needed.
export async function listKnownIPsChanged(
	db: D1Database,
	afterRevision: number,
	throughRevision: number,
): Promise<IPStatus[]> {
	const { results } = await db
		.prepare(
			`SELECT ip_pool.ip, revision, is_ipv6, scan_mode, first_seen, last_seen, last_rtt_ms, times_seen, last_checked_at, last_check_ok, COALESCE(ptr_cache.ptr_hostname, '') AS ptr_hostname
			 FROM ip_pool
			 LEFT JOIN ptr_cache ON ptr_cache.ip = ip_pool.ip
			 WHERE revision > ? AND revision <= ?
			 ORDER BY revision ASC, ip_pool.ip ASC`,
		)
		.bind(afterRevision, throughRevision)
		.all<IPPoolRow>();
	return results.map(rowToIPStatus);
}

// --- PTR / host / ASN caches, IP history -- ports of the matching
// functions in internal/store/queries.go, used by functions/query.ts and
// (PTR only) ptrRefresh.ts. ---

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

// savePTR upserts a PTR lookup result into the general cache and, in the
// same db.batch() (one D1 call), bumps ip_pool.ptr_checked_at for that IP --
// the round-robin cursor pendingIPsForPTRRefresh orders on. The UPDATE is a
// harmless no-op for IPs not currently in ip_pool (e.g. ad-hoc /query?ip=
// lookups on an IP that isn't a pool member): see migration 0005's comment
// for why ptr_checked_at can't just be read off ptr_cache.checked_at instead.
export async function savePTR(db: D1Database, e: PTRCacheEntry): Promise<void> {
	const checkedAt = toSQLiteDateTime(e.checkedAt);
	await db.batch([
		bumpPoolRevision(db),
		db
			.prepare(
				`INSERT INTO ptr_cache (ip, ptr_hostname, lookup_ok, ttl_seconds, checked_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(ip) DO UPDATE SET
					ptr_hostname = excluded.ptr_hostname,
					lookup_ok    = excluded.lookup_ok,
					ttl_seconds  = excluded.ttl_seconds,
					checked_at   = excluded.checked_at`,
			)
			.bind(e.ip, joinStrings(e.ptrHostnames), e.lookupOk ? 1 : 0, e.ttlSeconds, checkedAt),
		db
			.prepare(
				`UPDATE ip_pool SET ptr_checked_at = ?, revision = (SELECT version FROM pool_revision WHERE singleton = 1) WHERE ip = ?`,
			)
			.bind(checkedAt, e.ip),
	]);
}

// PTR_BATCH_CHUNK caps how many entries one savePTRBatch db.batch() call
// covers. Each entry is 2 statements (same as savePTR), and D1's Free plan
// caps a batch() call at 1,000 statements -- 400 keeps every chunk at 800,
// with headroom for Paid's higher per-statement bound parameter accounting
// to not matter here (each statement only binds a handful of params).
const PTR_BATCH_CHUNK = 400;

// savePTRBatch is savePTR for many IPs in one ptrRefresh.ts run --
// its TCP-pipelined resolver produces results for
// potentially thousands of IPs per invocation, and issuing one db.batch()
// (one D1 call/subrequest) per IP the way savePTR does would burn through
// the 50-subrequests-per-invocation limit exactly like the old fetch()-per-IP
// DoH approach did. Chunking into PTR_BATCH_CHUNK-sized batch() calls keeps
// the whole write phase at a handful of subrequests regardless of how many
// IPs were resolved.
export async function savePTRBatch(db: D1Database, entries: PTRCacheEntry[]): Promise<void> {
	if (entries.length === 0) return;
	for (let i = 0; i < entries.length; i += PTR_BATCH_CHUNK) {
		const chunk = entries.slice(i, i + PTR_BATCH_CHUNK);
		const statements = chunk.flatMap((e) => {
			const checkedAt = toSQLiteDateTime(e.checkedAt);
			return [
				db
					.prepare(
						`INSERT INTO ptr_cache (ip, ptr_hostname, lookup_ok, ttl_seconds, checked_at)
						VALUES (?, ?, ?, ?, ?)
						ON CONFLICT(ip) DO UPDATE SET
							ptr_hostname = excluded.ptr_hostname,
							lookup_ok    = excluded.lookup_ok,
							ttl_seconds  = excluded.ttl_seconds,
							checked_at   = excluded.checked_at`,
					)
					.bind(e.ip, joinStrings(e.ptrHostnames), e.lookupOk ? 1 : 0, e.ttlSeconds, checkedAt),
				db
					.prepare(
						`UPDATE ip_pool SET ptr_checked_at = ?, revision = (SELECT version FROM pool_revision WHERE singleton = 1) WHERE ip = ?`,
					)
					.bind(checkedAt, e.ip),
			];
		});
		await db.batch([bumpPoolRevision(db), ...statements]);
	}
}

// pendingIPsForPTRRefresh returns up to limit ip_pool IPs due for a PTR
// refresh: either never checked (ptr_checked_at IS NULL, which sorts first
// on the index) or checked more than 30 days ago. Seeks on the
// idx_ip_pool_ptr_checked_at index directly.
export async function pendingIPsForPTRRefresh(db: D1Database, limit: number): Promise<string[]> {
	const { results } = await db
		.prepare(
			`SELECT ip FROM ip_pool
			WHERE ptr_checked_at IS NULL OR ptr_checked_at < datetime('now', '-30 days')
			ORDER BY ptr_checked_at ASC LIMIT ?`,
		)
		.bind(limit)
		.all<{ ip: string }>();
	return results.map((r) => r.ip);
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
	prefix: string;
	asn: number | null;
	as_name: string | null;
	country: string | null;
	lookup_ok: number;
	ttl_seconds: number;
	checked_at: string;
}

// getASN returns a cached ASN/prefix lookup covering ip, if present and not
// past its observed DNS TTL -- keyed by the announced prefix's address
// range rather than the exact ip (migration 0004), since every ip sharing a
// prefix has identical asn/asName/country and querying by point-in-range
// lets them share one cache entry instead of each paying their own Cymru
// DNS round trip. ORDER BY prefix_len DESC picks the most specific match in
// the rare case of overlapping announcements (longest-prefix-match, same as
// real routing). The returned entry's ip is the *queried* ip, not whatever
// ip originally triggered this prefix's cache row.
export async function getASN(db: D1Database, ip: string): Promise<ASNCacheEntry | null> {
	const point = ipToHex(ip);
	if (!point) return null;
	const row = await db
		.prepare(
			`SELECT prefix, asn, as_name, country, lookup_ok, ttl_seconds, checked_at
			FROM asn_cache
			WHERE is_ipv6 = ? AND range_start <= ? AND range_end >= ?
			ORDER BY prefix_len DESC LIMIT 1`,
		)
		.bind(ip.includes(":") ? 1 : 0, point, point)
		.first<ASNCacheRow>();
	if (!row) return null;
	const checkedAt = fromSQLiteDateTime(row.checked_at)!;
	if (Date.now() - checkedAt.getTime() > row.ttl_seconds * 1000) return null;
	return {
		ip,
		asn: row.asn ?? 0,
		asName: row.as_name ?? "",
		prefix: row.prefix,
		country: row.country ?? "",
		lookupOk: row.lookup_ok !== 0,
		ttlSeconds: row.ttl_seconds,
		checkedAt,
	};
}

// saveASN upserts an ASN/prefix lookup result into the cache, keyed by
// e.prefix (not e.ip) -- see getASN.
export async function saveASN(db: D1Database, e: ASNCacheEntry): Promise<void> {
	const range = prefixToRange(e.prefix);
	if (!range) {
		console.error(`asn: saveASN: invalid prefix ${JSON.stringify(e.prefix)} for ip ${e.ip}`);
		return;
	}
	await db
		.prepare(
			`INSERT INTO asn_cache (prefix, is_ipv6, range_start, range_end, prefix_len, asn, as_name, country, lookup_ok, ttl_seconds, checked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(prefix) DO UPDATE SET
				asn         = excluded.asn,
				as_name     = excluded.as_name,
				country     = excluded.country,
				lookup_ok   = excluded.lookup_ok,
				ttl_seconds = excluded.ttl_seconds,
				checked_at  = excluded.checked_at`,
		)
		.bind(
			e.prefix,
			range.isIPv6 ? 1 : 0,
			range.start,
			range.end,
			range.prefixLen,
			e.asn || null,
			e.asName || null,
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
	scan_mode: string | null;
}

// ipHistory returns ip's most recent pass/fail checks, newest first.
export async function ipHistory(db: D1Database, ip: string, limit: number): Promise<IPCheckHistoryRow[]> {
	const { results } = await db
		.prepare(
			`SELECT ip, ok, rtt_ms, reason, detail, checked_at, scan_mode
			FROM ip_checks
			WHERE ip = ?
			ORDER BY checked_at DESC LIMIT ?`,
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
		scanMode: row.scan_mode ?? "",
	}));
}

// checkRateLimit enforces a per-client-IP probe-request cap for the
// on-demand probe button (functions/check.ts). One row per (client_ip, UTC
// minute); the count is incremented and compared against limit. Returns
// true if the request is allowed, false if over the limit. Old windows are
// pruned lazily so the table stays bounded. There's a benign race between
// the SELECT and INSERT under concurrent requests (two simultaneous clicks
// could both pass before either increments) -- acceptable for a rate limit
// whose purpose is abuse prevention, not exact metering.
export async function checkRateLimit(db: D1Database, clientIP: string, limit: number): Promise<boolean> {
	const window = new Date().toISOString().slice(0, 16); // 'YYYY-MM-DDTHH:MM' (UTC minute)
	await db
		.prepare(`DELETE FROM check_rate_limit WHERE client_ip = ? AND window < ?`)
		.bind(clientIP, window)
		.run();
	const row = await db
		.prepare(`SELECT count FROM check_rate_limit WHERE client_ip = ? AND window = ?`)
		.bind(clientIP, window)
		.first<{ count: number }>();
	if ((row?.count ?? 0) >= limit) return false;
	await db
		.prepare(
			`INSERT INTO check_rate_limit (client_ip, window, count) VALUES (?, ?, 1)
			ON CONFLICT(client_ip, window) DO UPDATE SET count = count + 1`,
		)
		.bind(clientIP, window)
		.run();
	return true;
}

export interface RecheckResult {
	ip: string;
	ok: boolean;
	rttMs: number | null;
	reason: string | null;
	detail: string | null;
	checkedAt: Date;
	scanMode: string;
}

// saveRecheckResult records the outcome of a single ad-hoc or on-demand
// probe: an ip_checks row (no owning scan — the scans table is gone). Ports
// internal/store/queries.go's SaveRecheck exactly, including its asymmetric
// branches. A failure is only recorded if the IP has some prior ok=1
// history (isKnownGood) -- probing arbitrary IPs can't grow permanent state
// for IPs nobody has ever seen reachable.
export async function saveRecheckResult(db: D1Database, r: RecheckResult): Promise<void> {
	if (r.ok) {
		await db
			.prepare(
				`INSERT INTO ip_checks (ip, ok, rtt_ms, reason, detail, checked_at, scan_mode)
				VALUES (?, 1, ?, NULL, ?, ?, ?)`,
			)
			.bind(r.ip, r.rttMs, r.detail, toSQLiteDateTime(r.checkedAt), r.scanMode)
			.run();
		return;
	}

	if (!(await isKnownGood(db, r.ip))) return;

	await db
		.prepare(
			`INSERT INTO ip_checks (ip, ok, rtt_ms, reason, detail, checked_at, scan_mode)
			VALUES (?, 0, NULL, ?, ?, ?, ?)`,
		)
		.bind(r.ip, r.reason, r.detail, toSQLiteDateTime(r.checkedAt), r.scanMode)
		.run();
}

// updatePoolForCheck is a lightweight single-IP pool update for on-demand
// probes (/check, /recheck/result). Instead of refreshPoolForIPs (which
// recomputes the entire ip_pool row from all ip_checks rows for that IP via
// window functions — ~5k rows read per call), this does a targeted UPDATE
// by primary key (1 row read). Only the columns that change on a single
// probe are touched: last_checked_at, last_check_ok, and on success also
// last_seen/last_rtt_ms/times_seen. If the IP isn't in ip_pool yet and the
// check succeeded, it INSERTs; if it failed and the IP isn't known, the
// caller (saveRecheckResult) already skipped the ip_checks insert, so
// there's nothing to update.
//
// pruneCheckHistory is intentionally NOT called here — a single probe adds
// 1 row, which can't push an IP past CHECK_HISTORY_RETENTION (300) unless
// it already has 299, and the next batch ingest flush will prune it anyway.
export async function updatePoolForCheck(
	db: D1Database,
	ip: string,
	ok: boolean,
	rttMs: number | null,
	checkedAt: Date,
	scanMode: string,
): Promise<void> {
	const isIPv6 = ip.includes(":") ? 1 : 0;
	const ts = toSQLiteDateTime(checkedAt);

	// Try UPDATE first (common case: IP already in pool). reads 1 row by PK.
	const results = await db.batch([
		bumpPoolRevision(db),
		db
			.prepare(
			`UPDATE ip_pool SET
				last_checked_at = ?,
				last_check_ok = ?,
				last_rtt_ms = CASE WHEN ? THEN ? ELSE last_rtt_ms END,
				last_seen = CASE WHEN ? THEN ? ELSE last_seen END,
				times_seen = CASE WHEN ? THEN times_seen + 1 ELSE times_seen END,
				revision = (SELECT version FROM pool_revision WHERE singleton = 1)
			 WHERE ip = ?`,
		)
			.bind(ts, ok ? 1 : 0, ok ? 1 : 0, rttMs ?? 0, ok ? 1 : 0, ts, ok ? 1 : 0, ip),
	]);
	const result = results[1];
	if (!result) throw new Error("pool update result missing");

	// IP not in pool and check succeeded: INSERT (mirrors refreshPoolForIPs's
	// HAVING times_seen > 0 gate — only reachable IPs belong in the pool).
	if (result.meta.changes === 0 && ok) {
		await db.batch([
			bumpPoolRevision(db),
			db
				.prepare(
				`INSERT INTO ip_pool (ip, is_ipv6, scan_mode, first_seen, last_seen, last_rtt_ms, times_seen, last_checked_at, last_check_ok, revision)
				 VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1, (SELECT version FROM pool_revision WHERE singleton = 1))
				 ON CONFLICT(ip) DO UPDATE SET
					scan_mode = excluded.scan_mode,
					last_seen = excluded.last_seen,
					last_rtt_ms = excluded.last_rtt_ms,
					times_seen = ip_pool.times_seen + 1,
					last_checked_at = excluded.last_checked_at,
					last_check_ok = 1,
					revision = excluded.revision`,
			)
				.bind(ip, isIPv6, scanMode, ts, ts, rttMs ?? 0, ts),
		]);
	}
}
