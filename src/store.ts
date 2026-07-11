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
import type { Scan } from "./types";

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
