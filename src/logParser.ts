// Ports internal/ingest/ingest.go's parseLog (+ its regexes + SanitizeNetErr)
// to TypeScript, restructured as two streaming passes over the log's lines
// rather than one function returning a fully-materialized result, so a
// ~100MB decompressed log never has to be held in memory at once (see
// lineStream.ts). Only the log-only path is ported for phase 1 --
// scripts/scan_and_ingest.sh already runs gwsdb ingest with -log-only, so
// readOutputIPs/output-file handling isn't needed here.
//
// Two passes are needed (see internal/store/queries.go's SaveScan for the
// Go original this mirrors):
//   Pass A collects run metadata (Started/FinishedAt, Scanned/FoundCount)
//   and, per unique IP that was ever seen OK, its *last* RTT/timestamp in
//   the log (Go's RTTByIP/seenAt maps are last-write-wins across the whole
//   file too -- see the comments below).
//   Pass B walks the log again to find failure lines, keeping only the
//   ones for an IP that's known-good -- either found OK somewhere in this
//   same log (pass A's result set) or already known-good from a prior scan
//   (checked against D1, memoized by the caller). A scan can probe
//   thousands of never-seen-good IPs and their failures aren't kept.
// A stream can only be read once, so the caller re-opens the decompression
// stream from the same underlying (small, compressed) Blob for pass B.

const logLineTS = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})\s/;
const netErrSrcAddrRE = /((?:read|write|dial)\s+(?:tcp|udp|ip[46]?)\s+)\S+->/g;
const foundRecordRE = /Found a record: IP=(\S+), RTT=(\S+)/;
const failRecordRE = /Tested IP=(\S+) RESULT=fail(?: REASON=(\S+))?(?: DETAIL=(.*))?/;
const summaryRE = /Scanned (\d+) IP in ([^,]+), found (\d+) records/;

// SanitizeNetErr strips the local (source) address from Go net error strings
// like "read ip4 192.168.1.110->74.125.207.126: i/o timeout". With IPv6 the
// source is the machine's public address, which must not be stored or shown.
export function sanitizeNetErr(s: string): string {
	return s.replace(netErrSrcAddrRE, "$1");
}

// parseLogTimestamp parses a bare "YYYY/MM/DD HH:mm:ss" gscan_quic log
// timestamp as wall-clock time in the scanning box's local timezone
// (tzOffsetMinutes east of UTC -- e.g. 480 for China Standard Time, which
// has no DST), converting it to a true UTC instant. The Go original ran on
// the same box as the scanner and used time.Local, which was correct there;
// a Worker has no "the box's local time" of its own, so the offset must be
// passed in explicitly.
function parseLogTimestamp(s: string, tzOffsetMinutes: number): Date | null {
	const m = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(s);
	if (!m) return null;
	const [, y, mo, d, h, mi, se] = m as unknown as [string, string, string, string, string, string, string];
	const wallUTCMs = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(se));
	return new Date(wallUTCMs - tzOffsetMinutes * 60_000);
}

// parseGoDuration converts a single-unit Go time.Duration string (e.g.
// "123.456ms", "1.2s") to milliseconds, or null if unparseable. gscan_quic's
// RTT field only ever emits a single unit, so this isn't a byte-for-byte
// port of time.ParseDuration (which also accepts compound durations like
// "1h2m3s") -- just of the subset gscan_quic actually produces.
function parseGoDuration(s: string): number | null {
	const m = /^(\d+(?:\.\d+)?)(ns|µs|us|ms|s|m|h)$/.exec(s);
	if (!m) return null;
	const value = parseFloat(m[1]!);
	const perMs: Record<string, number> = { ns: 1e-6, "µs": 1e-3, us: 1e-3, ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
	return value * (perMs[m[2]!] ?? 0);
}

export interface FoundResult {
	rttMs: number; // 0 if never successfully parsed, matching Go's zero-value map read
	checkedAt: Date;
}

export interface PassASummary {
	startedAt: Date | null;
	finishedAt: Date | null;
	scannedCount: number;
	foundCount: number;
	// Insertion order is first-OK-occurrence order (foundIPsFromLog's
	// ordering); rttMs/checkedAt are last-write-wins across the whole log,
	// same as Go's RTTByIP/seenAt maps.
	results: Map<string, FoundResult>;
}

// scanPassA walks the log once collecting run metadata and, per IP ever
// seen OK, its last-seen RTT/timestamp.
export async function scanPassA(lines: AsyncIterable<string>, tzOffsetMinutes: number): Promise<PassASummary> {
	const sum: PassASummary = { startedAt: null, finishedAt: null, scannedCount: 0, foundCount: 0, results: new Map() };
	let lineTime: Date | null = null;

	for await (const line of lines) {
		const ts = logLineTS.exec(line);
		if (ts) {
			const t = parseLogTimestamp(ts[1]!, tzOffsetMinutes);
			if (t) {
				lineTime = t;
				if (sum.startedAt === null) sum.startedAt = t;
				sum.finishedAt = t;
			}
		}

		const found = foundRecordRE.exec(line);
		if (found) {
			const ip = found[1]!;
			const existing = sum.results.get(ip);
			const checkedAt = lineTime ?? existing?.checkedAt ?? new Date(0);
			const parsedMs = parseGoDuration(found[2]!);
			// rttMs only updates on a successfully-parsed duration (Go only
			// writes RTTByIP on parse success); checkedAt updates on every OK
			// occurrence regardless, mirroring seenAt in Go's SaveScan.
			sum.results.set(ip, {
				rttMs: parsedMs !== null ? Math.round(parsedMs) : (existing?.rttMs ?? 0),
				checkedAt,
			});
			continue;
		}

		const summary = summaryRE.exec(line);
		if (summary) {
			sum.scannedCount = parseInt(summary[1]!, 10) || 0;
			sum.foundCount = parseInt(summary[3]!, 10) || 0;
		}
	}

	return sum;
}

export interface FailRow {
	ip: string;
	reason: string;
	detail: string;
	checkedAt: Date;
}

// scanPassB walks the log a second time (a fresh stream over the same
// underlying compressed bytes -- see the module comment) collecting failure
// lines, calling isKnownGood per candidate IP (memoized by the caller) to
// decide whether to keep it, and invoking onFail for every kept row. onFail
// is expected to buffer/flush to D1 in bounded-size batches rather than
// accumulating every row in memory, since a long scan's log can carry a
// very large number of failure lines.
export async function scanPassB(
	lines: AsyncIterable<string>,
	tzOffsetMinutes: number,
	isKnownGood: (ip: string) => Promise<boolean>,
	onFail: (row: FailRow) => Promise<void>,
): Promise<void> {
	let lineTime: Date | null = null;

	for await (const line of lines) {
		const ts = logLineTS.exec(line);
		if (ts) {
			const t = parseLogTimestamp(ts[1]!, tzOffsetMinutes);
			if (t) lineTime = t;
		}

		const fail = failRecordRE.exec(line);
		if (!fail) continue;
		const ip = fail[1]!;
		if (!(await isKnownGood(ip))) continue; // never seen reachable -- not part of the tracked pool
		await onFail({
			ip,
			reason: fail[2] ?? "",
			detail: sanitizeNetErr((fail[3] ?? "").replace(/\r$/, "")),
			checkedAt: lineTime ?? new Date(0),
		});
	}
}

