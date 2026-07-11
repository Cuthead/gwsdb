// Pages Function for POST /ingest -- file-based routing maps this file to
// that exact path (functions/ingest.ts -> /ingest). See src/logParser.ts's
// module comment for why ingest is a two-pass streaming read over the
// decompressed log rather than a single Response.text() call.
import { checkBearerAuth } from "../src/auth";
import { streamLines } from "../src/lineStream";
import { scanPassA, scanPassB } from "../src/logParser";
import { forMode, type GScannerConfig } from "../src/scanConfig";
import { type CheckRow, insertCheckRows, insertScan, isKnownGood } from "../src/store";
import type { Scan } from "../src/types";
import type { Env } from "../src/env";

const DEFAULT_FLUSH_SIZE = 500;

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;

	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}

	try {
		return await handleIngest(request, env);
	} catch (err) {
		console.error("ingest failed:", err);
		return new Response(`ingest failed: ${(err as Error).message}`, { status: 500 });
	}
};

async function handleIngest(request: Request, env: Env): Promise<Response> {
	const form = await request.formData();
	const configPart = form.get("config");
	const logPart = form.get("log");
	if (!(configPart instanceof File) || !(logPart instanceof File)) {
		return new Response("multipart form must include 'config' and 'log' file fields", { status: 400 });
	}

	let cfg: GScannerConfig;
	try {
		cfg = JSON.parse(await configPart.text());
	} catch (err) {
		return new Response(`invalid config JSON: ${(err as Error).message}`, { status: 400 });
	}

	const mode = cfg.ScanMode;
	if (!mode) return new Response("config's ScanMode is empty", { status: 400 });
	const sub = forMode(cfg, mode);
	if (!sub) return new Response(`unknown scan mode ${JSON.stringify(mode)}`, { status: 400 });
	if (mode.toUpperCase() === "SNI" && !sub.HTTPMethod) {
		// gscan_quic's testSni is the only mode that actually reads HTTPMethod;
		// it defaults to HEAD there too (gscan.go's loadConfig).
		sub.HTTPMethod = "HEAD";
	}

	const tzOffsetMinutes = parseInt(env.LOG_TZ_OFFSET_MINUTES ?? "480", 10);
	const openLogStream = () => logPart.stream().pipeThrough(new DecompressionStream("gzip"));

	const passA = await scanPassA(streamLines(openLogStream()), tzOffsetMinutes);

	const scan: Scan = {
		ScanMode: mode.toUpperCase(),
		ServerName: sub.ServerName.join(","),
		VerifyCommonName: sub.VerifyCommonName,
		HTTPPath: sub.HTTPPath,
		HTTPMethod: sub.HTTPMethod,
		HTTPVerifyHosts: sub.HTTPVerifyHosts.join(","),
		ValidStatusCode: sub.ValidStatusCode,
		InputFile: sub.InputFile,
		OutputFile: "", // log-only ingest: no output file in phase 1
		Level: sub.Level,
		ConfigJSON: JSON.stringify(sub),
		StartedAt: passA.startedAt,
		FinishedAt: passA.finishedAt,
		ScannedCount: passA.scannedCount,
		FoundCount: passA.foundCount || passA.results.size,
	};
	const scanId = await insertScan(env.DB, scan);

	const okRows: CheckRow[] = [];
	for (const [ip, r] of passA.results) {
		okRows.push({
			scanId,
			ip,
			ok: true,
			rttMs: r.rttMs || null,
			reason: null,
			detail: null,
			checkedAt: r.checkedAt,
			scanMode: scan.ScanMode,
		});
	}
	await insertCheckRows(env.DB, okRows);

	// Memoize known-good status per IP across pass B: seeded with every IP
	// this run just found OK, falling back to a D1 lookup (cached) for IPs
	// that only ever failed in this log but were reachable in a past scan.
	const knownGoodCache = new Map<string, boolean>();
	for (const ip of passA.results.keys()) knownGoodCache.set(ip, true);
	async function checkKnownGood(ip: string): Promise<boolean> {
		const cached = knownGoodCache.get(ip);
		if (cached !== undefined) return cached;
		const good = await isKnownGood(env.DB, ip);
		knownGoodCache.set(ip, good);
		return good;
	}

	let pending: CheckRow[] = [];
	await scanPassB(streamLines(openLogStream()), tzOffsetMinutes, checkKnownGood, async (row) => {
		pending.push({
			scanId,
			ip: row.ip,
			ok: false,
			rttMs: null,
			reason: row.reason || null,
			detail: row.detail || null,
			checkedAt: row.checkedAt,
			scanMode: scan.ScanMode,
		});
		if (pending.length >= DEFAULT_FLUSH_SIZE) {
			const toWrite = pending;
			pending = [];
			await insertCheckRows(env.DB, toWrite);
		}
	});
	if (pending.length > 0) await insertCheckRows(env.DB, pending);

	return Response.json({ scanId, scannedCount: scan.ScannedCount, foundCount: scan.FoundCount });
}
