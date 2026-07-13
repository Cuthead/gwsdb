// Pages Function for GET/POST /ingest -- file-based routing maps this file
// to that exact path (functions/ingest.ts -> /ingest). Log parsing now
// happens on the China box itself (internal/ingest/ingest.go's Parse, plus
// FilterChecks replicating the old known-good gate) -- this endpoint is
// just: GET returns the known-good IP set the box needs to pre-filter
// failures with, POST accepts the already-parsed/filtered scan and inserts
// it. No decompression, no regex, no streaming.
import { checkBearerAuth } from "../src/auth";
import { triggerPTRRefresh } from "../src/ptrRefreshTrigger";
import { syncPublish } from "../src/publish";
import { allKnownGoodIPs, type CheckRow, insertCheckRows, insertScan, refreshPoolForIPs } from "../src/store";
import type { Scan } from "../src/types";
import type { Env } from "../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}
	const ips = await allKnownGoodIPs(env.DB);
	return Response.json({ ips });
};

// WireScan/WireCheck mirror internal/store's Go Scan/IPCheck structs
// (PascalCase, no json tags -- Go's encoding/json marshals field names
// as-is), so the China box can send its native types straight across
// without a parallel wire-format struct on the Go side.
interface WireScan {
	ScanMode: string;
	ServerName: string;
	VerifyCommonName: string;
	HTTPPath: string;
	HTTPMethod: string;
	HTTPVerifyHosts: string;
	ValidStatusCode: number;
	InputFile: string;
	OutputFile: string;
	Level: number;
	ConfigJSON: string;
	StartedAt: string | null;
	FinishedAt: string | null;
	ScannedCount: number;
	FoundCount: number;
}

interface WireCheck {
	IP: string;
	OK: boolean;
	RTTMs: number;
	Reason: string;
	Detail: string;
	CheckedAt: string;
}

interface IngestBody {
	scan: WireScan;
	checks: WireCheck[];
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}

	try {
		return await handleIngest(request, env, context.waitUntil.bind(context));
	} catch (err) {
		console.error("ingest failed:", err);
		return new Response(`ingest failed: ${(err as Error).message}`, { status: 500 });
	}
};

async function handleIngest(request: Request, env: Env, waitUntil: (promise: Promise<unknown>) => void): Promise<Response> {
	let body: IngestBody;
	try {
		body = await request.json();
	} catch (err) {
		return new Response(`invalid JSON body: ${(err as Error).message}`, { status: 400 });
	}
	if (!body.scan || !Array.isArray(body.checks)) {
		return new Response("body must include 'scan' and 'checks'", { status: 400 });
	}

	const scan: Scan = {
		ScanMode: body.scan.ScanMode,
		ServerName: body.scan.ServerName,
		VerifyCommonName: body.scan.VerifyCommonName,
		HTTPPath: body.scan.HTTPPath,
		HTTPMethod: body.scan.HTTPMethod,
		HTTPVerifyHosts: body.scan.HTTPVerifyHosts,
		ValidStatusCode: body.scan.ValidStatusCode,
		InputFile: body.scan.InputFile,
		OutputFile: body.scan.OutputFile,
		Level: body.scan.Level,
		ConfigJSON: body.scan.ConfigJSON,
		StartedAt: body.scan.StartedAt ? new Date(body.scan.StartedAt) : null,
		FinishedAt: body.scan.FinishedAt ? new Date(body.scan.FinishedAt) : null,
		ScannedCount: body.scan.ScannedCount,
		FoundCount: body.scan.FoundCount,
	};
	const scanId = await insertScan(env.DB, scan);

	const rows: CheckRow[] = body.checks.map((c) => ({
		scanId,
		ip: c.IP,
		ok: c.OK,
		rttMs: c.OK ? c.RTTMs || null : null,
		reason: c.OK ? null : c.Reason || null,
		detail: c.OK ? null : c.Detail || null,
		checkedAt: new Date(c.CheckedAt),
		scanMode: scan.ScanMode,
	}));
	await insertCheckRows(env.DB, rows);

	// Tracks every IP this run wrote an ip_checks row for, so ip_pool only
	// gets recomputed for the IPs that could have actually changed -- see
	// refreshPoolForIPs's module comment.
	await refreshPoolForIPs(env.DB, [...new Set(rows.map((r) => r.ip))]);

	// A bulk ingest can shift the top set a lot; reconcile published DNS
	// records after responding so a slow Cloudflare API call doesn't add
	// latency to the China box's ingest round trip. Publish failure doesn't
	// fail the ingest -- the scan is already saved.
	waitUntil(syncPublish(env, env.DB).catch((err) => console.error("ingest: publish:", err)));

	// Newly-discovered IPs (ptr_checked_at NULL) would otherwise sit with no
	// PTR/country until cron-ptr-refresh's next run -- ask it to refresh now
	// instead. Same waitUntil/non-fatal treatment as publish above.
	waitUntil(triggerPTRRefresh(env).catch((err) => console.error("ingest: ptr-refresh trigger:", err)));

	return Response.json({ scanId, scannedCount: scan.ScannedCount, foundCount: scan.FoundCount });
}
