// Pages Function for GET/POST /ingest -- file-based routing maps this file
// to that exact path (functions/ingest.ts -> /ingest). Log parsing now
// happens on the China box itself (internal/ingest/ingest.go's Parse, plus
// FilterChecks replicating the old known-good gate) -- this endpoint is
// just: GET returns the known-good IP set the box needs to pre-filter
// failures with, POST accepts the already-parsed/filtered scan and inserts
// it. No decompression, no regex, no streaming.
import { checkBearerAuth } from "../src/auth";
import { normalizeIPAddress } from "../src/ipAddr";
import { runPTRRefresh } from "../src/ptrRefresh";
import { syncPublish } from "../src/publish";
import { allKnownGoodIPs, type CheckRow, insertCheckRows, pruneCheckHistory, updatePoolBatch } from "../src/store";
import type { Env } from "../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}
	// No edge cache here, deliberately: the only caller is the scanner's
	// flusher, which fetches once per flush and then POSTs — bumping
	// poolVersion — so every subsequent GET sees a fresh version and a
	// version-keyed cache would never hit. The scanner instead keeps the
	// known-good set in memory and refreshes it hourly (see
	// internal/scan/flush.go), so this endpoint is only hit ~24x/day.
	const ips = await allKnownGoodIPs(env.DB);
	return Response.json({ ips });
};

// WireCheck mirrors internal/store's Go IPCheck struct (PascalCase, no json
// tags -- Go's encoding/json marshals field names as-is), so the China box
// can send its native type straight across without a parallel wire-format
// struct on the Go side.
interface WireCheck {
	IP: string;
	OK: boolean;
	RTTMs: number;
	Reason: string;
	Detail: string;
	CheckedAt: string;
	ScanMode: string;
}

interface IngestBody {
	checks: WireCheck[];
	maintenance?: boolean;
	pruneIPs?: string[];
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
	if (!Array.isArray(body.checks)) {
		return new Response("body must include 'checks'", { status: 400 });
	}
	if (body.pruneIPs !== undefined && (!Array.isArray(body.pruneIPs) || body.pruneIPs.some((ip) => typeof ip !== "string"))) {
		return new Response("pruneIPs must be an array of strings", { status: 400 });
	}
	if (body.checks.some((c) => !c || typeof c.IP !== "string" || normalizeIPAddress(c.IP) === null)) {
		return new Response("checks contain an invalid IP", { status: 400 });
	}
	const pruneIPs = body.pruneIPs?.map((ip) => normalizeIPAddress(ip));
	if (pruneIPs?.some((ip) => ip === null)) {
		return new Response("pruneIPs contain an invalid IP", { status: 400 });
	}

	const rows: CheckRow[] = body.checks.map((c) => ({
		ip: normalizeIPAddress(c.IP)!,
		ok: c.OK,
		rttMs: c.OK ? c.RTTMs || null : null,
		reason: c.Reason || null,
		detail: c.Detail || null,
		checkedAt: new Date(c.CheckedAt),
		scanMode: c.ScanMode,
	}));
	await insertCheckRows(env.DB, rows);
	await updatePoolBatch(env.DB, rows);

	const touchedIPs = [...new Set(rows.map((r) => r.ip))];
	const legacyPruneProtocol = body.pruneIPs === undefined;
	let pruneOk = true;
	if (legacyPruneProtocol) {
		// Old scanner binaries do not accumulate between micro-batches, so they
		// must retain the old per-request pruning behavior during rollout.
		waitUntil(pruneCheckHistory(env.DB, touchedIPs).catch((err) => console.error("ingest: prune:", err)));
	}

	// The scanner sends frequent micro-batches but requests these expensive
	// follow-up jobs only every ten minutes. Missing means true so old scanner
	// binaries retain their pre-micro-batch behavior during rollout.
	if (body.maintenance !== false) {
		if (!legacyPruneProtocol) {
			// Checks are already committed, so report prune failure separately;
			// scanner retries only the candidate set, not the accepted checks.
			try {
				await pruneCheckHistory(env.DB, [...new Set(pruneIPs as string[])]);
			} catch (err) {
				pruneOk = false;
				console.error("ingest: prune:", err);
			}
		}
		waitUntil(syncPublish(env, env.DB).catch((err) => console.error("ingest: publish:", err)));
		waitUntil(runPTRRefresh(env.DB).catch((err) => console.error("ingest: ptr-refresh:", err)));
	}

	return Response.json({ checks: rows.length, pruneOk });
}
