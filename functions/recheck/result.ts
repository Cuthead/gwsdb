// Pages Function for POST /recheck/result -- the China box's pull-model
// worker (gwsdb recheck -worker) submits a probe outcome here after fetching
// it from GET /recheck/next. Ports internal/web/recheck.go's (now-deleted)
// processNextRecheck: saves the ip_checks row, marks the queue entry
// processed, prunes old processed entries, and reconciles published DNS
// records -- all four happened on every tick of Go's original worker loop,
// so they happen on every submitted result here too.
import { checkBearerAuth } from "../../src/auth";
import { syncPublish } from "../../src/publish";
import { markRecheckProcessed, pruneRecheckQueue, refreshPoolForIPs, saveRecheckResult } from "../../src/store";
import type { Env } from "../../src/env";

// RECHECK_QUEUE_RETENTION_DAYS mirrors internal/web/recheck.go's
// recheckQueueRetention (30 days) -- how long a processed recheck_queue row
// is kept around for debugging/audit before being pruned.
const RECHECK_QUEUE_RETENTION_DAYS = 30;

interface ResultBody {
	id: number;
	ip: string;
	ok: boolean;
	rttMs: number | null;
	reason: string | null;
	detail: string | null;
	scanMode: string;
	configScanId: number | null;
	checkedAt: string;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}

	let body: ResultBody;
	try {
		body = await request.json();
	} catch {
		return new Response("invalid JSON body", { status: 400 });
	}
	if (!body.ip || typeof body.id !== "number" || typeof body.ok !== "boolean" || !body.checkedAt) {
		return new Response("missing required fields", { status: 400 });
	}

	const checkedAt = new Date(body.checkedAt);
	if (Number.isNaN(checkedAt.getTime())) {
		return new Response("invalid checkedAt", { status: 400 });
	}

	await saveRecheckResult(env.DB, {
		ip: body.ip,
		ok: body.ok,
		rttMs: body.rttMs ?? null,
		reason: body.reason ?? null,
		detail: body.detail ?? null,
		checkedAt,
		scanMode: body.scanMode,
		configScanId: body.configScanId ?? null,
	});
	await refreshPoolForIPs(env.DB, [body.ip]);
	await markRecheckProcessed(env.DB, body.id, body.ok, checkedAt);
	await pruneRecheckQueue(env.DB, RECHECK_QUEUE_RETENTION_DAYS);

	// A recheck just changed this IP's status, so the top set may have
	// shifted. Reconcile after responding so a slow Cloudflare API call
	// doesn't add latency to the China box's submit round trip; publish
	// failure doesn't fail the recheck -- the result is already saved.
	context.waitUntil(syncPublish(env, env.DB).catch((err) => console.error("recheck: publish:", err)));

	return Response.json({});
};
