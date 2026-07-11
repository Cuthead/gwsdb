// Pages Function for POST /recheck/result -- the China box's pull-model
// worker (gwsdb recheck -worker) submits a probe outcome here after fetching
// it from GET /recheck/next. Ports internal/web/recheck.go's
// processNextRecheck (minus the in-process loop/DNS-publish, which stays
// deferred): saves the ip_checks row, marks the queue entry processed, and
// prunes old processed entries -- all three happened on every tick of Go's
// original worker loop, so they happen on every submitted result here too.
import { checkBearerAuth } from "../../src/auth";
import { markRecheckProcessed, pruneRecheckQueue, saveRecheckResult } from "../../src/store";
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
	await markRecheckProcessed(env.DB, body.id, body.ok, checkedAt);
	await pruneRecheckQueue(env.DB, RECHECK_QUEUE_RETENTION_DAYS);

	return Response.json({});
};
