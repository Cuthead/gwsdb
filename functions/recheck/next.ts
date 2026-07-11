// Pages Function for GET /recheck/next -- the China box's pull-model worker
// (gwsdb recheck -worker) polls this to find out what to probe next. Ports
// internal/store/queries.go's NextPendingRecheck + LatestScanConfig, called
// together since the caller needs both the target IP and the scan config to
// probe it with in one round trip.
import { checkBearerAuth } from "../../src/auth";
import { latestScanConfig, nextPendingRecheck } from "../../src/store";
import type { Env } from "../../src/env";

// DEFAULT_SCAN_MODE mirrors internal/recheck.DefaultScanMode -- the only
// scan mode CheckSNI currently knows how to probe.
const DEFAULT_SCAN_MODE = "SNI";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}

	const item = await nextPendingRecheck(env.DB);
	if (!item) {
		return new Response(null, { status: 204 });
	}

	const config = await latestScanConfig(env.DB, DEFAULT_SCAN_MODE);
	if (!config) {
		return new Response(`no ${DEFAULT_SCAN_MODE} scan on file yet`, { status: 503 });
	}

	return Response.json({
		id: item.id,
		ip: item.ip,
		scanMode: DEFAULT_SCAN_MODE,
		configScanId: config.scanId,
		configJson: config.configJSON,
	});
};
