// Pages Function for GET /recheck/latest-scan-id -- gwsdb recheck -ip (ad-hoc
// mode) polls this so its submitted result's config_scan_id points at a
// real scans row, the same way the pull-model worker's item does (see
// functions/recheck/next.ts). Without this, ad-hoc submissions had
// config_scan_id NULL, which broke the query page's "Probe Request" column
// (ipHistory's LEFT JOIN scans ON s.id = COALESCE(scan_id, config_scan_id)
// matches nothing) even though the probe used the exact same config.
import { checkBearerAuth } from "../../src/auth";
import { latestScanConfig } from "../../src/store";
import type { Env } from "../../src/env";

// DEFAULT_SCAN_MODE mirrors internal/recheck.DefaultScanMode -- the only
// scan mode CheckSNI currently knows how to probe.
const DEFAULT_SCAN_MODE = "SNI";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}

	const config = await latestScanConfig(env.DB, DEFAULT_SCAN_MODE);
	return Response.json({ scanId: config?.scanId ?? null });
};
