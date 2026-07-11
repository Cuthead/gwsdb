// Pages Function for GET /api/pool -- ports internal/web/server.go's
// handleAPIPool. Search, sort, filter, and pagination are all handled
// client-side by static/home.js over this payload, so it's fetched once,
// unfiltered, newest-first, and cached in the browser until
// /api/pool/version moves.
import { formatTime } from "../../src/html";
import { loadPool } from "../../src/pool";
import { poolVersion } from "../../src/store";
import type { Env } from "../../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const version = await poolVersion(context.env.DB);
	const { ips, scanMode, stats } = await loadPool(context.env.DB);

	const body = {
		version,
		ips,
		count: ips.length,
		scanMode,
		totalKnownIPs: stats.totalKnownIPs,
		totalScans: stats.totalScans,
		lastScanAt: formatTime(stats.lastScanAt),
	};
	return Response.json(body, { headers: { "Cache-Control": "no-store" } });
};
