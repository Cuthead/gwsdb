import { formatTime } from "../../../src/html";
import { loadPoolChanges } from "../../../src/pool";
import { poolResetVersion, poolVersion } from "../../../src/store";
import type { Env } from "../../../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const url = new URL(context.request.url);
	const since = Number(url.searchParams.get("since"));
	if (!Number.isSafeInteger(since) || since < 0) {
		return Response.json({ error: "since must be a non-negative integer" }, { status: 400 });
	}

	const version = await poolVersion(context.env.DB);
	if (since > version) {
		return Response.json({ reset: true, version }, { headers: { "Cache-Control": "no-store" } });
	}
	if (since < (await poolResetVersion(context.env.DB))) {
		return Response.json({ reset: true, version }, { headers: { "Cache-Control": "no-store" } });
	}
	if (since === version) {
		return Response.json({ version, ips: [] }, { headers: { "Cache-Control": "no-store" } });
	}

	const cache = caches.default;
	const cacheURL = new URL(context.request.url);
	cacheURL.searchParams.set("since", String(since));
	cacheURL.searchParams.set("v", String(version));
	const cacheKey = new Request(cacheURL.toString(), context.request);
	const cached = await cache.match(cacheKey);
	if (cached) {
		const response = new Response(cached.body, cached);
		response.headers.set("Cache-Control", "no-store");
		return response;
	}

	const { ips, scanMode, stats } = await loadPoolChanges(context.env.DB, since, version);
	// A writer may commit between the version read and payload queries. Do not
	// cache mixed-version rows/stats; the client keeps its existing snapshot
	// and retries on its next load.
	if ((await poolVersion(context.env.DB)) !== version) {
		return Response.json({ retry: true }, { status: 503, headers: { "Cache-Control": "no-store" } });
	}
	const apiIPs = ips.map(({ country: _country, countryCode: _countryCode, ...rest }) => rest);
	const body = {
		version,
		ips: apiIPs,
		scanMode,
		totalKnownIPs: stats.totalKnownIPs,
		totalChecks: stats.totalChecks,
		lastCheckAt: formatTime(stats.lastCheckAt),
	};
	const response = Response.json(body, { headers: { "Cache-Control": "public, max-age=86400" } });
	context.waitUntil(cache.put(cacheKey, response.clone()));
	response.headers.set("Cache-Control", "no-store");
	return response;
};
