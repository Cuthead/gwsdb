// Pages Function for GET /api/pool -- ports internal/web/server.go's
// handleAPIPool. Search, sort, filter, and pagination are all handled
// client-side by static/home.js over this payload, so it's fetched once,
// unfiltered, newest-first, and cached in the browser until
// /api/pool/version moves.
import { formatTime } from "../../src/html";
import { loadPool } from "../../src/pool";
import { poolVersion } from "../../src/store";
import type { Env } from "../../src/env";

// version is baked into the cache key (not just the response body) so this
// edge cache and the browser's localStorage cache (home.js) invalidate on
// exactly the same signal: a version bump makes both look like a miss,
// nothing in between requires manual purging. Populated lazily per colo --
// the first request after a version bump in each colo still pays the D1
// read, every later request/colo hits the edge cache instead.
export const onRequestGet: PagesFunction<Env> = async (context) => {
	const version = await poolVersion(context.env.DB);

	const cache = caches.default;
	const cacheURL = new URL(context.request.url);
	cacheURL.searchParams.set("v", String(version));
	const cacheKey = new Request(cacheURL.toString(), context.request);

	// cache.match/put need Cache-Control: public + max-age to actually store
	// the entry, but that same header on the response we hand back to the
	// browser would let fetch()'s own HTTP cache keep it under the literal
	// (unversioned) /api/pool URL -- silently serving stale data past a
	// version bump, bypassing home.js's version check entirely. So the
	// header is only ever set on the copy that goes into cache.put; what
	// reaches the client (hit or miss) is always no-store.
	const cached = await cache.match(cacheKey);
	if (cached) {
		const resp = new Response(cached.body, cached);
		resp.headers.set("Cache-Control", "no-store");
		return resp;
	}

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
	// max-age just bounds how long this colo holds the entry -- correctness
	// doesn't depend on it, since a version bump already changes cacheKey.
	const response = Response.json(body, { headers: { "Cache-Control": "public, max-age=86400" } });
	context.waitUntil(cache.put(cacheKey, response.clone()));
	response.headers.set("Cache-Control", "no-store");
	return response;
};
