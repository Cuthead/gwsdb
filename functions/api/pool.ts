// Pages Function for GET /api/pool -- ports internal/web/server.go's
// handleAPIPool. Search, sort, filter, and pagination are normally handled
// client-side by static/home.js over this payload; ?family=4|6 restricts the
// payload for scanner rechecks. It supplies the initial IndexedDB snapshot;
// later visits merge /api/pool/changes responses.
import { formatTime } from "../../src/html";
import { loadPool } from "../../src/pool";
import { poolVersion } from "../../src/store";
import type { Env } from "../../src/env";

// version is baked into the cache key (not just the response body) so this
// edge cache and the browser's IndexedDB snapshot use the same revision
// signal. Populated lazily per colo --
// the first request after a version bump in each colo still pays the D1
// read, every later request/colo hits the edge cache instead.
export const onRequestGet: PagesFunction<Env> = async (context) => {
	const familyParam = new URL(context.request.url).searchParams.get("family");
	const family = familyParam === "4" || familyParam === "6" ? Number(familyParam) : undefined;
	const version = await poolVersion(context.env.DB);

	const cache = caches.default;
	const cacheURL = new URL(context.request.url);
	cacheURL.searchParams.set("schema", "2");
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

	const { ips, scanMode, stats } = await loadPool(context.env.DB, { family });
	if ((await poolVersion(context.env.DB)) !== version) {
		return Response.json({ error: "pool changed while loading" }, { status: 503, headers: { "Cache-Control": "no-store" } });
	}

	// country/countryCode are dropped here -- the browser decodes ptrList
	// itself (see public/static/home.js + geo.js), so shipping the
	// server's precomputed copy would just be redundant bytes. The
	// server-rendered crawler path (functions/index.ts) still uses the
	// full IPRow with country attached, since it has no client-side JS
	// to decode with.
	const apiIPs = ips.map(({ country: _country, countryCode: _countryCode, ...rest }) => rest);

	const body = {
		version,
		ips: apiIPs,
		count: apiIPs.length,
		scanMode,
		totalKnownIPs: stats.totalKnownIPs,
		totalChecks: stats.totalChecks,
		lastCheckAt: formatTime(stats.lastCheckAt),
	};
	// max-age just bounds how long this colo holds the entry -- correctness
	// doesn't depend on it, since a version bump already changes cacheKey.
	const response = Response.json(body, { headers: { "Cache-Control": "public, max-age=86400" } });
	context.waitUntil(cache.put(cacheKey, response.clone()));
	response.headers.set("Cache-Control", "no-store");
	return response;
};
