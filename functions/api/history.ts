import { normalizeIPAddress } from "../../src/ipAddr";
import { CHECK_HISTORY_RETENTION, ipHistory, ipHistoryVersion } from "../../src/store";
import type { Env } from "../../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const url = new URL(context.request.url);
	const ip = normalizeIPAddress(url.searchParams.get("ip") ?? "");
	if (!ip) {
		return Response.json({ error: "invalid ip" }, { status: 400 });
	}

	const sinceParam = url.searchParams.get("since");
	const since = sinceParam === null ? null : Number(sinceParam);
	if (since !== null && (!Number.isSafeInteger(since) || since < 0)) {
		return Response.json({ error: "since must be a non-negative integer" }, { status: 400 });
	}

	const version = await ipHistoryVersion(context.env.DB, ip);
	if (since === version) {
		return Response.json({ version, checks: [] }, { headers: { "Cache-Control": "no-store" } });
	}
	const reset = since !== null && since > version;

	const cache = caches.default;
	const cacheURL = new URL("/api/history", url);
	cacheURL.searchParams.set("ip", ip);
	cacheURL.searchParams.set("schema", "1");
	cacheURL.searchParams.set("v", String(version));
	const cacheKey = new Request(cacheURL.toString(), context.request);
	const cached = reset ? undefined : await cache.match(cacheKey);
	if (cached) {
		const response = new Response(cached.body, cached);
		response.headers.set("Cache-Control", "no-store");
		return response;
	}

	const checks = await ipHistory(context.env.DB, ip, CHECK_HISTORY_RETENTION, 0);
	if ((await ipHistoryVersion(context.env.DB, ip)) !== version) {
		return Response.json({ retry: true }, { status: 503, headers: { "Cache-Control": "no-store" } });
	}

	const body = {
		version,
		reset,
		checks: checks.map((check) => ({
			ok: check.ok,
			rttMs: check.rttMs,
			reason: check.reason,
			detail: check.detail,
			checkedAt: check.checkedAt?.toISOString() ?? null,
			scanMode: check.scanMode,
		})),
	};
	if (reset) {
		return Response.json(body, { headers: { "Cache-Control": "no-store" } });
	}
	const response = Response.json(body, { headers: { "Cache-Control": "public, max-age=86400" } });
	context.waitUntil(cache.put(cacheKey, response.clone()));
	response.headers.set("Cache-Control", "no-store");
	return response;
};
