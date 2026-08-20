// Pages Function for POST /check -- the query page's on-demand probe button.
// Calls the gwsdb-probe Worker (worker/) via the PROBE_PROXY service binding,
// which VPC-fetches the China box's probe server over Cloudflare Mesh.
// Writes the result to ip_checks via saveRecheckResult and returns it to the
// caller. Rate-limited per client IP. Replaces the old report ->
// recheck_queue -> pull-worker chain with one synchronous round trip — no
// queue, no random delay.
import { isGoogleASN, lookupGoogleASN } from "../src/dnsCache";
import { normalizeIPAddress } from "../src/ipAddr";
import { clientCountry } from "../src/request";
import { checkRateLimit, saveRecheckResult, updatePoolForCheck } from "../src/store";
import { syncPublish } from "../src/publish";
import type { ASNInfo } from "../src/asn";
import type { Env } from "../src/env";

const ASN_TIMEOUT_MS = 3000;
const PROBE_TIMEOUT_MS = 15_000;
const RATE_LIMIT_PER_MINUTE = 10;
const DEFAULT_SCAN_MODE = "SNI";

interface ProbeResponse {
	ok: boolean;
	rttMs: number;
	reason: string;
	detail: string;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;

	// CN-only, same gate the old report page had -- the probe runs from
	// China-based infrastructure and is meaningless for anyone elsewhere.
	if (clientCountry(request) !== "CN") {
		return Response.json({ error: "forbidden" }, { status: 403 });
	}

	const ip = normalizeIPAddress(new URL(request.url).searchParams.get("ip") ?? "");
	if (!ip) {
		return Response.json({ error: "invalid ip" }, { status: 400 });
	}

	const cip = request.headers.get("CF-Connecting-IP") ?? "";
	if (!cip) {
		return Response.json({ error: "could not determine client ip" }, { status: 400 });
	}
	const allowed = await checkRateLimit(env.DB, cip, RATE_LIMIT_PER_MINUTE);
	if (!allowed) {
		return Response.json({ error: "rate limit exceeded, try again later" }, { status: 429 });
	}

	// ASN gate -- only probe Google IPs (same as the query page's lookup).
	let asn: { info: ASNInfo; ok: boolean };
	try {
		asn = await lookupGoogleASN(env.DB, ip, ASN_TIMEOUT_MS, env.DOH_JSON_URL);
	} catch (err) {
		console.warn(`check: ASN lookup ${ip}:`, err);
		return Response.json({ error: "could not verify this IP's ASN right now" }, { status: 503 });
	}
	if (!asn.ok || !isGoogleASN(asn.info)) {
		return Response.json({ error: "this IP does not belong to a Google ASN" }, { status: 400 });
	}

	// Call the gwsdb-probe Worker via service binding — it VPC-fetches the
	// China box's probe server over Cloudflare Mesh. PROBE_TOKEN
	// authenticates both hops (Pages -> Worker, Worker -> probe server).
	let result: ProbeResponse;
	try {
		const resp = await env.PROBE_PROXY.fetch("https://probe.local/probe", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Probe-Token": env.PROBE_TOKEN,
			},
			body: JSON.stringify({ ip }),
			signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
		});
		if (!resp.ok) {
			console.warn(`check: probe worker ${resp.status}`);
			return Response.json({ error: "probe server error" }, { status: 502 });
		}
		result = (await resp.json()) as ProbeResponse;
	} catch (err) {
		console.warn(`check: probe call:`, err);
		return Response.json({ error: "could not reach the probe server" }, { status: 504 });
	}

	const checkedAt = new Date();
	await saveRecheckResult(env.DB, {
		ip,
		ok: result.ok,
		rttMs: result.rttMs ?? null,
		reason: result.reason ?? null,
		detail: result.detail ?? null,
		checkedAt,
		scanMode: DEFAULT_SCAN_MODE,
	});
	await updatePoolForCheck(env.DB, ip, result.ok, result.rttMs ?? null, checkedAt, DEFAULT_SCAN_MODE);

	// A probe just changed this IP's status, so the top set may have
	// shifted. Reconcile after responding so a slow publish doesn't add
	// latency to the user's probe round trip.
	context.waitUntil(syncPublish(env, env.DB).catch((err) => console.error("check: publish:", err)));

	return Response.json(result);
};
