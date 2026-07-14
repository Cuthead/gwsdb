// Ports internal/web/server.go's three cache-first "look up live on a miss,
// then upsert" wrappers (resolveAndCachePTR, resolveAndCacheHost,
// lookupASN) plus isGoogleASN/conflictingLocations/clampTTL. Shared by
// functions/query.ts, functions/report.ts, and ptrRefresh.ts (PTR only --
// the latter never touches host_cache/asn_cache).
import { decode } from "./geo";
import { lookupASN, type ASNInfo } from "./asn";
import { lookupHost, lookupPTR } from "./resolver";
import { getASN, getHost, getPTR, saveASN, saveHost, savePTR } from "./store";
import type { ASNCacheEntry, HostCacheEntry, PTRCacheEntry } from "./types";

// minCacheTTLSeconds floors the DNS TTL observed on a DoH response before
// it's stored -- a 0/near-0 TTL is common for some providers (Team Cymru's
// whois TXT records in particular, and any failed/empty lookup) and taking
// it literally would force a fresh DoH round trip on nearly every request.
// Applies uniformly to PTR/host/ASN cache writes, not just no-result ones.
const MIN_CACHE_TTL_SECONDS = 60 * 60;

export function clampTTL(ttlSeconds: number): number {
	return Math.max(ttlSeconds, MIN_CACHE_TTL_SECONDS);
}

// conflictingLocations reports whether hostnames' matched, resolvable
// entries decode to more than one distinct city/country. A single IP with
// multiple PTRs normally agrees (an f-numeric and x-hex form of the same
// host); disagreement would mean Google published genuinely inconsistent
// PTRs for that IP, worth a log line even though decodeBest silently picks
// a deterministic winner.
function conflictingLocations(hostnames: string[]): boolean {
	let city = "";
	let country = "";
	for (const h of hostnames) {
		const loc = decode(h);
		if (!loc.matched || !loc.city) continue;
		if (!city) {
			city = loc.city;
			country = loc.country;
		} else if (loc.city !== city || loc.country !== country) {
			return true;
		}
	}
	return false;
}

// resolveAndCachePTR does a live PTR lookup for ip and upserts the result
// into ptr_cache, regardless of what's already cached. Shared by the
// on-demand /query lookup (cache miss) and ptrRefresh.ts.
export async function resolveAndCachePTR(
	db: D1Database,
	ip: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ hostnames: string[]; ok: boolean }> {
	const { hostnames, ttlSeconds, ok } = await lookupPTR(ip, timeoutMs, dohUrl);
	if (conflictingLocations(hostnames)) {
		console.warn(`ptr: ${ip} has PTR records disagreeing on location: ${hostnames.join(", ")}`);
	}
	const entry: PTRCacheEntry = {
		ip,
		ptrHostnames: hostnames,
		lookupOk: ok,
		ttlSeconds: clampTTL(ttlSeconds),
		checkedAt: new Date(),
	};
	try {
		await savePTR(db, entry);
	} catch (err) {
		console.error(`ptr: savePTR(${ip}):`, err);
	}
	return { hostnames, ok };
}

// resolveAndCacheHost does a live forward A/AAAA lookup for hostname and
// upserts the result into host_cache -- unless the lookup came back empty
// (failed, or no A/AAAA records), in which case nothing is cached. /query's
// hostname mode only requires the input end in ".1e100.net" (src/geo.ts's
// isHostname), not that it match a real naming pattern, so an arbitrary
// garbage hostname reaches this unauthenticated -- caching every miss would
// let anyone grow host_cache without bound. A repeat query for the same
// garbage hostname just re-resolves (no negative-result caching); that's a
// deliberate trade against RAM/rows, not an oversight.
export async function resolveAndCacheHost(
	db: D1Database,
	hostname: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ ipv4: string[]; ipv6: string[] }> {
	const { ipv4, ipv6, ttlSeconds, ok } = await lookupHost(hostname, timeoutMs, dohUrl);
	if (!ok || (ipv4.length === 0 && ipv6.length === 0)) return { ipv4, ipv6 };
	const entry: HostCacheEntry = { hostname, ipv4, ipv6, lookupOk: ok, ttlSeconds: clampTTL(ttlSeconds), checkedAt: new Date() };
	try {
		await saveHost(db, entry);
	} catch (err) {
		console.error(`host: saveHost(${hostname}):`, err);
	}
	return { ipv4, ipv6 };
}

// googleASNNameSubstr is matched case-insensitively against Team Cymru's AS
// name field (e.g. "GOOGLE, US", "GOOGLE-CLOUD-PLATFORM, US") to decide
// whether an IP belongs to Google.
const GOOGLE_ASN_NAME_SUBSTR = "GOOGLE";

export function isGoogleASN(info: ASNInfo): boolean {
	return info.asName.toUpperCase().includes(GOOGLE_ASN_NAME_SUBSTR);
}

// lookupGoogleASN resolves ip's announced prefix and AS, checking asn_cache
// first so repeat lookups don't re-trigger a Cymru DNS round trip. Only
// Google-ASN results are cached (mirrors Go's lookupASN exactly) -- a
// non-Google IP is looked up live every time, since the cache's only
// purpose is this gate check and there's nothing worth remembering about
// IPs that fail it.
export async function lookupGoogleASN(
	db: D1Database,
	ip: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ info: ASNInfo; ok: boolean }> {
	const cached = await getASN(db, ip);
	if (cached) {
		return { info: { asn: cached.asn, asName: cached.asName, prefix: cached.prefix, country: cached.country }, ok: cached.lookupOk };
	}

	const { info, ttlSeconds, ok } = await lookupASN(ip, timeoutMs, dohUrl);
	if (!ok || !isGoogleASN(info)) return { info, ok };

	const entry: ASNCacheEntry = { ip, ...info, lookupOk: ok, ttlSeconds: clampTTL(ttlSeconds), checkedAt: new Date() };
	try {
		await saveASN(db, entry);
	} catch (err) {
		console.error(`asn: saveASN(${ip}):`, err);
	}
	return { info, ok };
}
