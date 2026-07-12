// @license magnet:?xt=urn:btih:1f739d935676111cfff4b4693e3816e664797050&dn=gpl-3.0.txt GPL-3.0

// Client-side PTR resolution for IPs the server hasn't cached yet (fresh
// ingest, cron-ptr-refresh hasn't caught up). home.js calls resolvePTR for
// any pool row with an empty ptrList; this does the reverse-DNS lookup
// itself via Cloudflare's DoH JSON API (dns.google would work the same way,
// but every visitor's browser would be leaking its IP + query pattern to
// Google specifically -- cloudflare-dns.com doesn't add a new party, Pages
// already puts the visitor's IP in front of Cloudflare). Results (both hits
// and misses) are cached in localStorage with a TTL floor, mirroring
// src/dnsCache.ts's clampTTL -- a genuinely PTR-less IP costs one lookup per
// TTL window, not one per page load.
//
// reverseName/expandIPv6/dedupeSorted below port src/resolver.ts's
// same-named functions; kept in sync by hand since this runs in the browser
// and that file runs in the Pages Function worker.

const DOH_URL = "https://cloudflare-dns.com/dns-query";
const CACHE_KEY = "gwsdb_ptr_client_v1";
const MIN_TTL_SECONDS = 60 * 60;
const CONCURRENCY = 24;

function dedupeSorted(names) {
	const seen = new Set();
	const out = [];
	for (const raw of names) {
		const n = raw.replace(/\.$/, "");
		if (n && !seen.has(n)) {
			seen.add(n);
			out.push(n);
		}
	}
	out.sort();
	return out;
}

function expandIPv6(ip) {
	const withoutZone = ip.split("%")[0];
	let head = withoutZone;
	let tail = "";
	const dbl = withoutZone.indexOf("::");
	if (dbl >= 0) {
		head = withoutZone.slice(0, dbl);
		tail = withoutZone.slice(dbl + 2);
	}
	const headParts = head ? head.split(":") : [];
	const tailParts = tail ? tail.split(":") : [];
	if (dbl < 0 && headParts.length !== 8) return null;
	if (dbl >= 0 && headParts.length + tailParts.length >= 8) return null;
	const missing = 8 - headParts.length - tailParts.length;
	const groups = dbl >= 0 ? headParts.concat(Array(missing).fill("0"), tailParts) : headParts;
	if (groups.length !== 8) return null;
	let hex = "";
	for (const g of groups) {
		if (!/^[0-9a-fA-F]{0,4}$/.test(g)) return null;
		hex += g.padStart(4, "0").toLowerCase();
	}
	return hex;
}

function reverseNibblesDotted(fullHex) {
	const nibbles = [];
	for (let i = fullHex.length - 1; i >= 0; i--) nibbles.push(fullHex[i]);
	return nibbles.join(".");
}

function reverseName(ip) {
	if (ip.indexOf(".") !== -1 && ip.indexOf(":") === -1) {
		const parts = ip.split(".");
		if (parts.length !== 4) return null;
		return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
	}
	const full = expandIPv6(ip);
	if (!full) return null;
	return reverseNibblesDotted(full) + ".ip6.arpa";
}

let memCache = null;
function loadCache() {
	if (memCache) return memCache;
	try {
		const raw = localStorage.getItem(CACHE_KEY);
		memCache = raw ? JSON.parse(raw) : {};
	} catch (e) {
		memCache = {};
	}
	return memCache;
}

let writeScheduled = false;
function scheduleWrite() {
	if (writeScheduled) return;
	writeScheduled = true;
	setTimeout(function () {
		writeScheduled = false;
		try {
			const cache = loadCache();
			const t = Date.now();
			const pruned = {};
			for (const ip in cache) {
				if (cache[ip].exp > t) pruned[ip] = cache[ip];
			}
			memCache = pruned;
			localStorage.setItem(CACHE_KEY, JSON.stringify(pruned));
		} catch (e) {
			// Storage full or unavailable -- next page load just re-resolves.
		}
	}, 500);
}

function queryDoH(name) {
	const url = DOH_URL + "?name=" + encodeURIComponent(name) + "&type=PTR";
	return fetch(url, { headers: { accept: "application/dns-json" } }).then(function (resp) {
		if (!resp.ok) throw new Error("doh status " + resp.status);
		return resp.json();
	});
}

function resolveLive(ip) {
	const name = reverseName(ip);
	if (!name) return Promise.resolve({ hostnames: [], ok: false, ttlSeconds: 0 });
	return queryDoH(name)
		.then(function (json) {
			const hostnames = [];
			let minSeconds = 0;
			(json.Answer || []).forEach(function (a) {
				if (a.type !== 12) return; // PTR
				const h = String(a.data || "").replace(/\.$/, "");
				if (h) {
					hostnames.push(h);
					if (minSeconds === 0 || a.TTL < minSeconds) minSeconds = a.TTL;
				}
			});
			const deduped = dedupeSorted(hostnames);
			return { hostnames: deduped, ok: deduped.length > 0, ttlSeconds: minSeconds };
		})
		.catch(function () {
			return { hostnames: [], ok: false, ttlSeconds: 0 };
		});
}

let active = 0;
const queue = [];

function startJob(item) {
	active++;
	resolveLive(item.ip).then(function (result) {
		active--;
		const cache = loadCache();
		cache[item.ip] = {
			hostnames: result.hostnames,
			ok: result.ok,
			exp: Date.now() + Math.max(result.ttlSeconds, MIN_TTL_SECONDS) * 1000,
		};
		scheduleWrite();
		item.resolve({ hostnames: result.hostnames, ok: result.ok });
		pump();
	});
}

function pump() {
	while (active < CONCURRENCY && queue.length > 0) {
		startJob(queue.shift());
	}
}

// resolvePTR looks up ip's PTR hostnames, live via DoH on a cache miss
// (queued/capped at CONCURRENCY in-flight requests -- a bulk ingest can
// dump hundreds of unresolved IPs on the page at once). Never rejects: a
// failed/negative lookup resolves to {hostnames: [], ok: false}, which the
// caller (home.js) treats the same as "still unknown".
export function resolvePTR(ip) {
	const cached = loadCache()[ip];
	if (cached && cached.exp > Date.now()) {
		return Promise.resolve({ hostnames: cached.hostnames, ok: cached.ok });
	}
	return new Promise(function (resolve) {
		queue.push({ ip: ip, resolve: resolve });
		pump();
	});
}
// @license-end
