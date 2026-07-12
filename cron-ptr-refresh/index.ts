// Separate small Workers project (own wrangler.jsonc, same D1 database as
// the gwsdb Pages project) running a Cron Trigger -- ports
// internal/web/server.go's StartPTRRefresher. Pages Functions have no
// scheduled-execution primitive, so this can't live in the Pages project
// itself. Runs once a day (see wrangler.jsonc), refreshing every IP due for
// a round-robin PTR check in a single invocation over one pipelined
// DNS-over-TCP connection -- see src/store.ts's pendingIPsForPTRRefresh and
// migration 0005 for the round-robin scheduling this replaced TTL-staleness
// with, and src/dnsWire.ts for the wire format this speaks.
//
// Why TCP sockets instead of the JSON-form DoH fetch() used everywhere else
// in gwsdb: each fetch() is its own subrequest, capping how many IPs one
// invocation could refresh well under the old 50-subrequests-per-invocation
// wall (see git history for the MAX_REFRESHED_PER_RUN=20 this replaced). A
// single pipelined TCP connection is 1 subrequest regardless of how many
// PTR queries ride it.
//
// Resolver is ns1.google.com, not a public recursive resolver -- two
// reasons, found the hard way. First, Cloudflare blocks outbound TCP
// sockets to Cloudflare's own IP ranges, which rules out 1.1.1.1 entirely
// (worked in every local/dev test, since that restriction is
// production-only; failed instantly in production with no useful error).
// Second, ip_pool is Google-owned address space end to end (see
// isGoogleASN's gate in src/dnsCache.ts) -- ns1.google.com is authoritative
// for its reverse zones, so it answers directly with no recursion, and
// unlike a recursive resolver it has no reason to throttle/reset a large
// pipelined burst from one client. Benchmarked against the full real
// ip_pool (5,035 IPs, 98% IPv6): 100% answered in ~2.5s, rcodes only
// NOERROR/NXDOMAIN (every current pool IP is in Google's authority) --
// far faster than 1.1.1.1 ever was and well inside the 15-minute Cron
// Trigger wall-clock cap. An IP outside Google's authority would come back
// REFUSED and just be skipped (see the rcode filter below) -- acceptable
// since the pool is ASN-gated to Google space by construction.
import { connect } from "cloudflare:sockets";
import { buildPTRQuery, parseMessage } from "../src/dnsWire";
import { dedupeSorted } from "../src/resolver";
import { pendingIPsForPTRRefresh, savePTRBatch } from "../src/store";
import type { PTRCacheEntry } from "../src/types";

interface Env {
	DB: D1Database;
}

const RESOLVER = { hostname: "ns1.google.com", port: 53 };
// Caps one invocation's batch to the 16-bit DNS transaction ID space (each
// in-flight query on the connection needs a unique id to match its
// response). Comfortably above ip_pool's current size with room to grow;
// pendingIPsForPTRRefresh simply returns fewer if the pool is smaller.
const BATCH_LIMIT = 10000;
// ~48x the measured wall time for the full 5,035-IP pool against
// ns1.google.com (~2.5s, see module comment) -- generous margin while
// staying well under the 15-minute Cron Trigger cap.
const READ_TIMEOUT_MS = 120_000;
// Same floor src/dnsCache.ts's clampTTL uses -- kept in sync manually since
// this path doesn't go through resolveAndCachePTR (see that function for
// why a near-zero TTL isn't taken literally).
const MIN_CACHE_TTL_SECONDS = 60 * 60;

// pipelinePTRQueries opens one TCP connection to RESOLVER, writes a PTR
// query for every ip in ips back-to-back (pipelined, not one-at-a-time),
// and reads responses off the same connection until every query has been
// answered or readTimeoutMs elapses. IPs with no response by the deadline
// (dropped packet, resolver hiccup, or just not enough time) are simply
// absent from the result map -- pendingIPsForPTRRefresh's round-robin
// ordering means an unanswered IP just gets tried again on the next daily
// run, no separate retry bookkeeping needed.
async function pipelinePTRQueries(ips: string[], readTimeoutMs: number): Promise<Map<string, { rcode: number; hostnames: string[]; ttlSeconds: number }>> {
	const idToIP = new Map<number, string>();
	ips.forEach((ip, i) => idToIP.set(i + 1, ip));

	const socket = connect(RESOLVER);
	const results = new Map<string, { rcode: number; hostnames: string[]; ttlSeconds: number }>();

	const writer = socket.writable.getWriter();
	try {
		for (const [id, ip] of idToIP) {
			await writer.write(buildPTRQuery(id, ip));
		}
	} finally {
		writer.releaseLock();
	}

	const reader = socket.readable.getReader();
	let recvBuf = new Uint8Array(0);
	const deadline = Date.now() + readTimeoutMs;
	try {
		while (idToIP.size > results.size && Date.now() < deadline) {
			const remaining = deadline - Date.now();
			const { value, done } = await Promise.race([
				reader.read(),
				new Promise<{ value: undefined; done: true }>((resolve) => setTimeout(() => resolve({ value: undefined, done: true }), remaining)),
			]);
			if (done || !value) break;

			const merged = new Uint8Array(recvBuf.length + value.length);
			merged.set(recvBuf);
			merged.set(value, recvBuf.length);
			recvBuf = merged;

			while (recvBuf.length >= 2) {
				const msgLen = new DataView(recvBuf.buffer, recvBuf.byteOffset, recvBuf.byteLength).getUint16(0);
				if (recvBuf.length < 2 + msgLen) break;
				const msg = recvBuf.subarray(2, 2 + msgLen);
				recvBuf = recvBuf.subarray(2 + msgLen);
				try {
					const parsed = parseMessage(msg);
					const ip = idToIP.get(parsed.id);
					if (!ip) continue; // stray/duplicate id, ignore
					const hostnames = dedupeSorted(parsed.answers.filter((a) => a.type === 12).map((a) => a.data.replace(/\.$/, "")));
					const minTTL = parsed.answers.reduce((min, a) => (min === 0 || a.ttl < min ? a.ttl : min), 0);
					results.set(ip, { rcode: parsed.rcode, hostnames, ttlSeconds: minTTL });
				} catch (err) {
					console.error("ptr-refresh: malformed DNS response, skipping:", err);
				}
			}
		}
	} finally {
		reader.releaseLock();
		await socket.close().catch(() => {});
	}

	return results;
}

export default {
	async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
		const ips = await pendingIPsForPTRRefresh(env.DB, BATCH_LIMIT);
		if (ips.length === 0) {
			console.log("ptr-refresh: nothing due");
			return;
		}

		const results = await pipelinePTRQueries(ips, READ_TIMEOUT_MS);
		const checkedAt = new Date();
		const entries: PTRCacheEntry[] = [];
		for (const [ip, r] of results) {
			// rcode 0 (NOERROR) or 3 (NXDOMAIN) are both definitive answers --
			// NXDOMAIN just means "no PTR records", same as a NOERROR/no-answer
			// response (mirrors src/doh.ts's queryDoH: null-vs-thrown, not
			// present-vs-absent). Any other rcode (SERVFAIL, REFUSED, ...) is a
			// transient failure -- leave it out so it isn't wrongly marked
			// checked and gets retried on the next run.
			if (r.rcode !== 0 && r.rcode !== 3) continue;
			entries.push({
				ip,
				ptrHostnames: r.hostnames,
				lookupOk: r.hostnames.length > 0,
				ttlSeconds: Math.max(r.ttlSeconds, MIN_CACHE_TTL_SECONDS),
				checkedAt,
			});
		}

		await savePTRBatch(env.DB, entries);
		console.log(`ptr-refresh: queried ${ips.length}, answered ${results.size}, cached ${entries.length}`);
	},
} satisfies ExportedHandler<Env>;
