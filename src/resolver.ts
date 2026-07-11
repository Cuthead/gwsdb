// Ports internal/resolver/resolver.go's LookupPTR/LookupHost/LookupTXT to
// the JSON-form DoH client in src/doh.ts (see that file's module comment
// for why). dohUrl is required throughout -- there's no system-resolver
// fallback, same as the Go original (the whole point is TTL visibility).
import { DNSType, queryDoH } from "./doh";

// dedupeSorted trims trailing dots, dedupes, and sorts names/addresses for
// deterministic output regardless of the order a resolver returned them in.
function dedupeSorted(names: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
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

// reverseNibblesDotted renders a 32-char hex string (as produced by
// expandIPv6) as dot-separated nibbles in reverse order -- the scheme both
// ip6.arpa PTR names and Team Cymru's origin6.asn.cymru.com queries use
// (see src/asn.ts's reverseNibbles).
export function reverseNibblesDotted(fullHex: string): string {
	const nibbles: string[] = [];
	for (let i = fullHex.length - 1; i >= 0; i--) nibbles.push(fullHex[i]!);
	return nibbles.join(".");
}

// reverseName builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6) query name
// for ip, the same name a PTR query would use over classic DNS.
function reverseName(ip: string): string {
	if (ip.includes(".") && !ip.includes(":")) {
		const parts = ip.split(".");
		if (parts.length !== 4) throw new Error(`invalid IP: ${ip}`);
		return `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
	}
	const full = expandIPv6(ip);
	if (!full) throw new Error(`invalid IP: ${ip}`);
	return `${reverseNibblesDotted(full)}.ip6.arpa`;
}

// expandIPv6 renders ip as 32 lowercase hex nibbles (no colons), or null if
// ip isn't a valid IPv6 address. Used by both reverseName and asn.ts's
// reverseNibbles (same expansion, different suffix/order requirements).
export function expandIPv6(ip: string): string | null {
	const withoutZone = ip.split("%")[0]!;
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
	const groups = dbl >= 0 ? [...headParts, ...Array(missing).fill("0"), ...tailParts] : headParts;
	if (groups.length !== 8) return null;
	let hex = "";
	for (const g of groups) {
		if (!/^[0-9a-fA-F]{0,4}$/.test(g)) return null;
		hex += g.padStart(4, "0").toLowerCase();
	}
	return hex;
}

// LookupPTR resolves every PTR record for ip, deduped and sorted for
// deterministic ordering, plus the minimum TTL across the matched records.
// ok is false with no thrown error when the record definitively does not
// exist (NXDOMAIN); a thrown error means the lookup failed transiently
// (timeout, HTTP error, malformed response) and says nothing about whether
// a PTR record exists.
export async function lookupPTR(
	ip: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ hostnames: string[]; ttlSeconds: number; ok: boolean }> {
	const name = reverseName(ip);
	const answers = await queryDoH(name, DNSType.PTR, timeoutMs, dohUrl);
	if (!answers) return { hostnames: [], ttlSeconds: 0, ok: false };

	let minSeconds = 0;
	const hostnames: string[] = [];
	for (const a of answers) {
		if (a.type !== DNSType.PTR) continue;
		const h = a.data.replace(/\.$/, "");
		if (h) {
			hostnames.push(h);
			if (minSeconds === 0 || a.TTL < minSeconds) minSeconds = a.TTL;
		}
	}
	if (hostnames.length === 0) return { hostnames: [], ttlSeconds: 0, ok: false };
	return { hostnames: dedupeSorted(hostnames), ttlSeconds: minSeconds, ok: true };
}

// LookupHost forward-resolves host's A and AAAA records, each deduped and
// sorted, plus the minimum TTL across every matched record. Both address
// lists are empty (ok=false) if the host has neither.
export async function lookupHost(
	host: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ ipv4: string[]; ipv6: string[]; ttlSeconds: number; ok: boolean }> {
	const [aAnswers, aaaaAnswers] = await Promise.all([
		queryDoH(host, DNSType.A, timeoutMs, dohUrl),
		queryDoH(host, DNSType.AAAA, timeoutMs, dohUrl),
	]);

	let minSeconds = 0;
	const observe = (ttl: number) => {
		if (minSeconds === 0 || ttl < minSeconds) minSeconds = ttl;
	};
	const ipv4: string[] = [];
	const ipv6: string[] = [];
	for (const a of aAnswers ?? []) {
		if (a.type === DNSType.A) {
			ipv4.push(a.data);
			observe(a.TTL);
		}
	}
	for (const a of aaaaAnswers ?? []) {
		if (a.type === DNSType.AAAA) {
			ipv6.push(a.data);
			observe(a.TTL);
		}
	}
	const dedupedV4 = dedupeSorted(ipv4);
	const dedupedV6 = dedupeSorted(ipv6);
	return { ipv4: dedupedV4, ipv6: dedupedV6, ttlSeconds: minSeconds, ok: dedupedV4.length + dedupedV6.length > 0 };
}

// unwrapTXT strips the double-quote wrapping JSON-form DoH puts around each
// TXT record character-string (possibly space-separated for multi-string
// records), concatenating them -- mirrors Go's strings.Join(txt.TXT, "").
function unwrapTXT(data: string): string {
	return data
		.split('" "')
		.join("")
		.replace(/^"|"$/g, "");
}

// LookupTXT resolves every TXT record for name, in answer order (not
// deduped -- unlike hostnames/addresses, repeated identical TXT strings can
// be meaningful), plus the minimum TTL across them.
export async function lookupTXT(
	name: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ txts: string[]; ttlSeconds: number; ok: boolean }> {
	const answers = await queryDoH(name, DNSType.TXT, timeoutMs, dohUrl);
	if (!answers) return { txts: [], ttlSeconds: 0, ok: false };

	let minSeconds = 0;
	const txts: string[] = [];
	for (const a of answers) {
		if (a.type !== DNSType.TXT) continue;
		txts.push(unwrapTXT(a.data));
		if (minSeconds === 0 || a.TTL < minSeconds) minSeconds = a.TTL;
	}
	if (txts.length === 0) return { txts: [], ttlSeconds: 0, ok: false };
	return { txts, ttlSeconds: minSeconds, ok: true };
}
