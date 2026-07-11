// Ports internal/asn/asn.go: resolves an IP address to its announcing AS
// number, AS name, and BGP-announced prefix via Team Cymru's DNS whois
// service (two DNS TXT lookups, no local GeoIP/ASN database file).
import { expandIPv6, lookupTXT, reverseNibblesDotted } from "./resolver";

export interface ASNInfo {
	asn: number;
	asName: string;
	prefix: string; // BGP-announced prefix containing the IP, e.g. "1.1.1.0/24"
	country: string;
}

function isIPv4(ip: string): boolean {
	return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

// lookupASN resolves ip's origin AS and announced prefix via DoH (dohUrl is
// required). ttlSeconds is the minimum TTL across both TXT queries used
// (origin lookup, plus the AS-name lookup when it succeeds); callers
// should not cache the result longer than that. ok is false if ip is
// invalid or the lookup failed/timed out.
export async function lookupASN(
	ip: string,
	timeoutMs: number,
	dohUrl: string,
): Promise<{ info: ASNInfo; ttlSeconds: number; ok: boolean }> {
	const empty = { info: { asn: 0, asName: "", prefix: "", country: "" }, ttlSeconds: 0, ok: false };

	let query: string;
	if (isIPv4(ip)) {
		const parts = ip.split(".");
		query = `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.origin.asn.cymru.com`;
	} else {
		const full = expandIPv6(ip);
		if (!full) return empty;
		query = `${reverseNibblesDotted(full)}.origin6.asn.cymru.com`;
	}

	const { txts, ttlSeconds, ok } = await lookupTXT(query, timeoutMs, dohUrl);
	if (!ok || txts.length === 0) return empty;

	// "13335 | 1.1.1.0/24 | US | apnic | 2011-08-11" -- multiple origin ASNs
	// are newline-joined within the record; take the first.
	const fields = (txts[0]!.split("\n")[0] ?? "").split("|");
	if (fields.length < 3) return empty;
	const asnField = fields[0]!.trim().split(/\s+/);
	if (asnField.length === 0 || !asnField[0]) return empty;
	const asn = parseInt(asnField[0], 10);
	if (Number.isNaN(asn)) return empty;

	const info: ASNInfo = { asn, asName: "", prefix: fields[1]!.trim(), country: fields[2]!.trim() };
	let ttl = ttlSeconds;

	const name = await lookupTXT(`AS${asn}.asn.cymru.com`, timeoutMs, dohUrl);
	if (name.ok && name.txts.length > 0) {
		// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
		const nf = name.txts[0]!.split("|");
		if (nf.length >= 5) info.asName = nf[4]!.trim();
		if (name.ttlSeconds < ttl) ttl = name.ttlSeconds;
	}

	return { info, ttlSeconds: ttl, ok: true };
}
