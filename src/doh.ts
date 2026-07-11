// JSON-form DNS-over-HTTPS client (RFC 8427-ish JSON, as served by Google's
// dns.google/resolve and Cloudflare's cloudflare-dns.com/dns-query with
// `Accept: application/dns-json`). Ports the same role as
// internal/resolver/resolver.go's doHQuery, which speaks RFC 8484
// wire-format instead -- Workers has no ready-made binary DNS message
// parser, and JSON form returns the same data (including per-record TTL,
// which is why the Go version avoided the system resolver in the first
// place) for a fraction of the code. Not a byte-for-byte port of doHQuery;
// same behavior (null = definitive NXDOMAIN, thrown error = transient
// failure), different wire format.

export const DNSType = { A: 1, PTR: 12, TXT: 16, AAAA: 28 } as const;

export interface DoHAnswer {
	name: string;
	type: number;
	TTL: number;
	data: string;
}

interface DoHResponse {
	Status: number; // 0 = NOERROR, 3 = NXDOMAIN
	Answer?: DoHAnswer[];
}

// queryDoH resolves name/type against dohUrl. Returns null for a definitive
// NXDOMAIN/no-such-name answer (mirrors doHQuery's nil-message-nil-error
// case); throws for any other failure (transport, timeout, non-success
// status).
export async function queryDoH(
	name: string,
	type: number,
	timeoutMs: number,
	dohUrl: string,
): Promise<DoHAnswer[] | null> {
	if (!dohUrl) throw new Error("doh: no endpoint configured");

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const url = `${dohUrl}?name=${encodeURIComponent(name)}&type=${type}`;
		const resp = await fetch(url, {
			headers: { Accept: "application/dns-json" },
			signal: controller.signal,
		});
		if (!resp.ok) {
			throw new Error(`doh ${dohUrl}: unexpected status ${resp.status}`);
		}
		const body = await resp.json<DoHResponse>();
		if (body.Status === 3) return null; // NXDOMAIN
		if (body.Status !== 0) {
			throw new Error(`doh ${dohUrl}: status ${body.Status}`);
		}
		return body.Answer ?? [];
	} finally {
		clearTimeout(timer);
	}
}
