// Minimal RFC 1035 message encode/decode for PTR queries only -- just
// enough to pipeline many queries over one DNS-over-TCP connection
// (ptrRefresh.ts), which needs raw wire format since Workers
// has no ready-made binary DNS client (see src/doh.ts's module comment for
// why the rest of gwsdb uses JSON-form DoH instead). Benchmarked against
// 1.1.1.1:53 with up to 10,000 pipelined queries on one connection --
// 8.8.8.8 resets the connection after a few dozen, so the caller must not
// point this at Google's resolver.
import { reverseName } from "./resolver";

function encodeQName(name: string): Uint8Array {
	const parts = name.split(".");
	const bytes: number[] = [];
	for (const p of parts) {
		if (p.length === 0) continue;
		bytes.push(p.length);
		for (let i = 0; i < p.length; i++) bytes.push(p.charCodeAt(i));
	}
	bytes.push(0);
	return new Uint8Array(bytes);
}

// buildPTRQuery returns a length-prefixed (RFC 7766 §8 TCP framing) DNS
// query message for ip's PTR record, tagged with id so the response can be
// matched back to it out of a pipelined stream. id must be unique among
// concurrently in-flight queries on the same connection (16-bit, wraps at
// 65536 -- callers batching more than that per connection must chunk).
export function buildPTRQuery(id: number, ip: string): Uint8Array {
	const qname = encodeQName(reverseName(ip));
	const msg = new Uint8Array(12 + qname.length + 4);
	const view = new DataView(msg.buffer);
	view.setUint16(0, id & 0xffff);
	view.setUint16(2, 0x0100); // standard query, RD=1
	view.setUint16(4, 1); // QDCOUNT=1
	msg.set(qname, 12);
	view.setUint16(12 + qname.length, 12); // QTYPE=PTR
	view.setUint16(12 + qname.length + 2, 1); // QCLASS=IN

	const framed = new Uint8Array(2 + msg.length);
	new DataView(framed.buffer).setUint16(0, msg.length);
	framed.set(msg, 2);
	return framed;
}

// skipQName advances past a (possibly compressed) name starting at offset,
// returning the offset immediately after it. Compression pointers inside
// the question section aren't legal per RFC 1035 (nothing precedes it to
// point at) but are tolerated here as a no-op safeguard rather than assumed
// absent.
function skipName(buf: Uint8Array, offset: number): number {
	let o = offset;
	while (o < buf.length) {
		const len = buf[o]!;
		if (len === 0) return o + 1;
		if ((len & 0xc0) === 0xc0) return o + 2; // pointer: 2 bytes, done
		o += 1 + len;
	}
	return o;
}

// decodeName reads a (possibly compressed) domain name starting at offset
// within the full message buf, returning the dotted name and the offset
// immediately after its on-the-wire encoding (i.e. after a pointer if one
// was followed, not after whatever the pointer jumped to). maxJumps guards
// against a malicious/corrupt pointer cycle.
function decodeName(buf: Uint8Array, offset: number): { name: string; next: number } {
	const labels: string[] = [];
	let o = offset;
	let next = -1;
	let jumps = 0;
	while (o < buf.length) {
		const len = buf[o]!;
		if (len === 0) {
			if (next < 0) next = o + 1;
			break;
		}
		if ((len & 0xc0) === 0xc0) {
			if (jumps++ > 20) throw new Error("dns: compression pointer loop");
			if (next < 0) next = o + 2;
			o = ((len & 0x3f) << 8) | buf[o + 1]!;
			continue;
		}
		const start = o + 1;
		labels.push(String.fromCharCode(...buf.subarray(start, start + len)));
		o = start + len;
	}
	return { name: labels.join("."), next: next < 0 ? o : next };
}

export interface DNSAnswer {
	type: number;
	ttl: number;
	data: string;
}

export interface DNSResponse {
	id: number;
	rcode: number;
	answers: DNSAnswer[];
}

// parseMessage decodes one complete (unframed -- length prefix already
// stripped) DNS message. Only extracts what pendingIPsForPTRRefresh's PTR
// batch needs: id/rcode for matching + gating, and PTR-type answer records
// (name-decompressed). Other record types in the answer section are walked
// past (need their length to find the next record) but not decoded.
export function parseMessage(buf: Uint8Array): DNSResponse {
	if (buf.length < 12) throw new Error("dns: message too short");
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const id = view.getUint16(0);
	const rcode = buf[3]! & 0x0f;
	const qdcount = view.getUint16(4);
	const ancount = view.getUint16(6);

	let o = 12;
	for (let i = 0; i < qdcount; i++) {
		o = skipName(buf, o);
		o += 4; // QTYPE + QCLASS
	}

	const answers: DNSAnswer[] = [];
	for (let i = 0; i < ancount; i++) {
		o = skipName(buf, o);
		const type = view.getUint16(o);
		const ttl = view.getUint32(o + 4);
		const rdlength = view.getUint16(o + 8);
		const rdataOffset = o + 10;
		if (type === 12 /* PTR */) {
			const { name } = decodeName(buf, rdataOffset);
			answers.push({ type, ttl, data: name });
		}
		o = rdataOffset + rdlength;
	}

	return { id, rcode, answers };
}
