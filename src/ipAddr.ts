// Minimal IP address validation shared by functions/query.ts and
// functions/report.ts (both need to tell "well-formed IP" apart from a
// 1e100.net hostname or garbage input) -- Workers has no net.ParseIP
// equivalent. expandIPv6 (src/resolver.ts) already validates IPv6 shape as
// a side effect of expanding it, so it's reused here rather than
// duplicating that logic.
import { expandIPv6 } from "./resolver";

export function isIPv4(s: string): boolean {
	if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) return false;
	return s.split(".").every((o) => Number(o) <= 255);
}

export function isIPAddress(s: string): boolean {
	return isIPv4(s) || expandIPv6(s) !== null;
}

// ipToHex encodes ip as a 32-hex-char (128-bit) zero-padded point value --
// IPv6 via expandIPv6 (already this exact shape); IPv4 embedded in the low
// 32 bits (high 96 zero). Used by prefixToRange and by store.ts's getASN to
// put a query point and stored ranges in the same comparable text format.
export function ipToHex(ip: string): string | null {
	if (isIPv4(ip)) {
		let v = 0;
		for (const octet of ip.split(".")) v = v * 256 + Number(octet);
		return v.toString(16).padStart(32, "0");
	}
	return expandIPv6(ip);
}

export interface IPRange {
	start: string; // 32-hex-char, inclusive
	end: string; // 32-hex-char, inclusive
	prefixLen: number;
	isIPv6: boolean;
}

// prefixToRange parses a CIDR prefix ("a.b.c.d/n" or an IPv6 equivalent)
// into its address range, both bounds in ipToHex's format so they compare
// directly against a point encoded the same way. BigInt handles the mask
// math uniformly for 32- and 128-bit widths -- only the low
// (addrBits - prefixLen) bits are touched, so IPv4's always-zero high 96
// bits (from ipToHex's padding) are never disturbed.
export function prefixToRange(prefix: string): IPRange | null {
	const slash = prefix.lastIndexOf("/");
	if (slash < 0) return null;
	const addr = prefix.slice(0, slash);
	const prefixLen = Number(prefix.slice(slash + 1));
	const isV6 = !isIPv4(addr);
	const addrBits = isV6 ? 128 : 32;
	if (!Number.isInteger(prefixLen) || prefixLen < 0 || prefixLen > addrBits) return null;

	const hex = ipToHex(addr);
	if (!hex) return null;
	const value = BigInt(`0x${hex}`);
	const hostBits = addrBits - prefixLen;
	const hostMask = hostBits <= 0 ? 0n : (1n << BigInt(hostBits)) - 1n;

	return {
		start: (value & ~hostMask).toString(16).padStart(32, "0"),
		end: (value | hostMask).toString(16).padStart(32, "0"),
		prefixLen,
		isIPv6: isV6,
	};
}
