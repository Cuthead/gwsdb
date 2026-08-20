// Minimal IP address parsing shared by request handlers and DNS helpers --
// Workers has no net.ParseIP equivalent.

export function isIPv4(s: string): boolean {
	if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) return false;
	return s.split(".").every((o) => Number(o) <= 255);
}

export function isIPAddress(s: string): boolean {
	return isIPv4(s) || expandIPv6(s) !== null;
}

// expandIPv6 renders ip as 32 lowercase hex nibbles (no colons), or null if
// ip isn't a valid IPv6 address.
export function expandIPv6(ip: string): string | null {
	if (ip.includes("%")) return null;
	let head = ip;
	let tail = "";
	const dbl = ip.indexOf("::");
	if (dbl >= 0) {
		if (dbl !== ip.lastIndexOf("::")) return null;
		head = ip.slice(0, dbl);
		tail = ip.slice(dbl + 2);
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
		if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
		hex += g.padStart(4, "0").toLowerCase();
	}
	return hex;
}

// normalizeIPAddress returns the conventional text form used as database
// identity: IPv6 is lowercase with leading zeroes removed and the longest
// leftmost run of zero groups compressed (RFC 5952 section 4).
export function normalizeIPAddress(s: string): string | null {
	if (isIPv4(s)) return s;
	const hex = expandIPv6(s);
	if (!hex) return null;

	const groups: string[] = [];
	for (let i = 0; i < hex.length; i += 4) groups.push(BigInt(`0x${hex.slice(i, i + 4)}`).toString(16));

	let bestStart = -1;
	let bestLength = 0;
	for (let i = 0; i < groups.length; ) {
		if (groups[i] !== "0") {
			i++;
			continue;
		}
		let end = i + 1;
		while (end < groups.length && groups[end] === "0") end++;
		if (end - i > bestLength) {
			bestStart = i;
			bestLength = end - i;
		}
		i = end;
	}

	if (bestLength < 2) return groups.join(":");
	const before = groups.slice(0, bestStart).join(":");
	const after = groups.slice(bestStart + bestLength).join(":");
	return `${before}::${after}`;
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
