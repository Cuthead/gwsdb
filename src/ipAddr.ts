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
