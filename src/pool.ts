// Shared "known-IP pool" query + shaping logic behind both the home page's
// server-rendered crawler path (functions/index.ts) and /api/pool
// (functions/api/pool.ts) -- mirrors internal/web/server.go's loadPool.
import { countryCode, decodeBest } from "./geo";
import { formatTime } from "./html";
import { latestScan, listKnownIPs, overview } from "./store";
import type { IPStatus, Stats } from "./types";

export interface IPRow {
	ip: string;
	ptrList: string[];
	country: string;
	countryCode: string;
	status: string; // "Reachable" / "Unreachable" / "-"
	firstSeen: string;
	lastSeen: string;
	lastRttMs: number;
}

function statusFor(st: IPStatus): string {
	if (!st.hasCheck) return "-";
	return st.lastCheckOk ? "Reachable" : "Unreachable";
}

function toIPRow(st: IPStatus): IPRow {
	let country = "";
	let code = "";
	if (st.ptrHostname.length > 0) {
		const loc = decodeBest(st.ptrHostname);
		country = loc.country;
		code = countryCode(loc.country);
	}
	return {
		ip: st.ip,
		ptrList: st.ptrHostname,
		country,
		countryCode: code,
		status: statusFor(st),
		firstSeen: formatTime(st.firstSeen),
		lastSeen: formatTime(st.lastSeen),
		lastRttMs: st.lastRttMs,
	};
}

export interface Pool {
	ips: IPRow[];
	scanMode: string;
	stats: Stats;
}

export async function loadPool(db: D1Database): Promise<Pool> {
	const known = await listKnownIPs(db, { sortBy: "last_seen", sortDesc: true });
	const ips = known.map(toIPRow);
	const latest = await latestScan(db, "");
	const stats = await overview(db);
	return { ips, scanMode: latest?.ScanMode ?? "", stats };
}
