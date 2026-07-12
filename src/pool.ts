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

export interface LoadPoolOptions {
	// sortBy is one of listKnownIPs' whitelisted DB columns (ip, ptr, status,
	// first_seen, last_seen, rtt), or "country" -- country isn't a DB column
	// (it's decoded from ptr_hostname in toIPRow, after the query runs), so
	// that case is sorted here instead of being passed through to SQL.
	// Defaults to "last_seen" (unsorted API callers keep their prior order).
	sortBy?: string;
	sortDesc?: boolean; // defaults to true, matching the pre-existing default
	family?: number; // 4 or 6 restricts to that address family; anything else is both
}

export async function loadPool(db: D1Database, opts: LoadPoolOptions = {}): Promise<Pool> {
	const sortBy = opts.sortBy ?? "last_seen";
	const sortDesc = opts.sortDesc ?? true;
	const known = await listKnownIPs(db, {
		sortBy: sortBy === "country" ? undefined : sortBy,
		sortDesc,
		family: opts.family,
	});
	const ips = known.map(toIPRow);
	if (sortBy === "country") {
		ips.sort((a, b) => {
			if (a.country < b.country) return sortDesc ? 1 : -1;
			if (a.country > b.country) return sortDesc ? -1 : 1;
			return 0;
		});
	}
	const latest = await latestScan(db, "");
	const stats = await overview(db);
	return { ips, scanMode: latest?.ScanMode ?? "", stats };
}
