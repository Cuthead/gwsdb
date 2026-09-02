export interface CheckRow {
	ip: string;
	ok: boolean;
	rttMs: number | null;
	reason: string | null;
	detail: string | null;
	checkedAt: Date;
	scanMode: string;
}

// Keep one latest result per IP, plus its latest success when a later failure
// would otherwise erase first-discovery evidence. This bounds each IP to at
// most two rows while preserving both known-good membership and final status.
export function coalesceCheckRows(rows: CheckRow[]): CheckRow[] {
	const byIP = new Map<string, { latest: CheckRow; latestSuccess: CheckRow | null }>();
	for (const row of rows) {
		const state = byIP.get(row.ip);
		if (!state) {
			byIP.set(row.ip, { latest: row, latestSuccess: row.ok ? row : null });
			continue;
		}
		if (row.checkedAt >= state.latest.checkedAt) state.latest = row;
		if (row.ok && (!state.latestSuccess || row.checkedAt >= state.latestSuccess.checkedAt)) state.latestSuccess = row;
	}
	const out: CheckRow[] = [];
	for (const { latest, latestSuccess } of byIP.values()) {
		if (latestSuccess && latestSuccess !== latest) out.push(latestSuccess);
		out.push(latest);
	}
	return out;
}
