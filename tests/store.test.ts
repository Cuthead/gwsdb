import assert from "node:assert/strict";
import test from "node:test";

import { type CheckRow, coalesceCheckRows } from "../src/checkRows.ts";

function check(ip: string, checkedAt: string, ok = true): CheckRow {
	return {
		ip,
		ok,
		rttMs: ok ? 10 : null,
		reason: ok ? null : "scan:timeout",
		detail: null,
		checkedAt: new Date(checkedAt),
		scanMode: "SNI",
	};
}

test("coalesceCheckRows preserves success before latest failure", () => {
	const older = check("192.0.2.1", "2026-09-02T00:00:00Z");
	const other = check("2001:db8::1", "2026-09-02T00:00:01Z");
	const newer = check("192.0.2.1", "2026-09-02T00:00:02Z", false);

	assert.deepEqual(coalesceCheckRows([older, other, newer]), [older, newer, other]);
});

test("coalesceCheckRows keeps last result when timestamps tie", () => {
	const first = check("192.0.2.1", "2026-09-02T00:00:00Z");
	const last = check("192.0.2.1", "2026-09-02T00:00:00Z", false);

	assert.deepEqual(coalesceCheckRows([first, last]), [first, last]);
});

test("coalesceCheckRows collapses repeated outcomes", () => {
	const oldFailure = check("192.0.2.1", "2026-09-02T00:00:00Z", false);
	const newFailure = check("192.0.2.1", "2026-09-02T00:00:01Z", false);
	const oldSuccess = check("2001:db8::1", "2026-09-02T00:00:00Z");
	const newSuccess = check("2001:db8::1", "2026-09-02T00:00:01Z");

	assert.deepEqual(coalesceCheckRows([oldFailure, newFailure, oldSuccess, newSuccess]), [newFailure, newSuccess]);
});
