// Pages Function for GET /scans -- ports internal/web/server.go's
// handleScans + describeScanConfig + templates/scans.tmpl.
import { buildInfoFromEnv, escapeHTML, formatTime, pageShell } from "../src/html";
import { listScans, scansVersion } from "../src/store";
import type { Env } from "../src/env";
import type { ScanRow } from "../src/types";

// maxScansListed caps how many rows the scans page table renders.
const MAX_SCANS_LISTED = 500;

// describeScanConfig summarizes a scan's request/target parameters into one
// compact line, mirroring describeProbe's label=value style (server.go).
function describeScanConfig(sc: ScanRow): string {
	const parts: string[] = [];
	if (sc.ServerName) parts.push(`server=${sc.ServerName}`);
	if (sc.VerifyCommonName) parts.push(`verify_cn=${sc.VerifyCommonName}`);
	if (sc.HTTPMethod) parts.push(`method=${sc.HTTPMethod}`);
	if (sc.HTTPPath) parts.push(`path=${sc.HTTPPath}`);
	if (sc.HTTPVerifyHosts) parts.push(`host=${sc.HTTPVerifyHosts}`);
	if (sc.ValidStatusCode !== 0) parts.push(`valid_code=${sc.ValidStatusCode}`);
	if (sc.Level !== 0) parts.push(`level=${sc.Level}`);
	if (sc.InputFile) parts.push(`input=${sc.InputFile}`);
	if (sc.OutputFile) parts.push(`output=${sc.OutputFile}`);
	return parts.join(" ");
}

function durationLabel(sc: ScanRow): string {
	if (!sc.StartedAt || !sc.FinishedAt || sc.FinishedAt <= sc.StartedAt) return "-";
	const seconds = Math.round((sc.FinishedAt.getTime() - sc.StartedAt.getTime()) / 1000);
	const h = Math.floor(seconds / 3600);
	const m = Math.floor((seconds % 3600) / 60);
	const s = seconds % 60;
	if (h > 0) return `${h}h${m}m${s}s`;
	return m > 0 ? `${m}m${s}s` : `${s}s`;
}

function renderScansTable(scans: ScanRow[], truncated: boolean): string {
	const rows = scans
		.map((sc) => {
			const summary = describeScanConfig(sc);
			const configJSON = sc.ConfigJSON;
			const configCell =
				!summary && !configJSON
					? "-"
					: `${summary ? `${escapeHTML(summary)}<br>` : ""}${configJSON ? `<tt>${escapeHTML(configJSON)}</tt>` : ""}`;
			return `<tr>
<td>${sc.id}</td>
<td>${escapeHTML(sc.ScanMode)}</td>
<td>${escapeHTML(formatTime(sc.StartedAt))}</td>
<td>${escapeHTML(formatTime(sc.FinishedAt))}</td>
<td>${durationLabel(sc)}</td>
<td>${sc.ScannedCount}</td>
<td>${sc.FoundCount}</td>
<td><font size="-1">${configCell}</font></td>
</tr>`;
		})
		.join("\n");

	const table = scans.length
		? `<div class="gwsdb-scroll">
<table border="1" cellpadding="4" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE">
<td><b>ID</b></td>
<td><b>Mode</b></td>
<td><b>Started</b></td>
<td><b>Finished</b></td>
<td><b>Duration</b></td>
<td><b>Scanned</b></td>
<td><b>Found</b></td>
<td><b>Config</b></td>
</tr>
${rows}
</table>
</div>`
		: `<p><i>No scans imported yet.</i></p>`;

	return `<p>Every previously imported scan run, newest first, with its start/finish time and the request configuration in effect for that run.</p>

<p>${scans.length} total${truncated ? ` (showing only the most recent ${scans.length})` : ""}</p>

${table}`;
}

// Edge-cached keyed on scansVersion, same pattern as /api/pool
// (functions/api/pool.ts): the first request after a new scan is imported in
// each colo pays the D1 read, every later request/colo hits the edge cache.
export const onRequestGet: PagesFunction<Env> = async (context) => {
	const version = await scansVersion(context.env.DB);

	const cache = caches.default;
	const cacheURL = new URL(context.request.url);
	cacheURL.searchParams.set("v", String(version));
	const cacheKey = new Request(cacheURL.toString(), context.request);

	const cached = await cache.match(cacheKey);
	if (cached) {
		const resp = new Response(cached.body, cached);
		resp.headers.set("Cache-Control", "no-store");
		return resp;
	}

	const scans = await listScans(context.env.DB, MAX_SCANS_LISTED);
	const build = buildInfoFromEnv(context.env.CF_PAGES_COMMIT_SHA);
	const html = pageShell({
		title: "Scan History",
		body: renderScansTable(scans, scans.length === MAX_SCANS_LISTED),
		build,
		description: "History of automated scans that populate the GWS Database's list of Google Web Server IPs reachable from China.",
	});
	// max-age just bounds how long this colo holds the entry -- correctness
	// doesn't depend on it, since a version bump already changes cacheKey.
	const response = new Response(html, {
		headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=86400" },
	});
	context.waitUntil(cache.put(cacheKey, response.clone()));
	response.headers.set("Cache-Control", "no-store");
	return response;
};
