// Pages Function for GET / -- ports internal/web/server.go's handleHome +
// loadPool + templates/home.tmpl. Two branches, same split as the Go
// original:
//   - default (JS-capable) visitors get a static shell that fetches
//     /api/pool client-side (static/home.js, unchanged from the Go version)
//   - known bots/archivers (isCrawlerUA) and ?nojs=1 (home.tmpl's <noscript>
//     meta-refresh target, for JS-disabled browsers) get the full
//     server-rendered table instead, so a one-shot fetcher or an archived
//     snapshot never sees an empty shell.
import { buildInfoFromEnv, escapeHTML, formatTime, isCrawlerUA, pageShell } from "../src/html";
import { loadPool, type IPRow } from "../src/pool";
import { poolVersion } from "../src/store";
import type { Env } from "../src/env";
import type { Stats } from "../src/types";

// sortColumns whitelists the nojs table's ?sort= values -- dbKey is what's
// passed through to loadPool (a listKnownIPs SQL column, or the literal
// "country" it special-cases for the client-side-only decode), defaultDesc
// mirrors static/home.js's data-sort-desc attributes so a first click on a
// header sorts the same direction whether JS is available or not.
const sortColumns: Record<string, { dbKey: string; label: string; defaultDesc: boolean }> = {
	ip: { dbKey: "ip", label: "IP Address", defaultDesc: false },
	ptr: { dbKey: "ptr", label: "PTR", defaultDesc: false },
	country: { dbKey: "country", label: "Country", defaultDesc: false },
	status: { dbKey: "status", label: "Status", defaultDesc: true },
	firstSeen: { dbKey: "first_seen", label: "First Seen", defaultDesc: true },
	lastSeen: { dbKey: "last_seen", label: "Last Reachable", defaultDesc: true },
	rtt: { dbKey: "rtt", label: "Last RTT", defaultDesc: true },
};
const sortColumnOrder: (keyof typeof sortColumns)[] = ["ip", "ptr", "country", "status", "firstSeen", "lastSeen", "rtt"];

// withParams clones url with the given query params set (nojs=1 always
// forced on, so a no-JS reader's sort/filter clicks stay on the
// server-rendered branch instead of falling back to the JS shell), every
// other existing param preserved -- e.g. clicking "Country" keeps whatever
// family filter was already active.
function withParams(url: URL, overrides: Record<string, string | null>): string {
	const next = new URL(url.toString());
	next.searchParams.set("nojs", "1");
	for (const [k, v] of Object.entries(overrides)) {
		if (v === null) next.searchParams.delete(k);
		else next.searchParams.set(k, v);
	}
	return next.pathname + next.search;
}

function statusHTML(status: string): string {
	if (status === "Reachable") return `<font color="#008000">&#x2713; Reachable</font>`;
	if (status === "Unreachable") return `<font color="#CC0000">&#x2717; Unreachable</font>`;
	return "-";
}

function ptrCellHTML(ptrList: string[]): string {
	if (ptrList.length === 0) return "-";
	const links = ptrList
		.map((h) => `<a href="/query?ip=${encodeURIComponent(h)}">${escapeHTML(h)}</a>`)
		.join("<br>");
	return `<tt>${links}</tt>`;
}

function countryCellHTML(row: IPRow): string {
	const img = row.countryCode
		? `<img src="/static/flags/${encodeURIComponent(row.countryCode)}.gif" alt="${escapeHTML(row.countryCode)}" title="${escapeHTML(row.country)}" height="11"> `
		: "";
	return `${img}${escapeHTML(row.country) || "-"}`;
}

// familyFilterHTML renders the "All | IPv4 only | IPv6 only" links above the
// table -- home.js's familyInput <select> equivalent for readers without JS,
// preserving whatever sort is currently active.
function familyFilterHTML(url: URL, family: number | undefined): string {
	const option = (label: string, value: string | null, active: boolean) =>
		active ? `<b>${escapeHTML(label)}</b>` : `<a href="${escapeHTML(withParams(url, { family: value }))}">${escapeHTML(label)}</a>`;
	return `<p>Family: ${option("All", null, family === undefined)} | ${option("IPv4 only", "4", family === 4)} | ${option("IPv6 only", "6", family === 6)}</p>`;
}

// sortHeaderHTML renders the table's header row as plain links -- clicking
// a column re-requests the page with ?sort=<col>&desc=<0|1>, toggling
// direction on a repeat click of the same column. No JS involved, so this
// is the no-JS equivalent of home.js's data-sort click handlers.
function sortHeaderHTML(url: URL, activeSort: string | undefined, activeDesc: boolean): string {
	const cells = sortColumnOrder
		.map((param) => {
			// sortColumns is keyed by every entry of sortColumnOrder (see its
			// definition just above), so this lookup always hits.
			const col = sortColumns[param]!;
			const isActive = activeSort === param;
			const nextDesc = isActive ? !activeDesc : col.defaultDesc;
			const href = withParams(url, { sort: param, desc: nextDesc ? "1" : "0" });
			const arrow = isActive ? (activeDesc ? " ▼" : " ▲") : "";
			return `<td><b><a href="${escapeHTML(href)}">${escapeHTML(col.label)}</a>${arrow}</b></td>`;
		})
		.join("\n");
	return `<tr bgcolor="#EEEEEE">\n${cells}\n</tr>`;
}

function renderFullTable(
	url: URL,
	ips: IPRow[],
	stats: Stats,
	scanMode: string,
	activeSort: string | undefined,
	activeDesc: boolean,
	family: number | undefined,
): string {
	const rows = ips
		.map(
			(row) => `<tr>
<td><tt><a href="/query?ip=${encodeURIComponent(row.ip)}">${escapeHTML(row.ip)}</a></tt></td>
<td>${ptrCellHTML(row.ptrList)}</td>
<td>${countryCellHTML(row)}</td>
<td>${statusHTML(row.status)}</td>
<td>${escapeHTML(row.firstSeen)}</td>
<td>${escapeHTML(row.lastSeen)}</td>
<td>${row.lastRttMs ? `${row.lastRttMs} ms` : "-"}</td>
</tr>`,
		)
		.join("\n");

	const table = ips.length
		? `<div class="gwsdb-scroll">
<table border="1" cellpadding="4" cellspacing="0" width="100%">
${sortHeaderHTML(url, activeSort, activeDesc)}
${rows}
</table>
</div>`
		: `<p><i>No data yet. Please run a scan and import the results first.</i></p>`;

	return `<p>The table below lists tracked Google Web Server (GWS) IP addresses and their reachability status.</p>
${familyFilterHTML(url, family)}
${table}
<hr>
<table border="0" cellpadding="2" cellspacing="0">
<tr><td colspan="2"><b>Statistics</b></td></tr>
<tr><td>Total Known IPs</td><td>${stats.totalKnownIPs}</td></tr>
<tr><td>Total Scans</td><td>${stats.totalScans}</td></tr>
<tr><td>Last Scan</td><td>${escapeHTML(formatTime(stats.lastScanAt))}${scanMode ? ` (${escapeHTML(scanMode)})` : ""}</td></tr>
</table>`;
}

// jsShellBody is identical on every request (matches home.tmpl's non-.Bot
// branch, which never touches IPs/Stats) -- the IP list is fetched
// client-side by static/home.js against /api/pool.
const jsShellBody = `<p>The table below lists tracked Google Web Server (GWS) IP addresses and their reachability status.</p>

<noscript><p><i>This page needs JavaScript to fetch and render the IP list client-side. You should have been redirected automatically -- if not, <a href="/?nojs=1">click here for the full list</a>.</i></p></noscript>

<p id="poolStatus">Loading&hellip;</p>

<p>
<span id="visibleCount">0</span> / <span id="familyCount">0</span> match filter
</p>

<p>
<input type="text" id="searchInput" placeholder="Search IP, PTR or country" size="30">
<input type="button" id="clearButton" value="Clear">
&nbsp;&nbsp;
<select id="familyInput">
<option value="4">IPv4</option>
<option value="6">IPv6</option>
</select>
&nbsp;&nbsp;
<select id="statusInput">
<option value="up">Reachable only</option>
<option value="all">All (including history)</option>
</select>
</p>

<div class="gwsdb-scroll gwsdb-hidden" id="ipTableWrap">
<table border="1" cellpadding="4" cellspacing="0" width="100%" id="ipTable">
<tr bgcolor="#EEEEEE">
<td><b><a href="#" data-sort="ip" data-sort-desc="0">IP Address</a> <span class="arrow" data-col="ip"></span></b></td>
<td><b><a href="#" data-sort="ptr" data-sort-desc="0">PTR</a> <span class="arrow" data-col="ptr"></span></b></td>
<td><b><a href="#" data-sort="country" data-sort-desc="0">Country</a> <span class="arrow" data-col="country"></span></b></td>
<td><b><a href="#" data-sort="status" data-sort-desc="1">Status</a> <span class="arrow" data-col="status"></span></b></td>
<td><b><a href="#" data-sort="firstSeen" data-sort-desc="1">First Seen</a> <span class="arrow" data-col="firstSeen"></span></b></td>
<td><b><a href="#" data-sort="lastSeen" data-sort-desc="1">Last Reachable</a> <span class="arrow" data-col="lastSeen"></span></b></td>
<td><b><a href="#" data-sort="rtt" data-sort-desc="1">Last RTT</a> <span class="arrow" data-col="rtt"></span></b></td>
</tr>
<tbody id="ipTableBody">
</tbody>
</table>
</div>
<p align="center" id="pagerWrap" class="gwsdb-hidden">
<input type="button" id="prevButton" value="&lt; Prev">
<span id="pageInfo"></span>
<input type="button" id="nextButton" value="Next &gt;">
&nbsp;&nbsp;
<select id="pageSizeInput">
<option value="100">100 / page</option>
<option value="250">250 / page</option>
<option value="500">500 / page</option>
<option value="all">All</option>
</select>
</p>
<script type="module" src="/static/home.js"></script>

<hr>
<table border="0" cellpadding="2" cellspacing="0">
<tr><td colspan="2"><b>Statistics</b></td></tr>
<tr><td>Total Known IPs</td><td id="totalKnownIPs">-</td></tr>
<tr><td>Total Scans</td><td id="totalScans">-</td></tr>
<tr><td>Last Scan</td><td id="lastScan">-</td></tr>
</table>`;

const nojsRefresh = `<noscript><meta http-equiv="refresh" content="0;url=/?nojs=1"></noscript>`;

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const url = new URL(context.request.url);
	const bot = isCrawlerUA(context.request.headers.get("User-Agent") ?? "") || url.searchParams.get("nojs") === "1";
	const build = buildInfoFromEnv(context.env.CF_PAGES_COMMIT_SHA);

	if (!bot) {
		const html = pageShell({ title: "Home", body: jsShellBody, build, extraHead: nojsRefresh });
		return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
	}

	// Crawler/archiver and nojs=1 path: full server-rendered table, sortable
	// (?sort=/&desc=) and filterable by family (?family=4|6) via plain links
	// since there's no JS to do it client-side. Edge-cached per exact URL the
	// same way api/pool.ts caches /api/pool -- otherwise every bot hit (and
	// every ?nojs=1, trivially repeatable by anyone) pays a full D1 read.
	const sortParam = url.searchParams.get("sort");
	const sortCol = sortParam && Object.prototype.hasOwnProperty.call(sortColumns, sortParam) ? sortColumns[sortParam] : undefined;
	const activeSort = sortCol ? sortParam! : undefined;
	const activeDesc = sortCol
		? url.searchParams.get("desc") === null
			? sortCol.defaultDesc
			: url.searchParams.get("desc") === "1"
		: true;
	const familyParam = url.searchParams.get("family");
	const family = familyParam === "4" ? 4 : familyParam === "6" ? 6 : undefined;

	const version = await poolVersion(context.env.DB);
	const cache = caches.default;
	const cacheURL = new URL(url.toString());
	cacheURL.searchParams.set("v", String(version));
	const cacheKey = new Request(cacheURL.toString(), context.request);

	const cached = await cache.match(cacheKey);
	if (cached) {
		const resp = new Response(cached.body, cached);
		resp.headers.set("Cache-Control", "no-store");
		return resp;
	}

	const { ips, scanMode, stats } = await loadPool(context.env.DB, { sortBy: sortCol?.dbKey, sortDesc: activeDesc, family });
	const html = pageShell({
		title: "Home",
		body: renderFullTable(url, ips, stats, scanMode, activeSort, activeDesc, family),
		build,
	});
	const response = new Response(html, {
		headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=86400" },
	});
	context.waitUntil(cache.put(cacheKey, response.clone()));
	response.headers.set("Cache-Control", "no-store");
	return response;
};
