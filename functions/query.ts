// Pages Function for GET /query -- ports internal/web/server.go's
// handleQuery/lookup/lookupHostname/resolveHostnameForm/statusForIP/
// reachabilityStatus/reasonLabel/describeProbe + templates/query.tmpl.
import { lookupGoogleASN, resolveAndCacheHost, resolveAndCachePTR, isGoogleASN } from "../src/dnsCache";
import { decode, decodeBest, isHostname, siblingHostname } from "../src/geo";
import { buildInfoFromEnv, escapeHTML, formatTime, pageShell } from "../src/html";
import { isIPAddress, normalizeIPAddress } from "../src/ipAddr";
import { clientCountry } from "../src/request";
import { CHECK_HISTORY_RETENTION, getHost, getPTR, ipHistory, ipStatusFor } from "../src/store";
import type { ASNInfo } from "../src/asn";
import type { Env } from "../src/env";
import type { IPCheckHistoryRow, IPStatus } from "../src/types";

const PTR_TIMEOUT_MS = 3000;
const ASN_TIMEOUT_MS = 3000;
const HISTORY_PAGE_SIZE = 30;
const MAX_HISTORY_PAGE = Math.ceil(CHECK_HISTORY_RETENTION / HISTORY_PAGE_SIZE);

function reachabilityStatus(st: IPStatus | null): string {
	if (!st || !st.hasCheck) return "-";
	return st.lastCheckOk ? "Reachable" : "Unreachable";
}

// reasonLabels translates gscan_quic's REASON tags into short human-readable labels.
const REASON_LABELS: Record<string, string> = {
	dial: "tcp: TCP dial timeout",
	handshake: "tls: TLS handshake failed",
	cn: "tls: Certificate CN mismatch",
	http: "http: HTTP timeout",
	status: "http: HTTP status code mismatch",
	ping: "icmp: ICMP ping timeout",
};

function reasonLabel(reason: string, detail: string): string {
	if (reason === "ping") return detail.includes("rtt_too_low") ? "icmp: RTT too low" : "icmp: ICMP ping timeout";
	return REASON_LABELS[reason] ?? reason;
}

interface CheckRow {
	time: string;
	ok: boolean;
	rtt: number;
	reasonLabel: string;
	detail: string;
}

interface AddrStatus {
	addr: string;
	status: string;
}

interface HostnameForm {
	hostname: string;
	ipv4: AddrStatus[];
	ipv6: AddrStatus[];
	// failed marks a forward lookup that errored out, so the address columns
	// read as "lookup failed" rather than a definitive "none".
	failed: boolean;
}

interface QueryData {
	query: string;
	submitted: boolean;
	error: string;
	ptrHostnames: string[];
	// ptrFailed distinguishes "the PTR lookup itself errored out" from the
	// ptrHostnames-empty "this IP definitively has no PTR record" case, so
	// the page can say which.
	ptrFailed: boolean;
	matched: boolean;
	airportCode: string;
	city: string;
	country: string;
	hasHistory: boolean;
	status: string;
	firstSeen: string;
	lastSeen: string;
	timesSeen: number;
	lastRttMs: number;
	checks: CheckRow[];
	historyPage: number;
	historyHasNext: boolean;
	queryIsHostname: boolean;
	hostnameForms: HostnameForm[];
	canProbe: boolean;
}

function emptyData(query: string): QueryData {
	return {
		query,
		submitted: false,
		error: "",
		ptrHostnames: [],
		ptrFailed: false,
		matched: false,
		airportCode: "",
		city: "",
		country: "",
		hasHistory: false,
		status: "",
		firstSeen: "",
		lastSeen: "",
		timesSeen: 0,
		lastRttMs: 0,
		checks: [],
		historyPage: 1,
		historyHasNext: false,
		queryIsHostname: false,
		hostnameForms: [],
		canProbe: false,
	};
}

async function statusForIP(db: D1Database, ip: string): Promise<string> {
	return reachabilityStatus(await ipStatusFor(db, ip));
}

// resolveHostnameForm resolves one hostname's A/AAAA records. A failed
// forward lookup yields an empty (failed=true) form rather than throwing:
// lookupHostnameQuery resolves both a hostname and its sibling, and one
// side's SERVFAIL shouldn't discard the other side's good answer.
async function resolveHostnameForm(db: D1Database, hostname: string, dohUrl: string): Promise<HostnameForm> {
	const form: HostnameForm = { hostname, ipv4: [], ipv6: [], failed: false };
	let ipv4: string[] = [];
	let ipv6: string[] = [];
	try {
		const cached = await getHost(db, hostname);
		({ ipv4, ipv6 } = cached ?? (await resolveAndCacheHost(db, hostname, PTR_TIMEOUT_MS, dohUrl)));
	} catch (err) {
		console.warn(`query: host lookup ${hostname}:`, err);
		form.failed = true;
		return form;
	}
	for (const addr of ipv4) form.ipv4.push({ addr, status: await statusForIP(db, addr) });
	for (const rawAddr of ipv6) {
		const addr = normalizeIPAddress(rawAddr) ?? rawAddr;
		form.ipv6.push({ addr, status: await statusForIP(db, addr) });
	}
	return form;
}

async function lookupHostnameQuery(db: D1Database, hostname: string, dohUrl: string, data: QueryData): Promise<void> {
	const loc = decode(hostname);
	data.matched = loc.matched;
	data.airportCode = loc.airportCode;
	data.city = loc.city;
	data.country = loc.country;

	data.hostnameForms.push(await resolveHostnameForm(db, hostname, dohUrl));
	const sibling = siblingHostname(hostname);
	if (sibling) data.hostnameForms.push(await resolveHostnameForm(db, sibling, dohUrl));
}

async function lookupIPQuery(db: D1Database, ip: string, dohUrl: string, historyPage: number, data: QueryData): Promise<void> {
	// A PTR lookup failure is non-fatal: it costs one row of the result,
	// while the reachability overview/check history/reports below it are all
	// independent of it. Large parts of Google's reverse space (notably the
	// GCP /31s) are delegated to authorities that answer REFUSED, which
	// queryDoH surfaces as a thrown SERVFAIL -- letting that propagate would
	// 500 the whole page over a cosmetic row.
	let hostnames: string[] = [];
	let ok = false;
	try {
		const cached = await getPTR(db, ip);
		({ hostnames, ok } = cached
			? { hostnames: cached.ptrHostnames, ok: cached.lookupOk }
			: await resolveAndCachePTR(db, ip, PTR_TIMEOUT_MS, dohUrl));
	} catch (err) {
		console.warn(`query: PTR lookup ${ip}:`, err);
		data.ptrFailed = true;
	}

	if (ok) {
		data.ptrHostnames = hostnames;
		const loc = decodeBest(hostnames);
		data.matched = loc.matched;
		data.airportCode = loc.airportCode;
		data.city = loc.city;
		data.country = loc.country;
	}

	const st = await ipStatusFor(db, ip);
	if (st) {
		data.hasHistory = true;
		data.firstSeen = formatTime(st.firstSeen);
		data.lastSeen = formatTime(st.lastSeen);
		data.timesSeen = st.timesSeen;
		data.lastRttMs = st.lastRttMs;
	}
	data.status = reachabilityStatus(st);

	data.historyPage = historyPage;
	const checks = await ipHistory(db, ip, HISTORY_PAGE_SIZE + 1, (historyPage - 1) * HISTORY_PAGE_SIZE);
	data.historyHasNext = checks.length > HISTORY_PAGE_SIZE;
	data.checks = checks.slice(0, HISTORY_PAGE_SIZE).map((c) => ({
		time: formatTime(c.checkedAt),
		ok: c.ok,
		rtt: c.rttMs,
		reasonLabel: c.ok ? "" : reasonLabel(c.reason, c.detail),
		detail: c.detail,
	}));

}

// queryDescription summarizes the lookup result for the page's og:description,
// so a shared link previews the specific IP/hostname's reachability and
// estimated location instead of the generic query-page blurb.
function queryDescription(data: QueryData): string {
	if (!data.submitted) return "Look up whether an IP address or 1e100.net hostname belongs to a Google Web Server reachable from China.";
	if (data.error) return `${data.query}: ${data.error}.`;

	const location = data.matched ? (data.city ? `${data.city}, ${data.country}` : data.country) : "";
	if (data.queryIsHostname) {
		return location ? `${data.query}: 1e100.net hostname, estimated location ${location}.` : `${data.query}: 1e100.net hostname.`;
	}

	const parts = [`${data.query}: ${data.hasHistory ? data.status : "no scan history"}`];
	if (location) parts.push(`estimated location ${location}`);
	return `${parts.join(", ")}.`;
}

function statusHTML(status: string, reachableLabel: string, unreachableLabel: string): string {
	if (status === "Reachable") return `<font color="#008000">&#x2713; ${reachableLabel}</font>`;
	if (status === "Unreachable") return `<font color="#CC0000">&#x2717; ${unreachableLabel}</font>`;
	return "-";
}

function renderHostnameBranch(data: QueryData): string {
	const rows = data.hostnameForms
		.map((form) => {
			const addrCol = (addrs: AddrStatus[]) =>
				addrs.length
					? addrs
							.map(
								(a) =>
									`<tt><a href="/query?ip=${encodeURIComponent(a.addr)}">${escapeHTML(a.addr)}</a></tt> ${statusHTML(a.status, "", "")}<br>`,
							)
							.join("")
					: form.failed
						? "<i>lookup failed</i>"
						: "<i>none</i>";
			return `<tr>
<td><tt><a href="/query?ip=${encodeURIComponent(form.hostname)}">${escapeHTML(form.hostname)}</a></tt></td>
<td>${addrCol(form.ipv4)}</td>
<td>${addrCol(form.ipv6)}</td>
</tr>`;
		})
		.join("\n");

	const locationRows = data.matched
		? `<tr>
<td>Airport Code</td>
<td colspan="2"><tt>${escapeHTML(data.airportCode)}</tt></td>
</tr>
<tr>
<td>Estimated Location</td>
<td colspan="2">${data.country ? (data.city ? `${escapeHTML(data.city)}, ${escapeHTML(data.country)}` : escapeHTML(data.country)) : "<i>Airport code not in database, cannot estimate</i>"}</td>
</tr>`
		: `<tr>
<td colspan="3"><i>This does not match the known 1e100.net naming convention, cannot estimate a location</i></td>
</tr>`;

	return `<div class="gwsdb-scroll">
<table border="1" cellpadding="6" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="3"><b>Query Result: ${escapeHTML(data.query)}</b></td></tr>
<tr bgcolor="#EEEEEE"><td><b>Hostname</b></td><td><b>A (IPv4)</b></td><td><b>AAAA (IPv6)</b></td></tr>
${rows}
${locationRows}
</table>
</div>`;
}

function renderIPBranch(data: QueryData): string {
	const ptrCell = data.ptrHostnames.length
		? `<tt>${data.ptrHostnames.map((h) => `<a href="/query?ip=${encodeURIComponent(h)}">${escapeHTML(h)}</a>`).join("<br>")}</tt>`
		: data.ptrFailed
			? `<i>(PTR lookup failed -- the reverse zone for this address did not answer)</i>`
			: "<i>(no PTR record)</i>";

	const locationRows = data.matched
		? `<tr>
<td>Airport Code</td>
<td><tt>${escapeHTML(data.airportCode)}</tt></td>
</tr>
<tr>
<td>Estimated Location</td>
<td>${data.country ? (data.city ? `${escapeHTML(data.city)}, ${escapeHTML(data.country)}` : escapeHTML(data.country)) : "<i>Airport code not in database, cannot estimate</i>"}</td>
</tr>`
		: data.ptrHostnames.length
			? `<tr>
<td>Estimated Location</td>
<td><i>This PTR does not match the known 1e100.net naming convention, cannot parse</i></td>
</tr>`
			: "";

	const overview = data.hasHistory
		? `<tr bgcolor="#EEEEEE"><td colspan="2"><b>Reachability Overview</b></td></tr>
<tr><td>Current Status</td><td>${statusHTML(data.status, "Reachable", "Unreachable")}</td></tr>
<tr><td>First Seen</td><td>${escapeHTML(data.firstSeen)}</td></tr>
<tr><td>Last Reachable</td><td>${escapeHTML(data.lastSeen)}</td></tr>
<tr><td>Total Times Seen</td><td>${data.timesSeen}</td></tr>
<tr><td>Last RTT</td><td>${data.lastRttMs ? `${data.lastRttMs} ms` : "-"}</td></tr>`
		: `<tr><td colspan="2"><i>This IP is not in the known scan results (it may not have been scanned, or was never found reachable)</i></td></tr>`;

	const firstCheck = (data.historyPage - 1) * HISTORY_PAGE_SIZE + 1;
	const lastCheck = firstCheck + data.checks.length - 1;
	const historyRange = data.checks.length ? `checks ${firstCheck}-${lastCheck}, newest first` : `page ${data.historyPage}`;
	const historyLinks = [
		data.historyPage > 1
			? `<a href="/query?ip=${encodeURIComponent(data.query)}&amp;page=${data.historyPage - 1}">&laquo; Previous</a>`
			: "",
		data.historyHasNext
			? `<a href="/query?ip=${encodeURIComponent(data.query)}&amp;page=${data.historyPage + 1}">Next &raquo;</a>`
			: "",
	].filter(Boolean);
	const historyPagination = historyLinks.length
		? `<p>Page ${data.historyPage} &nbsp; ${historyLinks.join(" &nbsp; ")}</p>`
		: "";
	const checkRows = data.checks.length
		? data.checks
				.map(
					(c) => `<tr>
<td>${escapeHTML(c.time)}</td>
<td>${c.ok ? `<font color="#008000">&#x2713; Reachable</font>` : `<font color="#CC0000">&#x2717; Unreachable</font>`}</td>
<td>${c.reasonLabel ? escapeHTML(c.reasonLabel) : ""}${c.reasonLabel && c.detail ? "<br>" : ""}${c.detail ? `<tt>${escapeHTML(c.detail)}</tt>` : (c.reasonLabel ? "" : "-")}</td>
<td>${c.rtt ? `${c.rtt} ms` : "-"}</td>
</tr>`,
				)
				.join("\n")
		: `<tr><td colspan="4"><i>No checks on this page</i></td></tr>`;
	const checksTable = data.checks.length || data.historyPage > 1
		? `<p></p>
<div class="gwsdb-scroll">
<table border="1" cellpadding="4" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="4"><b>Check History</b> (${historyRange})</td></tr>
<tr bgcolor="#EEEEEE"><td><b>Time</b></td><td><b>Result</b></td><td><b>Reason</b></td><td><b>RTT</b></td></tr>
${checkRows}
</table>
</div>
${historyPagination}`
		: "";

	const probeCell = data.canProbe
		? `<button type="button" id="probeBtn" data-ip="${escapeHTML(data.query)}">立即检测</button> <span id="probeStatus"></span>`
		: `<font color="#666666">仅中国大陆IP可即时检测</font>`;

	return `<div class="gwsdb-scroll">
<table border="1" cellpadding="6" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="2"><b>Query Result: ${escapeHTML(data.query)}</b></td></tr>
<tr>
<td width="30%">PTR Record</td>
<td>${ptrCell}</td>
</tr>
${locationRows}
${overview}
</table>
</div>
${checksTable}

<p></p>
<div class="gwsdb-scroll">
<table border="1" cellpadding="6" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="2"><b>即时检测</b></td></tr>
<tr>
<td colspan="2">
${probeCell}
</td>
</tr>
</table>
</div>
<script src="/static/query.js"></script>`;
}

function renderQueryBody(data: QueryData): string {
	const form = `<p>Enter an IP address within a Google ASN to look up its PTR record, or a 1e100.net hostname to look up its A/AAAA records, and estimate its geographic location.</p>

<form method="GET" action="/query">
<table border="0" cellpadding="4" cellspacing="0">
<tr>
<td>IP or 1e100.net Hostname</td>
<td><input type="text" name="ip" size="28" value="${escapeHTML(data.query)}"></td>
<td><input type="submit" value="Query"></td>
</tr>
</table>
</form>`;

	let result = "";
	if (data.submitted) {
		if (data.error) {
			result = `<hr>\n<p><font color="#CC0000">${escapeHTML(data.error)}</font></p>`;
		} else if (data.queryIsHostname) {
			result = `<hr>\n${renderHostnameBranch(data)}`;
		} else {
			result = `<hr>\n${renderIPBranch(data)}`;
		}
	}

	return `${form}
${result}

<hr>
<p><font size="-2" color="#666666">
Location estimates are based on the <a href="https://github.com/lennylxx/ipv6-hosts/wiki/1e100.net">1e100.net PTR naming convention</a> (a community-maintained, unofficial document, for reference only).
</font></p>`;
}

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const url = new URL(context.request.url);
	const pageParam = url.searchParams.get("page") ?? "1";
	const historyPage = /^\d+$/.test(pageParam) ? Math.min(Math.max(Number(pageParam), 1), MAX_HISTORY_PAGE) : 1;
	let q = (url.searchParams.get("ip") ?? "").trim();
	if (isIPAddress(q)) {
		const normalized = normalizeIPAddress(q)!;
		if (normalized !== q) {
			url.searchParams.set("ip", normalized);
			return Response.redirect(url.toString(), 308);
		}
		q = normalized;
	}
	const data = emptyData(q);
	data.canProbe = clientCountry(context.request) === "CN";
	const dohUrl = context.env.DOH_JSON_URL;

	if (q === "") {
		// not submitted; render the empty form
	} else if (isIPAddress(q)) {
		data.submitted = true;
		// The ASN check is this page's gate, not a display field, so a failed
		// lookup can't fail open (it would show scan history for arbitrary
		// non-Google IPs) and shouldn't fail closed under the flat "not a
		// Google ASN" message either -- that asserts something we didn't
		// establish. Report the transient failure as itself instead.
		let asn: { info: ASNInfo; ok: boolean } | null = null;
		try {
			asn = await lookupGoogleASN(context.env.DB, q, ASN_TIMEOUT_MS, dohUrl);
		} catch (err) {
			console.warn(`query: ASN lookup ${q}:`, err);
			data.error = "Could not verify this IP's ASN right now (the lookup failed); please try again";
		}
		if (asn) {
			if (!asn.ok || !isGoogleASN(asn.info)) {
				data.error = "This IP does not belong to a Google ASN";
			} else {
				await lookupIPQuery(context.env.DB, q, dohUrl, historyPage, data);
			}
		}
	} else if (isHostname(q)) {
		data.submitted = true;
		data.queryIsHostname = true;
		// No catch needed here: resolveHostnameForm absorbs each hostname's
		// own lookup failure, and nothing else on this path does DNS.
		await lookupHostnameQuery(context.env.DB, q, dohUrl, data);
	} else {
		data.submitted = true;
		data.error = "Not a valid IP address or 1e100.net hostname";
	}

	const build = buildInfoFromEnv(context.env.CF_PAGES_COMMIT_SHA);
	const html = pageShell({
		title: "Query",
		body: renderQueryBody(data),
		build,
		description: queryDescription(data),
	});
	return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
};
