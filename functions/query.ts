// Pages Function for GET /query -- ports internal/web/server.go's
// handleQuery/lookup/lookupHostname/resolveHostnameForm/statusForIP/
// reachabilityStatus/reasonLabel/describeProbe + templates/query.tmpl.
import { lookupGoogleASN, resolveAndCacheHost, resolveAndCachePTR, isGoogleASN } from "../src/dnsCache";
import { decode, decodeBest, isHostname, siblingHostname } from "../src/geo";
import { buildInfoFromEnv, escapeHTML, formatTime, pageShell } from "../src/html";
import { isIPAddress } from "../src/ipAddr";
import { getHost, getPTR, ipHistory, ipStatusFor, listReports } from "../src/store";
import type { Env } from "../src/env";
import type { IPCheckHistoryRow, IPReport, IPStatus } from "../src/types";

const PTR_TIMEOUT_MS = 3000;
const ASN_TIMEOUT_MS = 3000;
const MAX_REPORT_ROWS = 100;
const MAX_HISTORY_ROWS = 30;
const DEFAULT_DOH_URL = "https://dns.google/resolve";

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
};

function reasonLabel(reason: string, detail: string): string {
	if (reason === "ping") return detail === "rtt_too_low" ? "ping: RTT too low" : "ping: Ping timeout";
	return REASON_LABELS[reason] ?? reason;
}

// describeProbe summarizes the request parameters a check was made with, so
// a failure reason can be read alongside exactly what was sent/expected.
function describeProbe(c: IPCheckHistoryRow): string {
	const parts: string[] = [];
	if (c.recheck) parts.push("recheck");
	if (c.scanMode) parts.push(c.scanMode);
	if (c.serverName) parts.push(`sni=${c.serverName}`);
	if (c.httpMethod) parts.push(`method=${c.httpMethod}`);
	if (c.httpPath) parts.push(`path=${c.httpPath}`);
	if (c.httpVerifyHosts) parts.push(`host=${c.httpVerifyHosts}`);
	if (c.verifyCommonName) parts.push(`want_cn=${c.verifyCommonName}`);
	if (c.validStatusCode !== 0) parts.push(`want_code=${c.validStatusCode}`);
	return parts.join(" ");
}

interface CheckRow {
	time: string;
	ok: boolean;
	rtt: number;
	reasonLabel: string;
	detail: string;
	probe: string;
}

interface ReportRow {
	time: string;
	verdict: boolean;
	reporterPrefix: string;
	reporterASN: number;
	reporterASName: string;
	comment: string;
}

interface AddrStatus {
	addr: string;
	status: string;
}

interface HostnameForm {
	hostname: string;
	ipv4: AddrStatus[];
	ipv6: AddrStatus[];
}

interface QueryData {
	query: string;
	submitted: boolean;
	error: string;
	ptrHostnames: string[];
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
	reports: ReportRow[];
	usableCount: number;
	unusableCount: number;
	queryIsHostname: boolean;
	hostnameForms: HostnameForm[];
}

function emptyData(query: string): QueryData {
	return {
		query,
		submitted: false,
		error: "",
		ptrHostnames: [],
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
		reports: [],
		usableCount: 0,
		unusableCount: 0,
		queryIsHostname: false,
		hostnameForms: [],
	};
}

async function statusForIP(db: D1Database, ip: string): Promise<string> {
	return reachabilityStatus(await ipStatusFor(db, ip));
}

async function resolveHostnameForm(db: D1Database, hostname: string, dohUrl: string): Promise<HostnameForm> {
	const cached = await getHost(db, hostname);
	const { ipv4, ipv6 } = cached ?? (await resolveAndCacheHost(db, hostname, PTR_TIMEOUT_MS, dohUrl));
	const form: HostnameForm = { hostname, ipv4: [], ipv6: [] };
	for (const addr of ipv4) form.ipv4.push({ addr, status: await statusForIP(db, addr) });
	for (const addr of ipv6) form.ipv6.push({ addr, status: await statusForIP(db, addr) });
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

async function lookupIPQuery(db: D1Database, ip: string, dohUrl: string, data: QueryData): Promise<void> {
	const cached = await getPTR(db, ip);
	const { hostnames, ok } = cached
		? { hostnames: cached.ptrHostnames, ok: cached.lookupOk }
		: await resolveAndCachePTR(db, ip, PTR_TIMEOUT_MS, dohUrl);

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

	const checks = await ipHistory(db, ip, MAX_HISTORY_ROWS);
	data.checks = checks.map((c) => ({
		time: formatTime(c.checkedAt),
		ok: c.ok,
		rtt: c.rttMs,
		reasonLabel: c.ok ? "" : reasonLabel(c.reason, c.detail),
		detail: c.detail,
		probe: describeProbe(c),
	}));

	const reports = await listReports(db, ip, MAX_REPORT_ROWS);
	for (const rep of reports) {
		if (rep.verdict) data.usableCount++;
		else data.unusableCount++;
	}
	data.reports = reports.map((rep: IPReport) => ({
		time: formatTime(rep.createdAt),
		verdict: rep.verdict,
		reporterPrefix: rep.reporterPrefix,
		reporterASN: rep.reporterASN,
		reporterASName: rep.reporterASName,
		comment: rep.comment,
	}));
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
<td colspan="2">${data.city ? `${escapeHTML(data.city)}, ${escapeHTML(data.country)}` : "<i>Airport code not in database, cannot estimate</i>"}</td>
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
		: "<i>(no PTR record)</i>";

	const locationRows = data.matched
		? `<tr>
<td>Airport Code</td>
<td><tt>${escapeHTML(data.airportCode)}</tt></td>
</tr>
<tr>
<td>Estimated Location</td>
<td>${data.city ? `${escapeHTML(data.city)}, ${escapeHTML(data.country)}` : "<i>Airport code not in database, cannot estimate</i>"}</td>
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

	const checksTable = data.checks.length
		? `<p></p>
<div class="gwsdb-scroll">
<table border="1" cellpadding="4" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="5"><b>Check History</b> (last ${data.checks.length} checks, including the probe request sent at the time)</td></tr>
<tr bgcolor="#EEEEEE"><td><b>Time</b></td><td><b>Result</b></td><td><b>Reason</b></td><td><b>Probe Request</b></td><td><b>RTT</b></td></tr>
${data.checks
	.map(
		(c) => `<tr>
<td>${escapeHTML(c.time)}</td>
<td>${c.ok ? `<font color="#008000">&#x2713; Reachable</font>` : `<font color="#CC0000">&#x2717; Unreachable</font>`}</td>
<td>${c.reasonLabel ? escapeHTML(c.reasonLabel) : "-"}</td>
<td><font size="-1">${c.probe ? `${escapeHTML(c.probe)}<br>` : ""}${c.detail ? `<tt>${escapeHTML(c.detail)}</tt>` : ""}</font></td>
<td>${c.rtt ? `${c.rtt} ms` : "-"}</td>
</tr>`,
	)
	.join("\n")}
</table>
</div>`
		: "";

	const reportsTable = data.reports.length
		? `<p></p>
<div class="gwsdb-scroll">
<table border="1" cellpadding="4" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="5"><b>社区报告</b>（${data.usableCount} 可用 / ${data.unusableCount} 不可用）</td></tr>
<tr bgcolor="#EEEEEE"><td><b>时间</b></td><td><b>结论</b></td><td><b>前缀</b></td><td><b>AS</b></td><td><b>备注</b></td></tr>
${data.reports
	.map(
		(r) => `<tr>
<td>${escapeHTML(r.time)}</td>
<td>${r.verdict ? `<font color="#008000">&#x2713; 可用</font>` : `<font color="#CC0000">&#x2717; 不可用</font>`}</td>
<td><tt>${r.reporterPrefix ? escapeHTML(r.reporterPrefix) : "-"}</tt></td>
<td>${r.reporterASN ? `AS${r.reporterASN}${r.reporterASName ? ` ${escapeHTML(r.reporterASName)}` : ""}` : "-"}</td>
<td>${r.comment ? escapeHTML(r.comment) : "-"}</td>
</tr>`,
	)
	.join("\n")}
</table>
</div>`
		: "";

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
<tr bgcolor="#EEEEEE"><td colspan="2"><b>报告IP</b></td></tr>
<tr>
<td colspan="2">
<form method="POST" action="/report">
<input type="hidden" name="ip" value="${escapeHTML(data.query)}">
备注（可选）：<input type="text" name="comment" size="40" maxlength="500">
<button type="submit" name="verdict" value="usable">可用</button>
<button type="submit" name="verdict" value="unusable">不可用</button>
</form>
</td>
</tr>
</table>
</div>
${reportsTable}`;
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
	const q = (url.searchParams.get("ip") ?? "").trim();
	const data = emptyData(q);
	const dohUrl = context.env.DOH_JSON_URL || DEFAULT_DOH_URL;

	if (q === "") {
		// not submitted; render the empty form
	} else if (isIPAddress(q)) {
		data.submitted = true;
		const { info, ok } = await lookupGoogleASN(context.env.DB, q, ASN_TIMEOUT_MS, dohUrl);
		if (!ok || !isGoogleASN(info)) {
			data.error = "This IP does not belong to a Google ASN";
		} else {
			await lookupIPQuery(context.env.DB, q, dohUrl, data);
		}
	} else if (isHostname(q)) {
		data.submitted = true;
		data.queryIsHostname = true;
		await lookupHostnameQuery(context.env.DB, q, dohUrl, data);
	} else {
		data.submitted = true;
		data.error = "Not a valid IP address or 1e100.net hostname";
	}

	const build = buildInfoFromEnv(context.env.CF_PAGES_COMMIT_SHA);
	const html = pageShell({ title: "Query", body: renderQueryBody(data), build });
	return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
};
