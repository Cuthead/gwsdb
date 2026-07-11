// Shared HTML helpers for the Pages Functions that render pages directly
// (functions/index.ts, functions/scans.ts), replacing internal/web's
// html/template-based rendering (templates/*.tmpl). Go's html/template
// auto-escapes every interpolated value; nothing here does that for us, so
// escapeHTML() must be applied to every dynamic value before it goes into a
// template string -- PTR hostnames in particular come from reverse-DNS
// data, not trusted input (the same reasoning static/home.js's buildRow
// already documents for the client-side render).

export function escapeHTML(s: string): string {
	return s
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

export const repoURL = "https://github.com/cuthead/gwsdb";

// crawlerUAs are substrings (matched case-insensitively) identifying
// well-known bots and web archivers -- mirrors internal/web/server.go's
// crawlerUAs/isCrawlerUA. These skip the client-side fetch-and-cache path
// for two reasons: search/social crawlers commonly don't execute JS at all,
// and an archiver's JS -- if it does run -- would replay later against a
// live /api/pool that may no longer reflect (or even reach) the state at
// capture time, leaving the archived snapshot showing a blank shell instead
// of the list it captured.
const crawlerUAs = [
	"bot",
	"crawl",
	"spider",
	"slurp",
	"archiver",
	"archive.org",
	"archive.ph",
	"archive.today",
	"heritrix",
	"facebookexternalhit",
	"embedly",
	"quora link preview",
	"outbrain",
	"pinterest",
	"whatsapp",
	"telegrambot",
];

export function isCrawlerUA(ua: string): boolean {
	const lower = ua.toLowerCase();
	return crawlerUAs.some((s) => lower.includes(s));
}

export interface BuildInfo {
	revision: string; // short (7-char) commit sha, "" if unknown
	commitURL: string; // "" if unknown
}

// buildInfoFromEnv derives the footer's build stamp from the CF_PAGES_*
// vars Cloudflare Pages injects automatically at request time (seen in the
// `wrangler pages dev` binding list). There's no equivalent build-date env
// var, so unlike the Go original's footer (which showed a VCS timestamp),
// this omits the date rather than fabricate one.
export function buildInfoFromEnv(commitSha: string | undefined): BuildInfo {
	if (!commitSha) return { revision: "", commitURL: "" };
	return { revision: commitSha.slice(0, 7), commitURL: `${repoURL}/commit/${commitSha}` };
}

function footerHTML(build: BuildInfo): string {
	if (build.revision) {
		return `commit <a href="${escapeHTML(build.commitURL)}">${escapeHTML(build.revision)}</a>`;
	}
	return `<a href="${repoURL}">gwsdb</a>`;
}

// NAV_EN/NAV_ZH are the two nav-bar variants used across the site.
// report_confirm.tmpl is Chinese (<html lang="zh">, "首页/查询/扫描记录") while
// every other page is English -- documented as intentional per-page i18n in
// AGENTS.md, not a bug to normalize away.
const NAV_EN = { home: "Home", query: "Query", scans: "Scans" };
const NAV_ZH = { home: "首页", query: "查询", scans: "扫描记录" };

// pageShell wraps body in the same table-based chrome (title bar, nav,
// footer) shared by home.tmpl/scans.tmpl/query.tmpl. extraHead is injected
// verbatim into <head> (e.g. home.tmpl's <noscript> refresh meta tag).
// lang defaults to "en" (NAV_EN); pass "zh" for report_confirm's Chinese
// chrome (NAV_ZH).
export function pageShell(opts: { title: string; body: string; build: BuildInfo; extraHead?: string; lang?: "en" | "zh" }): string {
	const lang = opts.lang ?? "en";
	const nav = lang === "zh" ? NAV_ZH : NAV_EN;
	return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${opts.extraHead ?? ""}
<title>${escapeHTML(opts.title)} - GWS Database</title>
<link rel="stylesheet" href="/static/gwsdb.css">
</head>
<body bgcolor="#FFFFFF" text="#000000" link="#0000EE" vlink="#551A8B">
<center>
<table border="0" cellpadding="4" cellspacing="0" class="gwsdb-wrap">
<tr bgcolor="#000080">
<td><font color="#FFFFFF" face="Arial,Helvetica,sans-serif" size="+1"><b>GWS Database</b></font></td>
</tr>
<tr bgcolor="#DDDDDD">
<td>
<font face="Arial,Helvetica,sans-serif" size="-1">
<a href="/">${nav.home}</a> |
<a href="/query">${nav.query}</a> |
<a href="/scans">${nav.scans}</a>
</font>
</td>
</tr>
<tr>
<td>
<font face="Arial,Helvetica,sans-serif" size="-1">
${opts.body}
</font>
</td>
</tr>
<tr bgcolor="#DDDDDD">
<td align="center">
<font face="Arial,Helvetica,sans-serif" size="-2" color="#666666">
${footerHTML(opts.build)}
</font>
</td>
</tr>
</table>
</center>
</body>
</html>
`;
}

// formatTime renders a Date the way internal/web/server.go's formatTime
// does ("-" for null, otherwise "YYYY-MM-DD HH:mm:ss"), except in UTC
// rather than the Go binary's host-local time zone -- a Worker has no
// meaningful "local" time zone of its own (see src/logParser.ts's
// parseLogTimestamp comment for the same issue on the ingest side).
export function formatTime(d: Date | null): string {
	if (!d) return "-";
	const pad = (n: number) => String(n).padStart(2, "0");
	return (
		`${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
		`${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
	);
}
