// Pages Function for POST /report -- ports internal/web/server.go's
// handleReport/maybeEnqueueRecheck/sameOrigin/clientIP +
// templates/report_confirm.tmpl.
import { timingSafeEqual } from "../src/auth";
import { isGoogleASN, lookupGoogleASN } from "../src/dnsCache";
import { buildInfoFromEnv, escapeHTML, pageShell } from "../src/html";
import { isIPAddress } from "../src/ipAddr";
import { enqueueRecheck, ipStatusFor, saveReport } from "../src/store";
import type { Env } from "../src/env";

const ASN_TIMEOUT_MS = 3000;
const MAX_REPORT_COMMENT_LEN = 500;

// sameOrigin reports whether request's Origin (or, failing that, Referer)
// header names this same host -- a lightweight CSRF guard for the
// same-origin HTML form that's the only thing meant to POST here.
function sameOrigin(request: Request): boolean {
	const host = new URL(request.url).host;
	for (const header of ["Origin", "Referer"]) {
		const v = request.headers.get(header);
		if (v) {
			try {
				return new URL(v).host === host;
			} catch {
				return false;
			}
		}
	}
	return false;
}

// clientCountry reads Cloudflare's CF-IPCountry edge header, populated for
// every request that reaches a Pages Function -- unspoofable the same way
// CF-Connecting-IP is (see clientIP below).
function clientCountry(request: Request): string {
	return request.headers.get("CF-IPCountry") ?? "";
}

// clientIP extracts the real client address from Cloudflare's
// CF-Connecting-IP edge header -- always present and trustworthy for a
// Pages deployment, since there's no way to reach it except through
// Cloudflare's edge (unlike the Go binary, which also had to fall back to
// X-Forwarded-For/the raw socket peer for a self-hosted origin that might
// be reachable directly).
function clientIP(request: Request): string {
	const cf = request.headers.get("CF-Connecting-IP");
	if (cf) return cf;
	const xff = request.headers.get("X-Forwarded-For");
	if (xff) return xff.split(",")[0]!.trim();
	return "";
}

// maybeEnqueueRecheck schedules a re-scan of ip if either we've never
// tested it before and the report claims it's usable (a first look might
// gain us a working IP; an "unusable" claim about an IP nobody uses gains
// nothing) or this report postdates our last check of it and disagrees
// with what that check found.
async function maybeEnqueueRecheck(
	db: D1Database,
	reportId: number,
	ip: string,
	verdict: boolean,
	createdAt: Date,
): Promise<void> {
	const st = await ipStatusFor(db, ip);
	if (!st || !st.hasCheck) {
		if (!verdict) return;
	} else if (!(createdAt.getTime() > (st.lastCheckedAt?.getTime() ?? 0)) || verdict === st.lastCheckOk) {
		return;
	}
	await enqueueRecheck(db, reportId, ip, createdAt);
}

function renderConfirmBody(opts: {
	ip: string;
	verdict: boolean;
	// displayComment is what's shown in the table (blank for an operator-test
	// submission); formComment is what the hidden field resubmits on confirm
	// -- these must NOT be the same value for an operator-test submission, or
	// the token that made it one is lost before the confirm step can see it
	// again (see onRequestPost's comment on isOperatorTest).
	displayComment: string;
	formComment: string;
	reporterPrefix: string;
	reporterASN: number;
	reporterASName: string;
}): string {
	const verdictHTML = opts.verdict ? `<font color="#008000">&#x2713; 可用</font>` : `<font color="#CC0000">&#x2717; 不可用</font>`;
	return `<p><b>确认提交报告</b></p>

<div class="gwsdb-scroll">
<table border="1" cellpadding="6" cellspacing="0" width="100%">
<tr bgcolor="#EEEEEE"><td colspan="2"><b>以下内容将被存储并公开显示</b></td></tr>
<tr><td width="30%">目标IP</td><td><tt>${escapeHTML(opts.ip)}</tt></td></tr>
<tr><td>结论</td><td>${verdictHTML}</td></tr>
${opts.displayComment ? `<tr><td>备注</td><td>${escapeHTML(opts.displayComment)}</td></tr>` : ""}
<tr><td>你的前缀</td><td><tt>${opts.reporterPrefix ? escapeHTML(opts.reporterPrefix) : ""}</tt></td></tr>
<tr><td>你的AS</td><td>${opts.reporterASN ? `AS${opts.reporterASN}${opts.reporterASName ? ` ${escapeHTML(opts.reporterASName)}` : ""}` : ""}</td></tr>
</table>
</div>

<p><font color="#CC0000">你的IP地址路由公告前缀与AS号码将对查看此IP报告历史的任何人可见。</font></p>

<form method="POST" action="/report">
<input type="hidden" name="ip" value="${escapeHTML(opts.ip)}">
<input type="hidden" name="comment" value="${escapeHTML(opts.formComment)}">
<input type="hidden" name="confirm" value="1">
<button type="submit" name="verdict" value="${opts.verdict ? "usable" : "unusable"}">${opts.verdict ? "确认提交为可用" : "确认提交为不可用"}</button>
</form>
<p><a href="/query?ip=${encodeURIComponent(opts.ip)}">取消</a></p>`;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!sameOrigin(request)) {
		return new Response("cross-origin request rejected", { status: 403 });
	}
	if (clientCountry(request) !== "CN") {
		return new Response("forbidden", { status: 403 });
	}

	let form: FormData;
	try {
		form = await request.formData();
	} catch {
		return new Response("bad form", { status: 400 });
	}

	const ip = String(form.get("ip") ?? "").trim();
	if (!isIPAddress(ip)) {
		return new Response("invalid ip", { status: 400 });
	}

	const dohUrl = env.DOH_JSON_URL;
	const { info, ok } = await lookupGoogleASN(env.DB, ip, ASN_TIMEOUT_MS, dohUrl);
	if (!ok || !isGoogleASN(info)) {
		return new Response("this IP does not belong to a Google ASN", { status: 400 });
	}

	let verdict: boolean;
	switch (form.get("verdict")) {
		case "usable":
			verdict = true;
			break;
		case "unusable":
			verdict = false;
			break;
		default:
			return new Response("invalid verdict", { status: 400 });
	}

	let comment = String(form.get("comment") ?? "").trim();
	if (comment.length > MAX_REPORT_COMMENT_LEN) comment = comment.slice(0, MAX_REPORT_COMMENT_LEN);

	// Operator self-test escape hatch: the Go original could submit a report
	// from inside the LAN (bypassing Cloudflare, no public IP for the reporter
	// lookup to resolve) to test without publishing its own prefix/AS. There's
	// no equivalent bypass here -- every request has a real CF-Connecting-IP --
	// so pasting the ingest token into the comment field opts out of the
	// reporter lookup instead. Re-derived fresh on *every* request (both the
	// unconfirmed and confirm=1 POSTs) by comparing the raw comment timing-
	// safely -- comment itself is deliberately left untouched here (still
	// carries the token) so the hidden form field can resubmit it and the
	// confirm=1 request re-detects the same operator-test state; only
	// display/storage points below use a blanked copy, never this one.
	const isOperatorTest = timingSafeEqual(comment, env.INGEST_TOKEN);
	const storedComment = isOperatorTest ? "" : comment;

	// The reporter's address is used only to resolve their announced
	// prefix/AS; it is never persisted.
	let reporterPrefix = "";
	let reporterASN = 0;
	let reporterASName = "";
	if (!isOperatorTest) {
		const reporterIP = clientIP(request);
		if (reporterIP) {
			const r = await lookupGoogleASN(env.DB, reporterIP, ASN_TIMEOUT_MS, dohUrl);
			if (r.ok) {
				reporterPrefix = r.info.prefix;
				reporterASN = r.info.asn;
				reporterASName = r.info.asName;
			}
		}
	}

	const build = buildInfoFromEnv(env.CF_PAGES_COMMIT_SHA);

	// Require an explicit confirm step so the reporter sees what's about to
	// be published (their announced prefix/AS) before it's stored.
	if (form.get("confirm") !== "1") {
		const html = pageShell({
			title: "确认",
			body: renderConfirmBody({ ip, verdict, displayComment: storedComment, formComment: comment, reporterPrefix, reporterASN, reporterASName }),
			build,
			lang: "zh",
		});
		return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
	}

	const createdAt = new Date();
	const reportId = await saveReport(env.DB, {
		ip,
		verdict,
		comment: storedComment,
		reporterPrefix,
		reporterASN,
		reporterASName,
		createdAt,
	});
	await maybeEnqueueRecheck(env.DB, reportId, ip, verdict, createdAt);

	return Response.redirect(`${new URL(request.url).origin}/query?ip=${encodeURIComponent(ip)}`, 303);
};
