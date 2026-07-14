// Pages Function for GET /privacy -- static content, no DB access. Content
// is derived from what the codebase actually collects/stores (see D1
// migrations/*.sql and functions/report.ts, functions/ingest.ts): there is
// no analytics, no cookies, no accounts anywhere in this site.
import { buildInfoFromEnv, pageShell } from "../src/html";
import type { Env } from "../src/env";

const BODY = `<h2>Privacy Policy</h2>

<p>GWS Database (gwsdb) is a community-maintained record of which Google
Web Server (GWS) IPs are reachable from China. This page describes exactly
what the site collects, in plain terms, based on how it's actually built.</p>

<h3>What this site does not have</h3>
<p>No accounts, no sign-in, no cookies, no analytics scripts, no ad
trackers. There is nothing to opt out of.</p>

<p>The home page does use your browser's <code>localStorage</code> -- not
for tracking, but to cache the public IP list itself (the same data
<code>/api/pool</code> serves) so a repeat visit can render instantly
without refetching it. It holds no information about you, only about
Google's servers, and clearing it just means the next visit re-fetches the
list.</p>

<h3>Hosting logs (every visitor)</h3>
<p>The site runs on Cloudflare Pages. Like any web host, Cloudflare's edge
sees the standard connection metadata for each request (IP address, country,
user agent, etc.) as part of serving the page; this is Cloudflare's own
infrastructure logging, governed by Cloudflare's privacy policy, not
something this application stores or processes further. The application
code itself reads only the <code>CF-IPCountry</code> header, and only to
decide whether to show the report form (see below) -- that value is never
written to the database.</p>

<h3>Looking up an IP or hostname (/query)</h3>
<p>Queries are answered live (or from a shared DNS cache keyed by the IP or
hostname you looked up, not by who asked). Nothing about who ran a query is
stored. If the PTR record for the address you looked up isn't already
cached on the server, your browser resolves it directly against
Cloudflare's public DNS-over-HTTPS resolver (<code>cloudflare-dns.com</code>)
-- the same party already fronting this site, not a new third party --
which is a standard DNS request visible to that resolver like any other DNS
lookup your browser makes.</p>

<h3>Submitting a report (/report, mainland China only)</h3>
<p>A report stores: the IP address you're reporting on, your usable/unusable
verdict, and an optional free-text comment (please don't put personal
information in it -- it's shown publicly). It also stores the network
prefix and AS number your own connection is announced from (e.g. "AS4134
CHINANET-BACKBONE"), looked up from your request's source IP at submission
time -- this identifies your ISP/network, not you personally, and is shown
publicly next to the report so other visitors can judge how representative
it is. Your raw IP address itself is never written to this site's database,
but that lookup works by embedding it in a DNS query (Team Cymru's DNS
whois service, via the same Cloudflare DoH resolver used elsewhere on this
site) -- so your IP is visible to Cloudflare and Team Cymru as part of
resolving it, the same way it would be to any DNS resolver you use
normally.</p>

<h3>Scan and check history</h3>
<p>The reachability history shown throughout the site (which IPs work, since
when, at what latency) comes from the site operator's own scanning
infrastructure submitting results over an authenticated, bearer-token-only
endpoint. This data describes Google's server IPs, not site visitors.</p>

<h3>Data retention</h3>
<p>Reports and check history are kept indefinitely -- they're the historical
record this site exists to publish. Cached DNS lookups (PTR/forward/ASN)
expire and are refreshed automatically per their DNS TTL.</p>

<h3>Questions or removal requests</h3>
<p>If you accidentally included personal information in a report comment
and want it removed, or have any other question, open an issue on
<a href="https://github.com/cuthead/gwsdb">the project's GitHub repo</a>.</p>
`;

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const build = buildInfoFromEnv(context.env.CF_PAGES_COMMIT_SHA);
	const html = pageShell({
		title: "Privacy Policy",
		body: BODY,
		build,
		description: "What GWS Database collects and stores, and what it doesn't.",
	});
	return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
};
