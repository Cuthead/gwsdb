// Global Pages Functions middleware -- ports internal/web/server.go's
// securityHeaders wrapper. Applies to every request (static assets included,
// via ctx.next() falling through to them). Response compression
// (internal/web/compress.go's zstd/gzip negotiation) is intentionally not
// ported: Cloudflare's edge already compresses HTML/CSS/JS in transit, which
// is the layer that custom logic existed to substitute for on the old
// origin-facing Go binary.
import type { Env } from "../src/env";

// contentSecurityPolicy locks the pages down to their own origin. Everything
// the pages need is served from /static/, so there is no 'unsafe-inline'
// here. connect-src allows the home page's JS to fetch /api/pool and
// /api/pool/version, plus cloudflare-dns.com for ptrResolve.js's
// client-side PTR lookups on rows the server hasn't cached yet.
const CONTENT_SECURITY_POLICY =
	"default-src 'none'; " +
	"img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self' https://cloudflare-dns.com; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

export const onRequest: PagesFunction<Env> = async (context) => {
	const response = await context.next();
	const headers = new Headers(response.headers);
	headers.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
	headers.set("X-Content-Type-Options", "nosniff");
	headers.set("X-Frame-Options", "DENY");
	// same-origin (not no-referrer) so a Referer still arrives on the future
	// /report POST (a usable CSRF signal), while outbound links to GitHub
	// disclose nothing.
	headers.set("Referrer-Policy", "same-origin");
	return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};
