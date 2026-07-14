// clientCountry reads Cloudflare's CF-IPCountry edge header, populated for
// every request that reaches a Pages Function -- unspoofable the same way
// CF-Connecting-IP is. Shared by functions/report.ts (which enforces it) and
// functions/query.ts (which uses it to decide whether to show the report
// form at all).
export function clientCountry(request: Request): string {
	return request.headers.get("CF-IPCountry") ?? "";
}
