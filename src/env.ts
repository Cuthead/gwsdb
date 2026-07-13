export interface Env {
	DB: D1Database;
	// Bearer token the China-box scan/ingest script authenticates with.
	// Set via `wrangler pages secret put INGEST_TOKEN --project-name=gwsdb`.
	INGEST_TOKEN: string;
	// JSON-form DoH endpoint (Accept: application/dns-json) used for all DNS
	// resolution (PTR/host/ASN) -- see src/doh.ts. Defaults to
	// "https://dns.google/resolve" in code if unset, same provider as the Go
	// original's defaultDoHURL.
	DOH_JSON_URL?: string;
	// DNS publish (src/publish.ts) -- reconciles A/AAAA records at
	// DNS_PUBLISH_NAME to the store's current top IPs. Publishing stays off
	// unless DNS_PUBLISH_NAME is set, mirroring Go's Config.Name gate.
	DNS_PUBLISH_NAME?: string;
	DNS_PUBLISH_ZONE_ID?: string;
	DNS_PUBLISH_TTL?: string;
	DNS_PUBLISH_LIMIT?: string;
	// Bearer token for the Cloudflare API (DNS-edit permission on the zone
	// above). Set via `wrangler pages secret put CLOUDFLARE_DNS_API_TOKEN`.
	CLOUDFLARE_DNS_API_TOKEN: string;
	// On-demand PTR refresh trigger (src/ptrRefreshTrigger.ts) -- the
	// cron-ptr-refresh Worker's fetch URL (e.g. its workers.dev URL) and the
	// bearer secret it expects, must match that Worker's REFRESH_SECRET. URL
	// is a plain var (wrangler.jsonc); secret via
	// `wrangler pages secret put PTR_REFRESH_SECRET`. Triggering stays off
	// unless PTR_REFRESH_URL is set, same gate DNS_PUBLISH_NAME uses.
	PTR_REFRESH_URL?: string;
	PTR_REFRESH_SECRET?: string;
	// Injected automatically by Cloudflare Pages at request time (see
	// src/html.ts's buildInfoFromEnv) -- not set in wrangler.jsonc.
	CF_PAGES_COMMIT_SHA?: string;
	CF_PAGES_BRANCH?: string;
	CF_PAGES_URL?: string;
}
