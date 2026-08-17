export interface Env {
	DB: D1Database;
	// Bearer token the China-box scan/ingest script authenticates with.
	// Set via `wrangler pages secret put INGEST_TOKEN --project-name=gwsdb`.
	INGEST_TOKEN: string;
	// JSON-form DoH endpoint (Accept: application/dns-json) used for all DNS
	// resolution (PTR/host/ASN) -- see src/doh.ts. Set in wrangler.jsonc's
	// vars.
	DOH_JSON_URL: string;
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
	// Service binding to the gwsdb-probe Worker (worker/), which holds the
	// vpc_networks binding Pages can't and proxies probe requests to the
	// China box's internal probe server via Cloudflare Mesh. See
	// worker/src/index.ts.
	PROBE_PROXY: Fetcher;
	// Shared secret authenticating the Pages -> probe Worker -> probe server
	// chain. Must match the -probe-token the China box's `gwsdb scan -worker`
	// was started with. Set via `wrangler pages secret put PROBE_TOKEN`
	// (Pages) and `wrangler secret put PROBE_TOKEN` (worker/).
	PROBE_TOKEN: string;
	// Injected automatically by Cloudflare Pages at request time (see
	// src/html.ts's buildInfoFromEnv) -- not set in wrangler.jsonc.
	CF_PAGES_COMMIT_SHA?: string;
	CF_PAGES_BRANCH?: string;
	CF_PAGES_URL?: string;
}
