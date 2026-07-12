// Separate small Workers project (own wrangler.jsonc, same D1 database as
// the gwsdb Pages project) running a Cron Trigger -- ports
// internal/web/server.go's StartPTRRefresher. Pages Functions have no
// scheduled-execution primitive, so this can't live in the Pages project
// itself. Runs every minute (see wrangler.jsonc), each tick refreshing the
// MAX_REFRESHED_PER_RUN IPs with the oldest ptr_checked_at -- round-robin
// over the whole ip_pool, not TTL-based staleness (see pendingIPsForPTRRefresh's
// module comment in src/store.ts and migration 0005).
import { resolveAndCachePTR } from "../src/dnsCache";
import { pendingIPsForPTRRefresh } from "../src/store";

interface Env {
	DB: D1Database;
	// Same JSON-form DoH endpoint as the Pages project -- see src/doh.ts.
	DOH_JSON_URL?: string;
}

const PTR_TIMEOUT_MS = 3000;
const DEFAULT_DOH_URL = "https://dns.google/resolve";
// Caps a single invocation well under the Workers Free plan's 50
// subrequests-per-invocation limit (D1 calls count as subrequests too, same
// as fetch) -- each refreshed IP costs one DoH fetch (resolveAndCachePTR)
// plus one D1 batch() write (savePTR), so 20 IPs + the 1 D1 read
// pendingIPsForPTRRefresh itself stays comfortably under 50. Confirmed the
// hard way: with a real multi-thousand-row backlog, 200 tripped
// "Too many subrequests by single Worker invocation". Any remainder is
// picked up on the next tick.
const MAX_REFRESHED_PER_RUN = 20;

export default {
	async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
		const dohUrl = env.DOH_JSON_URL || DEFAULT_DOH_URL;
		// Fetched once per tick, not once per IP -- see pendingIPsForPTRRefresh's
		// module comment (src/store.ts) for why looping a per-IP query here
		// used to be expensive.
		const ips = await pendingIPsForPTRRefresh(env.DB, MAX_REFRESHED_PER_RUN);
		for (const ip of ips) {
			await resolveAndCachePTR(env.DB, ip, PTR_TIMEOUT_MS, dohUrl);
		}
		console.log(`ptr-refresh: refreshed ${ips.length} IP(s)`);
	},
} satisfies ExportedHandler<Env>;
