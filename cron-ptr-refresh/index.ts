// Separate small Workers project (own wrangler.jsonc, same D1 database as
// the gwsdb Pages project) running a Cron Trigger -- ports
// internal/web/server.go's StartPTRRefresher. Pages Functions have no
// scheduled-execution primitive, so this can't live in the Pages project
// itself. Unlike Go's one-IP-per-15-second-tick loop, this drains the
// entire stale/missing ptr_cache backlog (capped) once per 15-minute tick,
// since running the same "one per tick" shape on a 15-minute cron would
// take forever to converge on a real backlog.
import { resolveAndCachePTR } from "../src/dnsCache";
import { nextIPForPTRRefresh } from "../src/store";

interface Env {
	DB: D1Database;
	// Same JSON-form DoH endpoint as the Pages project -- see src/doh.ts.
	DOH_JSON_URL?: string;
}

const PTR_TIMEOUT_MS = 3000;
const DEFAULT_DOH_URL = "https://dns.google/resolve";
// Caps a single invocation so a large first-run backlog can't blow the
// Workers CPU-time limit -- any remainder is picked up on the next tick.
const MAX_REFRESHED_PER_RUN = 200;

export default {
	async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
		const dohUrl = env.DOH_JSON_URL || DEFAULT_DOH_URL;
		let refreshed = 0;
		for (; refreshed < MAX_REFRESHED_PER_RUN; refreshed++) {
			const ip = await nextIPForPTRRefresh(env.DB);
			if (!ip) break;
			await resolveAndCachePTR(env.DB, ip, PTR_TIMEOUT_MS, dohUrl);
		}
		console.log(`ptr-refresh: refreshed ${refreshed} IP(s)`);
	},
} satisfies ExportedHandler<Env>;
