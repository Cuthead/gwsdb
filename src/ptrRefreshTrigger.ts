// Asks the standalone cron-ptr-refresh Worker (see its own module comment)
// to run its round-robin PTR refresh immediately, instead of waiting for a
// timer -- functions/ingest.ts calls this via context.waitUntil right after
// writing new IPs, so a fresh scan's newly-discovered IPs (ptr_checked_at
// NULL, which pendingIPsForPTRRefresh sorts first) get PTR-resolved within
// the same run rather than up to a day later. A no-op if PTR_REFRESH_URL
// isn't configured -- same off-by-default gate DNS_PUBLISH_NAME uses.
import type { Env } from "./env";

export async function triggerPTRRefresh(env: Env): Promise<void> {
	if (!env.PTR_REFRESH_URL) return;
	const resp = await fetch(env.PTR_REFRESH_URL, {
		headers: { Authorization: `Bearer ${env.PTR_REFRESH_SECRET}` },
	});
	if (!resp.ok) throw new Error(`ptr-refresh trigger: ${resp.status} ${await resp.text()}`);
}
