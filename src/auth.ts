// Shared bearer-token auth for endpoints the China box calls (ingest,
// recheck pull/submit) -- all guarded by the same INGEST_TOKEN secret, since
// it's the same box and the same trust boundary.
import type { Env } from "./env";

export function timingSafeEqual(a: string, b: string): boolean {
	const enc = new TextEncoder();
	const aBytes = enc.encode(a);
	const bBytes = enc.encode(b);
	if (aBytes.length !== bBytes.length) return false;
	let diff = 0;
	for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i]! ^ bBytes[i]!;
	return diff === 0;
}

export function checkBearerAuth(request: Request, env: Env): boolean {
	const auth = request.headers.get("Authorization") ?? "";
	if (!auth.startsWith("Bearer ")) return false;
	return timingSafeEqual(auth.slice("Bearer ".length), env.INGEST_TOKEN);
}
