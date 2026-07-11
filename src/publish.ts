// Ports internal/publish/publish.go: maintains a small set of DNS records on
// Cloudflare that point at the currently best-known GWS IPs. Reads the top
// IPs per address family from D1, diffs them against the records already on
// file for the target name, and applies only the difference -- an unchanged
// top set makes no write calls. Triggered from functions/ingest.ts and
// functions/recheck/result.ts via context.waitUntil, not a timer.
import { topIPsForPublish } from "./store";
import type { Env } from "./env";

const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";
const DEFAULT_TTL = 300;
const DEFAULT_LIMIT = 4;

interface DNSRecord {
	id: string;
	content: string;
}

interface CFError {
	code: number;
	message: string;
}

interface CFResponse<T> {
	success: boolean;
	errors: CFError[];
	result: T;
}

function cfErr(op: string, errors: CFError[]): Error {
	if (errors.length === 0) return new Error(`${op}: cloudflare reported failure with no error detail`);
	return new Error(`${op}: cloudflare error ${errors[0]!.code}: ${errors[0]!.message}`);
}

// syncPublish reconciles both A and AAAA records for env.DNS_PUBLISH_NAME.
// A no-op if DNS_PUBLISH_NAME is unset -- publishing stays off until
// configured, mirroring Go's Config.Name gate. Errors from one family don't
// abort the other; the first error seen is thrown.
export async function syncPublish(env: Env, db: D1Database): Promise<void> {
	if (!env.DNS_PUBLISH_NAME) return;

	let firstErr: unknown;
	for (const { family, dnsType } of [
		{ family: 4 as const, dnsType: "A" },
		{ family: 6 as const, dnsType: "AAAA" },
	]) {
		try {
			await syncFamily(env, db, family, dnsType);
		} catch (err) {
			firstErr ??= err;
		}
	}
	if (firstErr) throw firstErr;
}

async function syncFamily(env: Env, db: D1Database, family: 4 | 6, dnsType: string): Promise<void> {
	const limit = env.DNS_PUBLISH_LIMIT ? parseInt(env.DNS_PUBLISH_LIMIT, 10) : DEFAULT_LIMIT;
	const want = await topIPsForPublish(db, family, limit);
	const wantSet = new Set(want);

	const have = await listRecords(env, dnsType);
	const haveByContent = new Map(have.map((r) => [r.content, r.id]));

	for (const ip of wantSet) {
		if (!haveByContent.has(ip)) {
			await createRecord(env, dnsType, ip);
		}
	}
	for (const [content, id] of haveByContent) {
		if (!wantSet.has(content)) {
			await deleteRecord(env, id);
		}
	}
}

async function cfFetch<T>(env: Env, method: string, url: string, body?: unknown): Promise<T> {
	const resp = await fetch(url, {
		method,
		headers: {
			Authorization: `Bearer ${env.CLOUDFLARE_DNS_API_TOKEN}`,
			"Content-Type": "application/json",
		},
		body: body !== undefined ? JSON.stringify(body) : undefined,
	});
	return (await resp.json()) as T;
}

async function listRecords(env: Env, dnsType: string): Promise<DNSRecord[]> {
	const url = `${CLOUDFLARE_API_BASE}/zones/${env.DNS_PUBLISH_ZONE_ID}/dns_records?type=${dnsType}&name=${encodeURIComponent(env.DNS_PUBLISH_NAME!)}`;
	const body = await cfFetch<CFResponse<DNSRecord[]>>(env, "GET", url);
	if (!body.success) throw cfErr("list", body.errors);
	return body.result;
}

async function createRecord(env: Env, dnsType: string, content: string): Promise<void> {
	const url = `${CLOUDFLARE_API_BASE}/zones/${env.DNS_PUBLISH_ZONE_ID}/dns_records`;
	const ttl = env.DNS_PUBLISH_TTL ? parseInt(env.DNS_PUBLISH_TTL, 10) : DEFAULT_TTL;
	const body = await cfFetch<CFResponse<unknown>>(env, "POST", url, {
		type: dnsType,
		name: env.DNS_PUBLISH_NAME,
		content,
		ttl,
		proxied: false, // must resolve to the real Google IP, not a CF proxy
	});
	if (!body.success) throw cfErr("create", body.errors);
}

async function deleteRecord(env: Env, id: string): Promise<void> {
	const url = `${CLOUDFLARE_API_BASE}/zones/${env.DNS_PUBLISH_ZONE_ID}/dns_records/${id}`;
	const body = await cfFetch<CFResponse<unknown>>(env, "DELETE", url);
	if (!body.success) throw cfErr("delete", body.errors);
}
