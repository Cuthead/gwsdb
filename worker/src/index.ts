// gwsdb-probe: a thin VPC proxy Worker. Pages Functions can't bind
// vpc_networks (Pages rejects the field), so this standalone Worker holds
// the VPC binding and proxies probe requests to the China box's internal
// probe server via Cloudflare Mesh (cf1:network). The Pages project calls
// it through a service binding (PROBE_PROXY), so this Worker has no public
// workers.dev URL (workers_dev: false in wrangler.jsonc).
export interface Env {
	PROBE_NETWORK: Fetcher;
	PROBE_ADDR: string;
	PROBE_TOKEN: string;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		if (request.method !== "POST") {
			return new Response("method not allowed", { status: 405 });
		}
		// Shared-secret auth — even though service bindings are internal,
		// this guards against any other Worker in the account binding to
		// this one and driving probes.
		if (request.headers.get("X-Probe-Token") !== env.PROBE_TOKEN) {
			return new Response("unauthorized", { status: 401 });
		}
		const body = (await request.json()) as { ip?: string };
		if (!body.ip) {
			return new Response("missing ip", { status: 400 });
		}
		// VPC fetch the China box's probe server. The host is the China
		// box's private IP (reachable via Cloudflare Mesh), port matches
		// `gwsdb scan -worker`'s -probe-addr.
		return env.PROBE_NETWORK.fetch(`http://${env.PROBE_ADDR}/probe`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Probe-Token": env.PROBE_TOKEN,
			},
			body: JSON.stringify({ ip: body.ip }),
		});
	},
};
