// Pages Function for GET /api/pool/version -- ports
// internal/web/server.go's handleAPIPoolVersion: a single cheap query the
// home page's JS polls to decide, without refetching the full payload,
// whether its localStorage-cached copy of /api/pool is still current.
import { poolVersion } from "../../../src/store";
import type { Env } from "../../../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const version = await poolVersion(context.env.DB);
	return Response.json({ version }, { headers: { "Cache-Control": "no-store" } });
};
