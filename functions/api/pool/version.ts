// Pages Function for GET /api/pool/version -- ports
// internal/web/server.go's handleAPIPoolVersion: a single cheap query the
// lightweight version signal retained for API consumers. The home page now
// asks /api/pool/changes directly, which returns this version with its delta.
import { poolVersion } from "../../../src/store";
import type { Env } from "../../../src/env";

export const onRequestGet: PagesFunction<Env> = async (context) => {
	const version = await poolVersion(context.env.DB);
	return Response.json({ version }, { headers: { "Cache-Control": "no-store" } });
};
