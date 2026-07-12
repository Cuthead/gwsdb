// Pages Function for POST /delete-scan -- gwsdb delete-scan (ops CLI on the
// China box) uses this instead of a local sqlite file, same as ingest/
// recheck. Bearer-authed with the same INGEST_TOKEN -- one box, one trust
// boundary.
import { checkBearerAuth } from "../src/auth";
import { deleteScan } from "../src/store";
import type { Env } from "../src/env";

interface DeleteScanBody {
	id: number;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
	const { request, env } = context;
	if (!checkBearerAuth(request, env)) {
		return new Response("unauthorized", { status: 401 });
	}

	let body: DeleteScanBody;
	try {
		body = await request.json();
	} catch {
		return new Response("invalid JSON body", { status: 400 });
	}
	if (typeof body.id !== "number" || body.id <= 0) {
		return new Response("id is required", { status: 400 });
	}

	await deleteScan(env.DB, body.id);
	return Response.json({});
};
