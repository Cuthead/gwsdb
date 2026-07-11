export interface Env {
	DB: D1Database;
	// Bearer token the China-box scan/ingest script authenticates with.
	// Set via `wrangler pages secret put INGEST_TOKEN --project-name=gwsdb`.
	INGEST_TOKEN: string;
	// Minutes east of UTC the scanning box's log timestamps are in --
	// defaults to 480 (China Standard Time, no DST). See logParser.ts's
	// parseLogTimestamp for why this can't just be assumed as the Worker's
	// own timezone.
	LOG_TZ_OFFSET_MINUTES?: string;
}
