#!/usr/bin/env bash
# Run the gscan_quic scanner once, then upload its config + captured log to
# the gwsdb Pages project's /ingest Function (Cloudflare Pages + D1 -- see
# AGENTS.md). Intended to be invoked from cron (e.g. daily) on the scanning
# box; the scan/recheck probe itself must stay on real China-based network
# infrastructure (Cloudflare's edge doesn't sit behind the GFW), but storage
# and ingest now live on Cloudflare.
#
# Required env vars beyond the GWSDB_* ones below:
#   GWSDB_API           base URL of the deployed Pages project, e.g. https://gwsdb.pages.dev
#   GWSDB_INGEST_TOKEN   bearer token matching the Pages project's INGEST_TOKEN secret
set -euo pipefail

SCANNER_DIR="${GWSDB_SCANNER_DIR:-$HOME/gscan_quic}"
SCANNER_CONFIG="${GWSDB_SCAN_CONFIG:-$SCANNER_DIR/config.user.json}"
: "${GWSDB_API:?GWSDB_API (Pages project base URL) is required}"
: "${GWSDB_INGEST_TOKEN:?GWSDB_INGEST_TOKEN is required}"

LOG_DIR="$SCANNER_DIR/scan_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"

cd "$SCANNER_DIR"
sudo ./gscan_quic -Config "$SCANNER_CONFIG" < /dev/null > >(tee "$LOG_FILE") 2>&1 &
trap 'sudo pkill -TERM gscan_quic 2>/dev/null; wait; rm -f "$LOG_FILE" "$LOG_FILE.gz"; exit 130' INT TERM
wait || true
trap - INT TERM

gzip -c "$LOG_FILE" > "$LOG_FILE.gz"
curl -sf -X POST "$GWSDB_API/ingest" \
	-H "Authorization: Bearer $GWSDB_INGEST_TOKEN" \
	-F "config=@$SCANNER_CONFIG" \
	-F "log=@$LOG_FILE.gz;type=application/gzip" \
	&& rm "$LOG_FILE" "$LOG_FILE.gz"
