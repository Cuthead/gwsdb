#!/usr/bin/env bash
# Run the gscan_quic scanner once, then hand its config + captured log to
# `gwsdb ingest`, which parses the log locally (internal/ingest -- real
# compute on the box, no need to ship the log anywhere) and submits the
# filtered result to the gwsdb Pages project's /ingest Function (Cloudflare
# Pages + D1 -- see AGENTS.md). Intended to be invoked from cron (e.g. daily)
# on the scanning box; the scan/recheck probe itself must stay on real
# China-based network infrastructure (Cloudflare's edge doesn't sit behind
# the GFW), but storage lives on Cloudflare.
#
# Required env vars:
#   GWSDB_API            base URL of the deployed Pages project, e.g. https://gwsdb.pages.dev
#   GWSDB_INGEST_TOKEN    bearer token matching the Pages project's INGEST_TOKEN secret
set -euo pipefail

SCANNER_DIR="${GWSDB_SCANNER_DIR:-$HOME/gscan_quic}"
SCANNER_CONFIG="${GWSDB_SCAN_CONFIG:-$SCANNER_DIR/config.user.json}"
BIN_DIR="${GWSDB_BIN_DIR:-$HOME/gwsdb}"
: "${GWSDB_API:?GWSDB_API (Pages project base URL) is required}"
: "${GWSDB_INGEST_TOKEN:?GWSDB_INGEST_TOKEN is required}"

LOG_DIR="$SCANNER_DIR/scan_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"

cd "$SCANNER_DIR"
sudo ./gscan_quic -Config "$SCANNER_CONFIG" < /dev/null > >(tee "$LOG_FILE") 2>&1 &
trap 'sudo pkill -TERM gscan_quic 2>/dev/null; wait; rm -f "$LOG_FILE"; exit 130' INT TERM
wait || true
trap - INT TERM

"$BIN_DIR/gwsdb" ingest -scanner-config "$SCANNER_CONFIG" -log "$LOG_FILE" \
	&& rm "$LOG_FILE"
