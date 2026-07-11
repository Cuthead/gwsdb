#!/usr/bin/env bash
# Drain the due recheck_queue backlog from the gwsdb Pages project (Cloudflare
# Pages + D1 -- see AGENTS.md) and probe each item, same as scan_and_ingest.sh
# but for report-triggered rechecks instead of a full scan. Intended to be
# invoked from cron (e.g. every 5 minutes) on the scanning box; the probe
# itself must stay on real China-based network infrastructure (Cloudflare's
# edge doesn't sit behind the GFW), but storage and queue coordination now
# live on Cloudflare.
#
# Required env vars:
#   GWSDB_API            base URL of the deployed Pages project, e.g. https://gwsdb.pages.dev
#   GWSDB_INGEST_TOKEN    bearer token matching the Pages project's INGEST_TOKEN secret
set -euo pipefail

BIN_DIR="${GWSDB_BIN_DIR:-$HOME/gwsdb}"
: "${GWSDB_API:?GWSDB_API (Pages project base URL) is required}"
: "${GWSDB_INGEST_TOKEN:?GWSDB_INGEST_TOKEN is required}"

"$BIN_DIR/gwsdb" recheck -worker
