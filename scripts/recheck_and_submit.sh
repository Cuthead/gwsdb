#!/usr/bin/env bash
# Drain the due recheck_queue backlog from the gwsdb Pages project (Cloudflare
# Pages + D1 -- see AGENTS.md) and probe each item, same as scan_and_ingest.sh
# but for report-triggered rechecks instead of a full scan. Intended to be
# invoked from cron (e.g. every 5 minutes) on the scanning box; the probe
# itself must stay on real China-based network infrastructure (Cloudflare's
# edge doesn't sit behind the GFW), but storage and queue coordination now
# live on Cloudflare.
#
# GWSDB_API/GWSDB_INGEST_TOKEN aren't required here -- `gwsdb` itself reads
# them from the environment or, if unset, from ~/.config/gwsdb/env (see
# `gwsdb -h`), so there's nowhere else they need to be exported.
set -euo pipefail

BIN_DIR="${GWSDB_BIN_DIR:-$HOME/gwsdb}"

"$BIN_DIR/gwsdb" recheck -worker
