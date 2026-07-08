#!/usr/bin/env bash
# Run the gscan_quic scanner once, then ingest its output + log into gwsdb.
# Intended to be invoked from cron (e.g. daily) on the same machine that
# hosts both the scanner and the gwsdb web server.
set -euo pipefail

SCANNER_DIR="${GWSDB_SCANNER_DIR:-$HOME/gscan_quic}"
GWSDB_DIR="${GWSDB_HOME:-$HOME/git/gwsdb}"
GWSDB_BIN="$GWSDB_DIR/gwsdb"
DB_PATH="${GWSDB_DB:-$GWSDB_DIR/gwsdb.sqlite3}"
CONFIG_FILE="${GWSDB_SCAN_CONFIG:-$SCANNER_DIR/config.user.json}"

LOG_DIR="$SCANNER_DIR/scan_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"

cd "$SCANNER_DIR"
# `< /dev/null` prevents the scanner's "Press [Enter] to exit..." pause from
# blocking a non-interactive cron run.
sudo ./gscan_quic < /dev/null > "$LOG_FILE" 2>&1 || true

"$GWSDB_BIN" ingest -db "$DB_PATH" -config "$CONFIG_FILE" -log "$LOG_FILE"
