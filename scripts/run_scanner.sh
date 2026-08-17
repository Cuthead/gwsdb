#!/usr/bin/env bash
# Always-on GWS scanner: continuously probes candidate Google IPs from
# real China-based network infrastructure and flushes results to the
# Cloudflare-hosted API every few minutes. Replaces the old
# scan_and_ingest.sh (cron-driven gscan_quic one-shot) + recheck_and_submit.sh
# (separate recheck worker) with a single long-running process.
#
# GWSDB_API/GWSDB_INGEST_TOKEN/GWSDB_PROBE_TOKEN are read by `gwsdb` from
# the environment or ~/.config/gwsdb/env (see `gwsdb -h`). GWSDB_PROBE_TOKEN
# must match the Cloudflare side's PROBE_TOKEN (wrangler pages secret).
#
# Intended to run under systemd (Restart=always) or tmux — restart on exit.
set -euo pipefail

SCANNER_DIR="${GWSDB_SCANNER_DIR:-$HOME/gscan_quic}"
SCANNER_CONFIG="${GWSDB_SCAN_CONFIG:-$SCANNER_DIR/config.user.json}"
BIN_DIR="${GWSDB_BIN_DIR:-$HOME/gwsdb}"

# IP range files: gwsdb scan always loads the config's SNI.InputFile (v4)
# as the default; GWSDB_IP_RANGES adds more (e.g. v6). Space-separated.
# Default adds the v6 ranges alongside so both address families get scanned
# (requires the China box to have IPv6 connectivity — v6 probes will simply
# fail otherwise, no harm to v4 scanning).
IP_RANGES="${GWSDB_IP_RANGES:-$SCANNER_DIR/iprange/iprange_gws_6_a.txt}"

args=(-scanner-config "$SCANNER_CONFIG" -scanner-dir "$SCANNER_DIR")
for r in $IP_RANGES; do
	args+=(-ip-range "$r")
done
exec "$BIN_DIR/gwsdb" scan "${args[@]}"
