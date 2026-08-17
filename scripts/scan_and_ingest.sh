#!/usr/bin/env bash
set -euo pipefail

SCANNER_DIR="${GWSDB_SCANNER_DIR:-$HOME/gscan_quic}"
SCANNER_CONFIG="${GWSDB_SCAN_CONFIG:-$SCANNER_DIR/config.user.json}"
BIN_DIR="${GWSDB_BIN_DIR:-$HOME/gwsdb}"

LOG_DIR="$SCANNER_DIR/scan_logs"
mkdir -p "$LOG_DIR"
LOCK_DIR="$LOG_DIR/.scan.lock"
lock_held=false

lock_holder_alive() {
	local pidfile
	for pidfile in "$LOCK_DIR/scanner_pid" "$LOCK_DIR/pid"; do
		[ -f "$pidfile" ] || continue
		local p
		p=$(cat "$pidfile" 2>/dev/null) || continue
		[ -n "$p" ] || continue
		if kill -0 "$p" 2>/dev/null; then
			return 0
		fi
	done
	if [ ! -f "$LOCK_DIR/pid" ]; then
		return 0
	fi
	return 1
}

acquire_lock() {
	if mkdir "$LOCK_DIR" 2>/dev/null; then
		lock_held=true
		echo $$ > "$LOCK_DIR/pid"
		return 0
	fi
	if lock_holder_alive; then
		return 1
	fi
	echo "clearing stale lock from pid $(cat "$LOCK_DIR/pid" 2>/dev/null)" >&2
	rm -rf "$LOCK_DIR"
	if mkdir "$LOCK_DIR" 2>/dev/null; then
		lock_held=true
		echo $$ > "$LOCK_DIR/pid"
		return 0
	fi
	return 1
}

if ! acquire_lock; then
	echo "another scan_and_ingest run holds $LOCK_DIR, exiting" >&2
	exit 0
fi

release_lock() {
	if [ "$lock_held" = true ]; then
		rm -rf "$LOCK_DIR"
		lock_held=false
	fi
}
trap release_lock EXIT

LOG_FILE="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"

PARTIAL_LOG="$LOG_FILE.partial"

cd "$SCANNER_DIR"
sudo ./gscan_quic -Config "$SCANNER_CONFIG" < /dev/null > >(tee "$PARTIAL_LOG") 2>&1 &
scanner_pid=$!
echo "$scanner_pid" > "$LOCK_DIR/scanner_pid"

stop_scanner() {
	sudo pkill -TERM -P "$scanner_pid" 2>/dev/null || true
	kill -TERM "$scanner_pid" 2>/dev/null || true
	wait "$scanner_pid" 2>/dev/null || true
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		sudo pkill -0 -P "$scanner_pid" 2>/dev/null || return 0
		sleep 1
	done
	sudo pkill -KILL -P "$scanner_pid" 2>/dev/null || true
}
trap 'stop_scanner; rm -f "$PARTIAL_LOG"; release_lock; exit 130' INT TERM
scanner_status=0
wait "$scanner_pid" || scanner_status=$?
trap - INT TERM
rm -f "$LOCK_DIR/scanner_pid"

if [ "$scanner_status" -ne 0 ]; then
	echo "gscan_quic exited with status $scanner_status, not ingesting partial $PARTIAL_LOG" >&2
	exit 1
fi

mv "$PARTIAL_LOG" "$LOG_FILE"

"$BIN_DIR/gwsdb" ingest -scanner-config "$SCANNER_CONFIG" -log "$LOG_FILE" \
	&& rm "$LOG_FILE"

shopt -s nullglob
for old_log in "$LOG_DIR"/scan_*.log; do
	if [ "$old_log" = "$LOG_FILE" ]; then
		continue
	fi
	if "$BIN_DIR/gwsdb" ingest -scanner-config "$SCANNER_CONFIG" -log "$old_log" -log-only; then
		rm "$old_log"
	else
		echo "warning: retry ingest failed for $old_log, leaving in place" >&2
	fi
done
