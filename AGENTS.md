# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Codex, Cursor, etc.) when working with code in this repository.

## What this is

gwsdb ("GWS Database") tracks which Google Web Server IPs are reachable from China. It ingests scan output from an external tool, `gscan_quic` (not in this repo — lives alongside it on the same host, see `scripts/scan_and_ingest.sh`), stores results in SQLite, and serves a web UI for browsing/querying known IPs and their reachability history.

## Commands

Build:
```
go build ./...
```

Run locally:
```
go run ./cmd/gwsdb serve -db gwsdb.sqlite3 -addr :8080
```

Vet:
```
go vet ./...
```

No test suite exists in this repo currently (`find . -name '*_test.go'` is empty) — don't assume `go test` coverage exists for a change.

CLI has three subcommands (see `cmd/gwsdb/main.go`):
```
gwsdb serve       -db PATH [-addr :8080]
gwsdb ingest      -db PATH -config PATH [-scanner-dir PATH] [-log PATH] [-mode SNI|QUIC|TLS|PING] [-output PATH] [-log-only]
gwsdb delete-scan -db PATH -id N
```

`scripts/scan_and_ingest.sh` is the production cron entrypoint: runs `gscan_quic`, then pipes its output + captured log into `gwsdb ingest`.

## Architecture

**Data flow**: `gscan_quic` (external scanner) writes an output IP list + optionally a stdout log → `internal/ingest` parses both against the scanner's `config.json`/`config.user.json` shape (mirrored in `internal/ingest/config.go`) → `internal/store` persists as one `Scan` row + `ScanResult`/`IPCheck` rows in SQLite → `internal/web` serves it.

**internal/store** is the only package touching SQL. Key tables:
- `scans` — one row per ingest run (config snapshot + counts).
- `ip_pool` — a SQL view (not a table), computed live from `ip_checks` via window functions (`ipPoolViewSQL` in `internal/store/store.go`). An IP appears here only while at least one `ok=1` row for it survives in `ip_checks`; delete the checks and it falls out of the pool automatically, no aggregate-maintenance path to keep in sync. This is what the home page lists. (Replaces the old `ip_status` table, which stored `times_seen`/`last_seen`/etc. as incrementally-maintained columns — `DeleteScan` could leave those aggregates stale after removing a scan's checks; see commit `cf82331`.)
- `ip_checks` — full pass/fail timeline, now the sole source of truth `ip_pool` derives from. Successes come from the scan's output-file results (plus log-only successes the output file missed); failures are kept *only* for IPs that already have at least one recorded success — a scan can probe thousands of never-seen IPs and failures for those aren't kept. Each row also carries `scan_mode` (backfilled via `migrate()` from the owning scan for pre-existing rows, since the old `ip_status.scan_mode` fallback no longer exists). (A legacy `scan_results` table once held per-scan success snapshots; `mergeScanResultsIntoChecks` folded it into `ip_checks` and dropped it.)
- `ptr_cache` / `asn_cache` — TTL'd caches for reverse-DNS and Team Cymru ASN lookups, to avoid re-querying on every page view.
- `ip_reports` — community usable/unusable reports, keyed to reporter's ASN/prefix (not raw IP) for public display.

New columns on existing tables go through `migrate()` in `internal/store/store.go` (idempotent `ALTER TABLE ... ADD COLUMN`, since `CREATE TABLE IF NOT EXISTS` doesn't touch existing tables) — follow that pattern rather than editing the `schema` constant for anything but new tables.

**internal/ingest** parses two independent sources of truth for the same scan and reconciles them: the output IP file (`readOutputIPs`, handles both plain-separator and `gop` quoted-comma formats) for the authoritative hit list, and the captured stdout log (`parseLog`, regex-driven) for per-IP RTT, pass/fail reasons, and timestamps. Either can be missing (`-log-only` / no output file) — see `Run()`'s fallback chain. The log only has failure detail if `gscan_quic` was run with `LogLevel: 5`.

**internal/web** is framework-free (standard library `net/http` + `html/template`, no JS framework). Templates are embedded via `//go:embed templates/*.tmpl` and parsed once at startup — no hot reload; restart the server after editing a `.tmpl`. Routes: `/` (home page shell — the known-IP list itself is fetched client-side, see below), `/api/pool` (JSON: full known-IP list + summary stats), `/api/pool/version` (JSON: cheap `{version}` signal, `store.PoolVersion()` — `MAX(id) FROM ip_checks`), `/query` (single IP lookup + history + reports), `/report` (POST, two-step confirm before publishing a report), `/scans` (scan history).

The home page no longer queries the DB or renders the IP list server-side on every hit — that was wasteful since `ip_pool` became a live view (window functions over all of `ip_checks`) rather than a maintained table (see `ip_pool` above). Instead `/static/home.js` fetches `/api/pool/version` on load, compares it against a cached copy in `localStorage` (`gwsdb_pool_v1`), and only fetches the full `/api/pool` payload — then renders rows client-side via the DOM API (never `innerHTML`, since PTR hostnames/country are derived from live untrusted DNS data) — when the version has moved. Both ingest and recheck write `ip_checks` rows, so `PoolVersion()` bumps on either, and a repeat visit in between is served entirely from `localStorage` with no request to `/api/pool` at all. This means the home page now requires JS to show any data (no more no-JS fallback with visible rows) — CSP's `connect-src 'self'` was added to allow the fetches.

`/query` gates on ASN: an IP is only looked up if Team Cymru's ASN data says it belongs to Google (`isGoogleASN`, substring match on AS name). PTR and ASN lookups are cached in `store` with separate TTLs (`ptrCacheTTL` 30d, `asnCacheTTL` 7d).

**internal/geo** decodes Google's `1e100.net` PTR hostname naming convention (four regex patterns for airport-code/regional/metro/anycast forms) into an approximate city/country, purely offline (no external GeoIP DB). `internal/asn` and `internal/resolver` do live DNS lookups (Team Cymru whois-via-TXT-record, and standard PTR) with bounded timeouts — no external HTTP APIs or API keys involved anywhere in this repo.

**Client IP handling**: `clientIP()` in `internal/web/server.go` trusts `CF-Connecting-IP` first — this is only safe because the deployment assumes the origin refuses direct (non-Cloudflare) connections; keep that assumption in mind if touching deployment/networking.

## Gotchas

- SQLite writer is single-connection (`db.SetMaxOpenConns(1)`) — the driver isn't safe for concurrent writers. Don't parallelize writes.
- `listKnownIPsSortColumns` in `internal/store/queries.go` whitelists sortable columns because `SortBy` comes straight from a query param — never interpolate caller-controlled strings into SQL directly; extend the whitelist map instead.
- Templates are a mix of `lang="en"` and `lang="zh"` (`report_confirm.tmpl` is Chinese; the rest are English) — this is intentional per-page, not a bug, per the i18n commit history.
- `gwsdb.sqlite3*` and the `gwsdb` binary are gitignored — don't commit them.
- Fetching anything from he.net / bgp.he.net (e.g. flag gifs under `bgp.he.net/images/flags/`) requires a browser User-Agent or the request is rejected — use `curl -H "User-Agent: Mozilla/5.0" ...`.
