# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Codex, Cursor, etc.) when working with code in this repository.

## What this is

gwsdb ("GWS Database") tracks which Google Web Server IPs are reachable from China. It ingests scan output from an external tool, `gscan_quic` (not in this repo — lives alongside it on the same host, see `scripts/scan_and_ingest.sh`), stores results in SQLite, and serves a deliberately JS-minimal web UI for browsing/querying known IPs and their reachability history.

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
- `scan_results` — IPs found reachable in a given scan (only successes).
- `ip_status` — rolling per-IP summary across all scans ("ever found reachable" pool). This is what the home page lists.
- `ip_checks` — full pass/fail timeline, but *only* for IPs already in `ip_status`; a scan can probe thousands of never-seen IPs and failures for those aren't kept. This is why `SaveScan`'s failure path is a conditional `UPDATE ip_status ... WHERE ip = ?` before it decides whether to log the check at all.
- `ptr_cache` / `asn_cache` — TTL'd caches for reverse-DNS and Team Cymru ASN lookups, to avoid re-querying on every page view.
- `ip_reports` — community usable/unusable reports, keyed to reporter's ASN/prefix (not raw IP) for public display.

New columns on existing tables go through `migrate()` in `internal/store/store.go` (idempotent `ALTER TABLE ... ADD COLUMN`, since `CREATE TABLE IF NOT EXISTS` doesn't touch existing tables) — follow that pattern rather than editing the `schema` constant for anything but new tables.

**internal/ingest** parses two independent sources of truth for the same scan and reconciles them: the output IP file (`readOutputIPs`, handles both plain-separator and `gop` quoted-comma formats) for the authoritative hit list + rank, and the captured stdout log (`parseLog`, regex-driven) for per-IP RTT, pass/fail reasons, and timestamps. Either can be missing (`-log-only` / no output file) — see `Run()`'s fallback chain. The log only has failure detail if `gscan_quic` was run with `LogLevel: 5`.

**internal/web** is intentionally framework-free, Web 1.0 (see the package doc comment — "deliberately Web 1.0, JS-free" for the backend; a couple of pages now layer small inline `<script>` blocks for client-side search/sort/filter, see `home.tmpl`, rather than reintroducing a JS framework). Templates are embedded via `//go:embed templates/*.tmpl` and parsed once at startup — no hot reload; restart the server after editing a `.tmpl`. Four routes: `/` (home, known-IP list), `/query` (single IP lookup + history + reports), `/report` (POST, two-step confirm before publishing a report), `/scans` (scan history).

`/query` gates on ASN: an IP is only looked up if Team Cymru's ASN data says it belongs to Google (`isGoogleASN`, substring match on AS name). PTR and ASN lookups are cached in `store` with separate TTLs (`ptrCacheTTL` 30d, `asnCacheTTL` 7d).

**internal/geo** decodes Google's `1e100.net` PTR hostname naming convention (four regex patterns for airport-code/regional/metro/anycast forms) into an approximate city/country, purely offline (no external GeoIP DB). `internal/asn` and `internal/resolver` do live DNS lookups (Team Cymru whois-via-TXT-record, and standard PTR) with bounded timeouts — no external HTTP APIs or API keys involved anywhere in this repo.

**Client IP handling**: `clientIP()` in `internal/web/server.go` trusts `CF-Connecting-IP` first — this is only safe because the deployment assumes the origin refuses direct (non-Cloudflare) connections; keep that assumption in mind if touching deployment/networking.

## Gotchas

- SQLite writer is single-connection (`db.SetMaxOpenConns(1)`) — the driver isn't safe for concurrent writers. Don't parallelize writes.
- `listKnownIPsSortColumns` in `internal/store/queries.go` whitelists sortable columns because `SortBy` comes straight from a query param — never interpolate caller-controlled strings into SQL directly; extend the whitelist map instead.
- Templates are a mix of `lang="en"` and `lang="zh"` (`report_confirm.tmpl` is Chinese; the rest are English) — this is intentional per-page, not a bug, per the i18n commit history.
- `gwsdb.sqlite3*` and the `gwsdb` binary are gitignored — don't commit them.
