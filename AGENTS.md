# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Codex, Cursor, etc.) when working with code in this repository.

## What this is

gwsdb ("GWS Database") tracks which Google Web Server IPs are reachable from China. It ingests scan output from an external tool, `gscan_quic` (not in this repo — lives alongside it on the same host, see `scripts/scan_and_ingest.sh`), stores results in Cloudflare D1, and serves a web UI for browsing/querying known IPs and their reachability history.

"GWS" is Google's own server identifier (the `Server: gws` response header), not "Google Web Search" — these are not crawler/spider IPs. China's GFW blocks most Google IPs; this project exists to find and track the ones still reachable, so don't describe the tracked IPs as a "search crawler" or "web search crawler" anywhere (UI copy, meta tags, comments).

The stack is split across two runtimes:
- **`cmd/gwsdb`** (Go) — runs only the probe-side pieces that must stay on real China-based network infrastructure: parsing `gscan_quic` output/logs and the recheck worker. It holds no local database; every subcommand talks to the Cloudflare-hosted API over HTTP.
- **`functions/` + `src/`** (TypeScript, Cloudflare Pages Functions + D1) — everything else: web UI, `/api/*`, ingest/delete-scan/recheck endpoints, PTR/ASN caching, community reports. This is the full replacement for what used to be a Go `net/http` server (`internal/web`) backed by local SQLite (`internal/store`'s DB layer) — both are gone; see git history around the Cloudflare migration if you need the old implementation for reference.

## Commands

Build the Go CLI:
```
go build ./...
```

Run the Cloudflare Pages dev server locally:
```
npx wrangler pages dev
```

Vet:
```
go vet ./...
```

`internal/ingest` has a test suite (`internal/ingest/ingest_test.go`); nothing else in the Go tree does — don't assume `go test ./...` coverage exists elsewhere.

Go CLI has three subcommands (see `cmd/gwsdb/main.go`), all of which submit to the Cloudflare-hosted API via `$GWSDB_API`/`$GWSDB_INGEST_TOKEN`:
```
gwsdb ingest      -scanner-config PATH [-scanner-dir PATH] [-log PATH] [-mode SNI|QUIC|TLS|PING] [-output PATH] [-log-only]
gwsdb delete-scan -id N
gwsdb recheck     -ip IP -scanner-config PATH [-timeout 10s]   (ad-hoc single probe)
gwsdb recheck     -worker [-max 200] [-timeout 10s]            (drains recheck_queue)
```

`GWSDB_API`/`GWSDB_INGEST_TOKEN` can come from the environment or a `KEY=VALUE` file (`~/.config/gwsdb/env` by default, or `$GWSDB_ENV_FILE`); chmod 600 it, it holds a bearer token.

`scripts/scan_and_ingest.sh` is the production cron entrypoint: runs `gscan_quic`, then pipes its output + captured log into `gwsdb ingest`. `scripts/recheck_and_submit.sh` drains the recheck queue via `gwsdb recheck -worker`.

## Architecture

**Data flow**: `gscan_quic` (external scanner) writes an output IP list + optionally a stdout log → `internal/ingest` parses both against the scanner's `config.json`/`config.user.json` shape (mirrored in `internal/ingest/config.go`) → `gwsdb ingest` submits the parsed `store.Scan`/`store.IPCheck` structs as JSON to the Pages Function at `/ingest` (`functions/ingest.ts`) → that writes to D1 via `src/store.ts`.

**`internal/store`** (Go) now holds only data-shape types (`Scan`, `ScanResult`, `IPCheck`, etc. in `models.go`) shared between the ingest CLI and its JSON submission to Cloudflare — no SQL, no `*sql.DB`. The real database logic lives in `src/store.ts` against D1.

**D1 schema** (`migrations/*.sql`, applied via `wrangler d1 migrations apply`). Key tables:
- `scans` — one row per ingest run (config snapshot + counts).
- `ip_pool` — a maintained table (not a live view — SQLite's `db.SetMaxOpenConns(1)` + window-function view trick from the old Go/SQLite version doesn't carry over to D1's HTTP-based access model) kept in sync by `refreshPoolForIPs`/`deleteScan` in `src/store.ts`. This is what the home page lists.
- `ip_checks` — full pass/fail timeline, source of truth `ip_pool` is derived from. Successes come from the scan's output-file results (plus log-only successes the output file missed); failures are kept *only* for IPs that already have at least one recorded success. Each row carries `scan_mode`.
- `ptr_cache` / `asn_cache` — TTL'd caches for reverse-DNS and Team Cymru ASN lookups, to avoid re-querying on every page view.
- `ip_reports` — community usable/unusable reports, keyed to reporter's ASN/prefix (not raw IP) for public display.
- `recheck_queue` — pull-model queue of report-triggered rechecks; drained by `gwsdb recheck -worker` via `functions/recheck/next.ts` + `functions/recheck/result.ts`.

**`internal/ingest`** (Go) parses two independent sources of truth for the same scan and reconciles them: the output IP file (`readOutputIPs`, handles both plain-separator and `gop` quoted-comma formats) for the authoritative hit list, and the captured stdout log (`parseLog`, regex-driven) for per-IP RTT, pass/fail reasons, and timestamps. Either can be missing (`-log-only` / no output file) — see `Run()`'s fallback chain. The log only has failure detail if `gscan_quic` was run with `LogLevel: 5`. `FilterChecks` (`internal/ingest/filter.go`) trims the failure flood: a scan can probe thousands of never-seen IPs, and failures for those aren't submitted — only for IPs already known-good (fetched once per run via `FetchKnownGood` against `/api/pool`).

**`internal/recheck`** (Go) is the probe-only counterpart used by `gwsdb recheck`: `CheckSNI` runs one probe with the scanner's SNI config, `PullAndRun` drains one `recheck_queue` item at a time from Cloudflare (`functions/recheck/next.ts`), and `Submit`/`FetchLatestScanID` talk to `functions/recheck/result.ts` / `functions/recheck/latest-scan-id.ts`.

**`functions/`** is the Cloudflare Pages Functions app (framework-free, one file per route). `functions/_middleware.ts` applies security headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) to every response, including static assets under `public/static/`. Routes: `functions/index.ts` (home page shell — the known-IP list itself is fetched client-side, see below), `functions/api/pool.ts` (JSON: full known-IP list + summary stats), `functions/api/pool/version.ts` (JSON: cheap `{version}` signal, `src/store.ts`'s `poolVersion` — `MAX(id) FROM ip_checks`), `functions/query.ts` (single IP lookup + history + reports), `functions/report.ts` (POST, two-step confirm before publishing a report), `functions/scans.ts` (scan history), `functions/ingest.ts` / `functions/delete-scan.ts` (bearer-token-gated, called by the Go CLI), `functions/recheck/*` (queue pull + result submission, also bearer-token-gated).

The home page doesn't query D1 or render the IP list server-side on every hit, since D1 is HTTP-based (no local process to keep a hot view). Instead `public/static/home.js` fetches `/api/pool/version` on load, compares it against a cached copy in `localStorage` (`gwsdb_pool_v1`), and only fetches the full `/api/pool` payload — then renders rows client-side via the DOM API (never `innerHTML`, since PTR hostnames/country are derived from live untrusted DNS data) — when the version has moved. Both ingest and recheck submissions write `ip_checks` rows, so `poolVersion` bumps on either, and a repeat visit in between is served entirely from `localStorage` with no request to `/api/pool` at all. JS-disabled visitors aren't left with an empty shell: the page's `<head>` has a `<noscript><meta http-equiv="refresh" ...></noscript>` pointing at `/?nojs=1` (the HTML parser honors this regardless of script execution), and `functions/index.ts` treats `nojs=1` the same as a crawler UA — full server-rendered table via `src/pool.ts`'s `loadPool`.

`functions/index.ts` special-cases known bots/archivers (`isCrawlerUA` in `src/html.ts`, substring match on User-Agent — Googlebot, ia_archiver, archive.today, etc.): they get the full server-rendered table instead of the JS shell, since search/social crawlers commonly don't run JS at all, and an archived snapshot's JS would otherwise replay against a live `/api/pool` at some later, unpredictable state (or a dead origin) instead of showing what was actually captured.

`functions/query.ts` gates on ASN: an IP is only looked up if Team Cymru's ASN data says it belongs to Google (`isGoogleASN`, substring match on AS name, `src/asn.ts`). PTR and ASN lookups are cached in D1 with separate TTLs (`ptrCacheTTL` 30d, `asnCacheTTL` 7d).

**`src/geo.ts`/`src/geoData.ts`** decode Google's `1e100.net` PTR hostname naming convention (four regex patterns for airport-code/regional/metro/anycast forms) into an approximate city/country, purely offline (no external GeoIP DB). `src/asn.ts` and `src/resolver.ts`/`src/doh.ts`/`src/dnsWire.ts` do live DNS lookups (Team Cymru whois-via-TXT-record, and standard PTR via DNS-over-HTTPS/wire format) with bounded timeouts — no external HTTP APIs or API keys involved anywhere in this repo. (The Go tree had `internal/asn`/`internal/geo`/`internal/resolver` equivalents; removed as dead code once nothing in `cmd/gwsdb` called them — all lookups now happen edge-side in these `src/*.ts` files.)

**Client IP handling**: request handlers trust `CF-Connecting-IP` first (see `src/env.ts`/callers) — this is inherent to running as a Cloudflare Pages Function, there's no "origin" to spoof around.

**cron-ptr-refresh** (`cron-ptr-refresh/`) is a separate Cloudflare Worker on its own cron trigger that round-robins through `ip_pool` refreshing stale PTR cache entries — see its own source for details.

## Gotchas

- `internal/ingest/filter.go`'s `FilterChecks` and D1's `ip_pool`/`ip_checks` gating logic in `src/store.ts` must stay in sync — the Go side pre-filters before submission, the TS side is the final gate on write.
- `listKnownIPsSortColumns`-equivalent in `src/store.ts`'s `listKnownIPs` whitelists sortable columns because `sortBy` comes straight from a query param — never interpolate caller-controlled strings into SQL directly; extend the whitelist map instead.
- Templates/pages are a mix of English and Chinese (`functions/report.ts`'s confirm step renders `lang="zh"`; the rest are English) — this is intentional per-page, not a bug, per the i18n commit history.
- New D1 migrations go in `migrations/*.sql`, applied with `wrangler d1 migrations apply` — don't hand-edit existing migration files once applied anywhere.
- Fetching anything from he.net / bgp.he.net (e.g. flag gifs under `bgp.he.net/images/flags/`) requires a browser User-Agent or the request is rejected — use `curl -H "User-Agent: Mozilla/5.0" ...`.
