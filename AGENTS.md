# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, Codex, Cursor, etc.) when working with code in this repository.

## What this is

gwsdb ("GWS Database") tracks which Google Web Server IPs are reachable from China. An always-on Go scanner (`gwsdb scan`, see `internal/scan/` + `scripts/run_scanner.sh`) continuously probes candidate Google IPs from real China-based network infrastructure and flushes results to Cloudflare D1 every few minutes; a web UI serves browsing/querying of known IPs and their reachability history.

"GWS" is Google's own server identifier (the `Server: gws` response header), not "Google Web Search" — these are not crawler/spider IPs. China's GFW blocks most Google IPs; this project exists to find and track the ones still reachable, so don't describe the tracked IPs as a "search crawler" or "web search crawler" anywhere (UI copy, meta tags, comments).

The stack is split across two runtimes:
- **`cmd/gwsdb`** (Go) — runs only the probe-side pieces that must stay on real China-based network infrastructure: the always-on scanner (`gwsdb scan`, which also serves on-demand probes via a VPC proxy Worker), ad-hoc `gwsdb recheck -ip`, and `gwsdb ingest` for manual ops. It holds no local database; every subcommand talks to the Cloudflare-hosted API over HTTP.
- **`functions/` + `src/`** (TypeScript, Cloudflare Pages Functions + D1) — everything else: web UI, `/api/*`, ingest/recheck endpoints, PTR/ASN caching, on-demand probes. This is the full replacement for what used to be a Go `net/http` server (`internal/web`) backed by local SQLite (`internal/store`'s DB layer) — both are gone; see git history around the Cloudflare migration if you need the old implementation for reference.

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
gwsdb scan        -scanner-config PATH [-scanner-dir PATH] [-mode SNI] [-ip-range PATH...]
                  [-ipv4-worker 6] [-ipv6-worker 1]
                  [-ipv4-recheck-worker 2] [-ipv6-recheck-worker 1]
                  [-interval 1s] [-timeout 10s] [-flush 10m]
                  [-probe-addr 0.0.0.0:8787] [-probe-token SECRET]
                                (always-on: probes random IPs from CIDR range files, flushes to $GWSDB_API
                                 every -flush, serves on-demand probes via VPC proxy Worker)
gwsdb ingest      -scanner-config PATH [-scanner-dir PATH] [-log PATH] [-mode SNI|QUIC|TLS|PING] [-output PATH]   (parses locally, submits via $GWSDB_API/$GWSDB_INGEST_TOKEN)
gwsdb recheck     -ip IP -scanner-config PATH [-timeout 10s]   (ad-hoc: probe one IP, print result, submit it)
```

`GWSDB_API`/`GWSDB_INGEST_TOKEN` can come from the environment or a `KEY=VALUE` file (`~/.config/gwsdb/env` by default, or `$GWSDB_ENV_FILE`); chmod 600 it, it holds a bearer token.

`scripts/run_scanner.sh` is the production entrypoint: starts `gwsdb scan` as a long-running process (under systemd or tmux — restart on exit). The scanner continuously probes random IPs from CIDR range files (`~/gscan_quic/iprange/`), flushes accumulated results to the API every 10 minutes, and serves on-demand probes from the query page via a VPC proxy Worker (`worker/`). `scripts/scan_and_ingest.sh` and `scripts/recheck_and_submit.sh` are gone (superseded by the single scanner process).

## Architecture

**Data flow** (always-on scanner): `gwsdb scan` runs independently sized IPv4/IPv6 scan and recheck goroutine pools. Scan workers loop `sleep(interval) → pick a random IP of their configured address family from the CIDR range files → recheck.CheckSNI probe → record`; recheck workers consume known IPs from address-family-specific queues. A flush ticker periodically drains the accumulated checks: `FetchKnownGood` → `FilterChecks` → `Submit` POSTs `[]store.IPCheck` to `/ingest` (`functions/ingest.ts`), which writes them directly to `ip_checks` via `src/store.ts` (no `scans` row — that table is gone). The probe config comes from gscan_quic's `config.user.json` (SNI block), so the scanner probes with the same ServerName/HTTPPath/timeout settings a manual scan would.

**`internal/store`** (Go) now holds only data-shape types (`Scan`, `ScanResult`, `IPCheck`, etc. in `models.go`) shared between the ingest CLI and its JSON submission to Cloudflare — no SQL, no `*sql.DB`. The real database logic lives in `src/store.ts` against D1.

**D1 schema** (`migrations/*.sql`, applied via `wrangler d1 migrations apply`). Key tables:
- `ip_pool` — a maintained table (not a live view — SQLite's `db.SetMaxOpenConns(1)` + window-function view trick from the old Go/SQLite version doesn't carry over to D1's HTTP-based access model) kept in sync by `refreshPoolForIPs`/`deleteScan` in `src/store.ts`. This is what the home page lists.
- `ip_checks` — full pass/fail timeline, source of truth `ip_pool` is derived from. Successes come from the scan's output-file results (plus log-only successes the output file missed); failures are kept *only* for IPs that already have at least one recorded success. Each row carries `scan_mode`.
- `ptr_cache` / `asn_cache` — TTL'd caches for reverse-DNS and Team Cymru ASN lookups, to avoid re-querying on every page view.
- `check_rate_limit` — per-client-IP rate-limit counter for the on-demand probe button (one row per client_ip + UTC minute window); see `src/store.ts`'s `checkRateLimit`.

**`internal/ingest`** (Go) parses two independent sources of truth for the same scan and reconciles them: the output IP file (`readOutputIPs`, handles both plain-separator and `gop` quoted-comma formats) for the authoritative hit list, and the captured stdout log (`parseLog`, regex-driven) for per-IP RTT, pass/fail reasons, and timestamps. Either can be missing (`-log-only` / no output file) — see `Run()`'s fallback chain. The log only has failure detail if `gscan_quic` was run with `LogLevel: 5`. `FilterChecks` (`internal/ingest/filter.go`) trims the failure flood: a scan can probe thousands of never-seen IPs, and failures for those aren't submitted — only for IPs already known-good (fetched once per run via `FetchKnownGood` against `/api/pool`).

**`internal/recheck`** (Go) is the probe-only package shared by `gwsdb scan` and `gwsdb recheck -ip`: `CheckSNI` runs one probe with the scanner's SNI config (a Go port of gscan_quic's testSni), and `Submit`/`FetchLatestScanID` talk to `functions/recheck/result.ts` / `functions/recheck/latest-scan-id.ts` (ad-hoc probes only — the scanner's own flush goes through `/ingest`).

**`internal/scan`** (Go) is the always-on scanner package (`gwsdb scan`): `IPRangeSource` loads CIDR range files (gscan_quic's `iprange/*.txt` format, v4/v6 mixed) and picks a random address per probe; `Scanner` runs independently sized IPv4/IPv6 worker pools + a flush ticker + a network monitor (HEADs bing.com, sleeps workers when the network looks down — mirrors XX-Net's check_local_network); `probeserver.go` serves `POST /probe` on localhost, reachable from the `gwsdb-probe` Worker (`worker/`) over Cloudflare Mesh so the query page's on-demand probe button can synchronously call it (`functions/check.ts` → service binding → `worker/` → VPC → `recheck.CheckSNI` → response, ~1-3s round trip). The probe server authenticates with `X-Probe-Token` (crypto/subtle.ConstantTimeCompare against `-probe-token`). No queue, no delay — on-demand probes are synchronous.

**`functions/`** is the Cloudflare Pages Functions app (framework-free, one file per route). `functions/_middleware.ts` applies security headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) to every response, including static assets under `public/static/`. Routes: `functions/index.ts` (home page shell — the known-IP list itself is fetched client-side, see below), `functions/api/pool.ts` (JSON: full known-IP list + summary stats), `functions/api/pool/version.ts` (JSON: cheap `{version}` signal, `src/store.ts`'s `poolVersion` — `MAX(id) FROM ip_checks`), `functions/query.ts` (single IP lookup + history + on-demand probe button), `functions/check.ts` (POST — calls the gwsdb-probe Worker via service binding, which VPC-fetches the China box's probe server over Cloudflare Mesh, writes the result, rate-limited per client IP), `functions/ingest.ts` (bearer-token-gated, called by the Go CLI), `functions/recheck/result.ts` (ad-hoc recheck -ip submission, bearer-token-gated).

**`worker/`** is a standalone Cloudflare Worker (`gwsdb-probe`) that exists only because Pages Functions can't bind `vpc_networks` (Pages rejects the field). It holds the VPC Network binding (`cf1:network`, Cloudflare Mesh) and proxies probe requests from `functions/check.ts` to the China box's internal probe server over the Mesh — no public hostname, no `workers.dev` URL (`workers_dev: false`, reachable only via the Pages project's `PROBE_PROXY` service binding). `worker/src/index.ts` authenticates with `X-Probe-Token` (same secret as the probe server) and `env.PROBE_NETWORK.fetch()`es the probe server's private IP:port. Deploy separately: `cd worker && npx wrangler deploy`.

The home page doesn't query D1 or render the IP list server-side on every hit, since D1 is HTTP-based (no local process to keep a hot view). Instead `public/static/home.js` fetches `/api/pool/version` on load, compares it against a cached copy in `localStorage` (`gwsdb_pool_v1`), and only fetches the full `/api/pool` payload — then renders rows client-side via the DOM API (never `innerHTML`, since PTR hostnames/country are derived from live untrusted DNS data) — when the version has moved. Both ingest and recheck submissions write `ip_checks` rows, so `poolVersion` bumps on either, and a repeat visit in between is served entirely from `localStorage` with no request to `/api/pool` at all. JS-disabled visitors aren't left with an empty shell: the page's `<head>` has a `<noscript><meta http-equiv="refresh" ...></noscript>` pointing at `/?nojs=1` (the HTML parser honors this regardless of script execution), and `functions/index.ts` treats `nojs=1` the same as a crawler UA — full server-rendered table via `src/pool.ts`'s `loadPool`.

`functions/index.ts` special-cases known bots/archivers (`isCrawlerUA` in `src/html.ts`, substring match on User-Agent — Googlebot, ia_archiver, archive.today, etc.): they get the full server-rendered table instead of the JS shell, since search/social crawlers commonly don't run JS at all, and an archived snapshot's JS would otherwise replay against a live `/api/pool` at some later, unpredictable state (or a dead origin) instead of showing what was actually captured.

`functions/query.ts` gates on ASN: an IP is only looked up if Team Cymru's ASN data says it belongs to Google (`isGoogleASN`, substring match on AS name, `src/asn.ts`). PTR and ASN lookups are cached in D1 with separate TTLs (`ptrCacheTTL` 30d, `asnCacheTTL` 7d).

**`src/geo.ts`/`src/geoData.ts`** decode Google's `1e100.net` PTR hostname naming convention (four regex patterns for airport-code/regional/metro/anycast forms) into an approximate city/country, purely offline (no external GeoIP DB). `src/asn.ts` and `src/resolver.ts`/`src/doh.ts`/`src/dnsWire.ts` do live DNS lookups (Team Cymru whois-via-TXT-record, and standard PTR via DNS-over-HTTPS/wire format) with bounded timeouts — no external HTTP APIs or API keys involved anywhere in this repo. (The Go tree had `internal/asn`/`internal/geo`/`internal/resolver` equivalents; removed as dead code once nothing in `cmd/gwsdb` called them — all lookups now happen edge-side in these `src/*.ts` files.)

**Client IP handling**: request handlers trust `CF-Connecting-IP` first (see `src/env.ts`/callers) — this is inherent to running as a Cloudflare Pages Function, there's no "origin" to spoof around.

**`src/ptrRefresh.ts`** round-robins through `ip_pool` refreshing stale PTR cache entries over one pipelined DNS-over-TCP connection — run from `functions/ingest.ts` via `waitUntil` right after each scan's ingest, not on a schedule (used to be a separate Cloudflare Worker on its own cron trigger, back when Pages Functions had no scheduled-execution primitive; folded in once ingest started triggering it on demand and the cron became redundant).

## Gotchas

- `internal/ingest/filter.go`'s `FilterChecks` and D1's `ip_pool`/`ip_checks` gating logic in `src/store.ts` must stay in sync — the Go side pre-filters before submission, the TS side is the final gate on write.
- `listKnownIPsSortColumns`-equivalent in `src/store.ts`'s `listKnownIPs` whitelists sortable columns because `sortBy` comes straight from a query param — never interpolate caller-controlled strings into SQL directly; extend the whitelist map instead.
- The query page's on-demand probe button and its status text are Chinese (`functions/query.ts`'s probeCell + `public/static/query.js`); the rest of the UI is English — this is intentional per-page, not a bug, per the i18n commit history.
- New D1 migrations go in `migrations/*.sql`, applied with `wrangler d1 migrations apply` — don't hand-edit existing migration files once applied anywhere.
- Fetching anything from he.net / bgp.he.net (e.g. flag gifs under `bgp.he.net/images/flags/`) requires a browser User-Agent or the request is rejected — use `curl -H "User-Agent: Mozilla/5.0" ...`.
