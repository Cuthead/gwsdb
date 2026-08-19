# GWSDB

GWS Database (gwsdb) tracks which Google Web Server (GWS) IP addresses are reachable from China, with a web UI for browsing/querying known IPs and their reachability history.

"GWS" is Google's own server identifier (the `Server: gws` response header), not "Google Web Search" — these are not crawler/spider IPs. China's GFW blocks most Google IPs; this project finds and tracks the ones still reachable from real China-based network infrastructure.

## Stack

- **Go CLI** (`cmd/gwsdb`) — the probe side that must run on a China box:
  - `gwsdb scan` — always-on scanner. Independently sized IPv4/IPv6 goroutine pools scan random addresses and re-check known IPs; a flusher submits accumulated results to the Cloudflare-hosted API every few minutes; a probe server serves on-demand probes from the query page via a VPC proxy Worker.
  - `gwsdb recheck -ip` — ad-hoc: probe one IP, print result, submit it.
  - `gwsdb ingest` — manual ops: parse a captured gscan_quic scan, submit checks.
- **Cloudflare Pages Functions + D1** (`functions/`, `src/`) — everything else:
  - Web UI (home page, single-IP query with history + on-demand probe button).
  - `/api/pool` (JSON: known-IP list + summary stats), `/api/pool/version` (cheap cache-busting signal).
  - `/ingest` (bearer-token-gated, called by the Go CLI), `/check` (on-demand probe, CN-only, rate-limited, ASN-gated).
  - PTR/ASN caching, on-demand probes relayed through `worker/` (gwsdb-probe Worker) over Cloudflare Mesh.
- **Standalone Worker** (`worker/`) — `gwsdb-probe`, exists only because Pages Functions can't bind `vpc_networks`. Holds the VPC Network binding and proxies probe requests from `functions/check.ts` to the China box's probe server over Cloudflare Mesh.

## DNS publish

Latest GWS IP addresses are published through DNS records of:

- `google.com.c.0.8.0.d.0.0.0.0.7.4.0.1.0.0.2.ip6.arpa` ([radar.cloudflare.com](https://radar.cloudflare.com/domains/domain/google.com.c.0.8.0.d.0.0.0.0.7.4.0.1.0.0.2.ip6.arpa), [dns.google](https://dns.google/query?name=google.com.c.0.8.0.d.0.0.0.0.7.4.0.1.0.0.2.ip6.arpa), [bgp.he.net](https://bgp.he.net/dns/google.com.c.0.8.0.d.0.0.0.0.7.4.0.1.0.0.2.ip6.arpa))

## Commands

Build the Go CLI:

```sh
go build ./...
```

Run the Cloudflare Pages dev server locally:

```sh
npx wrangler pages dev
```

Vet:

```sh
go vet ./...
```

Deploy the standalone probe-proxy Worker:

```sh
cd worker && npx wrangler deploy
```

Apply D1 migrations:

```sh
npx wrangler d1 migrations apply gwsdb --remote
```

## gwsdb scan

```
gwsdb scan        -scanner-config PATH [-scanner-dir PATH] [-mode SNI] [-ip-range PATH...]
                  [-ipv4-worker 6] [-ipv6-worker 1]
                  [-ipv4-recheck-worker 2] [-ipv6-recheck-worker 1]
                  [-interval 1s] [-timeout 10s] [-flush 10s] [-flush-size 100]
                  [-probe-addr 0.0.0.0:8787] [-probe-token SECRET]
```

Always-on: probes random IPs from CIDR range files and flushes to `$GWSDB_API` after `-flush` or `-flush-size`, whichever comes first. Failed batches remain buffered and retry with exponential backoff. IPv4 and IPv6 scan/recheck worker counts are independent; each option accepts `0` to disable that worker class. Setting all four to `0` leaves only the on-demand probe server running. Known IPs are re-checked oldest-first within the shared pool order.

Probe pipeline per IP: ICMP ping gate (unprivileged `udp4`/`udp6` datagram, no root needed on Linux) → `CheckSNI` (TLS handshake + CN verification + HTTP status check, per `config.user.json`'s SNI block). Ping failures skip the TCP probe entirely.

`GWSDB_API` / `GWSDB_INGEST_TOKEN` / `GWSDB_PROBE_TOKEN` come from the environment or a `KEY=VALUE` file (`~/.config/gwsdb/env` by default, or `$GWSDB_ENV_FILE`; chmod 600 — it holds bearer tokens).

See [`AGENTS.md`](AGENTS.md) for full architecture, data flow, and gotchas.
