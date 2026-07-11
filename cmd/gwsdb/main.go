// Command gwsdb serves the GWS Database web app and ingests gscan_quic scan
// results into its SQLite store.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/cuthead/gwsdb/internal/config"
	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/publish"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/store"
	"github.com/cuthead/gwsdb/internal/web"
)

// defaultDoHURL is used when config.json doesn't set ptrDohUrl. DNS
// resolution (PTR/host/ASN) has no system-resolver fallback -- it's DoH
// wire format (RFC 8484) only, since that's the only way to see each
// record's real DNS TTL for cache staleness.
const defaultDoHURL = "https://dns.google/dns-query"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "ingest":
		runIngest(os.Args[2:])
	case "delete-scan":
		runDeleteScan(os.Args[2:])
	case "recheck":
		runRecheck(os.Args[2:])
	case "dns-sync":
		// Hidden: a one-shot DNS reconcile, spawned detached by recheck so
		// the recheck process can exit without waiting on the Cloudflare API.
		runDNSSync(os.Args[2:])
	case "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `gwsdb - GWS Database

Usage:
  gwsdb serve  -db PATH [-addr :8080] [-config config.json]
  gwsdb ingest -db PATH -scanner-config PATH [-scanner-dir PATH] [-log PATH] [-mode SNI|QUIC|TLS|PING] [-output PATH] [-config config.json]
  gwsdb delete-scan -db PATH -id N
  gwsdb recheck -ip IP -scanner-config PATH [-timeout 10s]   (ad-hoc: probe one IP, print result, no queue/D1)
  gwsdb recheck -worker [-max 200] [-timeout 10s]            (pull-model: drain the due recheck_queue backlog via $GWSDB_API/$GWSDB_INGEST_TOKEN)`)
}

// buildPublisher loads gwsdb's config.json from configPath and returns a
// Publisher when DNS publishing is configured, or nil when dns.name is unset.
// Fatal on unreadable config or bad credentials. Shared by serve, ingest and
// recheck so all three reconcile records after they change the store.
func buildPublisher(st *store.Store, configPath string) *publish.Publisher {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.DNS.Name == "" {
		return nil
	}
	pub, err := publish.New(st, publish.Config{
		APIToken: cfg.DNS.CloudflareAPIToken,
		ZoneID:   cfg.DNS.CloudflareZoneID,
		Name:     cfg.DNS.Name,
		TTL:      cfg.DNS.TTL,
		Limit:    cfg.DNS.Limit,
	})
	if err != nil {
		log.Fatalf("dns publish: %v", err)
	}
	return pub
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", "gwsdb.sqlite3", "path to the SQLite database file")
	addr := fs.String("addr", ":8080", "address to listen on")
	configPath := fs.String("config", "config.json", "path to gwsdb's config.json (holds DNS-publish settings)")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	srv, err := web.New(st)
	if err != nil {
		log.Fatalf("build web server: %v", err)
	}

	if pub := buildPublisher(st, *configPath); pub != nil {
		srv.SetPublisher(pub)
		log.Printf("dns publish enabled from %s", *configPath)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	dohURL := cfg.PTRDoHURL
	if dohURL == "" {
		dohURL = defaultDoHURL
	}
	srv.SetDoHURL(dohURL)
	log.Printf("DNS resolution (PTR/host/ASN) via DoH: %s", dohURL)

	go srv.StartPTRRefresher(15 * time.Second)

	log.Printf("gwsdb serving on %s (db=%s)", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

func runIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	dbPath := fs.String("db", "gwsdb.sqlite3", "path to the SQLite database file")
	scannerConfigPath := fs.String("scanner-config", "", "path to the gscan_quic config.json/config.user.json used for the scan")
	scanDir := fs.String("scanner-dir", "", "dir gscan_quic ran in; base for relative OutputFile paths (defaults to -scanner-config's dir)")
	logPath := fs.String("log", "", "path to the captured gscan_quic stdout log (optional)")
	mode := fs.String("mode", "", "scan mode to ingest (SNI/QUIC/TLS/PING); defaults to the config's ScanMode")
	output := fs.String("output", "", "override path to the scan output IP list; defaults to the config's OutputFile")
	logOnly := fs.Bool("log-only", false, "ignore the output file even if present; derive hits from -log only (use when a later scan overwrote the output file at this path)")
	configPath := fs.String("config", "config.json", "path to gwsdb's config.json for post-ingest DNS publish")
	fs.Parse(args)

	if *scannerConfigPath == "" {
		fmt.Fprintln(os.Stderr, "ingest: -scanner-config is required")
		fs.Usage()
		os.Exit(2)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	scanID, err := ingest.Run(st, ingest.Options{
		ConfigPath: *scannerConfigPath,
		ScanDir:    *scanDir,
		LogPath:    *logPath,
		ScanMode:   *mode,
		OutputPath: *output,
		LogOnly:    *logOnly,
	})
	if err != nil {
		log.Fatalf("ingest: %v", err)
	}
	log.Printf("ingested scan #%d", scanID)

	// A bulk ingest can shift the top set a lot; reconcile the published
	// records once, at the end, rather than per IP. Publish failure doesn't
	// fail the ingest -- the scan is already saved.
	if pub := buildPublisher(st, *configPath); pub != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cliPublishTimeout)
		defer cancel()
		if err := pub.Sync(ctx); err != nil {
			log.Printf("ingest: publish: %v", err)
		} else {
			log.Printf("ingest: dns publish synced")
		}
	}
}

// cliPublishTimeout bounds the one-shot DNS reconcile a CLI command runs after
// it changes the store (ingest, recheck).
const cliPublishTimeout = 15 * time.Second

func runDeleteScan(args []string) {
	fs := flag.NewFlagSet("delete-scan", flag.ExitOnError)
	dbPath := fs.String("db", "gwsdb.sqlite3", "path to the SQLite database file")
	id := fs.Int64("id", 0, "id of the scan to delete")
	fs.Parse(args)

	if *id == 0 {
		fmt.Fprintln(os.Stderr, "delete-scan: -id is required")
		fs.Usage()
		os.Exit(2)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if err := st.DeleteScan(*id); err != nil {
		log.Fatalf("delete-scan: %v", err)
	}
	log.Printf("deleted scan #%d", *id)
}

// recheckDefaultMaxPerRun caps how many queue items one "gwsdb recheck
// -worker" invocation drains, mirroring the Cloudflare-side cron-ptr-refresh
// project's per-run cap -- a large backlog can't block a single cron tick
// forever; any remainder is picked up on the next invocation.
const recheckDefaultMaxPerRun = 200

func runRecheck(args []string) {
	fs := flag.NewFlagSet("recheck", flag.ExitOnError)
	ip := fs.String("ip", "", "ad-hoc mode: IP address to re-test once, printing OK/FAIL -- no queue, no D1")
	scannerConfigPath := fs.String("scanner-config", "", "ad-hoc mode: path to the local gscan_quic config.json/config.user.json to probe with")
	worker := fs.Bool("worker", false, "pull-model mode: drain the due backlog from the Cloudflare-hosted recheck_queue via $GWSDB_API/$GWSDB_INGEST_TOKEN")
	maxPerRun := fs.Int("max", recheckDefaultMaxPerRun, "worker mode: cap on items drained in one invocation")
	timeout := fs.Duration("timeout", 10*time.Second, "probe timeout")
	fs.Parse(args)

	switch {
	case *ip != "" && *worker:
		fmt.Fprintln(os.Stderr, "recheck: -ip and -worker are mutually exclusive")
		fs.Usage()
		os.Exit(2)
	case *ip != "":
		runRecheckAdHoc(*ip, *scannerConfigPath, *timeout)
	case *worker:
		runRecheckWorker(*maxPerRun, *timeout)
	default:
		fmt.Fprintln(os.Stderr, "recheck: exactly one of -ip or -worker is required")
		fs.Usage()
		os.Exit(2)
	}
}

// runRecheckAdHoc is a manual ops diagnostic: probe one IP with the scan
// config gscan_quic already has on disk, print the result, and exit. It
// doesn't touch recheck_queue or D1 -- there's no local store on the China
// box to read/write anymore.
func runRecheckAdHoc(ip, scannerConfigPath string, timeout time.Duration) {
	if net.ParseIP(ip) == nil {
		log.Fatalf("recheck: invalid ip %q", ip)
	}
	if scannerConfigPath == "" {
		log.Fatal("recheck: -scanner-config is required with -ip")
	}

	raw, err := os.ReadFile(scannerConfigPath)
	if err != nil {
		log.Fatalf("recheck: read scanner config: %v", err)
	}
	var gcfg ingest.GScannerConfig
	if err := json.Unmarshal(raw, &gcfg); err != nil {
		log.Fatalf("recheck: parse scanner config: %v", err)
	}
	cfg := gcfg.ForMode(recheck.DefaultScanMode)
	if cfg == nil {
		log.Fatalf("recheck: scanner config has no %s block", recheck.DefaultScanMode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result := recheck.CheckSNI(ctx, ip, cfg)
	if result.OK {
		fmt.Printf("OK ip=%s rtt=%dms\n", ip, result.RTTMs)
	} else {
		fmt.Printf("FAIL ip=%s reason=%s detail=%s\n", ip, result.Reason, result.Detail)
	}
}

// runRecheckWorker drains the due recheck_queue backlog from the
// Cloudflare-hosted API, one item at a time via recheck.PullAndRun, until
// it's empty or maxPerRun is hit -- meant to be invoked by cron every few
// minutes (see scripts/recheck_and_submit.sh), not run as a long-lived
// daemon.
func runRecheckWorker(maxPerRun int, probeTimeout time.Duration) {
	apiBase := requireEnv("GWSDB_API")
	token := requireEnv("GWSDB_INGEST_TOKEN")

	ctx := context.Background()
	processed := 0
	for ; processed < maxPerRun; processed++ {
		drained, result, err := recheck.PullAndRun(ctx, apiBase, token, probeTimeout)
		if err != nil {
			log.Fatalf("recheck: %v", err)
		}
		if drained {
			break
		}
		if result.OK {
			log.Printf("recheck: OK rtt=%dms", result.RTTMs)
		} else {
			log.Printf("recheck: FAIL reason=%s detail=%s", result.Reason, result.Detail)
		}
	}
	log.Printf("recheck: processed %d item(s)", processed)
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("recheck: %s is required", name)
	}
	return v
}

// spawnDetachedPublish starts "gwsdb dns-sync" in a new session so it outlives
// this process, and returns without waiting. A slow Cloudflare API therefore
// can't delay the caller's exit.
func spawnDetachedPublish(dbPath, configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "dns-sync", "-db", dbPath, "-config", configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// runDNSSync is the hidden dns-sync subcommand: build the publisher from config
// and run one reconcile. Spawned detached by recheck so publishing doesn't
// block the recheck's exit.
func runDNSSync(args []string) {
	fs := flag.NewFlagSet("dns-sync", flag.ExitOnError)
	dbPath := fs.String("db", "gwsdb.sqlite3", "path to the SQLite database file")
	configPath := fs.String("config", "config.json", "path to gwsdb's config.json")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("dns-sync: open store: %v", err)
	}
	defer st.Close()

	pub := buildPublisher(st, *configPath)
	if pub == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliPublishTimeout)
	defer cancel()
	if err := pub.Sync(ctx); err != nil {
		log.Printf("dns-sync: %v", err)
	}
}
