// Command gwsdb runs the probe-side pieces of the GWS Database that must
// stay on real China-based network infrastructure: ingesting gscan_quic scan
// results into D1 (legacy local-sqlite mode, kept for manual debugging) and
// the recheck_queue pull-model worker. Serving the web UI, DNS publish, and
// bulk ingest all now live on Cloudflare (Pages Functions + D1) --
// see AGENTS.md and scripts/scan_and_ingest.sh.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "ingest":
		runIngest(os.Args[2:])
	case "delete-scan":
		runDeleteScan(os.Args[2:])
	case "recheck":
		runRecheck(os.Args[2:])
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
  gwsdb ingest -scanner-config PATH [-scanner-dir PATH] [-log PATH] [-mode SNI|QUIC|TLS|PING] [-output PATH]   (parses locally, submits via $GWSDB_API/$GWSDB_INGEST_TOKEN)
  gwsdb delete-scan -db PATH -id N
  gwsdb recheck -ip IP -scanner-config PATH [-timeout 10s]   (ad-hoc: probe one IP, print result, no queue/D1)
  gwsdb recheck -worker [-max 200] [-timeout 10s]            (pull-model: drain the due recheck_queue backlog via $GWSDB_API/$GWSDB_INGEST_TOKEN)`)
}

func runIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	scannerConfigPath := fs.String("scanner-config", "", "path to the gscan_quic config.json/config.user.json used for the scan")
	scanDir := fs.String("scanner-dir", "", "dir gscan_quic ran in; base for relative OutputFile paths (defaults to -scanner-config's dir)")
	logPath := fs.String("log", "", "path to the captured gscan_quic stdout log (optional)")
	mode := fs.String("mode", "", "scan mode to ingest (SNI/QUIC/TLS/PING); defaults to the config's ScanMode")
	output := fs.String("output", "", "override path to the scan output IP list; defaults to the config's OutputFile")
	logOnly := fs.Bool("log-only", false, "ignore the output file even if present; derive hits from -log only (use when a later scan overwrote the output file at this path)")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP timeout for the known-good fetch + submit round trip")
	fs.Parse(args)

	if *scannerConfigPath == "" {
		fmt.Fprintln(os.Stderr, "ingest: -scanner-config is required")
		fs.Usage()
		os.Exit(2)
	}

	parsed, err := ingest.Parse(ingest.Options{
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

	apiBase := requireEnv("GWSDB_API")
	token := requireEnv("GWSDB_INGEST_TOKEN")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Fetched once per run rather than checked per distinct failing IP --
	// gscan_quic logs every attempt at LogLevel: 5, so a scan can produce
	// tens of thousands of failure checks even though only a few hundred
	// IPs are ever known-good. See FilterChecks.
	knownGood, err := ingest.FetchKnownGood(ctx, apiBase, token)
	if err != nil {
		log.Fatalf("ingest: fetch known-good: %v", err)
	}
	filtered := ingest.FilterChecks(parsed.Results, parsed.Checks, knownGood, time.Now().UTC())

	scanID, err := ingest.Submit(ctx, apiBase, token, parsed.Scan, filtered)
	if err != nil {
		log.Fatalf("ingest: submit: %v", err)
	}
	log.Printf("ingested scan #%d", scanID)
}

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
		log.Fatalf("%s is required", name)
	}
	return v
}
