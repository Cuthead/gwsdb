// Command gwsdb runs the probe-side pieces of the GWS Database that must
// stay on real China-based network infrastructure: parsing gscan_quic scan
// output and the recheck_queue pull-model worker. None of its subcommands
// touch a local database anymore -- ingest/delete-scan/recheck all talk to
// the Cloudflare-hosted API (Pages Functions + D1) over HTTP. Serving the
// web UI and DNS publish live on Cloudflare too -- see AGENTS.md and
// scripts/scan_and_ingest.sh.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/scan"
)

func main() {
	loadEnvFile(envFilePath())

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "ingest":
		runIngest(os.Args[2:])
	case "recheck":
		runRecheck(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
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
  gwsdb ingest      -scanner-config PATH [-scanner-dir PATH] [-log PATH] [-mode SNI|QUIC|TLS|PING] [-output PATH]   (parses locally, submits via $GWSDB_API/$GWSDB_INGEST_TOKEN)
  gwsdb recheck     -ip IP -scanner-config PATH [-timeout 10s]   (ad-hoc: probe one IP, print result, submit it)
  gwsdb scan        -scanner-config PATH [-scanner-dir PATH] [-mode SNI] [-ip-range PATH...]
                    [-workers 10] [-interval 1s] [-timeout 10s] [-flush 10m]
                    [-probe-addr 0.0.0.0:8787] [-probe-token SECRET]
                                (always-on: probes random IPs from CIDR range files, flushes to $GWSDB_API
                                 every -flush, serves on-demand probes via VPC proxy Worker — replaces scan_and_ingest.sh + recheck_and_submit.sh)

GWSDB_API/GWSDB_INGEST_TOKEN/GWSDB_PROBE_TOKEN can also come from a KEY=VALUE
file instead of being exported by hand: ~/.config/gwsdb/env by default, or
$GWSDB_ENV_FILE. chmod 600 it -- it holds bearer/probe tokens.`)
}

func runIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	scannerConfigPath := fs.String("scanner-config", "", "path to the gscan_quic config.json/config.user.json used for the scan")
	scanDir := fs.String("scanner-dir", "", "dir gscan_quic ran in; base for relative OutputFile paths (defaults to -scanner-config's dir)")
	logPath := fs.String("log", "", "path to the captured gscan_quic stdout log (optional)")
	mode := fs.String("mode", "", "scan mode to ingest (SNI/QUIC/TLS/PING); defaults to the config's ScanMode")
	output := fs.String("output", "", "override path to the scan output IP list; defaults to the config's OutputFile")
	logOnly := fs.Bool("log-only", false, "ignore the output file even if present; derive hits from -log only (use when a later scan overwrote the output file at this path)")
	timeout := fs.Duration("timeout", 60*time.Second, "HTTP timeout for the known-good fetch + submit round trip")
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
	for i := range filtered {
		filtered[i].ScanMode = strings.ToUpper(*mode)
	}

	if err := ingest.Submit(ctx, apiBase, token, filtered); err != nil {
		log.Fatalf("ingest: submit: %v", err)
	}
	log.Printf("ingested %d checks", len(filtered))
}

func runRecheck(args []string) {
	fs := flag.NewFlagSet("recheck", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address to re-test once, printing OK/FAIL and submitting the result -- no queue involved")
	scannerConfigPath := fs.String("scanner-config", "", "path to the local gscan_quic config.json/config.user.json to probe with")
	timeout := fs.Duration("timeout", 10*time.Second, "probe timeout")
	fs.Parse(args)

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "recheck: -ip is required")
		fs.Usage()
		os.Exit(2)
	}
	runRecheckAdHoc(*ip, *scannerConfigPath, *timeout)
}

// runRecheckAdHoc is a manual ops diagnostic: probe one IP with the scan
// config gscan_quic already has on disk, print the result, and submit it to
// Cloudflare (POST /recheck/result with id 0 -- no queue involved).
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

	apiBase := requireEnv("GWSDB_API")
	token := requireEnv("GWSDB_INGEST_TOKEN")

	// timeout bounds only the probe (matching -timeout's documented meaning
	// and PullAndRun's shape) -- Submit gets its own budget below so a slow
	// probe can't starve the HTTP call that reports its result.
	ctx := context.Background()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	result := recheck.CheckSNI(probeCtx, ip, cfg)
	cancel()
	if result.OK {
		fmt.Printf("OK ip=%s rtt=%dms\n", ip, result.RTTMs)
	} else {
		fmt.Printf("FAIL ip=%s reason=%s detail=%s\n", ip, result.Reason, result.Detail)
	}

	if err := recheck.Submit(ctx, apiBase, token, recheck.SubmitResult{
		IP:        ip,
		OK:        result.OK,
		RTTMs:     result.RTTMs,
		Reason:    result.Reason,
		Detail:    result.Detail,
		ScanMode:  recheck.DefaultScanMode,
		CheckedAt: time.Now().UTC(),
	}); err != nil {
		log.Fatalf("recheck: submit: %v", err)
	}
}

// stringSliceFlag is a flag.Value that accumulates repeated -flag values
// into a slice (Go's stdlib flag has no built-in slice type). Used for
// -ip-range, which may be given more than once to mix v4 and v6 range
// files.
type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// runScan runs the always-on scanner: N probe workers continuously test
// random IPs drawn from CIDR range files, a flusher submits accumulated
// results to the Cloudflare-hosted API on a fixed cadence, and a
// separate goroutine drains the recheck queue — all in one long-lived
// process. Replaces the old cron-driven scan_and_ingest.sh (external
// gscan_quic one-shot) + recheck_and_submit.sh pair. See internal/scan.
//
// The probe config comes from gscan_quic's config.user.json (same file
// `gwsdb ingest`/`recheck` read), so the scanner probes with the exact
// same ServerName/HTTPPath/timeout settings the last manual scan used.
// The default IP range is the config's InputFile (typically v4); add
// more with -ip-range (e.g. the v6 range file). Stops cleanly on
// SIGINT/SIGTERM with one final flush.
func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	scannerConfigPath := fs.String("scanner-config", "", "path to gscan_quic config.json/config.user.json (probe config + default IP range source)")
	scanDir := fs.String("scanner-dir", "", "dir gscan_quic ran in; base for relative InputFile paths (defaults to -scanner-config's dir)")
	mode := fs.String("mode", "SNI", "scan mode block to use from the config")
	var extraRanges stringSliceFlag
	fs.Var(&extraRanges, "ip-range", "additional IP range file (CIDR per line, v4 or v6); may be repeated")
	workers := fs.Int("workers", 10, "number of probe worker goroutines")
	interval := fs.Duration("interval", time.Second, "per-worker sleep between probes")
	probeTimeout := fs.Duration("timeout", 10*time.Second, "per-probe timeout")
	flushInterval := fs.Duration("flush", 10*time.Minute, "how often to flush accumulated checks to the API")
	probeAddr := fs.String("probe-addr", "0.0.0.0:8787", "address for the on-demand probe HTTP server (reached by the gwsdb-probe Worker via Cloudflare Mesh); empty disables it")
	probeToken := fs.String("probe-token", "", "shared secret authenticating probe requests (X-Probe-Token header); must match the Cloudflare side's PROBE_TOKEN. Required if -probe-addr is set")
	fs.Parse(args)

	if *scannerConfigPath == "" {
		fmt.Fprintln(os.Stderr, "scan: -scanner-config is required")
		fs.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*scannerConfigPath)
	if err != nil {
		log.Fatalf("scan: read scanner config: %v", err)
	}
	var gcfg ingest.GScannerConfig
	if err := json.Unmarshal(raw, &gcfg); err != nil {
		log.Fatalf("scan: parse scanner config: %v", err)
	}
	sub := gcfg.ForMode(*mode)
	if sub == nil {
		log.Fatalf("scan: scanner config has no %s block", *mode)
	}
	if strings.EqualFold(*mode, "sni") && sub.HTTPMethod == "" {
		// Same default ingest.Parse applies for SNI mode (gscan_quic's
		// testSni is the only mode that reads HTTPMethod).
		sub.HTTPMethod = "HEAD"
	}

	// Default IP range comes from the config's InputFile (gscan_quic's
	// convention), resolved relative to scanDir or the config's dir.
	// Extra -ip-range files append to it so v4 and v6 can be scanned
	// together (the China box needs v6 connectivity for v6 probes to
	// succeed; v6 failures don't affect v4 scanning).
	base := *scanDir
	if base == "" {
		base = filepath.Dir(*scannerConfigPath)
	}
	var rangePaths []string
	if sub.InputFile != "" {
		p := sub.InputFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		rangePaths = append(rangePaths, p)
	}
	for _, p := range extraRanges {
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		rangePaths = append(rangePaths, p)
	}
	if len(rangePaths) == 0 {
		log.Fatalf("scan: no IP range files (config has no InputFile for %s, and no -ip-range given)", *mode)
	}

	ipRange, err := scan.LoadIPRanges(rangePaths)
	if err != nil {
		log.Fatalf("scan: load IP ranges: %v", err)
	}

	apiBase := requireEnv("GWSDB_API")
	token := requireEnv("GWSDB_INGEST_TOKEN")

	probeTokenVal := *probeToken
	if probeTokenVal == "" {
		probeTokenVal = os.Getenv("GWSDB_PROBE_TOKEN")
	}
	if *probeAddr != "" && probeTokenVal == "" {
		log.Fatal("scan: -probe-token is required when -probe-addr is set (or set GWSDB_PROBE_TOKEN in the env file)")
	}

	sc := scan.New(scan.Config{
		ProbeConfig:   sub,
		ScanMode:      strings.ToUpper(*mode),
		IPRange:       ipRange,
		InputFile:     strings.Join(rangePaths, ","),
		Workers:       *workers,
		Interval:      *interval,
		ProbeTimeout:  *probeTimeout,
		FlushInterval: *flushInterval,
		ProbeAddr:     *probeAddr,
		ProbeToken:    probeTokenVal,
		APIBase:       apiBase,
		Token:         token,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := sc.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("scan: %v", err)
	}
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

// envFilePath returns where to look for a KEY=VALUE file holding
// GWSDB_API/GWSDB_INGEST_TOKEN, so they don't need to be exported by hand
// (or pasted anywhere) before every invocation: $GWSDB_ENV_FILE if set,
// otherwise ~/.config/gwsdb/env. chmod 600 it -- it holds a bearer token.
// gwsdb only ever reads this file, never writes it.
func envFilePath() string {
	if p := os.Getenv("GWSDB_ENV_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "gwsdb", "env")
}

// loadEnvFile reads simple KEY=VALUE lines from path (blank lines and lines
// starting with # ignored) into the process environment. A variable already
// set in the real environment wins -- the file is a convenience default,
// not an override. A missing file is not an error.
func loadEnvFile(path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	if info, err := f.Stat(); err == nil && info.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: %s is readable by others (mode %o) -- chmod 600 it, it holds a bearer token", path, info.Mode().Perm())
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue
		}
		os.Setenv(key, strings.TrimSpace(value))
	}
	if err := scanner.Err(); err != nil {
		log.Printf("warning: reading %s: %v", path, err)
	}
}
