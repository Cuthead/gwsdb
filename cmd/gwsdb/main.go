// Command gwsdb serves the GWS Database web app and ingests gscan_quic scan
// results into its SQLite store.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cuthead/gwsdb/internal/config"
	"github.com/cuthead/gwsdb/internal/ingest"
	"github.com/cuthead/gwsdb/internal/publish"
	"github.com/cuthead/gwsdb/internal/recheck"
	"github.com/cuthead/gwsdb/internal/store"
	"github.com/cuthead/gwsdb/internal/web"
)

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
  gwsdb recheck -db PATH -ip IP [-timeout 10s] [-config config.json]`)
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

	go srv.StartPTRRefresher(15 * time.Second)
	go srv.StartRecheckWorker(15 * time.Second)

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

func runRecheck(args []string) {
	fs := flag.NewFlagSet("recheck", flag.ExitOnError)
	dbPath := fs.String("db", "gwsdb.sqlite3", "path to the SQLite database file")
	ip := fs.String("ip", "", "IP address to re-test")
	timeout := fs.Duration("timeout", 10*time.Second, "probe timeout")
	configPath := fs.String("config", "config.json", "path to gwsdb's config.json for post-recheck DNS publish")
	fs.Parse(args)

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "recheck: -ip is required")
		fs.Usage()
		os.Exit(2)
	}
	if net.ParseIP(*ip) == nil {
		log.Fatalf("recheck: invalid ip %q", *ip)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	result, err := recheck.RunAndSave(st, *ip, recheck.DefaultScanMode, *timeout)
	if err != nil {
		log.Fatalf("recheck: %v", err)
	}
	if result.OK {
		fmt.Printf("OK ip=%s rtt=%dms\n", *ip, result.RTTMs)
	} else {
		fmt.Printf("FAIL ip=%s reason=%s detail=%s\n", *ip, result.Reason, result.Detail)
	}

	// A recheck changed this IP's status, so the top set may have shifted;
	// reconcile the published records. Publish failure doesn't fail the
	// recheck -- the result is already saved.
	if pub := buildPublisher(st, *configPath); pub != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cliPublishTimeout)
		defer cancel()
		if err := pub.Sync(ctx); err != nil {
			log.Printf("recheck: publish: %v", err)
		} else {
			log.Printf("recheck: dns publish synced")
		}
	}
}
