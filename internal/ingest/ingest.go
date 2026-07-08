// Package ingest reads a completed gscan_quic run (its config file, output
// IP list, and captured stdout log) and loads it into the gwsdb store.
package ingest

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/store"
)

// Options controls one ingest run.
type Options struct {
	ConfigPath string // path to config.json / config.user.json used for the scan
	LogPath    string // path to captured stdout log, optional
	ScanMode   string // override scan mode; defaults to config's ScanMode
	OutputPath string // override output file path; defaults to config's OutputFile for the mode
}

var logLineTS = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s`)
var foundRecordRE = regexp.MustCompile(`Found a record: IP=(\S+), RTT=(\S+)`)
var failRecordRE = regexp.MustCompile(`Tested IP=(\S+) RESULT=fail(?: REASON=(\S+))?(?: DETAIL=(.*))?`)
var summaryRE = regexp.MustCompile(`Scanned (\d+) IP in ([^,]+), found (\d+) records`)

// Run parses the artifacts described by opts and stores them as one Scan.
func Run(st *store.Store, opts Options) (int64, error) {
	raw, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return 0, fmt.Errorf("read config: %w", err)
	}
	var cfg GScannerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("parse config: %w", err)
	}

	mode := opts.ScanMode
	if mode == "" {
		mode = cfg.ScanMode
	}
	if mode == "" {
		return 0, fmt.Errorf("scan mode not set in config or options")
	}
	sub := cfg.ForMode(mode)
	if sub == nil {
		return 0, fmt.Errorf("unknown scan mode %q", mode)
	}

	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = sub.OutputFile
	}
	if outputPath == "" {
		return 0, fmt.Errorf("no output file for mode %q", mode)
	}

	ips, err := readOutputIPs(outputPath, sub.OutputSeparator)
	if err != nil {
		return 0, fmt.Errorf("read output file: %w", err)
	}

	var logText string
	sum := logSummary{RTTByIP: map[string]int{}}

	if opts.LogPath != "" {
		logBytes, err := os.ReadFile(opts.LogPath)
		if err != nil {
			return 0, fmt.Errorf("read log: %w", err)
		}
		logText = string(logBytes)
		sum = parseLog(logText)

		if cfg.LogLevel < 5 {
			log.Printf("warning: config LogLevel=%d (<5) -- failed attempts won't be logged, so ip_checks history will be incomplete; set \"LogLevel\": 5 in the scan config", cfg.LogLevel)
		}
	}

	results := make([]store.ScanResult, 0, len(ips))
	for i, ip := range ips {
		results = append(results, store.ScanResult{
			IP:    ip,
			RTTMs: sum.RTTByIP[ip],
			Rank:  i + 1,
		})
	}
	foundCount := sum.FoundCount
	if foundCount == 0 {
		foundCount = len(results)
	}

	configJSON, err := store.MarshalConfig(cfg)
	if err != nil {
		return 0, fmt.Errorf("marshal config: %w", err)
	}

	scan := &store.Scan{
		ScanMode:         strings.ToUpper(mode),
		ServerName:       strings.Join(sub.ServerName, ","),
		VerifyCommonName: sub.VerifyCommonName,
		HTTPPath:         sub.HTTPPath,
		HTTPVerifyHosts:  strings.Join(sub.HTTPVerifyHosts, ","),
		ValidStatusCode:  sub.ValidStatusCode,
		InputFile:        sub.InputFile,
		OutputFile:       outputPath,
		Level:            sub.Level,
		ConfigJSON:       configJSON,
		LogText:          logText,
		StartedAt:        sum.StartedAt,
		FinishedAt:       sum.FinishedAt,
		ScannedCount:     sum.ScannedCount,
		FoundCount:       foundCount,
	}

	return st.SaveScan(scan, results, sum.Checks)
}

// readOutputIPs parses a gscan_quic output file. Handles both the plain
// separator-joined format and the "gop" quoted-and-comma format.
func readOutputIPs(path, sep string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}

	var fields []string
	if sep == "gop" || strings.Contains(text, `", "`) {
		text = strings.Trim(text, `",`)
		fields = strings.Split(text, `", "`)
	} else {
		if sep == "" {
			sep = "\n"
		}
		fields = strings.Split(text, sep)
	}

	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(strings.Trim(f, `"`))
		if f == "" {
			continue
		}
		// tolerate "N\tIP" index-prefixed lines produced by some scan modes
		if idx := strings.LastIndexByte(f, '\t'); idx >= 0 {
			f = strings.TrimSpace(f[idx+1:])
		}
		if f != "" {
			out = append(out, f)
		}
	}
	return out, nil
}

// logSummary is everything extracted from a captured gscan_quic stdout log.
type logSummary struct {
	RTTByIP      map[string]int
	Checks       []store.IPCheck // every attempted IP, success and failure alike
	StartedAt    time.Time
	FinishedAt   time.Time
	ScannedCount int
	FoundCount   int
}

// parseLog extracts per-IP RTTs, per-IP pass/fail checks, and run metadata
// from a captured gscan_quic stdout log. All fields are best-effort: a log
// that doesn't match the expected format simply yields zero values. Requires
// a gscan_quic build that logs failed attempts too (not just successes).
func parseLog(text string) logSummary {
	sum := logSummary{RTTByIP: map[string]int{}}
	lines := strings.Split(text, "\n")

	var lineTime time.Time
	for _, line := range lines {
		if ts := logLineTS.FindStringSubmatch(line); ts != nil {
			t, err := time.ParseInLocation("2006/01/02 15:04:05", ts[1], time.Local)
			if err == nil {
				lineTime = t
				if sum.StartedAt.IsZero() {
					sum.StartedAt = t
				}
				sum.FinishedAt = t
			}
		}
		if m := foundRecordRE.FindStringSubmatch(line); m != nil {
			rtt := 0
			if d, err := time.ParseDuration(m[2]); err == nil {
				rtt = int(d.Milliseconds())
				sum.RTTByIP[m[1]] = rtt
			}
			sum.Checks = append(sum.Checks, store.IPCheck{IP: m[1], OK: true, RTTMs: rtt, CheckedAt: lineTime})
			continue
		}
		if m := failRecordRE.FindStringSubmatch(line); m != nil {
			sum.Checks = append(sum.Checks, store.IPCheck{
				IP:        m[1],
				OK:        false,
				Reason:    m[2],
				Detail:    strings.TrimRight(m[3], "\r"),
				CheckedAt: lineTime,
			})
			continue
		}
		if m := summaryRE.FindStringSubmatch(line); m != nil {
			sum.ScannedCount, _ = strconv.Atoi(m[1])
			sum.FoundCount, _ = strconv.Atoi(m[3])
		}
	}
	return sum
}
