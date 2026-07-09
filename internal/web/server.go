// Package web implements the (deliberately Web 1.0, JS-free) HTTP frontend.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/geo"
	"github.com/cuthead/gwsdb/internal/resolver"
	"github.com/cuthead/gwsdb/internal/store"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

const ptrTimeout = 3 * time.Second
const ptrCacheTTL = 30 * 24 * time.Hour

// Server holds the dependencies for the HTTP frontend.
type Server struct {
	st   *store.Store
	tmpl *template.Template
}

// New builds a Server backed by st.
func New(st *store.Store) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		return nil, err
	}
	return &Server{st: st, tmpl: tmpl}, nil
}

// Handler returns the root http.Handler for the app.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/query", s.handleQuery)
	return mux
}

const timeLayout = "2006-01-02 15:04:05"

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format(timeLayout)
}

// maxIPsListed caps how many rows the home page table renders. IPs are
// ordered by last_seen DESC, so this simply hides the stalest tail.
const maxIPsListed = 500

type ipRow struct {
	IP        string
	Status    string // "可达" / "不可达" / "-" (never explicitly re-checked)
	FirstSeen string
	LastSeen  string
	LastRTTMs int
}

type homeData struct {
	Title      string
	FilterUp   bool
	IPs        []ipRow
	Count      int
	Truncated  bool
	ScanMode   string
	Stats      store.Stats
	LastScanAt string
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	onlyUp := r.URL.Query().Get("status") != "all"
	data := homeData{Title: "首页", FilterUp: onlyUp}

	known, err := s.st.ListKnownIPs(onlyUp, maxIPsListed)
	if err != nil {
		log.Printf("home: ListKnownIPs: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, st := range known {
		row := ipRow{
			IP:        st.IP,
			FirstSeen: formatTime(st.FirstSeen),
			LastSeen:  formatTime(st.LastSeen),
			LastRTTMs: st.LastRTTMs,
		}
		switch {
		case !st.HasCheck:
			row.Status = "-"
		case st.LastCheckOK:
			row.Status = "可达"
		default:
			row.Status = "不可达"
		}
		data.IPs = append(data.IPs, row)
	}
	data.Count = len(data.IPs)
	data.Truncated = len(known) == maxIPsListed

	if sc, err := s.st.LatestScan(""); err == nil && sc != nil {
		data.ScanMode = sc.ScanMode
	}

	stats, err := s.st.Overview()
	if err != nil {
		log.Printf("home: Overview: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.Stats = stats
	data.LastScanAt = formatTime(stats.LastScanAt)

	s.render(w, "home.tmpl", data)
}

type checkRow struct {
	Time        string
	OK          bool
	RTT         int
	ReasonLabel string // Chinese label for Reason, "" for successes
	Detail      string // e.g. "sni=g.cn host=www.google.com.hk got_code=403"
	Probe       string // the scan's request parameters in effect at check time
}

// reasonLabels translates gscan_quic's REASON tags into short Chinese labels.
var reasonLabels = map[string]string{
	"dial":      "连接失败",
	"handshake": "TLS 握手失败",
	"cn":        "证书 CN 不匹配",
	"status":    "HTTP 状态码不符",
	"ping":      "Ping 失败",
}

func reasonLabel(reason string) string {
	if label, ok := reasonLabels[reason]; ok {
		return label
	}
	return reason
}

// describeProbe summarizes the request parameters a check was made with, so
// a failure reason can be read alongside exactly what was sent/expected.
func describeProbe(c store.IPCheck) string {
	var parts []string
	if c.ScanMode != "" {
		parts = append(parts, c.ScanMode)
	}
	if c.HTTPMethod != "" {
		parts = append(parts, "method="+c.HTTPMethod)
	}
	if c.HTTPPath != "" {
		parts = append(parts, "path="+c.HTTPPath)
	}
	if c.HTTPVerifyHosts != "" {
		parts = append(parts, "host="+c.HTTPVerifyHosts)
	}
	if c.VerifyCommonName != "" {
		parts = append(parts, "want_cn="+c.VerifyCommonName)
	}
	if c.ValidStatusCode != 0 {
		parts = append(parts, fmt.Sprintf("want_code=%d", c.ValidStatusCode))
	}
	return strings.Join(parts, " ")
}

type queryData struct {
	Title       string
	Query       string
	Submitted   bool
	Error       string
	PTRHostname string
	Matched     bool
	AirportCode string
	City        string
	Country     string
	HasHistory  bool
	Status      string // "可达" / "不可达" / "-"
	FirstSeen   string
	LastSeen    string
	TimesSeen   int
	LastRTTMs   int
	Checks      []checkRow
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	ipParam := strings.TrimSpace(r.URL.Query().Get("ip"))
	data := queryData{Title: "查询", Query: ipParam}

	if ipParam != "" {
		data.Submitted = true
		if net.ParseIP(ipParam) == nil {
			data.Error = "不是合法的 IP 地址"
		} else {
			s.lookup(ipParam, &data)
		}
	}

	s.render(w, "query.tmpl", data)
}

func (s *Server) lookup(ip string, data *queryData) {
	var hostname string
	var ok bool

	if cached, err := s.st.GetPTR(ip, ptrCacheTTL); err == nil && cached != nil {
		hostname, ok = cached.PTRHostname, cached.LookupOK
	} else {
		hostname, ok = resolver.LookupPTR(ip, ptrTimeout)
		loc := geo.Decode(hostname)
		entry := store.PTRCacheEntry{
			IP:          ip,
			PTRHostname: hostname,
			AirportCode: loc.AirportCode,
			GeoCity:     loc.City,
			GeoCountry:  loc.Country,
			LookupOK:    ok,
			CheckedAt:   time.Now().UTC(),
		}
		if err := s.st.SavePTR(entry); err != nil {
			log.Printf("query: SavePTR(%s): %v", ip, err)
		}
	}

	if ok {
		data.PTRHostname = hostname
		loc := geo.Decode(hostname)
		data.Matched = loc.Matched
		data.AirportCode = loc.AirportCode
		data.City = loc.City
		data.Country = loc.Country
	}

	st, err := s.st.IPStatusFor(ip)
	if err != nil {
		log.Printf("query: IPStatusFor(%s): %v", ip, err)
	}
	if st != nil {
		data.HasHistory = true
		data.FirstSeen = formatTime(st.FirstSeen)
		data.LastSeen = formatTime(st.LastSeen)
		data.TimesSeen = st.TimesSeen
		data.LastRTTMs = st.LastRTTMs
		switch {
		case !st.HasCheck:
			data.Status = "-"
		case st.LastCheckOK:
			data.Status = "可达"
		default:
			data.Status = "不可达"
		}
	}

	const maxHistoryRows = 30
	checks, err := s.st.IPHistory(ip, maxHistoryRows)
	if err != nil {
		log.Printf("query: IPHistory(%s): %v", ip, err)
	}
	for _, c := range checks {
		row := checkRow{
			Time:   formatTime(c.CheckedAt),
			OK:     c.OK,
			RTT:    c.RTTMs,
			Detail: c.Detail,
			Probe:  describeProbe(c),
		}
		if !c.OK {
			row.ReasonLabel = reasonLabel(c.Reason)
		}
		data.Checks = append(data.Checks, row)
	}
}

func (s *Server) render(w http.ResponseWriter, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, page, data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}
