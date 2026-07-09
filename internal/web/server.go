// Package web implements the (deliberately Web 1.0, JS-free) HTTP frontend.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/asn"
	"github.com/cuthead/gwsdb/internal/geo"
	"github.com/cuthead/gwsdb/internal/resolver"
	"github.com/cuthead/gwsdb/internal/store"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

const ptrTimeout = 3 * time.Second
const ptrCacheTTL = 30 * 24 * time.Hour
const asnTimeout = 3 * time.Second
const asnCacheTTL = 7 * 24 * time.Hour
const maxReportRows = 100
const maxReportCommentLen = 500

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
	mux.HandleFunc("/report", s.handleReport)
	return mux
}

// clientIP extracts the real client address, preferring Cloudflare's
// CF-Connecting-IP edge header over the generic X-Forwarded-For chain, and
// falling back to the raw socket peer. CF-Connecting-IP is only trustworthy
// if the origin refuses direct (non-Cloudflare) connections -- otherwise a
// caller can set it themselves.
func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" && net.ParseIP(v) != nil {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
	IP          string
	PTR         string // cached PTR hostname, "" if never looked up
	Country     string // best-effort, decoded from PTR, "" if unknown
	CountryCode string // ISO 3166-1 alpha-2, "" if unknown
	Status      string // "可达" / "不可达" / "-" (never explicitly re-checked)
	FirstSeen   string
	LastSeen    string
	LastRTTMs   int
}

// sortColumnDefaultDesc lists the home page's sortable columns and which
// direction "feels right" the first time each is clicked (e.g. newest/
// highest first for dates and RTT, alphabetical for IP/PTR).
var sortColumnDefaultDesc = map[string]bool{
	"ip":         false,
	"ptr":        false,
	"status":     true,
	"first_seen": true,
	"last_seen":  true,
	"rtt":        true,
}

// colSort is a precomputed header link for one sortable column: where
// clicking it goes, and the arrow to show if it's the active sort.
type colSort struct {
	URL   string
	Arrow string
}

// sortLink builds the header link for column col given the request's
// current query params and the currently active sort. Clicking an inactive
// column sorts by it in its default direction; clicking the active column
// flips direction. All other params (q, status) are preserved.
func sortLink(q url.Values, col string, activeCol string, activeDesc bool) colSort {
	next := url.Values{}
	for k, v := range q {
		if k == "sort" || k == "dir" {
			continue
		}
		next[k] = v
	}

	desc := sortColumnDefaultDesc[col]
	arrow := ""
	if col == activeCol {
		arrow = "▲"
		if activeDesc {
			arrow = "▼"
		}
		desc = !activeDesc
	}
	next.Set("sort", col)
	if desc {
		next.Set("dir", "desc")
	} else {
		next.Set("dir", "asc")
	}
	return colSort{URL: "/?" + next.Encode(), Arrow: arrow}
}

type homeData struct {
	Title      string
	FilterUp   bool
	Search     string
	Sort       map[string]colSort
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

	q := r.URL.Query()
	onlyUp := q.Get("status") != "all"
	search := strings.TrimSpace(q.Get("q"))

	sortBy := q.Get("sort")
	defaultDesc, validSort := sortColumnDefaultDesc[sortBy]
	if !validSort {
		sortBy = "last_seen"
		defaultDesc = true
	}
	sortDesc := defaultDesc
	switch q.Get("dir") {
	case "asc":
		sortDesc = false
	case "desc":
		sortDesc = true
	}

	data := homeData{Title: "首页", FilterUp: onlyUp, Search: search}
	data.Sort = make(map[string]colSort, len(sortColumnDefaultDesc))
	for col := range sortColumnDefaultDesc {
		data.Sort[col] = sortLink(q, col, sortBy, sortDesc)
	}

	known, err := s.st.ListKnownIPs(store.ListKnownIPsOptions{
		OnlyUp:   onlyUp,
		Search:   search,
		SortBy:   sortBy,
		SortDesc: sortDesc,
		Limit:    maxIPsListed,
	})
	if err != nil {
		log.Printf("home: ListKnownIPs: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, st := range known {
		row := ipRow{
			IP:        st.IP,
			PTR:       st.PTRHostname,
			FirstSeen: formatTime(st.FirstSeen),
			LastSeen:  formatTime(st.LastSeen),
			LastRTTMs: st.LastRTTMs,
		}
		if st.PTRHostname != "" {
			loc := geo.Decode(st.PTRHostname)
			row.Country = loc.Country
			row.CountryCode = geo.CountryCode(loc.Country)
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
	ReasonLabel string // human-readable label for Reason, "" for successes
	Detail      string // e.g. "sni=g.cn host=www.google.com.hk got_code=403"
	Probe       string // the scan's request parameters in effect at check time
}

// reasonLabels translates gscan_quic's REASON tags into short human-readable labels.
var reasonLabels = map[string]string{
	"dial":      "Connection failed",
	"handshake": "TLS handshake failed",
	"cn":        "Certificate CN mismatch",
	"status":    "HTTP status code mismatch",
	"ping":      "Ping failed",
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

	Reports       []reportRow
	UsableCount   int
	UnusableCount int
}

// reportRow is one community report rendered on the query page. Only the
// reporter's announced prefix and AS are shown -- never their raw IP.
type reportRow struct {
	Time           string
	Verdict        bool // true = usable
	ReporterPrefix string
	ReporterASN    int
	ReporterASName string
	Comment        string
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

	reports, err := s.st.ListReports(ip, maxReportRows)
	if err != nil {
		log.Printf("query: ListReports(%s): %v", ip, err)
	}
	for _, rep := range reports {
		if rep.Verdict {
			data.UsableCount++
		} else {
			data.UnusableCount++
		}
		data.Reports = append(data.Reports, reportRow{
			Time:           formatTime(rep.CreatedAt),
			Verdict:        rep.Verdict,
			ReporterPrefix: rep.ReporterPrefix,
			ReporterASN:    rep.ReporterASN,
			ReporterASName: rep.ReporterASName,
			Comment:        rep.Comment,
		})
	}
}

// lookupReporterASN resolves ip's announced prefix and AS, checking the
// asn_cache first so repeat reporters don't re-trigger a Cymru DNS round trip.
func (s *Server) lookupReporterASN(ip string) (asn.Info, bool) {
	if cached, err := s.st.GetASN(ip, asnCacheTTL); err == nil && cached != nil {
		return asn.Info{ASN: cached.ASN, ASName: cached.ASName, Prefix: cached.Prefix, Country: cached.Country}, cached.LookupOK
	}
	info, ok := asn.Lookup(ip, asnTimeout)
	entry := store.ASNCacheEntry{
		IP:        ip,
		ASN:       info.ASN,
		ASName:    info.ASName,
		Prefix:    info.Prefix,
		Country:   info.Country,
		LookupOK:  ok,
		CheckedAt: time.Now().UTC(),
	}
	if err := s.st.SaveASN(entry); err != nil {
		log.Printf("report: SaveASN(%s): %v", ip, err)
	}
	return info, ok
}

// handleReport records a community "usable"/"unusable" report against an IP,
// attributing it to the submitter's announced prefix and AS rather than
// their raw address.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	ip := strings.TrimSpace(r.FormValue("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}

	var verdict bool
	switch r.FormValue("verdict") {
	case "usable":
		verdict = true
	case "unusable":
		verdict = false
	default:
		http.Error(w, "invalid verdict", http.StatusBadRequest)
		return
	}

	comment := strings.TrimSpace(r.FormValue("comment"))
	if len(comment) > maxReportCommentLen {
		comment = comment[:maxReportCommentLen]
	}

	reporterIP := clientIP(r)
	rep := store.IPReport{
		IP:         ip,
		Verdict:    verdict,
		Comment:    comment,
		ReporterIP: reporterIP,
		CreatedAt:  time.Now().UTC(),
	}
	if reporterIP != "" {
		if info, ok := s.lookupReporterASN(reporterIP); ok {
			rep.ReporterPrefix = info.Prefix
			rep.ReporterASN = info.ASN
			rep.ReporterASName = info.ASName
		}
	}

	if err := s.st.SaveReport(rep); err != nil {
		log.Printf("report: SaveReport: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/query?ip="+url.QueryEscape(ip), http.StatusSeeOther)
}

func (s *Server) render(w http.ResponseWriter, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, page, data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}
