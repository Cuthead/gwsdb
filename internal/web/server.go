// Package web implements the (deliberately Web 1.0, JS-free) HTTP frontend.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/cuthead/gwsdb/internal/asn"
	"github.com/cuthead/gwsdb/internal/geo"
	"github.com/cuthead/gwsdb/internal/resolver"
	"github.com/cuthead/gwsdb/internal/store"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// staticFS holds the stylesheet, the home page's script, and the country
// flag GIFs. Flags are served from here rather than hotlinked off a third
// party, so a visitor's browser never discloses their address or referrer to
// anyone but this origin.
//
//go:embed static
var staticFS embed.FS

const repoURL = "https://github.com/cuthead/gwsdb"

// buildRevision, buildCommitURL, and buildDate are read once from the Go
// module's VCS stamp (populated automatically by `go build` in a git
// checkout) and exposed to templates for the page footer.
var buildRevision, buildCommitURL, buildDate = readBuildStamp()

func readBuildStamp() (revision, commitURL, date string) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", ""
	}
	var fullRevision string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			fullRevision = s.Value
			revision = s.Value
			if len(revision) > 7 {
				revision = revision[:7]
			}
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				date = t.Local().Format("2006-01-02")
			}
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if fullRevision != "" {
		commitURL = repoURL + "/commit/" + fullRevision
	}
	if modified && revision != "" {
		revision += "-dirty"
	}
	return revision, commitURL, date
}

const ptrTimeout = 3 * time.Second
const asnTimeout = 3 * time.Second
const maxReportRows = 100
const maxReportCommentLen = 500

// minCacheTTL floors the DNS TTL observed on a DoH response before it's
// stored in ptr_cache/asn_cache/host_cache. A 0 or near-0 TTL is common for
// some providers (Team Cymru's whois TXT records in particular) and taking
// it literally would force a fresh DoH round trip on nearly every request.
const minCacheTTL = 5 * time.Minute

// clampTTL floors ttl at minCacheTTL.
func clampTTL(ttl time.Duration) time.Duration {
	if ttl < minCacheTTL {
		return minCacheTTL
	}
	return ttl
}

// Server holds the dependencies for the HTTP frontend.
type Server struct {
	st     *store.Store
	tmpl   *template.Template
	pub    Publisher // nil when DNS publishing is not configured
	dohURL string    // "" uses the system resolver for PTR lookups; see SetDoHURL
}

// Publisher reconciles the published GWS DNS records with the store's current
// top IPs. The recheck worker calls it after a user-driven recheck.
type Publisher interface {
	Sync(ctx context.Context) error
}

// SetPublisher enables DNS publishing after a recheck. Passing nil (the
// default) disables it.
func (s *Server) SetPublisher(p Publisher) { s.pub = p }

// SetDoHURL configures a DNS-over-HTTPS endpoint (RFC 8484 wire format,
// e.g. "https://dns.google/dns-query") for PTR resolution. Passing "" (the
// default) uses the host's system resolver instead.
func (s *Server) SetDoHURL(url string) { s.dohURL = url }

// New builds a Server backed by st.
func New(st *store.Store) (*Server, error) {
	funcs := template.FuncMap{
		"buildRevision":  func() string { return buildRevision },
		"buildCommitURL": func() string { return buildCommitURL },
		"buildDate":      func() string { return buildDate },
		"repoURL":        func() string { return repoURL },
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.tmpl")
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
	mux.HandleFunc("/scans", s.handleScans)
	mux.Handle("/static/", staticHandler())
	return securityHeaders(compressResponses(mux))
}

// contentSecurityPolicy locks the pages down to their own origin. Everything
// the templates need is served from /static/, so there is no 'unsafe-inline'
// here -- which is why the stylesheet and home.js are separate files rather
// than inline <style>/<script> blocks with inline event handlers.
const contentSecurityPolicy = "default-src 'none'; " +
	"img-src 'self'; style-src 'self'; script-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// securityHeaders sets the response headers that apply to every route.
// Referrer-Policy is same-origin rather than no-referrer so that a Referer
// still arrives on the /report POST (leaving that as a usable CSRF signal)
// while outbound links to GitHub disclose nothing.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// staticHandler serves the embedded assets. A flag GIF's contents never
// change for a given country code, so it can be cached indefinitely; the
// stylesheet and script are cached for an hour instead, so a redeploy is
// picked up without needing a cache-busting query string.
func staticHandler() http.Handler {
	files := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http.FileServer renders an index for a directory path; nothing
		// under /static/ should be browsable.
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/static/flags/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		files.ServeHTTP(w, r)
	})
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

// maxScansListed caps how many rows the scans page table renders.
const maxScansListed = 500

type ipRow struct {
	IP          string
	PTR         string   // cached PTR hostname(s), newline-joined, "" if never looked up; kept for client-side search matching
	PTRList     []string // same hostnames, for rendering one linked entry per PTR record
	Country     string   // best-effort, decoded from PTR, "" if unknown
	CountryCode string   // ISO 3166-1 alpha-2, "" if unknown
	Status      string   // "Reachable" / "Unreachable" / "-" (never explicitly re-checked)
	FirstSeen   string
	LastSeen    string
	LastRTTMs   int
}

type homeData struct {
	Title      string
	IPs        []ipRow
	Count      int
	ScanMode   string
	Stats      store.Stats
	LastScanAt string
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := homeData{Title: "Home"}

	// Search, column sort, the reachable-only filter, and pagination are all
	// handled client-side in JS over this page's rows, so the full list is
	// fetched once, unfiltered, in one fixed order (newest first).
	known, err := s.st.ListKnownIPs(store.ListKnownIPsOptions{
		SortBy:   "last_seen",
		SortDesc: true,
	})
	if err != nil {
		log.Printf("home: ListKnownIPs: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, st := range known {
		hostnames := store.SplitStrings(st.PTRHostname)
		row := ipRow{
			IP:        st.IP,
			PTR:       strings.Join(hostnames, "\n"),
			PTRList:   hostnames,
			FirstSeen: formatTime(st.FirstSeen),
			LastSeen:  formatTime(st.LastSeen),
			LastRTTMs: st.LastRTTMs,
		}
		if len(hostnames) > 0 {
			loc := geo.DecodeBest(hostnames)
			row.Country = loc.Country
			row.CountryCode = geo.CountryCode(loc.Country)
		}
		switch {
		case !st.HasCheck:
			row.Status = "-"
		case st.LastCheckOK:
			row.Status = "Reachable"
		default:
			row.Status = "Unreachable"
		}
		data.IPs = append(data.IPs, row)
	}
	data.Count = len(data.IPs)

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
	Detail      string // e.g. "got_code=403"
	Probe       string // the scan's request parameters in effect at check time
}

// reasonLabels translates gscan_quic's REASON tags into short human-readable labels.
var reasonLabels = map[string]string{
	"dial":      "tcp: TCP dial timeout",
	"handshake": "tls: TLS handshake failed",
	"cn":        "tls: Certificate CN mismatch",
	"http":      "http: HTTP timeout",
	"status":    "http: HTTP status code mismatch",
}

// reasonLabel translates a gscan_quic REASON tag (and, for "ping", its DETAIL)
// into a short human-readable label. "ping" is the only reason whose DETAIL
// carries a second-level distinction: the literal string "rtt_too_low" (see
// gscan_quic's scan.go) vs. an actual ping error/timeout.
func reasonLabel(reason, detail string) string {
	if reason == "ping" {
		if detail == "rtt_too_low" {
			return "ping: RTT too low"
		}
		return "ping: Ping timeout"
	}
	if label, ok := reasonLabels[reason]; ok {
		return label
	}
	return reason
}

// describeProbe summarizes the request parameters a check was made with, so
// a failure reason can be read alongside exactly what was sent/expected.
func describeProbe(c store.IPCheck) string {
	var parts []string
	if c.Recheck {
		// Recheck rows have no owning scan, so no per-row request context;
		// they run with the latest scan's config at the time.
		parts = append(parts, "recheck")
	}
	if c.ScanMode != "" {
		parts = append(parts, c.ScanMode)
	}
	if c.ServerName != "" {
		parts = append(parts, "sni="+c.ServerName)
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
	Title        string
	Query        string
	Submitted    bool
	Error        string
	PTRHostnames []string
	Matched      bool
	AirportCode  string
	City         string
	Country      string
	HasHistory   bool
	Status       string // "Reachable" / "Unreachable" / "-"
	FirstSeen    string
	LastSeen     string
	TimesSeen    int
	LastRTTMs    int
	Checks       []checkRow

	Reports       []reportRow
	UsableCount   int
	UnusableCount int

	// QueryIsHostname is true when Query was a 1e100.net hostname rather
	// than an IP -- the query page shows HostnameForms (forward A/AAAA
	// lookups for the queried name and its decimal<->hex sibling) instead
	// of the IP-oriented PTR/history/report sections.
	QueryIsHostname bool
	HostnameForms   []hostnameForm
}

// hostnameForm is one server-index form (decimal -f or hex -x) of a
// 1e100.net hostname, with its forward-resolved addresses.
type hostnameForm struct {
	Hostname string
	IPv4     []addrStatus
	IPv6     []addrStatus
}

// addrStatus is a resolved A/AAAA address paired with its known
// reachability, if any (blank when the address has no scan history).
type addrStatus struct {
	Addr   string
	Status string // "Reachable" / "Unreachable" / "-"
}

// reportRow is one community report rendered on the query page. Only the
// reporter's announced prefix and AS are shown -- never their raw IP.
type reportRow struct {
	IP             string
	Time           string
	Verdict        bool // true = usable
	ReporterPrefix string
	ReporterASN    int
	ReporterASName string
	Comment        string
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("ip"))
	data := queryData{Title: "Query", Query: q}

	switch {
	case q == "":
		// not submitted; render the empty form
	case net.ParseIP(q) != nil:
		data.Submitted = true
		if info, ok := s.lookupASN(q); !ok || !isGoogleASN(info) {
			data.Error = "This IP does not belong to a Google ASN"
		} else {
			s.lookup(q, &data)
		}
	case geo.IsHostname(q):
		data.Submitted = true
		data.QueryIsHostname = true
		s.lookupHostname(q, &data)
	default:
		data.Submitted = true
		data.Error = "Not a valid IP address or 1e100.net hostname"
	}

	s.render(w, "query.tmpl", data)
}

// conflictingLocations reports whether hostnames' matched, resolvable
// entries decode to more than one distinct city/country. A single IP with
// multiple PTRs normally agrees (an f-numeric and x-hex form of the same
// host); disagreement would mean Google published genuinely inconsistent
// PTRs for that IP, worth a log line even though DecodeBest silently picks
// a deterministic winner.
func conflictingLocations(hostnames []string) bool {
	var city, country string
	for _, h := range hostnames {
		loc := geo.Decode(h)
		if !loc.Matched || loc.City == "" {
			continue
		}
		if city == "" {
			city, country = loc.City, loc.Country
		} else if loc.City != city || loc.Country != country {
			return true
		}
	}
	return false
}

// resolveAndCachePTR does a live PTR lookup for ip and upserts the result
// into ptr_cache, regardless of what's already cached. Shared by the
// on-demand /query lookup (cache miss) and the background refresher.
// Transient lookup failures (timeout, SERVFAIL) are not cached, so the next
// lookup or refresher pass retries; only NXDOMAIN is cached as lookup_ok=0.
func (s *Server) resolveAndCachePTR(ip string) (hostnames []string, ok bool) {
	hostnames, ttl, ok, err := resolver.LookupPTR(ip, ptrTimeout, s.dohURL)
	if err != nil {
		log.Printf("ptr: lookup %s: %v (not cached)", ip, err)
		return nil, false
	}
	if conflictingLocations(hostnames) {
		log.Printf("ptr: %s has PTR records disagreeing on location: %v", ip, hostnames)
	}
	entry := store.PTRCacheEntry{
		IP:          ip,
		PTRHostname: store.JoinStrings(hostnames),
		LookupOK:    ok,
		TTL:         clampTTL(ttl),
		CheckedAt:   time.Now().UTC(),
	}
	if err := s.st.SavePTR(entry); err != nil {
		log.Printf("ptr: SavePTR(%s): %v", ip, err)
	}
	return hostnames, ok
}

// StartPTRRefresher resolves one missing/stale ptr_cache entry per interval
// tick, so ip_pool IPs accumulate PTR records in the background instead of
// only on a user's /query click. Intended to run in its own goroutine for
// the lifetime of the server.
func (s *Server) StartPTRRefresher(interval time.Duration) {
	for {
		ip, err := s.st.NextIPForPTRRefresh()
		if err != nil {
			log.Printf("ptr-refresh: NextIPForPTRRefresh: %v", err)
		} else if ip != "" {
			s.resolveAndCachePTR(ip)
		}
		time.Sleep(interval)
	}
}

// reachabilityStatus derives the display status from an IPStatus row ("-" if
// st is nil, meaning the address has no scan history at all).
func reachabilityStatus(st *store.IPStatus) string {
	switch {
	case st == nil || !st.HasCheck:
		return "-"
	case st.LastCheckOK:
		return "Reachable"
	default:
		return "Unreachable"
	}
}

// statusForIP is reachabilityStatus for a single address looked up by IP,
// for the compact per-address display in hostname-mode query results.
func (s *Server) statusForIP(ip string) string {
	st, err := s.st.IPStatusFor(ip)
	if err != nil {
		log.Printf("query: IPStatusFor(%s): %v", ip, err)
	}
	return reachabilityStatus(st)
}

// lookupHostname handles querying by a 1e100.net hostname directly (as
// opposed to by IP): decodes the location from the hostname's naming
// convention, then forward-resolves A/AAAA for it and, where a
// decimal<->hex sibling form exists (e.g. f202 <-> xca, the same server
// under its other base -- see geo.SiblingHostname), for that form too.
func (s *Server) lookupHostname(hostname string, data *queryData) {
	loc := geo.Decode(hostname)
	data.Matched = loc.Matched
	data.AirportCode = loc.AirportCode
	data.City = loc.City
	data.Country = loc.Country

	data.HostnameForms = append(data.HostnameForms, s.resolveHostnameForm(hostname))
	if sibling, ok := geo.SiblingHostname(hostname); ok {
		data.HostnameForms = append(data.HostnameForms, s.resolveHostnameForm(sibling))
	}
}

// resolveHostnameForm forward-resolves hostname's A/AAAA records (via
// host_cache, refreshing on a cache miss/expiry) and looks up each
// address's known reachability (blank/"-" if never scanned).
func (s *Server) resolveHostnameForm(hostname string) hostnameForm {
	var ipv4, ipv6 []string
	if cached, err := s.st.GetHost(hostname); err == nil && cached != nil {
		ipv4, ipv6 = cached.IPv4, cached.IPv6
	} else {
		ipv4, ipv6 = s.resolveAndCacheHost(hostname)
	}
	form := hostnameForm{Hostname: hostname}
	for _, addr := range ipv4 {
		form.IPv4 = append(form.IPv4, addrStatus{Addr: addr, Status: s.statusForIP(addr)})
	}
	for _, addr := range ipv6 {
		form.IPv6 = append(form.IPv6, addrStatus{Addr: addr, Status: s.statusForIP(addr)})
	}
	return form
}

// resolveAndCacheHost does a live forward A/AAAA lookup for hostname and
// upserts the result into host_cache, regardless of what's already cached.
func (s *Server) resolveAndCacheHost(hostname string) (ipv4, ipv6 []string) {
	ipv4, ipv6, ttl, ok, err := resolver.LookupHost(hostname, ptrTimeout, s.dohURL)
	if err != nil {
		log.Printf("host: lookup %s: %v (not cached)", hostname, err)
		return nil, nil
	}
	entry := store.HostCacheEntry{
		Hostname:  hostname,
		IPv4:      ipv4,
		IPv6:      ipv6,
		LookupOK:  ok,
		TTL:       clampTTL(ttl),
		CheckedAt: time.Now().UTC(),
	}
	if err := s.st.SaveHost(entry); err != nil {
		log.Printf("host: SaveHost(%s): %v", hostname, err)
	}
	return ipv4, ipv6
}

func (s *Server) lookup(ip string, data *queryData) {
	var hostnames []string
	var ok bool

	if cached, err := s.st.GetPTR(ip); err == nil && cached != nil {
		hostnames, ok = store.SplitStrings(cached.PTRHostname), cached.LookupOK
	} else {
		hostnames, ok = s.resolveAndCachePTR(ip)
	}

	if ok {
		data.PTRHostnames = hostnames
		loc := geo.DecodeBest(hostnames)
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
	}
	data.Status = reachabilityStatus(st)

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
			row.ReasonLabel = reasonLabel(c.Reason, c.Detail)
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

// googleASNNameSubstr is matched case-insensitively against Team Cymru's AS
// name field (e.g. "GOOGLE, US", "GOOGLE-CLOUD-PLATFORM, US") to decide
// whether an IP belongs to Google.
const googleASNNameSubstr = "GOOGLE"

// isGoogleASN reports whether info's AS name identifies it as Google's.
func isGoogleASN(info asn.Info) bool {
	return strings.Contains(strings.ToUpper(info.ASName), googleASNNameSubstr)
}

// lookupASN resolves ip's announced prefix and AS, checking the asn_cache
// first so repeat lookups don't re-trigger a Cymru DNS round trip.
func (s *Server) lookupASN(ip string) (asn.Info, bool) {
	if cached, err := s.st.GetASN(ip); err == nil && cached != nil {
		return asn.Info{ASN: cached.ASN, ASName: cached.ASName, Prefix: cached.Prefix, Country: cached.Country}, cached.LookupOK
	}
	info, ttl, ok := asn.Lookup(ip, asnTimeout, s.dohURL)
	if !ok {
		return info, ok
	}
	if !isGoogleASN(info) {
		return info, ok
	}
	entry := store.ASNCacheEntry{
		IP:        ip,
		ASN:       info.ASN,
		ASName:    info.ASName,
		Prefix:    info.Prefix,
		Country:   info.Country,
		LookupOK:  ok,
		TTL:       clampTTL(ttl),
		CheckedAt: time.Now().UTC(),
	}
	if err := s.st.SaveASN(entry); err != nil {
		log.Printf("report: SaveASN(%s): %v", ip, err)
	}
	return info, ok
}

func sameOrigin(r *http.Request) bool {
	for _, h := range []string{"Origin", "Referer"} {
		if v := r.Header.Get(h); v != "" {
			u, err := url.Parse(v)
			return err == nil && u.Host != "" && u.Host == r.Host
		}
	}
	return false
}

// handleReport records a community "usable"/"unusable" report against an IP,
// attributing it to the submitter's announced prefix and AS rather than
// their raw address.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
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
	if info, ok := s.lookupASN(ip); !ok || !isGoogleASN(info) {
		http.Error(w, "this IP does not belong to a Google ASN", http.StatusBadRequest)
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

	// The reporter's address is used only to resolve their announced
	// prefix/AS; it is never persisted.
	reporterIP := clientIP(r)
	rep := store.IPReport{
		IP:        ip,
		Verdict:   verdict,
		Comment:   comment,
		CreatedAt: time.Now().UTC(),
	}
	if reporterIP != "" {
		if info, ok := s.lookupASN(reporterIP); ok {
			rep.ReporterPrefix = info.Prefix
			rep.ReporterASN = info.ASN
			rep.ReporterASName = info.ASName
		}
	}

	// Require an explicit confirm step so the reporter sees what's about to
	// be published (their announced prefix/AS) before it's stored.
	if r.FormValue("confirm") != "1" {
		s.render(w, "report_confirm.tmpl", reportRow{
			IP:             rep.IP,
			Verdict:        rep.Verdict,
			Comment:        rep.Comment,
			ReporterPrefix: rep.ReporterPrefix,
			ReporterASN:    rep.ReporterASN,
			ReporterASName: rep.ReporterASName,
		})
		return
	}

	reportID, err := s.st.SaveReport(rep)
	if err != nil {
		log.Printf("report: SaveReport: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.maybeEnqueueRecheck(reportID, rep)

	http.Redirect(w, r, "/query?ip="+url.QueryEscape(ip), http.StatusSeeOther)
}

// maybeEnqueueRecheck schedules a re-scan of rep.IP if either we've never
// tested it before and the report claims it's usable (a first look might gain
// us a working IP; an "unusable" claim about an IP nobody uses gains nothing,
// and skipping it keeps the queue from being a free scanner of Google's
// address space) or this report postdates our last check of it and disagrees
// with what that check found. Evaluated once, right here at report-submission
// time, so each report can trigger at most one recheck regardless of how the
// underlying status changes later.
func (s *Server) maybeEnqueueRecheck(reportID int64, rep store.IPReport) {
	st, err := s.st.IPStatusFor(rep.IP)
	if err != nil {
		log.Printf("report: IPStatusFor(%s): %v", rep.IP, err)
		return
	}
	if st == nil || !st.HasCheck {
		if !rep.Verdict {
			return
		}
	} else if !rep.CreatedAt.After(st.LastCheckedAt) || rep.Verdict == st.LastCheckOK {
		return
	}
	if err := s.st.EnqueueRecheck(reportID, rep.IP, rep.CreatedAt); err != nil {
		log.Printf("report: EnqueueRecheck(%s): %v", rep.IP, err)
	}
}

type scanRow struct {
	ID            int64
	ScanMode      string
	StartedAt     string
	FinishedAt    string
	Duration      string
	ScannedCount  int
	FoundCount    int
	ConfigSummary string
	ConfigJSON    string
}

// describeScanConfig summarizes a scan's request/target parameters into one
// compact line, mirroring describeProbe's label=value style.
func describeScanConfig(sc store.Scan) string {
	var parts []string
	if sc.ServerName != "" {
		parts = append(parts, "server="+sc.ServerName)
	}
	if sc.VerifyCommonName != "" {
		parts = append(parts, "verify_cn="+sc.VerifyCommonName)
	}
	if sc.HTTPMethod != "" {
		parts = append(parts, "method="+sc.HTTPMethod)
	}
	if sc.HTTPPath != "" {
		parts = append(parts, "path="+sc.HTTPPath)
	}
	if sc.HTTPVerifyHosts != "" {
		parts = append(parts, "host="+sc.HTTPVerifyHosts)
	}
	if sc.ValidStatusCode != 0 {
		parts = append(parts, fmt.Sprintf("valid_code=%d", sc.ValidStatusCode))
	}
	if sc.Level != 0 {
		parts = append(parts, fmt.Sprintf("level=%d", sc.Level))
	}
	if sc.InputFile != "" {
		parts = append(parts, "input="+sc.InputFile)
	}
	if sc.OutputFile != "" {
		parts = append(parts, "output="+sc.OutputFile)
	}
	return strings.Join(parts, " ")
}

type scansData struct {
	Title     string
	Scans     []scanRow
	Count     int
	Truncated bool
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.st.ListScans(maxScansListed)
	if err != nil {
		log.Printf("scans: ListScans: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := scansData{Title: "Scan History"}
	for _, sc := range scans {
		row := scanRow{
			ID:            sc.ID,
			ScanMode:      sc.ScanMode,
			StartedAt:     formatTime(sc.StartedAt),
			FinishedAt:    formatTime(sc.FinishedAt),
			ScannedCount:  sc.ScannedCount,
			FoundCount:    sc.FoundCount,
			ConfigSummary: describeScanConfig(sc),
			ConfigJSON:    sc.ConfigJSON,
		}
		if !sc.StartedAt.IsZero() && !sc.FinishedAt.IsZero() && sc.FinishedAt.After(sc.StartedAt) {
			row.Duration = sc.FinishedAt.Sub(sc.StartedAt).Round(time.Second).String()
		}
		data.Scans = append(data.Scans, row)
	}
	data.Count = len(data.Scans)
	data.Truncated = len(scans) == maxScansListed

	s.render(w, "scans.tmpl", data)
}

func (s *Server) render(w http.ResponseWriter, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, page, data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}
