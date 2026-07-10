// Package geo decodes Google 1e100.net PTR hostnames into an approximate
// physical location, based on the naming convention documented at
// https://github.com/lennylxx/ipv6-hosts/wiki/1e100.net
package geo

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// pattern 1: e.g. dfw06s16-in-f31.1e100.net / dfw06s16-in-x1f.1e100.net
// [3-letter airport][2 digits]s[2 digits]-in-[f<dec>|x<hex>]
var pattern1 = regexp.MustCompile(`^([a-z]{3})(\d{2})s(\d{2})-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$`)

// pattern 2: e.g. tf-in-x64.1e100.net (regional, 2-letter code)
var pattern2 = regexp.MustCompile(`^([a-z]{2})-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$`)

// pattern 3: e.g. lcauzi-in-f90.1e100.net / nchkga-ag-in-f25.1e100.net
// [2-letter metro prefix][3-letter airport][1-3 letter server tag](-[cluster tag])?-in-[f<dec>|x<hex>]
var pattern3 = regexp.MustCompile(`^([a-z]{2})([a-z]{3})([a-z]{1,3})(?:-([a-z0-9]+))?-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$`)

// pattern 4: e.g. any-in-201d.1e100.net (anycast, no fixed airport)
// any-in-[hex, bare, no f/x marker]
var pattern4 = regexp.MustCompile(`^any-in-([0-9a-f]{2,6})\.1e100\.net\.?$`)

// siblingPattern isolates the trailing "-in-f<dec>" / "-in-x<hex>" server
// index marker shared by patterns 1-3, so it can be swapped to derive the
// other base's hostname for the same server. Doesn't match pattern 4 (no
// f/x marker), which has no sibling form.
var siblingPattern = regexp.MustCompile(`^(.+-in-)(?:f(\d{1,3})|x([0-9a-f]{2}))(\.1e100\.net\.?)$`)

// Location is the result of decoding a 1e100.net PTR hostname.
type Location struct {
	Hostname    string
	AirportCode string // e.g. "dfw", "" if not decodable
	Cluster     string // facility/cluster tag, if present (pattern 1 and 3 only)
	ServerIndex string // per-server suffix (decimal or hex, as found in the hostname)
	City        string // best-effort, "" if code unknown
	Country     string // best-effort, "" if code unknown
	Matched     bool   // true if the hostname matched a known 1e100.net pattern
}

// Decode extracts location information from a PTR hostname such as
// "dfw06s16-in-f31.1e100.net". Returns Matched=false for hostnames that don't
// follow a recognized 1e100.net naming pattern (e.g. non-Google PTRs).
func Decode(hostname string) Location {
	h := strings.ToLower(strings.TrimSpace(hostname))
	loc := Location{Hostname: hostname}

	if m := pattern1.FindStringSubmatch(h); m != nil {
		loc.Matched = true
		loc.AirportCode = m[1]
		loc.Cluster = m[2] + "s" + m[3]
		if m[4] != "" {
			loc.ServerIndex = m[4]
		} else {
			loc.ServerIndex = "0x" + m[5]
		}
		if city, country, ok := lookupAirport(loc.AirportCode); ok {
			loc.City, loc.Country = city, country
		}
		return loc
	}

	if m := pattern2.FindStringSubmatch(h); m != nil {
		loc.Matched = true
		loc.AirportCode = m[1]
		if m[2] != "" {
			loc.ServerIndex = m[2]
		} else {
			loc.ServerIndex = "0x" + m[3]
		}
		if city, country, ok := lookupRegional(loc.AirportCode); ok {
			loc.City, loc.Country = city, country
		}
		return loc
	}

	if m := pattern3.FindStringSubmatch(h); m != nil {
		loc.Matched = true
		loc.AirportCode = m[2]
		loc.Cluster = m[4]
		if m[5] != "" {
			loc.ServerIndex = m[5]
		} else {
			loc.ServerIndex = "0x" + m[6]
		}
		if city, country, ok := lookupAirport(loc.AirportCode); ok {
			loc.City, loc.Country = city, country
		}
		return loc
	}

	if m := pattern4.FindStringSubmatch(h); m != nil {
		loc.Matched = true
		loc.AirportCode = "any"
		loc.ServerIndex = "0x" + m[1]
		loc.City = "Anycast"
		return loc
	}

	return loc
}

// IsHostname reports whether s is a 1e100.net hostname (with or without a
// trailing dot), as opposed to an IP address or unrelated input.
func IsHostname(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	return strings.HasSuffix(s, ".1e100.net")
}

// SiblingHostname derives the other server-index base for hostname: given
// the decimal form (-in-f202) it returns the hex form (-in-xca) and vice
// versa. Both name the same server -- Google publishes both PTRs for it --
// so this lets the query page show one when given the other. Returns
// ok=false for hostnames with no sibling form, including pattern 4's "any"
// anycast hosts (bare hex, no f/x marker) and anything not ending in
// ".1e100.net".
func SiblingHostname(hostname string) (sibling string, ok bool) {
	if !IsHostname(hostname) {
		return "", false
	}
	h := strings.ToLower(strings.TrimSpace(hostname))
	m := siblingPattern.FindStringSubmatch(h)
	if m == nil {
		return "", false
	}
	prefix, decPart, hexPart, suffix := m[1], m[2], m[3], m[4]
	if decPart != "" {
		n, err := strconv.Atoi(decPart)
		if err != nil || n > 0xff {
			return "", false
		}
		return fmt.Sprintf("%sx%02x%s", prefix, n, suffix), true
	}
	n, err := strconv.ParseUint(hexPart, 16, 8)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%sf%d%s", prefix, n, suffix), true
}

// DecodeBest decodes every hostname in hostnames and returns the most
// specific match. Google sometimes publishes more than one PTR for the same
// IP (e.g. an f-numeric and an x-hex form of the same host, which always
// agree), but on the rare hostname that disagrees, a 3-letter airport-code
// match (pattern 1/3) outranks a 2-letter regional match (pattern 2), which
// outranks the "any" anycast fallback (pattern 4). Ties break on input
// order, so callers should pass a deterministically ordered slice (e.g.
// resolver.LookupPTR's sorted output) to get a stable result.
func DecodeBest(hostnames []string) Location {
	var best Location
	bestRank := -1
	for _, h := range hostnames {
		loc := Decode(h)
		if rank := decodeRank(loc); rank > bestRank {
			best, bestRank = loc, rank
		}
	}
	return best
}

func decodeRank(loc Location) int {
	switch {
	case !loc.Matched:
		return 0
	case loc.AirportCode == "any":
		return 1
	case len(loc.AirportCode) == 2:
		return 2
	default:
		return 3
	}
}

func lookupAirport(code string) (city, country string, ok bool) {
	e, ok := airportCodes[code]
	if !ok {
		return "", "", false
	}
	return e.city, e.country, true
}

func lookupRegional(code string) (city, country string, ok bool) {
	e, ok := regionalCodes[code]
	if !ok {
		return "", "", false
	}
	return e.city, e.country, true
}

// countryCodes maps the country names used in airportCodes/regionalCodes to
// their ISO 3166-1 alpha-2 code, for rendering flag icons (e.g. via
// bgp.he.net/images/flags/<code>.gif).
var countryCodes = map[string]string{
	"Argentina":            "ar",
	"Australia":            "au",
	"Austria":              "at",
	"Belgium":              "be",
	"Brazil":               "br",
	"Bulgaria":             "bg",
	"Canada":               "ca",
	"Chile":                "cl",
	"China":                "cn",
	"Colombia":             "co",
	"Czechia":              "cz",
	"Denmark":              "dk",
	"Egypt":                "eg",
	"Finland":              "fi",
	"France":               "fr",
	"Germany":              "de",
	"Hong Kong":            "hk",
	"Hungary":              "hu",
	"India":                "in",
	"Indonesia":            "id",
	"Ireland":              "ie",
	"Israel":               "il",
	"Italy":                "it",
	"Japan":                "jp",
	"Kenya":                "ke",
	"Malaysia":             "my",
	"Mexico":               "mx",
	"Netherlands":          "nl",
	"New Zealand":          "nz",
	"Norway":               "no",
	"Peru":                 "pe",
	"Philippines":          "ph",
	"Poland":               "pl",
	"Portugal":             "pt",
	"Qatar":                "qa",
	"Romania":              "ro",
	"Saudi Arabia":         "sa",
	"Singapore":            "sg",
	"South Africa":         "za",
	"South Korea":          "kr",
	"Spain":                "es",
	"Sweden":               "se",
	"Switzerland":          "ch",
	"Taiwan":               "tw",
	"Thailand":             "th",
	"United Arab Emirates": "ae",
	"United Kingdom":       "gb",
	"United States":        "us",
}

// CountryCode returns the ISO 3166-1 alpha-2 code for a country name as
// produced by Decode's Country field (e.g. "United States" -> "us").
// Returns "" if the name isn't recognized.
func CountryCode(country string) string {
	return countryCodes[country]
}
