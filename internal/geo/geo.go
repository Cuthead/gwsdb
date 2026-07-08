// Package geo decodes Google 1e100.net PTR hostnames into an approximate
// physical location, based on the naming convention documented at
// https://github.com/lennylxx/ipv6-hosts/wiki/1e100.net
package geo

import (
	"regexp"
	"strings"
)

// pattern 1: e.g. dfw06s16-in-f31.1e100.net / dfw06s16-in-x1f.1e100.net
// [3-letter airport][2 digits]s[2 digits]-in-[f<dec>|x<hex>]
var pattern1 = regexp.MustCompile(`^([a-z]{3})(\d{2})s(\d{2})-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$`)

// pattern 2: e.g. tf-in-x64.1e100.net (regional, 2-letter code)
var pattern2 = regexp.MustCompile(`^([a-z]{2})-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$`)

// Location is the result of decoding a 1e100.net PTR hostname.
type Location struct {
	Hostname    string
	AirportCode string // e.g. "dfw", "" if not decodable
	Cluster     string // facility/cluster digits, if present (pattern 1 only)
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

	return loc
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
