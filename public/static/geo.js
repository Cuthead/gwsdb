// @license magnet:?xt=urn:btih:1f739d935676111cfff4b4693e3816e664797050&dn=gpl-3.0.txt GPL-3.0

// Ports internal/geo/geo.go: decodes Google 1e100.net PTR hostnames into an
// approximate physical location, based on the naming convention documented
// at https://github.com/lennylxx/ipv6-hosts/wiki/1e100.net. Pure/offline --
// no network calls, no external service -- unlike internal/asn and
// internal/resolver (deferred to a later phase).
import { airportCodes, regionalCodes } from "./geoData.js";

// pattern 1: e.g. dfw06s16-in-f31.1e100.net / dfw06s16-in-x1f.1e100.net
// [3-letter airport][2 digits]s[2 digits]-in-[f<dec>|x<hex>]
const pattern1 = /^([a-z]{3})(\d{2})s(\d{2})-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$/;

// pattern 2: e.g. tf-in-x64.1e100.net (regional, 2-letter code)
const pattern2 = /^([a-z]{2})-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$/;

// pattern 3: e.g. lcauzi-in-f90.1e100.net / nchkga-ag-in-f25.1e100.net
// [2-letter metro prefix][3-letter airport][1-3 letter server tag](-[cluster tag])?-in-[f<dec>|x<hex>]
const pattern3 = /^([a-z]{2})([a-z]{3})([a-z]{1,3})(?:-([a-z0-9]+))?-in-(?:f(\d{1,3})|x([0-9a-f]{2}))\.1e100\.net\.?$/;

// pattern 4: e.g. any-in-201d.1e100.net (anycast, no fixed airport)
// any-in-[hex, bare, no f/x marker]
const pattern4 = /^any-in-([0-9a-f]{2,6})\.1e100\.net\.?$/;

// siblingPattern isolates the trailing "-in-f<dec>" / "-in-x<hex>" server
// index marker shared by patterns 1-3, so it can be swapped to derive the
// other base's hostname for the same server. Doesn't match pattern 4 (no
// f/x marker), which has no sibling form.
const siblingPattern = /^(.+-in-)(?:f(\d{1,3})|x([0-9a-f]{2}))(\.1e100\.net\.?)$/;

/**
 * @typedef {{
 *   hostname: string,
 *   airportCode: string,
 *   cluster: string,
 *   serverIndex: string,
 *   city: string,
 *   country: string,
 *   matched: boolean,
 * }} Location
 */

function emptyLocation(hostname) {
	return { hostname, airportCode: "", cluster: "", serverIndex: "", city: "", country: "", matched: false };
}

// decode extracts location information from a PTR hostname such as
// "dfw06s16-in-f31.1e100.net". Returns matched=false for hostnames that
// don't follow a recognized 1e100.net naming pattern (e.g. non-Google PTRs).
export function decode(hostname) {
	const h = hostname.trim().toLowerCase();
	const loc = emptyLocation(hostname);

	let m = pattern1.exec(h);
	if (m) {
		loc.matched = true;
		loc.airportCode = m[1];
		loc.cluster = m[2] + "s" + m[3];
		loc.serverIndex = m[4] ? m[4] : "0x" + m[5];
		const place = airportCodes[loc.airportCode];
		if (place) {
			loc.city = place.city;
			loc.country = place.country;
		}
		return loc;
	}

	m = pattern2.exec(h);
	if (m) {
		loc.matched = true;
		loc.airportCode = m[1];
		loc.serverIndex = m[2] ? m[2] : "0x" + m[3];
		const place = regionalCodes[loc.airportCode];
		if (place) {
			loc.city = place.city;
			loc.country = place.country;
		}
		return loc;
	}

	m = pattern3.exec(h);
	if (m) {
		loc.matched = true;
		loc.airportCode = m[2];
		loc.cluster = m[4] ?? "";
		loc.serverIndex = m[5] ? m[5] : "0x" + m[6];
		const place = airportCodes[loc.airportCode];
		if (place) {
			loc.city = place.city;
			loc.country = place.country;
		}
		return loc;
	}

	m = pattern4.exec(h);
	if (m) {
		loc.matched = true;
		loc.airportCode = "any";
		loc.serverIndex = "0x" + m[1];
		loc.city = "Anycast";
		return loc;
	}

	return loc;
}

// isHostname reports whether s is a 1e100.net hostname (with or without a
// trailing dot), as opposed to an IP address or unrelated input.
export function isHostname(s) {
	const h = s.trim().toLowerCase().replace(/\.$/, "");
	return h.endsWith(".1e100.net");
}

// siblingHostname derives the other server-index base for hostname: given
// the decimal form (-in-f202) it returns the hex form (-in-xca) and vice
// versa. Both name the same server -- Google publishes both PTRs for it --
// so this lets the query page show one when given the other. Returns
// null for hostnames with no sibling form, including pattern 4's "any"
// anycast hosts (bare hex, no f/x marker) and anything not ending in
// ".1e100.net".
export function siblingHostname(hostname) {
	if (!isHostname(hostname)) return null;
	const h = hostname.trim().toLowerCase();
	const m = siblingPattern.exec(h);
	if (!m) return null;
	const [, prefix, decPart, hexPart, suffix] = m;
	if (decPart) {
		const n = parseInt(decPart, 10);
		if (Number.isNaN(n) || n > 0xff) return null;
		return `${prefix}x${n.toString(16).padStart(2, "0")}${suffix}`;
	}
	const n = parseInt(hexPart, 16);
	if (Number.isNaN(n)) return null;
	return `${prefix}f${n}${suffix}`;
}

// decodeBest decodes every hostname in hostnames and returns the most
// specific match. Google sometimes publishes more than one PTR for the same
// IP (e.g. an f-numeric and an x-hex form of the same host, which always
// agree), but on the rare hostname that disagrees, a 3-letter airport-code
// match (pattern 1/3) outranks a 2-letter regional match (pattern 2), which
// outranks the "any" anycast fallback (pattern 4). Ties break on input
// order, so callers should pass a deterministically ordered array to get a
// stable result.
export function decodeBest(hostnames) {
	let best = emptyLocation("");
	let bestRank = -1;
	for (const h of hostnames) {
		const loc = decode(h);
		const rank = decodeRank(loc);
		if (rank > bestRank) {
			best = loc;
			bestRank = rank;
		}
	}
	return best;
}

function decodeRank(loc) {
	if (!loc.matched) return 0;
	if (loc.airportCode === "any") return 1;
	if (loc.airportCode.length === 2) return 2;
	return 3;
}

// countryCodes maps the country names used in airportCodes/regionalCodes to
// their ISO 3166-1 alpha-2 code, for rendering flag icons.
const countryCodes = {
	Argentina: "ar",
	Australia: "au",
	Austria: "at",
	Belgium: "be",
	Brazil: "br",
	Bulgaria: "bg",
	Canada: "ca",
	Chile: "cl",
	China: "cn",
	Colombia: "co",
	Czechia: "cz",
	Denmark: "dk",
	Egypt: "eg",
	Finland: "fi",
	France: "fr",
	Germany: "de",
	"Hong Kong": "hk",
	Hungary: "hu",
	India: "in",
	Indonesia: "id",
	Ireland: "ie",
	Israel: "il",
	Italy: "it",
	Japan: "jp",
	Kenya: "ke",
	Malaysia: "my",
	Mexico: "mx",
	Netherlands: "nl",
	"New Zealand": "nz",
	Norway: "no",
	Peru: "pe",
	Philippines: "ph",
	Poland: "pl",
	Portugal: "pt",
	Qatar: "qa",
	Romania: "ro",
	"Saudi Arabia": "sa",
	Singapore: "sg",
	"South Africa": "za",
	"South Korea": "kr",
	Spain: "es",
	Sweden: "se",
	Switzerland: "ch",
	Taiwan: "tw",
	Thailand: "th",
	"United Arab Emirates": "ae",
	"United Kingdom": "gb",
	"United States": "us",
};

// countryCode returns the ISO 3166-1 alpha-2 code for a country name as
// produced by decode's country field (e.g. "United States" -> "us").
// Returns "" if the name isn't recognized.
export function countryCode(country) {
	return countryCodes[country] ?? "";
}
// @license-end
