-- Migration number: 0004 	 2026-07-12T09:27:35.564Z

-- asn_cache was keyed by the exact IP queried, even though what's actually
-- cached is the announced *prefix* Team Cymru's whois returns (e.g.
-- 8.8.8.0/24) -- every IP in that prefix has identical asn/as_name/country,
-- so keying by IP meant every distinct IP in the same prefix paid its own
-- Cymru DNS round trip. Reworked to key by prefix, with a range-scan for
-- lookups (see src/ipAddr.ts's ipToHex/prefixToRange, src/store.ts's
-- getASN/saveASN). Pure cache data (no downstream consistency dependents
-- like ip_pool has) -- drop and recreate rather than backfill.
DROP TABLE asn_cache;

CREATE TABLE asn_cache (
	prefix        TEXT PRIMARY KEY,
	is_ipv6       INTEGER NOT NULL,
	range_start   TEXT NOT NULL, -- 32-hex-char (128-bit) zero-padded; IPv4 embedded in the low 32 bits
	range_end     TEXT NOT NULL,
	prefix_len    INTEGER NOT NULL,
	asn           INTEGER,
	as_name       TEXT,
	country       TEXT,
	lookup_ok     INTEGER NOT NULL DEFAULT 1,
	ttl_seconds   INTEGER NOT NULL DEFAULT 0,
	checked_at    DATETIME NOT NULL
);

CREATE INDEX idx_asn_cache_range ON asn_cache(is_ipv6, range_start, range_end);
