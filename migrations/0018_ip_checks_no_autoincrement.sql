-- Migration number: 0018 	 2026-09-04T00:00:00.000Z
--
-- ip_checks.id was INTEGER PRIMARY KEY AUTOINCREMENT, and every AUTOINCREMENT
-- insert also updates a sqlite_sequence bookkeeping row -- that was the third
-- row D1 billed per inserted check (table + unique(ip, checked_at) +
-- sqlite_sequence), ~12.5k rows written/day. Plain INTEGER PRIMARY KEY (rowid
-- alias) drops the sequence write: 2 rows per insert.
--
-- Losing AUTOINCREMENT's never-reuse guarantee is safe here: (ip, checked_at)
-- uniqueness (migration 0016) is the real row identity, and pruneCheckHistory
-- only ever deletes each IP's OLDEST rows (the newest always survive), so
-- MAX(id) never regresses and ids stay monotonic in practice.
--
-- SQLite cannot drop AUTOINCREMENT via ALTER TABLE -- rebuild via copy. This
-- migration rewrites every retained check row (~1M) once; expect a large
-- single-day rows-written spike the day it's applied.
CREATE TABLE ip_checks_rebuilt (
	id         INTEGER PRIMARY KEY,
	ip         TEXT NOT NULL,
	ok         INTEGER NOT NULL,
	rtt_ms     INTEGER,
	reason     TEXT,
	detail     TEXT,
	checked_at DATETIME NOT NULL,
	scan_mode  TEXT
);

INSERT INTO ip_checks_rebuilt (id, ip, ok, rtt_ms, reason, detail, checked_at, scan_mode)
SELECT id, ip, ok, rtt_ms, reason, detail, checked_at, scan_mode FROM ip_checks;

DROP TABLE ip_checks;
ALTER TABLE ip_checks_rebuilt RENAME TO ip_checks;

CREATE UNIQUE INDEX idx_ip_checks_ip ON ip_checks(ip, checked_at);
