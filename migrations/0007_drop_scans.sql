-- Drop the scans table and its FK columns. The always-on scanner now writes
-- ip_checks directly (no per-flush Scan row), the query page's "Probe
-- Request" column is removed (config is fixed by config.user.json, not per-
-- scan), and home page stats are now check-based (Total Checks / Last Check
-- from ip_checks, not scans).
DROP INDEX IF EXISTS idx_ip_checks_scan_id;
ALTER TABLE ip_checks DROP COLUMN scan_id;
ALTER TABLE ip_checks DROP COLUMN config_scan_id;
ALTER TABLE ip_pool DROP COLUMN last_scan_id;
DROP TABLE IF EXISTS scans;
