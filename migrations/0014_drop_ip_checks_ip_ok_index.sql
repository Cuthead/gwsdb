-- Known-good membership now uses ip_pool's primary key. No remaining query
-- filters ip_checks by both ip and ok, so this index only amplifies writes.
DROP INDEX idx_ip_checks_ip_ok;
