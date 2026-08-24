-- No current query orders or filters across all ip_checks by checked_at.
-- Per-IP history and pruning use idx_ip_checks_ip instead, so retaining this
-- index only adds one D1 row write for every inserted check.
DROP INDEX idx_ip_checks_checked_at;
