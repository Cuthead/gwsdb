-- Track retained history size on ip_pool so routine pruning can skip IPs
-- that cannot exceed the per-IP retention limit.
ALTER TABLE ip_pool ADD COLUMN history_count INTEGER NOT NULL DEFAULT 0;

UPDATE ip_pool
SET history_count = (
	SELECT COUNT(*) FROM ip_checks WHERE ip_checks.ip = ip_pool.ip
);

-- A deletion has no ip_pool row to carry its revision. Remember the latest
-- deletion revision so delta clients can discard their snapshot and fetch a
-- full replacement instead of retaining a deleted row forever.
ALTER TABLE pool_revision ADD COLUMN reset_version INTEGER NOT NULL DEFAULT 0;

-- Current writers always assign revisions explicitly. These rollout-only
-- triggers would otherwise treat history_count maintenance as a public pool
-- change and add unnecessary revision writes.
DROP TRIGGER IF EXISTS ip_pool_revision_legacy_insert;
DROP TRIGGER IF EXISTS ip_pool_revision_legacy_update;

-- Remove already-stale pool rows whose entire retained 300-check window is
-- unreachable. One reset revision makes existing browser snapshots reload.
UPDATE pool_revision
SET version = version + 1,
	reset_version = version + 1
WHERE singleton = 1;

DELETE FROM ip_pool
WHERE history_count >= 300
	AND NOT EXISTS (
		SELECT 1 FROM ip_checks
		WHERE ip_checks.ip = ip_pool.ip AND ip_checks.ok = 1
	);
