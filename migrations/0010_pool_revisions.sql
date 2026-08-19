-- Migration number: 0010 		2026-08-19
--
-- Give each published ip_pool mutation a monotonic revision. Clients can
-- then fetch only rows changed since their local snapshot instead of
-- replacing the full pool after every ingest. One singleton row allocates
-- revisions without retaining an ever-growing change log.
CREATE TABLE pool_revision (
	singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
	version   INTEGER NOT NULL
);

INSERT INTO pool_revision (singleton, version)
SELECT 1, COALESCE(MAX(id), 0) FROM ip_checks;

ALTER TABLE ip_pool ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;

UPDATE ip_pool
SET revision = (SELECT version FROM pool_revision WHERE singleton = 1);

CREATE INDEX idx_ip_pool_revision ON ip_pool(revision);

-- Keep migration-first rollout safe while old Pages isolates are still
-- serving. New writers set revision themselves, so these triggers only fire
-- for old INSERT/UPDATE statements that leave it unchanged.
CREATE TRIGGER ip_pool_revision_legacy_insert
AFTER INSERT ON ip_pool
WHEN NEW.revision = 0
BEGIN
	UPDATE pool_revision SET version = version + 1 WHERE singleton = 1;
	UPDATE ip_pool
	SET revision = (SELECT version FROM pool_revision WHERE singleton = 1)
	WHERE ip = NEW.ip;
END;

CREATE TRIGGER ip_pool_revision_legacy_update
AFTER UPDATE ON ip_pool
WHEN NEW.revision = OLD.revision
BEGIN
	UPDATE pool_revision SET version = version + 1 WHERE singleton = 1;
	UPDATE ip_pool
	SET revision = (SELECT version FROM pool_revision WHERE singleton = 1)
	WHERE ip = NEW.ip;
END;
