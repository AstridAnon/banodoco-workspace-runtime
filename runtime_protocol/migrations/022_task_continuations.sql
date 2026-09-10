-- A deliberately small dependency kernel for one ordered two-child
-- continuation.  The continuation task remains an ordinary task: claiming,
-- retries, cancellation, settlement idempotency, and attempt fencing all use
-- the existing runtime machinery.
CREATE TABLE IF NOT EXISTS task_dependencies (
    continuation_task_id TEXT NOT NULL REFERENCES tasks(id),
    predecessor_task_id TEXT NOT NULL REFERENCES tasks(id),
    ordinal INTEGER NOT NULL CHECK (ordinal IN (0, 1)),
    PRIMARY KEY (continuation_task_id, ordinal),
    UNIQUE (continuation_task_id, predecessor_task_id)
);
CREATE INDEX IF NOT EXISTS idx_task_dependencies_predecessor
    ON task_dependencies(predecessor_task_id, continuation_task_id);

CREATE TABLE IF NOT EXISTS continuation_admissions (
    continuation_task_id TEXT PRIMARY KEY REFERENCES tasks(id),
    dependency_snapshot_json TEXT NOT NULL,
    admitted_at TEXT NOT NULL
);
