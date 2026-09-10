-- One durable, task-owned publication checkpoint joins an authoring attempt
-- to the canonical timeline revision and the render admitted from that exact
-- revision.  The prepared JSON is immutable under request_hash; completion is
-- committed in the same SQLite transaction as the timeline save and task
-- admission.
CREATE TABLE IF NOT EXISTS timeline_render_publications (
    authoring_task_id TEXT PRIMARY KEY REFERENCES tasks(id),
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    fence INTEGER NOT NULL,
    runtime_epoch INTEGER NOT NULL,
    request_hash TEXT NOT NULL,
    prepared_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'published')),
    timeline_id TEXT REFERENCES timelines(id),
    timeline_version INTEGER,
    render_task_id TEXT REFERENCES tasks(id),
    render_run_id TEXT REFERENCES runs(id),
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_timeline_render_publications_render_task
    ON timeline_render_publications(render_task_id) WHERE render_task_id IS NOT NULL;
