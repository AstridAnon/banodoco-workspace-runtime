"""The one fresh-realm SQLite format owned by Runtime.

This is deliberately a schema declaration, not a runtime repair runner. A realm
is created explicitly from this format; an existing database must already
match it and is never upgraded while being opened or inspected.
"""

CANONICAL_FORMAT_ID = "astrid-runtime-sqlite-v2"

CANONICAL_SCHEMA_SQL = r"""
CREATE TABLE runtime_schema (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    format_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE realm (
    id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE projects (
    id TEXT PRIMARY KEY, realm_id TEXT NOT NULL REFERENCES realm(id),
    slug TEXT NOT NULL, name TEXT NOT NULL, metadata_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    idempotency_key TEXT, UNIQUE(realm_id, slug), UNIQUE(realm_id, idempotency_key)
);
CREATE TABLE objects (
    digest TEXT PRIMARY KEY, size INTEGER NOT NULL, media_type TEXT NOT NULL,
    original_name TEXT, created_at TEXT NOT NULL
);
CREATE TABLE project_objects (
    project_id TEXT NOT NULL REFERENCES projects(id), digest TEXT NOT NULL REFERENCES objects(digest),
    relation TEXT NOT NULL DEFAULT 'managed', created_at TEXT NOT NULL,
    PRIMARY KEY(project_id, digest, relation)
);
CREATE TABLE runs (
    id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), capability TEXT NOT NULL,
    spec_json TEXT NOT NULL, status TEXT NOT NULL, idempotency_key TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, idempotency_key)
);
CREATE TABLE tasks (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), capability TEXT NOT NULL,
    spec_json TEXT NOT NULL, status TEXT NOT NULL, lease_token TEXT,
    executor_id TEXT, attempt INTEGER NOT NULL DEFAULT 0, expected_effect_json TEXT,
    result_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    capability_digest TEXT, waiting_reason TEXT, lease_expires_at TEXT,
    lease_fence INTEGER NOT NULL DEFAULT 0, attempt_id TEXT, runtime_epoch INTEGER
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id),
    task_id TEXT, kind TEXT NOT NULL, payload_json TEXT NOT NULL,
    previous_hash TEXT, event_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE reservations (
    task_id TEXT NOT NULL REFERENCES tasks(id), resource_key TEXT NOT NULL,
    lease_token TEXT NOT NULL, created_at TEXT NOT NULL, released_at TEXT,
    executor_id TEXT, fence INTEGER NOT NULL DEFAULT 0, lease_expires_at TEXT,
    runtime_epoch INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(task_id, resource_key)
);
CREATE TABLE capabilities (
    id TEXT PRIMARY KEY, definition_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready', required_resource_keys_json TEXT NOT NULL DEFAULT '[]',
    estimated_scratch_bytes INTEGER NOT NULL DEFAULT 0, estimated_output_bytes INTEGER NOT NULL DEFAULT 0,
    unavailable_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE executors (
    id TEXT PRIMARY KEY, max_concurrency INTEGER NOT NULL,
    resource_keys_json TEXT NOT NULL, capabilities_json TEXT NOT NULL,
    protocol TEXT NOT NULL, created_at TEXT NOT NULL,
    runtime_epoch INTEGER NOT NULL DEFAULT 1, readiness TEXT NOT NULL DEFAULT 'ready',
    readiness_reason TEXT, last_seen_at TEXT, source_digest TEXT,
    dependency_digest TEXT, source_epoch TEXT
);
CREATE TABLE attempts (
    id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
    lease_id TEXT NOT NULL, fence INTEGER NOT NULL, executor_id TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL, settled INTEGER NOT NULL DEFAULT 0,
    runtime_epoch INTEGER NOT NULL DEFAULT 1, recovery_nonce TEXT,
    recovery_nonce_expires_at TEXT, recovery_nonce_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE timelines (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, archived_at TEXT
);
CREATE TABLE timeline_shots (
    id TEXT PRIMARY KEY, timeline_id TEXT NOT NULL REFERENCES timelines(id),
    start_ms INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
    reference_ids_json TEXT NOT NULL
);
CREATE TABLE timeline_references (
    id TEXT PRIMARY KEY, timeline_id TEXT NOT NULL REFERENCES timelines(id),
    object_id TEXT NOT NULL, role TEXT
);
CREATE TABLE project_documents (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    kind TEXT NOT NULL, content_json TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(project_id, id)
);
CREATE TABLE generations (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    source_task_id TEXT REFERENCES tasks(id), type TEXT NOT NULL DEFAULT 'generation',
    status TEXT NOT NULL DEFAULT 'created', metadata_json TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE generation_variants (
    id TEXT PRIMARY KEY, generation_id TEXT NOT NULL REFERENCES generations(id),
    object_id TEXT REFERENCES objects(digest), variant_type TEXT NOT NULL DEFAULT 'original',
    metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
    UNIQUE(generation_id, id)
);
CREATE TABLE timeline_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeline_id TEXT NOT NULL REFERENCES timelines(id), version INTEGER NOT NULL,
    shots_json TEXT NOT NULL, references_json TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(timeline_id, version)
);
CREATE TABLE timeline_shot_state (
    id TEXT PRIMARY KEY REFERENCES timeline_shots(id), version INTEGER NOT NULL DEFAULT 1,
    archived_at TEXT
);
CREATE TABLE timeline_reference_state (
    id TEXT PRIMARY KEY REFERENCES timeline_references(id), version INTEGER NOT NULL DEFAULT 1,
    archived_at TEXT
);
CREATE TABLE media_relations (
    project_id TEXT NOT NULL REFERENCES projects(id),
    from_digest TEXT NOT NULL REFERENCES objects(digest),
    to_digest TEXT NOT NULL REFERENCES objects(digest), kind TEXT NOT NULL,
    ordinal INTEGER NOT NULL DEFAULT 0, metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    PRIMARY KEY(project_id, from_digest, to_digest, kind, ordinal)
);
CREATE TABLE realm_lifecycle (
    realm_id TEXT PRIMARY KEY REFERENCES realm(id),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'tombstoned')),
    tombstoned_at TEXT, reason TEXT, version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE runtime_lifecycle (
    id INTEGER PRIMARY KEY CHECK (id = 1), runtime_epoch INTEGER NOT NULL,
    boot_id TEXT NOT NULL, previous_boot_id TEXT, started_at TEXT NOT NULL,
    recovered_task_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE recovery_checkpoints (
    id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES attempts(id),
    task_id TEXT NOT NULL REFERENCES tasks(id), executor_id TEXT NOT NULL,
    runtime_epoch INTEGER NOT NULL, lease_id TEXT NOT NULL, fence INTEGER NOT NULL,
    nonce TEXT NOT NULL UNIQUE, checkpoint_path TEXT NOT NULL,
    checkpoint_digest TEXT NOT NULL, checkpoint_size INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'durable', recovery_receipt_json TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE command_idempotency (
    command_kind TEXT NOT NULL, aggregate_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL,
    txn_id TEXT, primary_stream_id TEXT, resulting_stream_seq INTEGER,
    first_project_seq INTEGER, last_project_seq INTEGER, event_ids_json TEXT,
    PRIMARY KEY(command_kind, aggregate_id, idempotency_key)
);
CREATE TABLE herzchen_domains (
    domain_id TEXT PRIMARY KEY, descriptor_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE herzchen_identities (
    authority TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
    revision TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL,
    payload_json TEXT NOT NULL, edit_token TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY(authority, kind, id, revision)
);
CREATE TABLE herzchen_identity_heads (
    authority TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
    revision TEXT NOT NULL, version INTEGER NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY(authority, kind, id),
    FOREIGN KEY(authority, kind, id, revision)
      REFERENCES herzchen_identities(authority, kind, id, revision)
);
CREATE TABLE herzchen_references (
    authority TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
    revision TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
    PRIMARY KEY(authority, kind, id, revision)
);
CREATE TABLE project_shots (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL, archived_at TEXT
);
CREATE TABLE shot_items (
    id TEXT PRIMARY KEY, shot_id TEXT NOT NULL REFERENCES project_shots(id) ON DELETE CASCADE,
    media_id TEXT NOT NULL, sort_key TEXT NOT NULL, source_frame INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at TEXT NOT NULL, UNIQUE(shot_id, sort_key)
);
CREATE TABLE project_references (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('character','place','object','clothing','other')),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0), description TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL, archived_at TEXT
);
CREATE TABLE media_references (
    id TEXT PRIMARY KEY, reference_id TEXT NOT NULL REFERENCES project_references(id) ON DELETE CASCADE,
    media_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('canonical','used_as_input','depicts','inspired_by')),
    ordinal INTEGER NOT NULL DEFAULT 0 CHECK (ordinal >= 0),
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0,1)),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at TEXT NOT NULL,
    CHECK (role = 'canonical' OR is_primary = 0)
);
CREATE TABLE reference_links (
    from_reference_id TEXT NOT NULL REFERENCES project_references(id) ON DELETE CASCADE,
    to_reference_id TEXT NOT NULL REFERENCES project_references(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('belongs_to','wears','located_in','associated_with','related_to')),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at TEXT NOT NULL,
    PRIMARY KEY(from_reference_id, to_reference_id, kind),
    CHECK (from_reference_id <> to_reference_id)
);
CREATE TABLE project_selections (
    actor_id TEXT NOT NULL, scope TEXT NOT NULL CHECK (scope IN ('workspace', 'user')),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL, PRIMARY KEY (actor_id, scope)
);
CREATE TABLE project_sequences (
    project_id TEXT PRIMARY KEY, next_seq INTEGER NOT NULL CHECK (next_seq > 0)
);
CREATE TABLE shot_text_bindings (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    shot_id TEXT NOT NULL REFERENCES project_shots(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('prompt', 'voiceover_script', 'transcript')),
    slot TEXT CHECK (slot IS NULL OR (kind = 'prompt' AND length(slot) BETWEEN 1 AND 64)),
    media_digest TEXT NOT NULL REFERENCES objects(digest) ON DELETE RESTRICT,
    event_stream_id TEXT NOT NULL UNIQUE, head_seq INTEGER NOT NULL DEFAULT 0 CHECK (head_seq >= 0),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE shot_text_binding_events (
    event_id TEXT PRIMARY KEY, binding_id TEXT NOT NULL REFERENCES shot_text_bindings(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL CHECK (seq > 0),
    kind TEXT NOT NULL CHECK (kind IN ('shot.text_binding.created', 'shot.text_binding.rebound')),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)), previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(binding_id, seq)
);
CREATE TABLE task_dependencies (
    continuation_task_id TEXT NOT NULL REFERENCES tasks(id),
    predecessor_task_id TEXT NOT NULL REFERENCES tasks(id),
    ordinal INTEGER NOT NULL CHECK (ordinal IN (0, 1)),
    PRIMARY KEY (continuation_task_id, ordinal),
    UNIQUE (continuation_task_id, predecessor_task_id)
);
CREATE TABLE continuation_admissions (
    continuation_task_id TEXT PRIMARY KEY REFERENCES tasks(id),
    dependency_snapshot_json TEXT NOT NULL, admitted_at TEXT NOT NULL
);
CREATE TABLE timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeline_id TEXT NOT NULL REFERENCES timelines(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE timeline_render_publications (
    authoring_task_id TEXT PRIMARY KEY REFERENCES tasks(id),
    attempt_id TEXT NOT NULL REFERENCES attempts(id), fence INTEGER NOT NULL,
    runtime_epoch INTEGER NOT NULL, request_hash TEXT NOT NULL, prepared_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'published')),
    timeline_id TEXT REFERENCES timelines(id), timeline_version INTEGER,
    render_task_id TEXT REFERENCES tasks(id), render_run_id TEXT REFERENCES runs(id),
    result_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE managed_output_associations (
    association_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    project_id TEXT REFERENCES projects(id),
    output_port TEXT NOT NULL,
    group_key TEXT NOT NULL,
    generation_id TEXT REFERENCES generations(id),
    variant_key TEXT NOT NULL DEFAULT '',
    object_digest TEXT NOT NULL REFERENCES objects(digest),
    manifest_digest TEXT REFERENCES objects(digest),
    size INTEGER NOT NULL CHECK (size >= 0),
    filename TEXT NOT NULL,
    media_type TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    role TEXT NOT NULL,
    producer_json TEXT NOT NULL CHECK (json_valid(producer_json)),
    provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json)),
    durability TEXT NOT NULL CHECK (durability IN ('durable', 'temporary')),
    regeneration_json TEXT CHECK (regeneration_json IS NULL OR json_valid(regeneration_json)),
    coverage_json TEXT CHECK (coverage_json IS NULL OR json_valid(coverage_json)),
    created_at TEXT NOT NULL,
    UNIQUE(task_id, output_port, group_key, ordinal, variant_key)
);
CREATE TABLE managed_output_lifecycle (
    association_id TEXT PRIMARY KEY REFERENCES managed_output_associations(association_id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('available', 'temporary', 'expired', 'promoted', 'reclaimed')),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    expires_at TEXT, pinned_at TEXT, lease_id TEXT, lease_owner TEXT,
    lease_expires_at TEXT, updated_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_attempts_recovery_nonce ON attempts(recovery_nonce) WHERE recovery_nonce IS NOT NULL;
CREATE INDEX idx_events_run ON events(run_id, id);
CREATE INDEX idx_projects_realm ON projects(realm_id);
CREATE INDEX idx_reservations_active ON reservations(executor_id, resource_key, released_at);
CREATE INDEX idx_tasks_executor_status ON tasks(executor_id, status);
CREATE INDEX idx_task_dependencies_predecessor ON task_dependencies(predecessor_task_id, continuation_task_id);
CREATE INDEX idx_recovery_checkpoints_attempt ON recovery_checkpoints(attempt_id, created_at);
CREATE INDEX idx_media_relations_project ON media_relations(project_id, created_at);
CREATE INDEX idx_timeline_revisions_timeline ON timeline_revisions(timeline_id, version);
CREATE INDEX idx_timeline_events_timeline ON timeline_events(timeline_id, id);
CREATE INDEX project_selections_project ON project_selections(project_id);
CREATE INDEX shot_items_media ON shot_items(media_id, shot_id);
CREATE INDEX references_project_kind ON project_references(project_id, kind, name, id);
CREATE UNIQUE INDEX reference_one_primary_canonical ON media_references(reference_id) WHERE role='canonical' AND is_primary=1;
CREATE UNIQUE INDEX reference_media_role_unique ON media_references(reference_id, media_id, role);
CREATE INDEX shot_text_binding_events_order ON shot_text_binding_events(project_id, binding_id, seq);
CREATE INDEX shot_text_binding_lookup ON shot_text_bindings(project_id, shot_id, kind, slot);
CREATE UNIQUE INDEX shot_text_binding_singleton ON shot_text_bindings(project_id, shot_id, kind) WHERE slot IS NULL;
CREATE UNIQUE INDEX shot_text_binding_slot ON shot_text_bindings(project_id, shot_id, kind, slot) WHERE slot IS NOT NULL;
CREATE UNIQUE INDEX idx_timeline_render_publications_render_task
    ON timeline_render_publications(render_task_id) WHERE render_task_id IS NOT NULL;
CREATE INDEX idx_managed_output_task ON managed_output_associations(task_id, created_at);
CREATE INDEX idx_managed_output_manifest ON managed_output_associations(manifest_digest, created_at);
"""
