"""AST-04 proof for the final shared DAT owner capability.

This exercises the installed Herzchen content and extension facades through
Runtime's one RealmStore.  It deliberately keeps Runtime's project, shot,
task, and document authorities intact while checking shared CAS, replay,
association, and managed-field behavior.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from herzchen.contracts import ResourceRef, TransactionContext
from herzchen.content.model import (
    ContentDocument,
    ContentRevision,
    DocumentAssociation,
    ReferenceBinding,
)
from herzchen.extensions.model import ManagedFieldError
from herzchen.kernel.operations import request_digest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _context(bridge, key: str, *, version: int | None = None, revision: str | None = None) -> TransactionContext:
    return TransactionContext(
        bridge.actor,
        key,
        request_digest({"key": key, "version": version, "revision": revision}),
        expected_revision=revision,
        expected_version=version,
    )


def test_runtime_shared_content_and_extensions_use_one_owner(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    RealmStore.initialize(root, realm_id="ast04-shared").close()
    runtime = RuntimeService(root, realm_id="ast04-shared")
    try:
        bridge = runtime.herzchen
        assert bridge is not None
        assert bridge.content is not None
        assert bridge.extensions is not None
        assert bridge.generic_contract_error is None

        project = runtime.create_project(
            {
                "name": "AST04 Shared",
                "slug": "ast04-shared",
                "metadata": {"legacy": {"keep": True}},
            },
            idempotency_key="ast04-shared-project",
        )
        project_id = project["id"]
        project_ref = bridge.project_ref(project_id)
        shot_result = runtime.create_project_shot(
            project_id,
            {
                "shot_id": "opening",
                "name": "Opening",
                "metadata": {"legacy": {"keep": True}},
            },
            idempotency_key="ast04-shared-shot",
        )
        shot_ref = ResourceRef(bridge.authority, "runtime.shot", shot_result["data"]["shot_id"])
        capability = "render.basic"
        task_result = runtime.create_task(
            {
                "capability_id": capability,
                "capability_digest": "sha256:" + sha256(capability.encode()).hexdigest(),
                "project": project_id,
                "spec": {},
                "idempotency_key": "ast04-shared-task",
            }
        )
        task_ref = ResourceRef(bridge.authority, "runtime.task", task_result["task"]["id"])

        project_set = bridge.extensions.set(
            project_ref,
            "annotation.open",
            {"review": "pending"},
            _context(bridge, "ast04-project-annotation", version=1, revision="runtime-v1"),
        )
        assert project_set["metadata"] == {
            "annotation.open": {"review": "pending"},
            "legacy": {"keep": True},
        }
        project_replay = bridge.extensions.set(
            project_ref,
            "annotation.open",
            {"review": "pending"},
            _context(bridge, "ast04-project-annotation", version=1, revision="runtime-v1"),
        )
        assert project_replay["version"] == project_set["version"]
        assert project_replay["metadata"] == project_set["metadata"]
        with pytest.raises(ConflictError):
            bridge.extensions.set(
                project_ref,
                "annotation.open",
                {"review": "stale"},
                _context(bridge, "ast04-project-stale", version=1, revision="runtime-v1"),
            )
        with pytest.raises(ManagedFieldError):
            bridge.extensions.set(
                project_ref,
                "managed.state",
                {"status": "accepted"},
                _context(bridge, "ast04-project-managed", version=2, revision="runtime-v2"),
            )
        assert bridge.extensions.read(project_ref)["metadata"] == project_set["metadata"]

        shot_set = bridge.extensions.set(
            shot_ref,
            "annotation.open",
            {"review": "shot"},
            _context(bridge, "ast04-shot-annotation", version=1, revision="runtime-v1"),
        )
        assert shot_set["metadata"] == {
            "annotation.open": {"review": "shot"},
            "legacy": {"keep": True},
        }
        assert bridge.extensions.read(shot_ref)["metadata"] == shot_set["metadata"]

        task_set = bridge.extensions.set(
            task_ref,
            "annotation.open",
            {"source": "AST04"},
            _context(bridge, "ast04-task-annotation", version=1, revision="runtime-v1"),
        )
        assert task_set["metadata"] == {"annotation.open": {"source": "AST04"}}
        assert bridge.extensions.read(task_ref)["metadata"] == task_set["metadata"]

        document_ref = ResourceRef(bridge.authority, "runtime.document", "opening-brief")
        document = ContentDocument(
            document_ref,
            "shot.brief",
            "shared",
            "append",
            bridge.actor.actor,
            authoring_scope=project_ref,
        )
        initial = ContentRevision(
            document_ref,
            "rev-1",
            {"legacy": {"keep": True}, "creative": {"tone": "quiet"}},
            bridge.actor,
            initial=True,
        )
        create_context = _context(bridge, "ast04-document-create", version=0)
        create_receipt = bridge.content.execute(
            bridge.content.build_create_document(create_context, document, initial)
        )
        assert create_receipt.replayed is False
        assert bridge.content.read(document_ref)["revision"]["content"] == initial.content

        appended = ContentRevision(
            document_ref,
            "rev-2",
            {"legacy": {"keep": True}, "creative": {"tone": "bright"}},
            bridge.actor,
            parent_revision="rev-1",
        )
        append_context = _context(bridge, "ast04-document-append", version=1, revision="rev-1")
        append_envelope = bridge.content.build_append_revision(append_context, document, appended)
        append_receipt = bridge.content.execute(append_envelope)
        assert append_receipt.replayed is False
        replay_receipt = bridge.content.execute(append_envelope)
        assert replay_receipt.replayed is True
        assert bridge.content.read(document_ref)["revision"]["content"] == appended.content

        stale = ContentRevision(
            document_ref,
            "rev-3",
            {"creative": {"tone": "stale"}},
            bridge.actor,
            parent_revision="rev-2",
        )
        with pytest.raises(ConflictError):
            bridge.content.execute(
                bridge.content.build_append_revision(
                    _context(bridge, "ast04-document-stale", version=1, revision="rev-2"),
                    document,
                    stale,
                )
            )
        assert bridge.content.read(document_ref)["revision"]["content"] == appended.content

        association = DocumentAssociation(
            project_ref,
            "creative",
            "brief",
            ReferenceBinding(document_ref, "current"),
        )
        link_context = _context(bridge, "ast04-document-link", version=0)
        bridge.content.execute(bridge.content.build_link(link_context, association))
        association_ref = ResourceRef(bridge.authority, "document-association", association.identity)
        assert bridge.content.read(association_ref)["payload"]["active"] is True
        unlink_context = _context(bridge, "ast04-document-unlink", version=1)
        bridge.content.execute(bridge.content.build_unlink(unlink_context, association))
        detached = bridge.content.read(association_ref)
        assert detached["payload"]["active"] is False
        assert bridge.content.read(document_ref)["revision"]["content"] == appended.content
    finally:
        runtime.close()
