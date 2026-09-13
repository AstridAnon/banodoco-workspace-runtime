from __future__ import annotations

import hashlib

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_direct_managed_render_admission_freezes_snapshot_before_claim(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        service.register_executor({
            "executor_id": "worker",
            "capabilities": ["rendering.render"],
        })
        project = service.create_project({"slug": "managed-render", "name": "Managed Render"}, idempotency_key="project")
        source = service.ingest(project["id"], b"source-media", media_type="video/mp4", idempotency_key="source")
        source_id = source["data"]["object_id"]
        timeline = {
            "timeline_id": "main",
            "slug": "main",
            "name": "Main",
            "config": {"clips": [{"id": "source", "type": "video"}]},
            "registry": {"assets": {"source": {"media_id": "media-source", "content_sha256": source_id}}},
        }
        service.create_timeline_document(project["id"], timeline, idempotency_key="timeline")

        admitted = service.create_task({
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "input_object_ids": [source_id],
            "idempotency_key": "render",
            "spec": {
                "family": "render",
                "params": {
                    "timeline_ref": "main",
                    "expected_version": 1,
                    "selector": "rendering.remotion",
                },
            },
        })
        task = admitted["task"]
        admitted_spec = task["spec"]["spec"]
        assert admitted_spec["params"]["timeline_ref"] == "main"
        assert admitted_spec["timeline_snapshot"] == {
            "config": timeline["config"],
            "registry": timeline["registry"],
        }
        assert admitted_spec["inputs"]["timeline_ref"] == "main"
        assert admitted_spec["inputs"]["timeline_authority"]["project_id"] == project["id"]
        assert admitted_spec["inputs"]["timeline_authority"]["project_slug"] == "managed-render"
        assert admitted_spec["inputs"]["timeline_authority"]["config_version"] == 1
        assert admitted_spec["inputs"]["timeline_authority"]["managed_media_admissions"] == {"media-source": source_id}
        assert task["spec"]["input_object_ids"] == [source_id]

        epoch = service.health()["runtime_epoch"]
        claimed = service.claim_next({
            "executor_id": "worker",
            "capability_ids": ["rendering.render"],
            "runtime_epoch": epoch,
        })
        assert claimed["spec"]["spec"]["timeline_snapshot"] == admitted_spec["timeline_snapshot"]
        assert claimed["spec"]["spec"]["inputs"]["timeline_authority"] == admitted_spec["inputs"]["timeline_authority"]
        assert claimed["input_object_ids"] == [source_id]
    finally:
        service.close()


def test_direct_managed_render_rejects_stale_scope_and_path_injection(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "managed-render", "name": "Managed Render"}, idempotency_key="project")
        service.create_timeline_document(
            project["id"],
            {"timeline_id": "main", "slug": "main", "config": {}, "registry": {}},
            idempotency_key="timeline",
        )
        capability_digest = _digest("rendering.render")
        body = {
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "spec": {"params": {"timeline_ref": "main", "expected_version": 2}},
        }
        with pytest.raises(ConflictError, match="expected_version"):
            service.create_task(body)

        for field, message in (
            ("timeline", "caller-supplied timeline path"),
            ("assets_registry", "assets registry path"),
            ("materialized_root", "materialization is host-owned"),
        ):
            injected = {
                **body,
                "spec": {
                    "params": {"timeline_ref": "main"},
                    "inputs": {field: "/caller/project/input"},
                },
            }
            with pytest.raises(ValidationError, match=message):
                service.create_task(injected)

        other_project = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")
        wrong_scope = {**body, "project": other_project["id"], "spec": {"params": {"timeline_ref": "main"}}}
        with pytest.raises(NotFoundError, match="selected project"):
            service.create_task(wrong_scope)
    finally:
        service.close()
