from __future__ import annotations

import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.service import RuntimeService


def _digest(value: str | bytes) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _claim(service, capability, key):
    return service.claim_next(
        {"executor_id": "worker", "capability_ids": [capability], "runtime_epoch": service.health()["runtime_epoch"]},
        idempotency_key=key,
    )


def _settle(service, attempt, key, value):
    raw = value.encode()
    return service.settle_attempt(
        attempt["attempt_id"],
        {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
         "outputs": [{"digest": _digest(raw), "data_base64": base64.b64encode(raw).decode(),
                      "media_type": "video/mp4", "name": "primary", "role": "primary", "is_primary": True}]},
        idempotency_key=key,
    )


def _ready_authoring_attempt(service):
    project = service.create_project({"slug": "publication", "name": "Publication"})
    child_cap, author_cap, render_cap = "test.child", "rendering.assemble_timeline", "rendering.render"
    digests = {cap: _digest(cap) for cap in (child_cap, author_cap, render_cap)}
    for cap in digests:
        service.register_capability({"capability_id": cap, "definition_digest": digests[cap]})
    service.register_executor(
        {"executor_id": "worker", "capabilities": list(digests), "max_concurrency": 4},
        idempotency_key="register-worker",
    )
    service.create_timeline_document(
        project["id"], {"timeline_id": "main", "slug": "main", "name": "Main", "config": {}, "registry": {}},
        idempotency_key="create-timeline",
    )
    children = []
    for index in range(2):
        children.append(service.create_task({
            "project": project["id"], "capability_id": child_cap, "capability_digest": digests[child_cap],
            "input_object_ids": [], "spec": {"index": index}, "idempotency_key": f"child-{index}",
        }))
    child_ids = [value["task"]["id"] for value in children]
    author = service.create_task({
        "project": project["id"], "capability_id": author_cap, "capability_digest": digests[author_cap],
        "input_object_ids": [], "idempotency_key": "author",
        "spec": {"runtime_dependencies": {"edges": [
            {"from_task_id": task_id, "to": "self", "requires_event": "task.succeeded", "fence": "runtime_task"}
            for task_id in child_ids
        ], "aggregation": {"kind": "ordered_cas_inputs"}}},
    })
    attempts = {_claim(service, child_cap, f"claim-child-{index}")["task_id"]: None for index in range(2)}
    # Claims may arrive in either order; settle deliberately in reverse.
    for index, task_id in enumerate(list(attempts)):
        attempts[task_id] = service.store.conn.execute("SELECT attempt_id FROM tasks WHERE id=?", (task_id,)).fetchone()[0]
    claims = {}
    for task_id in child_ids:
        row = service.store.conn.execute("SELECT * FROM attempts WHERE task_id=?", (task_id,)).fetchone()
        claims[task_id] = {"attempt_id": row["id"], "lease_id": row["lease_id"], "fence": row["fence"], "runtime_epoch": row["runtime_epoch"]}
    _settle(service, claims[child_ids[1]], "settle-second", "second")
    _settle(service, claims[child_ids[0]], "settle-first", "first")
    return project, author, _claim(service, author_cap, "claim-author"), digests[render_cap]


def _publication_body(attempt, render_digest):
    return {
        "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
        "timeline_id": "main", "expected_version": 1,
        "config": {"tracks": [{"id": "video", "clips": []}]}, "registry": {"assets": {}},
        "render": {"capability_id": "rendering.render", "capability_digest": render_digest,
                   "spec": {"capability_id": "rendering.render", "kind": "executor", "inputs": {"output_name": "final.mp4"}, "outputs": {}}},
    }


def test_publication_is_fenced_atomic_and_exactly_replayable(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        _, author, attempt, render_digest = _ready_authoring_attempt(service)
        body = _publication_body(attempt, render_digest)
        result = service.publish_timeline_render(attempt["attempt_id"], body, idempotency_key="publish")
        assert result["timeline_version"] == 2
        assert service._timeline_resource("main")["config_version"] == 2
        render = service.task(result["render_task_id"])["task"]
        assert render["spec"]["spec"]["inputs"]["expected_version"] == 2
        assert render["spec"]["spec"]["inputs"]["timeline_snapshot"]["config"] == body["config"]
        assert service.publish_timeline_render(attempt["attempt_id"], body, idempotency_key="another-key") == result
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_render_publications").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'").fetchone()[0] == 1

        changed = {**body, "config": {"tracks": []}}
        with pytest.raises(ConflictError, match="payload changed"):
            service.publish_timeline_render(attempt["attempt_id"], changed, idempotency_key="publish-changed")

        service.cancel_task_canonical(author["task"]["id"], {}, idempotency_key="cancel-author")
        assert service.publish_timeline_render(attempt["attempt_id"], body, idempotency_key="replay-after-cancel") == result
    finally:
        service.close()


def test_prepared_checkpoint_cannot_publish_after_cancel_or_stale_fence(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    try:
        _, author, attempt, render_digest = _ready_authoring_attempt(service)
        body = _publication_body(attempt, render_digest)
        stale = {**body, "fence": attempt["fence"] - 1}
        with pytest.raises(LeaseError):
            service.publish_timeline_render(attempt["attempt_id"], stale, idempotency_key="stale")
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_render_publications").fetchone()[0] == 0

        original = service.store.prepare_timeline_render_publication
        def prepare_then_cancel(*args, **kwargs):
            value = original(*args, **kwargs)
            service.cancel_task_canonical(author["task"]["id"], {}, idempotency_key="cancel-at-seam")
            return value
        monkeypatch.setattr(service.store, "prepare_timeline_render_publication", prepare_then_cancel)
        with pytest.raises(LeaseError):
            service.publish_timeline_render(attempt["attempt_id"], body, idempotency_key="publish")
        assert service._timeline_resource("main")["config_version"] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'").fetchone()[0] == 0
        assert service.store.timeline_render_publication(author["task"]["id"])["state"] == "prepared"
    finally:
        service.close()


def test_prepared_checkpoint_resumes_on_retried_attempt_after_runtime_restart(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    service = RuntimeService(root)
    _, author, attempt, render_digest = _ready_authoring_attempt(service)
    body = _publication_body(attempt, render_digest)
    original = service.store.prepare_timeline_render_publication

    class SimulatedCrash(RuntimeError):
        pass

    def prepare_then_crash(*args, **kwargs):
        original(*args, **kwargs)
        raise SimulatedCrash

    monkeypatch.setattr(service.store, "prepare_timeline_render_publication", prepare_then_crash)
    with pytest.raises(SimulatedCrash):
        service.publish_timeline_render(attempt["attempt_id"], body, idempotency_key="publish")
    assert service.store.timeline_render_publication(author["task"]["id"])["state"] == "prepared"
    service.close()

    service = RuntimeService(root)
    try:
        service.register_executor(
            {"executor_id": "worker", "capabilities": ["test.child", "rendering.assemble_timeline", "rendering.render"],
             "max_concurrency": 4, "runtime_epoch": service.health()["runtime_epoch"]},
            idempotency_key="register-after-restart",
        )
        recovered = _claim(service, "rendering.assemble_timeline", "reclaim-author")
        resumed = {**body, "lease_id": recovered["lease_id"], "fence": recovered["fence"], "runtime_epoch": recovered["runtime_epoch"]}
        result = service.publish_timeline_render(recovered["attempt_id"], resumed, idempotency_key="resume-publication")
        assert result["timeline_version"] == 2
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'").fetchone()[0] == 1
    finally:
        service.close()
