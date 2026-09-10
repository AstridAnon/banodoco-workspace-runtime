from __future__ import annotations

import hashlib
import json
import os
import threading
import urllib.error
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from runtime_protocol.cas import ContentAddressedStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, OwnerBusyError, ValidationError
from banodoco_workspace_client import ApiError, WorkspaceClient
from http_helpers import Api


@pytest.fixture()
def daemon(tmp_path):
    instance = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        yield instance
    finally:
        instance.stop()


def test_project_managed_object_and_fake_executor_end_to_end(daemon):
    client = Api(daemon.endpoint, daemon.token)
    health = client.health()
    assert health["status"] == "ok"
    handshake = client.handshake()
    assert handshake["actor_id"] == "owner"
    project = client.create_project("demo", "Demo", {"theme": "neutral"}, idempotency_key="project-1")
    assert project["name"] == "Demo" and project["version"] == 1
    same = client.create_project("demo", "Demo", {"theme": "neutral"}, idempotency_key="project-1")
    assert same["project_id"] == project["project_id"]
    source = b"managed bytes\x00"
    obj = client.ingest("demo", source, media_type="application/octet-stream", original_name="source.bin", idempotency_key="source-object")
    digest = "sha256:" + hashlib.sha256(source).hexdigest()
    assert obj["data"]["digest"] == digest
    received, headers = client.read_object(digest)
    assert received == source
    assert headers["ETag"] == f'"{digest}"'
    ranged, range_headers = client.read_object(digest, range_header="bytes=0-6")
    assert ranged == source[:7]
    assert range_headers["Content-Range"] == f"bytes 0-6/{len(source)}"
    task = client.create_task("render.basic", {"text": "hello"}, project="demo", idempotency_key="task-1")
    task_id = task["task_id"]
    client.register_executor("fake", ["render.basic"], resource_keys=["cpu"], idempotency_key="executor-fake")
    worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
    claimed = worker.claim_task(executor_id="fake", capability_ids=["render.basic"], idempotency_key="claim-1", runtime_epoch=worker.health().runtime_epoch)
    assert claimed is not None and claimed["task_id"] == task_id
    settled = worker.settle_attempt(
        claimed["attempt_id"],
        {"lease_id": claimed["lease_id"], "fence": claimed["fence"], "runtime_epoch": claimed["runtime_epoch"], "outputs": [{"digest": digest}]},
        idempotency_key="settle-1",
    )
    assert settled.state == "succeeded"
    events = client.events(task["run_id"])
    assert [event["event_type"] for event in events["items"]] == ["task.admitted", "task.claimed", "task.completed"]


def test_threaded_http_dispatch_serializes_shared_runtime(daemon, monkeypatch):
    active = 0
    maximum = 0
    guard = threading.Lock()

    def slow_health():
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.03)
        with guard:
            active -= 1
        return {"status": "ok"}

    monkeypatch.setattr(daemon.service, "health", slow_health)

    def request_health():
        with urllib.request.urlopen(f"{daemon.endpoint}/v1/health", timeout=2) as response:
            assert response.status == 200

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: request_health(), range(4)))

    assert maximum == 1


def test_timeline_create_replays_receipt_and_conflicts_on_changed_request(daemon, tmp_path):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = client.create_project("timeline-idempotency", idempotency_key="timeline-project")
    first = client.create_timeline(project.project_id, "timeline-a", idempotency_key="timeline-create")
    replay = client.create_timeline(project.project_id, "timeline-a", idempotency_key="timeline-create")
    assert first == replay
    assert first.receipt["command_kind"] == "timeline.create"
    with pytest.raises(ApiError) as changed:
        client.create_timeline(project.project_id, "timeline-b", idempotency_key="timeline-create")
    assert changed.value.status == 409
    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        after_restart = WorkspaceClient(restarted.endpoint, restarted.token).create_timeline(project.project_id, "timeline-a", idempotency_key="timeline-create")
        assert after_restart == first
        assert restarted.service.store.conn.execute("SELECT COUNT(*) FROM timelines").fetchone()[0] == 1
    finally:
        restarted.stop()


def test_claim_requires_key_and_duplicate_or_changed_requests_replay_or_conflict(daemon):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("claim-idempotency", "Claim Idempotency", idempotency_key="claim-project")
    task = client.create_task("render.basic", {"text": "claim"}, project=project["project_id"], idempotency_key="claim-task")
    client.register_executor("claim-executor", ["render.basic"], idempotency_key="claim-executor")
    epoch = client.health()["runtime_epoch"]
    body = {"executor_id": "claim-executor", "capability_ids": ["render.basic"], "runtime_epoch": epoch}
    with pytest.raises(RuntimeError) as missing:
        client.request("POST", "/v1/tasks/claim", body)
    assert missing.value.status == 400
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: client.request("POST", "/v1/tasks/claim", body, headers={"Idempotency-Key": "claim-command"}), range(2)))
    first, replay = results
    assert replay == first
    claimed_task_id = first["task_id"] if "task_id" in first else first["task"]["task_id"]
    assert claimed_task_id == task["task_id"]
    with pytest.raises(RuntimeError) as changed:
        client.request("POST", "/v1/tasks/claim", {**body, "capability_ids": []}, headers={"Idempotency-Key": "claim-command"})
    assert changed.value.status == 409
    assert client.request("GET", f"/v1/tasks/{task['task_id']}")["state"] == "running"


def test_project_patch_and_run_cancel_retry_are_durable_and_idempotent(daemon, tmp_path):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = client.create_project("mutations", idempotency_key="mutation-project")
    updated = client.update_project(project.project_id, idempotency_key="project-update", expected_version=1, name="Mutated")
    assert updated.version == 2 and updated.name == "Mutated"
    assert client.update_project(project.project_id, idempotency_key="project-update", expected_version=1, name="Mutated").version == 2
    with pytest.raises(ApiError) as stale:
        client.update_project(project.project_id, idempotency_key="project-stale", expected_version=1, name="stale")
    assert stale.value.status == 409

    digest = "sha256:" + hashlib.sha256(b"render.basic").hexdigest()
    cancelled = client.admit_task(capability_id="render.basic", capability_digest=digest, input_object_ids=[], project_id=project.project_id, idempotency_key="cancel-child")
    run = client.cancel_run(cancelled.run_id, idempotency_key="run-cancel")
    assert run["status"] == "cancelled"
    assert client.get_task(cancelled.task_id).state == "cancelled"
    assert client.cancel_run(cancelled.run_id, idempotency_key="run-cancel")["status"] == "cancelled"
    with pytest.raises(ApiError) as conflict:
        client.cancel_run(cancelled.run_id, idempotency_key="run-cancel-conflict")
    assert conflict.value.status == 409

    failed = client.admit_task(capability_id="render.basic", capability_digest=digest, input_object_ids=[], project_id=project.project_id, idempotency_key="retry-child")
    client.register_executor({"executor_id": "mutation-worker", "max_concurrency": 1, "resource_keys": [], "capabilities": [{"capability_id": "render.basic", "definition_digest": digest, "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}], "protocol": "workspace.v1"}, idempotency_key="mutation-worker")
    worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
    first = worker.claim_task(executor_id="mutation-worker", capability_ids=["render.basic"], idempotency_key="mutation-claim-1", runtime_epoch=worker.health().runtime_epoch)
    assert first is not None
    worker.fail_attempt(first["attempt_id"], lease_id=first["lease_id"], fence=first["fence"], error={"reason": "probe"}, runtime_epoch=first["runtime_epoch"], idempotency_key="mutation-fail")
    retried = client.retry_run(failed.run_id, idempotency_key="run-retry")
    assert retried["status"] == "queued"
    assert client.retry_run(failed.run_id, idempotency_key="run-retry")["status"] == "queued"
    events, _cursor = client.list_run_events(failed.run_id)
    assert [event.event_type for event in events][-2:] == ["task.retried", "run.retried"]
    second = worker.claim_task(executor_id="mutation-worker", capability_ids=["render.basic"], idempotency_key="mutation-claim-2", runtime_epoch=worker.health().runtime_epoch)
    assert second["fence"] > first["fence"] and second["attempt_id"] != first["attempt_id"]

    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        replay = WorkspaceClient(restarted.endpoint, restarted.token)
        assert replay.retry_run(failed.run_id, idempotency_key="run-retry")["status"] == "queued"
        assert replay.get_project(project.project_id).name == "Mutated"
    finally:
        restarted.stop()


def test_project_shot_reference_crud_isolated_idempotent_and_restart_durable(daemon, tmp_path):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    first = client.create_project("shots-a", idempotency_key="shots-project-a")
    second = client.create_project("shots-b", idempotency_key="shots-project-b")
    media = client.ingest_project_object(first.project_id, b"reference-media", media_type="application/octet-stream", idempotency_key="shots-media")
    shot_body = {"shot_id": "project-shot", "name": "Project Shot", "metadata": {"scene": 1}}
    reference_body = {"reference_id": "project-reference", "kind": "character", "name": "Aria", "media_id": media.object_id}
    shot = client.create_project_shot(first.project_id, shot_body, idempotency_key="project-shot-create")
    reference = client.create_project_reference(first.project_id, reference_body, idempotency_key="project-reference-create")
    assert shot["project_id"] == first.project_id and reference["project_id"] == first.project_id
    assert client.create_project_shot(first.project_id, shot_body, idempotency_key="project-shot-create") == shot
    assert client.create_project_reference(first.project_id, reference_body, idempotency_key="project-reference-create") == reference
    with pytest.raises(ApiError) as mismatch:
        client.create_project_shot(first.project_id, {**shot_body, "name": "Changed"}, idempotency_key="project-shot-create")
    assert mismatch.value.status == 409
    assert client.list_project_shots(first.project_id)[0][0]["shot_id"] == "project-shot"
    assert client.list_project_shots(second.project_id)[0] == []
    assert client.list_project_references(second.project_id)[0] == []

    updated = client.update_project_shot(first.project_id, "project-shot", expected_version=1, name="Updated Shot", idempotency_key="project-shot-update")
    assert updated["version"] == 2 and updated["name"] == "Updated Shot"
    assert client.update_project_shot(first.project_id, "project-shot", expected_version=1, name="Updated Shot", idempotency_key="project-shot-update") == updated
    with pytest.raises(ApiError) as stale:
        client.update_project_shot(first.project_id, "project-shot", expected_version=1, name="stale", idempotency_key="project-shot-stale")
    assert stale.value.status == 409
    archived = client.archive_project_shot(first.project_id, "project-shot", expected_version=updated["version"], idempotency_key="project-shot-archive")
    assert archived["archived"] is True
    assert client.list_project_shots(first.project_id)[0] == []
    recovered = client.recover_project_shot(first.project_id, "project-shot", expected_version=archived["version"], idempotency_key="project-shot-recover")
    assert recovered["archived"] is False
    ref_updated = client.update_project_reference(first.project_id, "project-reference", expected_version=1, name="Aria Prime", idempotency_key="project-reference-update")
    ref_archived = client.archive_project_reference(first.project_id, "project-reference", expected_version=ref_updated["version"], idempotency_key="project-reference-archive")
    ref_recovered = client.recover_project_reference(first.project_id, "project-reference", expected_version=ref_archived["version"], idempotency_key="project-reference-recover")
    assert ref_recovered["name"] == "Aria Prime" and ref_recovered["archived"] is False
    second_media = client.ingest_project_object(first.project_id, b"second-media", media_type="application/octet-stream", idempotency_key="shots-media-2")
    with_item = client.add_shot_item(first.project_id, "project-shot", {"item_id": "item-a", "media_id": media.object_id, "position": 0}, idempotency_key="shot-item-a")
    with_two = client.add_shot_item(first.project_id, "project-shot", {"item_id": "item-b", "media_id": second_media.object_id, "position": 1}, idempotency_key="shot-item-b")
    reordered = client.reorder_shot_items(first.project_id, "project-shot", ["item-b", "item-a"], expected_version=with_two["version"], idempotency_key="shot-reorder")
    removed = client.remove_shot_item(first.project_id, "project-shot", "item-a", expected_version=reordered["version"], idempotency_key="shot-item-remove")
    assert [item["item_id"] for item in removed["items"]] == ["item-b"]
    associated = client.associate_reference(first.project_id, "project-reference", {"association_id": "assoc-b", "media_id": second_media.object_id, "role": "depicts"}, idempotency_key="reference-associate")
    primary = client.set_primary_reference(first.project_id, "project-reference", "assoc-b", expected_version=associated["version"], idempotency_key="reference-primary")
    linked_ref = client.create_project_reference(first.project_id, {"reference_id": "project-reference-2", "kind": "object", "name": "Prop", "media_id": media.object_id}, idempotency_key="reference-2")
    link = client.link_references(first.project_id, {"from_reference_id": "project-reference", "to_reference_id": linked_ref["reference_id"], "kind": "associated_with"}, idempotency_key="reference-link")
    assert primary["media_references"][-1]["is_primary"] is True and link["kind"] == "associated_with"

    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        replay = WorkspaceClient(restarted.endpoint, restarted.token)
        assert replay.create_project_shot(first.project_id, shot_body, idempotency_key="project-shot-create") == shot
        assert replay.get_project_shot(first.project_id, "project-shot")["name"] == "Updated Shot"
        assert replay.get_project_reference(first.project_id, "project-reference")["archived"] is False
    finally:
        restarted.stop()


def test_restart_reconnect_and_catalog_discovery(daemon, tmp_path):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("persist", "Persistent")
    realm_id = client.get_project(project["project_id"])["realm_id"]
    discovery = json.loads((tmp_path / "support" / "discovery.json").read_text())
    catalog = json.loads((tmp_path / "support" / "catalog.json").read_text())
    assert discovery["active_realm"] == realm_id
    assert "database" not in json.dumps(discovery).lower()
    assert catalog["selected_realm_id"] == realm_id
    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        second = Api(restarted.endpoint, restarted.token)
        assert second.get_project(project["project_id"])["realm_id"] == realm_id
        assert second.get_project(project["project_id"])["name"] == "Persistent"
    finally:
        restarted.stop()


def test_doctor_can_run_while_daemon_owns_realm(daemon, tmp_path):
    completed = subprocess.run(["python3", "-m", "runtime_protocol", "doctor", "--root", str(tmp_path / "realm"), "--json"], capture_output=True, text=True, check=True, cwd=str(Path(__file__).parents[1]), env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])})
    assert json.loads(completed.stdout)["ok"] is True


def test_concurrent_owner_refusal_and_reconnect(tmp_path):
    first = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        with pytest.raises(OwnerBusyError):
            RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    finally:
        first.stop()
    second = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    second.stop()


def test_cas_hash_and_path_safety(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    stored = cas.put(b"abc")
    assert cas.read(stored["digest"]) == b"abc"
    with pytest.raises(ValidationError):
        cas.path_for("../etc/passwd")
    path = cas.path_for(stored["digest"])
    path.write_bytes(b"tampered")
    with pytest.raises(ConflictError):
        cas.read(stored["digest"])


def test_offline_core_store_and_read_only_doctor(tmp_path):
    root = tmp_path / "realm"
    from runtime_protocol.service import RuntimeService
    service = RuntimeService(root)
    project = service.create_project({"slug": "offline", "name": "Offline", "metadata": {}})
    service.close()
    completed = subprocess.run(["python3", "-m", "runtime_protocol", "doctor", "--root", str(root), "--json"], capture_output=True, text=True, check=True, cwd=str(Path(__file__).parents[1]), env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])})
    report = json.loads(completed.stdout)
    assert report["state"] == "ready" and report["ok"] is True
    assert project["slug"] == "offline"


def test_non_health_routes_require_scoped_credential(daemon):
    import urllib.request
    request = urllib.request.Request(daemon.endpoint + "/v1/projects", method="GET")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request)
    assert error.value.code == 401


def test_astrid_scoped_actor_can_discover_capability_for_task_admission(daemon):
    """Product admission may read the catalog without worker authority."""
    import secrets

    token = secrets.token_hex(32)
    daemon.credentials.provision_static(
        "astrid",
        token,
        ["handshake", "projects:read", "projects:write", "tasks:read", "tasks:write"],
    )
    owner = Api(daemon.endpoint, daemon.token)
    owner.request(
        "POST",
        "/v1/capabilities",
        {"capability_id": "render.basic", "definition_digest": "sha256:" + "a" * 64},
    )
    product = Api(daemon.endpoint, token)
    catalog = product.request("GET", "/v1/capabilities")
    assert catalog["items"][0]["capability_id"] == "render.basic"


def test_stale_lease_and_undeclared_effect_are_rejected(daemon):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("effect-target", "Effect Target")
    effect = {"effect_type": "project.update", "target_id": project["project_id"], "expected_version": 1, "payload": {"name": "Settled Effect"}}
    task = client.create_task("render.basic", {}, project=project["project_id"], expected_effect=effect)
    task_id = task["task_id"]
    client.register_executor("effect-worker", ["render.basic"], idempotency_key="executor-effect")
    worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
    attempt = worker.claim_task(executor_id="effect-worker", capability_ids=["render.basic"], idempotency_key="effect-claim", runtime_epoch=worker.health().runtime_epoch)
    assert attempt is not None
    with pytest.raises(ApiError):
        worker.settle_attempt(attempt["attempt_id"], {"lease_id": "bad", "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": []}, idempotency_key="effect-bad-lease")
    with pytest.raises(ApiError):
        worker.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [], "effect": {"kind": "other"}}, idempotency_key="effect-bad-effect")
    settled = worker.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [], "effect": effect}, idempotency_key="effect-settle")
    assert settled.state == "succeeded"
    updated = client.get_project(project["project_id"])
    assert updated["name"] == "Settled Effect" and updated["version"] == 2
