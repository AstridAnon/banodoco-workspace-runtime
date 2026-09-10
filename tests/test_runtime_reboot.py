from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from banodoco_workspace_client import WorkspaceClient


def _digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def test_reboot_requeues_durable_task_and_fences_old_process(tmp_path):
    root = tmp_path / "realm"
    first = RuntimeService(root)
    first.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    admitted = first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "reboot-task"})
    task_id = admitted["task"]["id"]
    claimed = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": first.health()["runtime_epoch"]})
    assert claimed["task_id"] == task_id
    old_lease = {key: claimed[key] for key in ("attempt_id", "lease_id", "fence")}
    old_epoch = first.health()["runtime_epoch"]
    old_realm = first.realm["id"]
    first.close()

    second = RuntimeService(root)
    try:
        assert second.realm["id"] == old_realm
        assert second.health()["runtime_epoch"] == old_epoch + 1
        lifecycle = second.runtime_lifecycle()
        assert lifecycle["recovered_task_count"] == 1
        recovered = second.task(task_id)
        assert recovered["task"]["status"] == "queued"
        assert recovered["task"]["waiting_reason"] == "runtime_recovery"
        assert recovered["task"]["id"] == task_id

        with pytest.raises(LeaseError, match="stale or already settled"):
            second.settle_attempt(old_lease["attempt_id"], {"lease_id": old_lease["lease_id"], "fence": old_lease["fence"], "runtime_epoch": second.health()["runtime_epoch"], "outputs": []}, idempotency_key="reboot-old-settle")

        resumed = second.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": second.health()["runtime_epoch"]})
        assert resumed["task_id"] == task_id
        assert resumed["fence"] == old_lease["fence"] + 1
        settled = second.settle_attempt(resumed["attempt_id"], {"lease_id": resumed["lease_id"], "fence": resumed["fence"], "runtime_epoch": second.health()["runtime_epoch"], "outputs": [{"digest": _digest("reboot-output"), "data_base64": "cmVib290LW91dHB1dA=="}]}, idempotency_key="reboot-new-settle")
        assert settled["data"]["state"] == "succeeded"
        assert second.task(task_id)["task"]["status"] == "completed"
        events = second.events(admitted["run"]["id"])
        assert [event["kind"] for event in events][-3:] == ["task.runtime_recovered", "task.claimed", "task.completed"]
    finally:
        second.close()


def test_reboot_recovery_is_atomic_with_settlement_effects(tmp_path):
    root = tmp_path / "realm"
    first = RuntimeService(root)
    project = first.create_project({"slug": "effect", "name": "Before"})
    effect = {"effect_type": "project.update", "target_id": project["id"], "expected_version": 1, "payload": {"name": "After"}}
    admitted = first.create_task({"capability_id": "render.basic", "project": project["id"], "spec": {}, "settlement_effect": effect, "idempotency_key": "effect-reboot"})
    first.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    attempt = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": first.health()["runtime_epoch"]})
    first.close()

    second = RuntimeService(root)
    try:
        resumed = second.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": second.health()["runtime_epoch"]})
        assert resumed["task_id"] == admitted["task"]["id"]
        body = {"lease_id": resumed["lease_id"], "fence": resumed["fence"], "runtime_epoch": second.health()["runtime_epoch"], "outputs": [], "effect": effect}
        second.settle_attempt(resumed["attempt_id"], body, idempotency_key="effect-reboot-settle")
        assert second.get_project(project["id"])["name"] == "After"
        with pytest.raises(LeaseError):
            second.settle_attempt(resumed["attempt_id"], body, idempotency_key="effect-reboot-settle-retry")
        assert second.get_project(project["id"])["version"] == 2
        assert attempt["fence"] < resumed["fence"]
    finally:
        second.close()


def test_stale_settlement_rejects_before_cas_or_object_mutation(tmp_path):
    root = tmp_path / "realm"
    service = RuntimeService(root)
    service.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    admitted = service.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "stale-cas"})
    attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": service.health()["runtime_epoch"]})
    stale_epoch = attempt["runtime_epoch"]
    digest = _digest("stale-output").removeprefix("sha256:")
    service.store.conn.execute("UPDATE runtime_lifecycle SET runtime_epoch=runtime_epoch+1 WHERE id=1")
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": stale_epoch, "outputs": [{"digest": "sha256:" + digest, "data_base64": "c3RhbGUtb3V0cHV0"}]}, idempotency_key="stale-settlement")
    assert not service.cas.path_for(digest).exists()
    assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
    assert service.task(admitted["task"]["id"])["task"]["status"] == "running"
    service.close()


def test_checkpoint_reboot_resume_is_nonce_bound_and_test_injected(tmp_path):
    root = tmp_path / "realm"
    invoked = []

    def injected_executor(command, checkpoint):
        invoked.append((command, checkpoint))
        return {"test_injected": True}

    first = RuntimeService(root, reboot_executor=injected_executor)
    first.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "checkpoint"})
    attempt = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": first.health()["runtime_epoch"]})
    epoch = first.health()["runtime_epoch"]
    nonce = first.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})["nonce"]
    checkpoint = first.checkpoint_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": nonce, "authorization": nonce, "runtime_epoch": epoch, "state": {"step": 1}})
    assert json.loads((root / "checkpoints" / (checkpoint["checkpoint_id"] + ".json")).read_text())["step"] == 1
    with pytest.raises(ValidationError):
        first.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": "wrong", "runtime_epoch": epoch})
    receipt = first.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": nonce, "runtime_epoch": epoch})
    assert receipt["type"] == "runtime.recovery.receipt"
    assert invoked == [("reboot", {"step": 1})]
    first.close()


def test_reboot_request_claim_is_atomic_under_forced_race(tmp_path):
    root = tmp_path / "realm"
    started = threading.Event()
    release = threading.Event()
    invoked = []

    def blocking_executor(command, checkpoint):
        invoked.append((command, checkpoint))
        started.set()
        assert release.wait(5)
        return {"test_injected": True}

    service = RuntimeService(root, reboot_executor=blocking_executor)
    service.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    service.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "race"})
    attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": service.health()["runtime_epoch"]})
    epoch = service.health()["runtime_epoch"]
    nonce = service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})["nonce"]
    checkpoint = service.checkpoint_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": nonce, "authorization": nonce, "runtime_epoch": epoch, "state": {"step": 1}})
    body = {"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": nonce, "runtime_epoch": service.health()["runtime_epoch"]}
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(service.request_reboot, body)
        assert started.wait(5)
        second = pool.submit(service.request_reboot, body)
        with pytest.raises(ConflictError, match="consumed|already been requested"):
            second.result(timeout=5)
        release.set()
        receipt = first.result(timeout=5)
    assert receipt["status"] == "executed"
    assert invoked == [("reboot", {"step": 1})]
    # After completion, replay with the exact authorization is deterministic
    # and does not call the executor a second time.
    assert service.request_reboot(body) == receipt
    assert len(invoked) == 1
    service.close()


def test_generated_python_prepare_reboot_binds_path_attempt_id_on_live_daemon(tmp_path):
    invoked = []
    daemon = __import__("runtime_protocol.daemon", fromlist=["RuntimeDaemon"]).RuntimeDaemon(
        tmp_path / "realm", reboot_executor=lambda command, checkpoint: invoked.append((command, checkpoint)) or {"ok": True}
    ).start()
    try:
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        task = owner.admit_task(capability_id="render.basic", capability_digest=_digest("render.basic"), input_object_ids=[], idempotency_key="generated-reboot")
        owner.register_executor({"executor_id": "generated-worker", "max_concurrency": 1, "resource_keys": [], "capabilities": [{"capability_id": "render.basic", "definition_digest": _digest("render.basic"), "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}], "protocol": "workspace.v1"}, idempotency_key="generated-worker")
        worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
        epoch = worker.health().runtime_epoch
        attempt = worker.claim_task(executor_id="generated-worker", capability_ids=["render.basic"], idempotency_key="generated-claim", runtime_epoch=epoch)
        prepared = worker.prepare_reboot(attempt["attempt_id"], lease_id=attempt["lease_id"], fence=attempt["fence"], runtime_epoch=epoch)
        assert prepared["attempt_id"] == attempt["attempt_id"]
        checkpoint = worker.checkpoint_attempt(attempt["attempt_id"], lease_id=attempt["lease_id"], fence=attempt["fence"], nonce=prepared["nonce"], authorization=prepared["nonce"], state={"step": 2}, runtime_epoch=epoch)
        receipt = worker.request_reboot(checkpoint_id=checkpoint["checkpoint_id"], nonce=prepared["nonce"], authorization=prepared["nonce"], runtime_epoch=epoch)
        assert receipt["status"] == "executed" and invoked == [("reboot", {"step": 2})]
        assert task.task_id == attempt["task_id"]
    finally:
        daemon.stop()


def test_stale_or_omitted_worker_epoch_has_no_descriptor_side_effects(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    service.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    before_capabilities = service.store.conn.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0]
    before_executors = service.store.conn.execute("SELECT COUNT(*) FROM executors").fetchone()[0]
    old_epoch = service.store._current_runtime_epoch()
    service.store.conn.execute("UPDATE runtime_lifecycle SET runtime_epoch=runtime_epoch+1 WHERE id=1")
    descriptor = {"capability_id": "render.stale", "definition_digest": _digest("render.stale"), "required_resource_keys": []}
    with pytest.raises(LeaseError):
        service.register_executor({"executor_id": "worker", "capabilities": [descriptor], "runtime_epoch": old_epoch})
    with pytest.raises(LeaseError):
        service.register_executor({"executor_id": "worker", "capabilities": [descriptor]})
    assert service.store.conn.execute("SELECT COUNT(*) FROM capabilities").fetchone()[0] == before_capabilities
    assert service.store.conn.execute("SELECT COUNT(*) FROM executors").fetchone()[0] == before_executors
    assert service.store.conn.execute("SELECT 1 FROM capabilities WHERE id='render.stale'").fetchone() is None
    service.close()


def test_recovery_authorization_is_durable_one_shot_and_forgery_resistant(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    service.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    service.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "auth"})
    attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": service.health()["runtime_epoch"]})
    forged = {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": "forged", "authorization": "forged", "runtime_epoch": service.health()["runtime_epoch"], "state": {"step": 1}}
    with pytest.raises(ValidationError):
        service.checkpoint_attempt(attempt["attempt_id"], forged)
    epoch = service.health()["runtime_epoch"]
    prepared = service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})
    prepared_again = service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})
    assert prepared_again["nonce"] == prepared["nonce"]
    checkpoint_body = {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": epoch, "state": {"step": 1}}
    checkpoint = service.checkpoint_attempt(attempt["attempt_id"], checkpoint_body)
    assert service.checkpoint_attempt(attempt["attempt_id"], checkpoint_body)["checkpoint_id"] == checkpoint["checkpoint_id"]
    service.close()


def test_resume_verifies_exact_bytes_and_never_claims_another_task(tmp_path):
    root = tmp_path / "realm"
    first = RuntimeService(root, reboot_executor=lambda *_: {"injected": True})
    first.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "exact"})
    first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "unrelated"})
    epoch = first.health()["runtime_epoch"]
    target = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": epoch})
    nonce = first.prepare_reboot({"attempt_id": target["attempt_id"], "lease_id": target["lease_id"], "fence": target["fence"], "runtime_epoch": epoch})["nonce"]
    checkpoint = first.checkpoint_attempt(target["attempt_id"], {"lease_id": target["lease_id"], "fence": target["fence"], "nonce": nonce, "authorization": nonce, "runtime_epoch": epoch, "state": {"step": 2}})
    first.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": nonce, "runtime_epoch": epoch})
    first.close()
    second = RuntimeService(root, reboot_executor=lambda *_: {"injected": True})
    try:
        with pytest.raises(LeaseError):
            second.resume_attempt({"checkpoint_id": checkpoint["checkpoint_id"], "attempt_id": "wrong", "nonce": nonce, "authorization": nonce, "runtime_epoch": second.health()["runtime_epoch"]})
        with pytest.raises(ConflictError):
            Path(checkpoint["path"]).write_text("{\"step\": 999}\n", encoding="utf-8")
            second.resume_attempt({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": nonce, "runtime_epoch": second.health()["runtime_epoch"]})
    finally:
        second.close()


def test_stale_client_must_supply_runtime_epoch_after_reboot(tmp_path):
    root = tmp_path / "realm"
    first = RuntimeService(root)
    first.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "epoch"})
    old_epoch = first.health()["runtime_epoch"]
    first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": old_epoch})
    first.close()
    second = RuntimeService(root)
    try:
        with pytest.raises(LeaseError, match="stale runtime epoch"):
            second.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": old_epoch})
        claimed = second.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": second.health()["runtime_epoch"]})
        assert claimed["runtime_epoch"] == second.health()["runtime_epoch"]
    finally:
        second.close()
