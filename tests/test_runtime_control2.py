from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from runtime_protocol.backup import restore_backup, verify_backup
from runtime_protocol.errors import CapabilityUnavailableError, ConflictError, LeaseError, ValidationError
from runtime_protocol.daemon import RuntimeDaemon
from http_helpers import Api
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def _service(root, **kwargs):
    initialize_kwargs = {key: kwargs[key] for key in ("display_name", "realm_id") if key in kwargs}
    RealmStore.initialize(root, **initialize_kwargs).close()
    return RuntimeService(root, **kwargs)


def _daemon(root, support_root):
    RealmStore.initialize(root).close()
    return RuntimeDaemon(root, support_root=support_root).start()


def _task(service: RuntimeService, key: str):
    return service.create_task({
        "capability_id": "render.gpu",
        "capability_digest": _digest("render.gpu-v1"),
        "input_object_ids": [],
        "spec": {},
        "idempotency_key": key,
    })


def _claim(service: RuntimeService, task_id: str, body: dict, *, idempotency_key: str):
    task = service.store.get_task(task_id)
    result = service.claim_next({
        "executor_id": body.get("executor_id") or body.get("worker_id"),
        "capability_ids": [task["task"]["capability"]],
        "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key=idempotency_key)
    if result and result.get("attempt_id"):
        return {"task": service.store.get_task(task_id)["task"], **result}
    return result


def _claim_attempt(service: RuntimeService, capability: str = "render.gpu", executor: str = "worker", *, idempotency_key: str):
    return service.claim_next({
        "executor_id": executor,
        "capability_ids": [capability],
        "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key=idempotency_key)


def _settle_attempt(service: RuntimeService, attempt: dict, *, effect=None, idempotency_key: str):
    body = {
        "lease_id": attempt["lease_id"],
        "fence": attempt["fence"],
        "runtime_epoch": attempt["runtime_epoch"],
        "outputs": [],
    }
    if effect is not None:
        body["effect"] = effect
    return service.settle_attempt(attempt["attempt_id"], body, idempotency_key=idempotency_key)


def test_named_resource_reservation_blocks_and_releases_with_attempt_lease(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        service.register_capability({
            "capability_id": "render.gpu",
            "definition_digest": _digest("render.gpu-v1"),
            "required_resource_keys": ["gpu"],
        })
        service.register_executor({"executor_id": "gpu-worker", "capabilities": ["render.gpu"], "resource_keys": ["gpu"], "max_concurrency": 1, "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="gpu-worker-register")
        first = _task(service, "first")["task"]["id"]
        second = _task(service, "second")["task"]["id"]
        claimed = _claim_attempt(service, executor="gpu-worker", idempotency_key="gpu-worker-claim-1")
        assert claimed["task_id"] in {first, second}
        remaining = second if claimed["task_id"] == first else first
        blocked = _claim_attempt(service, executor="gpu-worker", idempotency_key="gpu-worker-claim-2")
        assert blocked["task"]["state"] == "queued"
        assert blocked["task"]["waiting_reason"] == "waiting_for_worker"
        _settle_attempt(service, claimed, idempotency_key="gpu-worker-settle-1")
        reservation = service.store.conn.execute("SELECT released_at FROM reservations WHERE task_id=? AND resource_key='gpu'", (claimed["task_id"],)).fetchone()
        assert reservation["released_at"] is not None
        released = _claim_attempt(service, executor="gpu-worker", idempotency_key="gpu-worker-claim-3")
        assert released["task_id"] == remaining
        assert service.task(remaining)["task"]["lease_fence"] == 1
    finally:
        service.close()


def test_missing_named_resource_has_exact_resource_waiting_reason(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "required_resource_keys": ["gpu"]})
        service.register_executor({"executor_id": "cpu-worker", "capabilities": ["render.gpu"], "resource_keys": ["cpu"]}, idempotency_key="cpu-worker-register")
        task_id = _task(service, "missing-gpu")["task"]["id"]
        result = _claim(service, task_id, {"worker_id": "cpu-worker", "lease_token": "lease"}, idempotency_key="cpu-worker-claim")
        assert result["task"]["state"] == "queued"
        assert result["task"]["waiting_reason"] == "waiting_for_gpu"
    finally:
        service.close()


def test_unavailable_capability_never_claims_even_when_worker_is_ready(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "status": "unavailable", "unavailable_reason": "model_missing"})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.gpu"], "resource_keys": []}, idempotency_key="unavailable-worker-register")
        task_id = _task(service, "capability-unavailable")["task"]["id"]
        result = _claim(service, task_id, {"worker_id": "worker", "lease_token": "lease"}, idempotency_key="unavailable-worker-claim")
        assert result["task"]["state"] == "queued"
        assert result["task"]["waiting_reason"] == "capability_unavailable"
    finally:
        service.close()


def test_worker_readiness_and_heartbeat_control_admission(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "required_resource_keys": ["gpu"]})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.gpu"], "resource_keys": ["gpu"], "readiness": "not_ready", "readiness_reason": "warming_up"}, idempotency_key="readiness-worker-register")
        task_id = _task(service, "readiness")["task"]["id"]
        blocked = _claim(service, task_id, {"worker_id": "worker", "lease_token": "lease"}, idempotency_key="readiness-worker-claim-1")
        assert blocked["task"]["waiting_reason"] == "waiting_for_worker"
        ready = service.store.heartbeat_executor("worker", ready=True, runtime_epoch=service.health()["runtime_epoch"])
        assert ready["readiness"] == "ready"
        claimed = _claim(service, task_id, {"worker_id": "worker", "lease_token": "lease"}, idempotency_key="readiness-worker-claim-2")
        before = claimed["task"]["lease_expires_at"]
        renewed = service.store.heartbeat_task(task_id, claimed["lease_id"], fence=claimed["task"]["lease_fence"], lease_seconds=120)
        assert renewed["task"]["lease_expires_at"] > before
        with pytest.raises(LeaseError):
            service.store.heartbeat_task(task_id, claimed["lease_id"], fence=99, lease_seconds=120)
    finally:
        service.close()


def test_executor_registration_uses_same_worker_capacity_contract(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        registered = service.register_executor({"executor_id": "executor", "max_concurrency": 2, "resource_keys": ["cpu"], "capabilities": ["render.basic"], "protocol": "workspace.v1"}, idempotency_key="executor-register")
        assert registered["max_concurrency"] == 2
        executor = service.store.conn.execute("SELECT max_concurrency, resource_keys_json FROM executors WHERE id='executor'").fetchone()
        assert executor["max_concurrency"] == 2
        assert executor["resource_keys_json"] == '["cpu"]'
    finally:
        service.close()


def test_http_executor_claim_heartbeat_and_release_surface(tmp_path):
    daemon = _daemon(tmp_path / "realm", tmp_path / "support")
    try:
        owner = Api(daemon.endpoint, daemon.token)
        owner.request("POST", "/v1/capabilities", {"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "required_resource_keys": ["gpu"]})
        owner.request("POST", "/v1/executors", {"executor_id": "executor", "max_concurrency": 1, "resource_keys": ["gpu"], "capabilities": ["render.gpu"], "protocol": "workspace.v1"}, headers={"Idempotency-Key": "executor-http-1"})
        headers = {"Idempotency-Key": "task-http-1"}
        task_body = {"capability_id": "render.gpu", "capability_digest": _digest("render.gpu-v1"), "input_object_ids": []}
        first = owner.request("POST", "/v1/tasks", task_body, headers=headers)
        second = owner.request("POST", "/v1/tasks", task_body, headers={**headers, "Idempotency-Key": "task-http-2"})
        worker = Api(daemon.endpoint, daemon.worker_token)
        first_attempt = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor", "capability_ids": ["render.gpu"], "runtime_epoch": worker.health()["runtime_epoch"]}, headers={"Idempotency-Key": "claim-http-1"})
        assert first_attempt["fence"] == 1
        blocked = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor", "capability_ids": ["render.gpu"], "runtime_epoch": worker.health()["runtime_epoch"]}, headers={"Idempotency-Key": "claim-http-2"})
        assert blocked["waiting_reason"] == "waiting_for_worker"
        renewed = worker.request("POST", f"/v1/attempts/{first_attempt['attempt_id']}/heartbeat", {"lease_id": first_attempt["lease_id"], "fence": first_attempt["fence"], "lease_seconds": 60, "runtime_epoch": worker.health()["runtime_epoch"]}, headers={"Idempotency-Key": "heartbeat-http-1"})
        assert renewed["data"]["fence"] == first_attempt["fence"] and renewed["data"]["lease_expires_at"] > first_attempt["lease_expires_at"]
    finally:
        daemon.stop()


def test_backup_restore_and_structured_export_verify_cas_and_sqlite(tmp_path):
    service = _service(tmp_path / "realm", display_name="Backup Realm")
    try:
        project = service.create_project({"slug": "demo", "name": "Demo", "metadata": {"kind": "test"}})
        ingested = service.ingest(project["id"], b"backup-payload", media_type="text/plain", original_name="payload.txt", idempotency_key="backup-object")
        exported = service.export_structured()
        assert exported["realm"]["display_name"] == "Backup Realm"
        assert exported["projects"][0]["metadata"] == {"kind": "test"}
        assert exported["objects"][0]["digest"] == ingested["data"]["digest"].removeprefix("sha256:")
        assert "owner.lock" not in json.dumps(exported)

        backup = tmp_path / "backup"
        result = service.backup(backup)
        assert result["manifest"]["realm_id"] == service.realm["id"]
        assert (backup / "cas-manifest.json").is_file()
        verify_backup(backup)

        restored = service.restore(backup, tmp_path / "restored")
        assert restored["verification"]["realm_id"] == service.realm["id"]
        handoff = json.loads((tmp_path / "restored" / "activation-handoff.json").read_text())
        assert handoff["state"] == "prepared"
        with pytest.raises(ConflictError):
            service.restore(backup, tmp_path / "restored")
    finally:
        service.close()


def test_restore_explicit_key_path_still_rejects_a_mismatched_key(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        backup = tmp_path / "backup"
        service.backup(backup)
        wrong_key = tmp_path / "wrong.key"
        wrong_key.write_bytes(os.urandom(32))
        with pytest.raises(ConflictError, match="does not match manifest realm"):
            restore_backup(backup, tmp_path / "restored", key_path=wrong_key)
    finally:
        service.close()


def test_http_admin_export_backup_and_restore_routes(tmp_path):
    daemon = _daemon(tmp_path / "realm", tmp_path / "support")
    try:
        owner = Api(daemon.endpoint, daemon.token)
        exported = owner.request("GET", "/v1/export")
        assert exported["realm"]["id"] == daemon.service.realm["id"]
        backup = tmp_path / "http-backup"
        created = owner.request("POST", "/v1/backup", {"destination": str(backup)})
        assert created["manifest"]["realm_id"] == daemon.service.realm["id"]
        restored = owner.request("POST", "/v1/restore", {"backup": str(backup), "destination": str(tmp_path / "http-restored")})
        assert restored["activation_handoff"].endswith("activation-handoff.json")
    finally:
        daemon.stop()


def test_retry_is_state_guarded_and_records_transition(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1")})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.gpu"], "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="retry-worker-register")
        cancelled = _task(service, "retry-cancelled")["task"]["id"]
        service.cancel(cancelled)
        retried = service.retry_task(cancelled, {"expected_version": 1}, idempotency_key="retry-task")
        assert retried["data"]["state"] == "queued"
        events = service.events(service.task(cancelled)["run"]["id"])
        assert events[-1]["kind"] == "task.retried"

        running = _task(service, "retry-running")["task"]["id"]
        _claim(service, running, {"worker_id": "worker", "lease_token": "running-lease"}, idempotency_key="retry-running-claim")
        with pytest.raises(ConflictError):
            service.retry_task(running, idempotency_key="retry-running")
    finally:
        service.close()


def test_settlement_effect_rejects_undeclared_stale_and_duplicate(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "effect", "name": "Effect"})
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1")})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.gpu"]}, idempotency_key="effect-worker-register")
        undeclared = _task(service, "effect-undeclared")["task"]["id"]
        undeclared_attempt = _claim_attempt(service, idempotency_key="effect-claim-undeclared")
        with pytest.raises(ValidationError):
            _settle_attempt(service, undeclared_attempt, effect={"effect_type": "project.update", "target_id": project["id"], "expected_version": 1}, idempotency_key="effect-settle-undeclared")
        service.cancel(undeclared)

        stale_effect = {"effect_type": "project.update", "target_id": project["id"], "expected_version": 2}
        stale = service.create_task({"capability_id": "render.gpu", "capability_digest": _digest("render.gpu-v1"), "settlement_effect": stale_effect, "idempotency_key": "effect-stale"})["task"]["id"]
        stale_attempt = _claim_attempt(service, idempotency_key="effect-claim-stale")
        with pytest.raises(ConflictError):
            _settle_attempt(service, stale_attempt, effect=stale_effect, idempotency_key="effect-settle-stale")
        service.cancel(stale)

        valid_effect = {
            "effect_type": "project.update",
            "target_id": project["id"],
            "expected_version": 1,
            "payload": {"name": "Settled Effect"},
        }
        duplicate = service.create_task({"capability_id": "render.gpu", "capability_digest": _digest("render.gpu-v1"), "settlement_effect": valid_effect, "idempotency_key": "effect-duplicate"})["task"]["id"]
        duplicate_attempt = _claim_attempt(service, idempotency_key="effect-claim-duplicate")
        settled = _settle_attempt(service, duplicate_attempt, effect=valid_effect, idempotency_key="effect-settle-duplicate")
        assert settled["data"]["state"] == "succeeded"
        assert service.get_project(project["id"])["name"] == "Settled Effect"
        assert service.get_project(project["id"])["version"] == 2
        replayed = _settle_attempt(service, duplicate_attempt, effect=valid_effect, idempotency_key="effect-settle-duplicate")
        assert replayed == settled
        assert service.get_project(project["id"])["version"] == 2
        with pytest.raises(LeaseError):
            _settle_attempt(service, duplicate_attempt, effect=valid_effect, idempotency_key="effect-settle-duplicate-retry")
    finally:
        service.close()


def test_hc04_admission_rejects_unready_duplicate_and_foreign_inputs(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "owner", "name": "Owner"})
        foreign_project = service.create_project({"slug": "foreign", "name": "Foreign"})
        foreign_object = service.ingest(foreign_project["id"], b"foreign", idempotency_key="foreign-object")["data"]["object_id"]
        digest = _digest("render.gpu-v1")
        service.register_capability({
            "capability_id": "render.gpu",
            "definition_digest": digest,
            "status": "unavailable",
            "unavailable_reason": "model_missing",
        })

        with pytest.raises(CapabilityUnavailableError):
            service.create_task({
                "capability_id": "render.gpu",
                "capability_digest": digest,
                "project": project["id"],
                "idempotency_key": "unready-admission",
            }, enforce_readiness=True)

        with pytest.raises(ValidationError, match="unique"):
            service.create_task({
                "capability_id": "render.gpu",
                "capability_digest": digest,
                "project": project["id"],
                "input_object_ids": [foreign_object, foreign_object],
                "idempotency_key": "duplicate-inputs",
            })

        with pytest.raises(ConflictError, match="not associated"):
            service.create_task({
                "capability_id": "render.gpu",
                "capability_digest": digest,
                "project": project["id"],
                "input_object_ids": [foreign_object],
                "idempotency_key": "foreign-input",
            })
    finally:
        service.close()


def test_storage_admission_sets_exact_waiting_reason(tmp_path, monkeypatch):
    service = _service(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.large", "definition_digest": _digest("render.large-v1"), "estimated_output_bytes": 1024})
        monkeypatch.setattr("runtime_protocol.store.shutil.disk_usage", lambda _path: SimpleNamespace(free=1))
        task = service.create_task({"capability_id": "render.large", "capability_digest": _digest("render.large-v1"), "idempotency_key": "disk-full"})
        assert task["task"]["waiting_reason"] == "insufficient_storage"
        service.register_executor({"executor_id": "worker", "capabilities": ["render.large"]}, idempotency_key="disk-worker-register")
        claimed = _claim(service, task["task"]["id"], {"worker_id": "worker", "lease_token": "disk-lease"}, idempotency_key="disk-worker-claim")
        assert claimed["task"]["waiting_reason"] == "insufficient_storage"
    finally:
        service.close()
