from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _new_service(root: Path, **kwargs):
    RealmStore.initialize(root).close()
    return RuntimeService(root, **kwargs)


def _new_daemon(root: Path, **kwargs):
    RealmStore.initialize(root).close()
    return RuntimeDaemon(root, **kwargs)


def _service_attempt(tmp_path: Path):
    service = _new_service(tmp_path / "realm")
    definition = _digest(b"render-settlement-v1")
    service.register_capability({"capability_id": "render.settlement", "definition_digest": definition})
    service.register_executor(
        {"executor_id": "worker", "capabilities": ["render.settlement"]},
        idempotency_key="settlement-worker-register",
    )
    task = service.create_task(
        {
            "capability_id": "render.settlement",
            "capability_digest": definition,
            "idempotency_key": "settlement-task",
        }
    )
    attempt = service.claim_next(
        {
            "executor_id": "worker",
            "capability_ids": ["render.settlement"],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key="settlement-worker-claim",
    )
    return service, task, attempt


def test_two_worker_credentials_cannot_cross_claim_or_mutate_attempt(tmp_path: Path) -> None:
    daemon = _new_daemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        capability = "render.security"
        definition = _digest(b"render-security-v1")
        owner.request("POST", "/v1/capabilities", {"capability_id": capability, "definition_digest": definition})
        for executor_id in ("worker-a", "worker-b"):
            owner.request(
                "POST", "/v1/executors",
                {"executor_id": executor_id, "capabilities": [{"capability_id": capability, "definition_digest": definition, "status": "ready", "required_resource_keys": []}]},
                headers={"Idempotency-Key": executor_id},
            )
        token_a, _ = daemon.credentials.provision("worker-a", ["handshake", "worker:execute", "tasks:read"])
        token_b, _ = daemon.credentials.provision("worker-b", ["handshake", "worker:execute", "tasks:read"])
        worker_a, worker_b = Api(daemon.endpoint, token_a), Api(daemon.endpoint, token_b)
        owner.request("POST", "/v1/tasks", {"capability_id": capability, "capability_digest": definition, "input_object_ids": []}, headers={"Idempotency-Key": "security-task"})
        epoch = owner.health()["runtime_epoch"]

        with pytest.raises(RuntimeError) as wrong_claim:
            worker_b.request("POST", "/v1/tasks/claim", {"executor_id": "worker-a", "capability_ids": [capability], "runtime_epoch": epoch}, headers={"Idempotency-Key": "wrong-claim"})
        assert wrong_claim.value.status == 401

        attempt = worker_a.request("POST", "/v1/tasks/claim", {"executor_id": "worker-a", "capability_ids": [capability], "runtime_epoch": epoch}, headers={"Idempotency-Key": "right-claim"})
        for action, body in (
            ("heartbeat", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch}),
            ("checkpoint", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "nonce": "forged", "authorization": "forged", "state": {}}),
            ("fail", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "error": {"code": "forged"}}),
            ("settle", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "outputs": []}),
        ):
            with pytest.raises(RuntimeError) as wrong_action:
                worker_b.request("POST", f"/v1/attempts/{attempt['attempt_id']}/{action}", body, headers={"Idempotency-Key": f"wrong-{action}"})
            assert wrong_action.value.status == 401
    finally:
        daemon.stop()


def test_settlement_stages_all_outputs_before_fenced_publication(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        definition = _digest(b"render-settlement-v1")
        service.register_capability({"capability_id": "render.settlement", "definition_digest": definition})
        service.register_executor(
            {"executor_id": "worker", "capabilities": ["render.settlement"]},
            idempotency_key="settlement-worker-register",
        )
        project = service.create_project({"slug": "settlement", "name": "Settlement"})
        task = service.create_task({"capability_id": "render.settlement", "capability_digest": definition, "project": project["id"], "idempotency_key": "settlement-task"})
        attempt = service.claim_next(
            {"executor_id": "worker", "capability_ids": ["render.settlement"], "runtime_epoch": service.health()["runtime_epoch"]},
            idempotency_key="settlement-worker-claim",
        )
        payload = b"first-output"
        valid = {"digest": _digest(payload), "data_base64": base64.b64encode(payload).decode("ascii"), "size": len(payload), "media_type": "application/octet-stream", "kind": "object", "name": "first"}
        with pytest.raises(ValidationError):
            service.settle_attempt(
                attempt["attempt_id"],
                {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [valid, {"digest": "malformed"}]},
                idempotency_key="settlement-invalid",
            )
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert list((service.store.cas_root).glob("*/*")) == []

        service.settle_attempt(
            attempt["attempt_id"],
            {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [valid]},
            idempotency_key="settlement-valid",
        )
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_objects WHERE project_id=?", (project["id"],)).fetchone()[0] == 1
        assert service.task(task["task"]["id"])["task"]["status"] == "completed"
        assert not (service.store.staging_root / "settlements" / attempt["attempt_id"]).exists()
    finally:
        service.close()


def test_staged_bytes_are_reverified_before_cas_promotion(tmp_path: Path) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"immutable-output"
    digest = _digest(payload).removeprefix("sha256:")
    staged = service._stage_outputs(
        attempt["attempt_id"],
        [
            {
                "digest": "sha256:" + digest,
                "data_base64": base64.b64encode(payload).decode("ascii"),
                "size": len(payload),
                "media_type": "application/octet-stream",
                "kind": "object",
                "name": "output",
            }
        ],
    )
    try:
        staged["items"][0]["path"].write_bytes(b"IMMUTABLE-output")
        with pytest.raises(ConflictError, match="hash or size"):
            with service.store._transaction():
                service._publish_staged_outputs(staged)
        service._recover_cas_publication_journals()
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
    finally:
        service._discard_staged_outputs(staged)
        service.close()


def test_stale_fence_rejects_output_before_any_staging_or_publication(tmp_path: Path) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"fenced-output"
    digest = _digest(payload).removeprefix("sha256:")
    try:
        with pytest.raises(LeaseError):
            service.settle_attempt(
                attempt["attempt_id"],
                {
                    "lease_id": attempt["lease_id"],
                    "fence": attempt["fence"] - 1,
                    "runtime_epoch": attempt["runtime_epoch"],
                    "outputs": [
                        {
                            "digest": "sha256:" + digest,
                            "data_base64": base64.b64encode(payload).decode("ascii"),
                            "size": len(payload),
                            "media_type": "application/octet-stream",
                            "kind": "object",
                            "name": "output",
                        }
                    ],
                },
                idempotency_key="stale-fence-settle",
            )
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert not (service.store.staging_root / "settlements" / attempt["attempt_id"]).exists()
    finally:
        service.close()


def test_attempt_staging_rejects_path_escape_ids(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        with pytest.raises(ValidationError, match="attempt_id is invalid"):
            service._stage_outputs("../outside", [])
        assert not (tmp_path / "outside").exists()
    finally:
        service.close()


def test_staged_cleanup_pins_directory_before_unlinking(tmp_path: Path) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"staged-cleanup"
    staged = service._stage_outputs(
        attempt["attempt_id"],
        [{"digest": _digest(payload), "data_base64": base64.b64encode(payload).decode("ascii")}],
    )
    stage_dir = staged["stage_dir"]
    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "must-survive"
    external.write_bytes(b"external")
    real_stage = stage_dir.with_name(stage_dir.name + "-real")
    try:
        stage_dir.rename(real_stage)
        stage_dir.symlink_to(outside, target_is_directory=True)
        service._discard_staged_outputs(staged)
        assert external.read_bytes() == b"external"
    finally:
        if stage_dir.is_symlink():
            stage_dir.unlink()
        if real_stage.exists():
            service._discard_staged_outputs({"stage_dir": real_stage, "items": []})
        service.close()


def test_promotion_uses_open_source_identity_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _task, attempt = _service_attempt(tmp_path)
    payload = b"trusted-staged-bytes"
    digest = _digest(payload).removeprefix("sha256:")
    staged = service._stage_outputs(
        attempt["attempt_id"],
        [{"digest": "sha256:" + digest, "data_base64": base64.b64encode(payload).decode("ascii")}],
    )
    source = staged["items"][0]["path"]
    replacement = source.with_name(source.name + "-original")
    attacker = b"attacker-bytes"
    swapped = False
    original_verify = service._verify_open_file

    def replace_after_verify(file_fd, expected_digest, expected_size, *, label):
        nonlocal swapped
        result = original_verify(file_fd, expected_digest, expected_size, label=label)
        if label == "staged output" and not swapped:
            swapped = True
            source.rename(replacement)
            source.write_bytes(attacker)
        return result

    monkeypatch.setattr(service, "_verify_open_file", replace_after_verify)
    try:
        with service.store._transaction():
            service._publish_staged_outputs(staged)
        assert swapped
        assert service.cas.path_for(digest).read_bytes() == payload
        staged["committed"] = True
    finally:
        service._discard_staged_outputs(staged)
        service.close()


def test_journal_recovery_pins_cas_prefix_before_unlinking(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    payload = b"journal-recovery"
    digest = _digest(payload).removeprefix("sha256:")
    service = _new_service(root)
    service._begin_cas_publication_journal("ingest", [{"digest": digest}], project_id="unscoped")
    service.cas.put(payload)
    destination = service.cas.path_for(digest)
    prefix = destination.parent
    service.close()

    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "must-survive"
    external.write_bytes(b"external")
    real_prefix = prefix.with_name(prefix.name + "-real")
    try:
        prefix.rename(real_prefix)
        prefix.symlink_to(outside, target_is_directory=True)
        recovered = RuntimeService(root)
        try:
            assert external.read_bytes() == b"external"
            assert prefix.is_symlink()
            assert (real_prefix / digest[2:]).read_bytes() == payload
        finally:
            recovered.close()
    finally:
        if prefix.is_symlink():
            prefix.unlink()
        if real_prefix.exists():
            real_prefix.rename(prefix)
