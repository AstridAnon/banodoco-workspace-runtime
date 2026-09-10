from __future__ import annotations

import hashlib
import json

import pytest

from runtime_protocol.errors import LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.util import durable_json_bytes


def _setup(tmp_path, *, reboot_executor=None):
    service = RuntimeService(tmp_path / "realm", reboot_executor=reboot_executor)
    service.register_executor(
        {"executor_id": "worker", "capabilities": ["render.basic"]},
        idempotency_key="b63-worker",
    )
    service.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "sol-b63"})
    epoch = service.health()["runtime_epoch"]
    attempt = service.claim_next(
        {"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": epoch},
        idempotency_key="b63-claim",
    )
    return service, attempt, epoch


def test_consumed_reboot_authorization_resumes_after_restart(tmp_path):
    invoked = []
    first, attempt, epoch = _setup(tmp_path, reboot_executor=lambda command, checkpoint: invoked.append((command, checkpoint)) or {"ok": True})
    prepared = first.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})
    checkpoint = first.checkpoint_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": epoch, "state": {"step": 7}})
    first.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": epoch})
    assert invoked == [("reboot", {"step": 7})]
    first.close()

    second = RuntimeService(tmp_path / "realm", reboot_executor=lambda *_: {"unused": True})
    try:
        resumed = second.resume_attempt({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": second.health()["runtime_epoch"]})
        assert resumed["receipt"]["status"] == "resumed"
        assert resumed["receipt"]["checkpoint"] == {"step": 7}
        assert resumed["attempt"]["runtime_epoch"] == second.health()["runtime_epoch"]
        assert second.store.conn.execute("SELECT recovery_nonce_used FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
    finally:
        second.close()


def test_expired_settlement_has_zero_cas_or_object_mutation(tmp_path):
    service, attempt, epoch = _setup(tmp_path)
    digest = hashlib.sha256(b"expired-output").hexdigest()
    expired = "2000-01-01T00:00:00+00:00"
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, attempt["task_id"]))
    try:
        with pytest.raises(LeaseError, match="expired"):
            service.settle_attempt(
                attempt["attempt_id"],
                {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "outputs": [{"digest": "sha256:" + digest, "data_base64": "ZXhwaXJlZC1vdXRwdXQ"}]},
                idempotency_key="b63-expired-settle",
            )
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (attempt["task_id"],)).fetchone()[0] == "running"
    finally:
        service.close()


def test_checkpoint_limit_is_measured_on_exact_durable_serializer(tmp_path):
    service, attempt, epoch = _setup(tmp_path)
    try:
        prepared = service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})
        payload = {"items": list(range(120_000))}
        assert len(durable_json_bytes(payload)) > 1024 * 1024
        with pytest.raises(ValidationError, match="1 MiB"):
            service.checkpoint_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": epoch, "state": payload})
        assert service.store.conn.execute("SELECT COUNT(*) FROM recovery_checkpoints").fetchone()[0] == 0
    finally:
        service.close()


def test_reboot_executor_typeerror_is_not_retried(tmp_path):
    calls = []

    def executor(command, checkpoint):
        calls.append((command, checkpoint))
        raise TypeError("failure from inside executor")

    service, attempt, epoch = _setup(tmp_path, reboot_executor=executor)
    try:
        prepared = service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch})
        checkpoint = service.checkpoint_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": epoch, "state": {"step": 1}})
        with pytest.raises(TypeError, match="inside executor"):
            service.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": prepared["nonce"], "authorization": prepared["nonce"], "runtime_epoch": epoch})
        assert calls == [("reboot", {"step": 1})]
        row = service.store.conn.execute("SELECT state, recovery_receipt_json FROM recovery_checkpoints WHERE id=?", (checkpoint["checkpoint_id"],)).fetchone()
        assert row["state"] == "executor_failed"
        assert json.loads(row["recovery_receipt_json"])["status"] == "failed"
    finally:
        service.close()


def test_recovery_epoch_is_required_before_mutation(tmp_path):
    service, attempt, epoch = _setup(tmp_path)
    try:
        with pytest.raises(ValidationError, match="request body is missing required fields"):
            service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"]})
        with pytest.raises(ValidationError, match="request body is missing required fields"):
            service.heartbeat_attempt(
                attempt["attempt_id"],
                {"lease_id": attempt["lease_id"], "fence": attempt["fence"]},
                idempotency_key="b63-missing-epoch-heartbeat",
            )
        stale_epoch = epoch + 1
        with pytest.raises(LeaseError, match="stale runtime epoch"):
            service.settle_attempt(
                attempt["attempt_id"],
                {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": stale_epoch, "outputs": []},
                idempotency_key="b63-missing-epoch-settle",
            )
        with pytest.raises(LeaseError, match="stale runtime epoch"):
            service.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": stale_epoch})
        with pytest.raises(LeaseError, match="stale runtime epoch"):
            service.heartbeat_attempt(
                attempt["attempt_id"],
                {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": stale_epoch},
                idempotency_key="b63-stale-epoch-heartbeat",
            )
        assert service.store.conn.execute("SELECT recovery_nonce FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] is None
    finally:
        service.close()
