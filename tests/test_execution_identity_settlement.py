from __future__ import annotations

import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _attempt(service: RuntimeService):
    capability_digest = _digest(b"identity-capability")
    service.register_capability({"capability_id": "identity.render", "definition_digest": capability_digest})
    service.register_executor({"executor_id": "identity-executor", "capabilities": ["identity.render"]}, idempotency_key="identity-register")
    task = service.create_task({"capability_id": "identity.render", "capability_digest": capability_digest, "idempotency_key": "identity-task"})
    attempt = service.claim_next(
        {"executor_id": "identity-executor", "capability_ids": ["identity.render"], "runtime_epoch": service.health()["runtime_epoch"]},
        idempotency_key="identity-claim",
    )
    return task, attempt


def test_executor_identity_is_migrated_persisted_and_reregistration_is_idempotent(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        digest = _digest(b"executor-source")
        body = {
            "executor_id": "provenance-executor",
            "capabilities": [],
            "source_digest": digest,
            "dependency_digest": _digest(b"executor-dependencies"),
            "source_epoch": "source-epoch-1",
            "schema_digest": service.health()["schema_digest"],
        }
        first = service.register_executor(body, idempotency_key="provenance-register")
        replay = service.register_executor(body, idempotency_key="provenance-register")
        assert replay == first
        assert first["source_digest"] == digest
        row = service.store.conn.execute(
            "SELECT source_digest, dependency_digest, source_epoch FROM executors WHERE id=?",
            ("provenance-executor",),
        ).fetchone()
        assert tuple(row) == (digest, body["dependency_digest"], "source-epoch-1")

        refreshed = {**body, "source_digest": _digest(b"executor-source-v2"), "source_epoch": "source-epoch-2", "runtime_epoch": service.health()["runtime_epoch"]}
        updated = service.register_executor(refreshed, idempotency_key="provenance-refresh")
        assert updated["source_digest"] == refreshed["source_digest"]
        with pytest.raises(ConflictError):
            service.register_executor({**refreshed, "source_epoch": "different"}, idempotency_key="provenance-refresh")
    finally:
        service.close()


def test_settlement_persists_flat_result_and_rejects_reserved_outputs(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        _task, attempt = _attempt(service)
        payload = b"identity-output"
        output = {
            "name": "output",
            "kind": "object",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
        }
        base = {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [output]}
        with pytest.raises(ValidationError, match="reserved"):
            service.settle_attempt(attempt["attempt_id"], {**base, "result": {"outputs": []}}, idempotency_key="reserved-result")
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0

        settled = service.settle_attempt(attempt["attempt_id"], {**base, "result": {"answer": 42}}, idempotency_key="flat-result")
        data = settled["data"]
        assert data["result"] == {"answer": 42, "outputs": [{"name": "output", "kind": "object", "digest": output["digest"], "media_type": output["media_type"], "size": len(payload)}]}
        assert service.settle_attempt(attempt["attempt_id"], {**base, "result": {"answer": 42}}, idempotency_key="flat-result") == settled
    finally:
        service.close()


def test_settlement_preserves_output_descriptors(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        task, attempt = _attempt(service)
        payload = b"descriptor-output"
        output = {
            "name": "primary",
            "kind": "object",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
            "ordinal": 0,
            "role": "primary_render",
            "is_primary": True,
        }
        settled = service.settle_attempt(
            attempt["attempt_id"],
            {
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"],
                "outputs": [output],
                "result": {"answer": 7},
            },
            idempotency_key="descriptor-settle",
        )
        expected = {key: output[key] for key in ("name", "kind", "digest", "media_type", "size", "ordinal", "role", "is_primary")}
        assert settled["data"]["result"]["outputs"] == [expected]
        assert service.task(task["task"]["id"])["task"]["result"]["outputs"] == [expected]
    finally:
        service.close()
