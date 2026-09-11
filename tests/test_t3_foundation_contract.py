from __future__ import annotations

import base64
import hashlib
import sqlite3

import pytest

from runtime_protocol.canonical_schema import CANONICAL_FORMAT_ID
from runtime_protocol.errors import ConflictError, LeaseError, RealmAdmissionError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore, SCHEMA_VERSION


CAPABILITY = "foundation.t3"


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(value: bytes, *, name: str, filename: str | None = None, **fields) -> dict:
    result = {
        "name": name,
        "kind": "object",
        "digest": _digest(value),
        "media_type": "application/octet-stream",
        "size": len(value),
        "data_base64": base64.b64encode(value).decode("ascii"),
    }
    if filename is not None:
        result["filename"] = filename
    result.update(fields)
    return result


def _attempt(service: RuntimeService, *, project: dict | None = None, input_object_ids=None, effect=None, key="t3") -> tuple[dict, dict]:
    capability_digest = _digest(CAPABILITY)
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": capability_digest})
    service.register_executor({"executor_id": f"{key}-worker", "capabilities": [CAPABILITY]}, idempotency_key=f"{key}-executor")
    body = {
        "capability_id": CAPABILITY,
        "capability_digest": capability_digest,
        "input_object_ids": list(input_object_ids or []),
        "idempotency_key": f"{key}-task",
    }
    if project is not None:
        body["project"] = project["id"]
    if effect is not None:
        body["settlement_effect"] = effect
    task = service.create_task(body)
    epoch = service.health()["runtime_epoch"]
    attempt = service.claim_next(
        {
            "executor_id": f"{key}-worker",
            "capability_ids": [CAPABILITY],
            "runtime_epoch": epoch,
        },
        idempotency_key=f"{key}-claim",
    )
    return task, attempt


def _settle(service: RuntimeService, attempt: dict, outputs: list[dict], *, key: str, result=None, effect=None, fence=None):
    body = {
        "lease_id": attempt["lease_id"],
        "fence": attempt["fence"] if fence is None else fence,
        "runtime_epoch": attempt["runtime_epoch"],
        "outputs": outputs,
    }
    if result is not None:
        body["result"] = result
    if effect is not None:
        body["effect"] = effect
    return service.settle_attempt(attempt["attempt_id"], body, idempotency_key=key)


def _new_service(root):
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def test_missing_root_service_open_has_no_creation_side_effects(tmp_path):
    root = tmp_path / "missing"
    with pytest.raises(RealmAdmissionError):
        RuntimeService(root)
    assert not root.exists()
    assert not (root / "realm.sqlite3").exists()
    assert not (root / "owner.lock").exists()


def test_canonical_verifier_refuses_shape_identity_fk_relational_and_cas_without_mutation(tmp_path):
    root = tmp_path / "realm"
    service = _new_service(root)
    task, attempt = _attempt(service, key="verify")
    _settle(
        service,
        attempt,
        [_output(b"managed", name="video", filename="video.mp4", output_port="video")],
        key="verify-settle",
    )
    service.close()

    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("ALTER TABLE attempts DROP COLUMN lease_id")
        connection.execute("DELETE FROM realm")
        connection.execute("UPDATE objects SET size=size+1")
        connection.execute("DELETE FROM managed_output_lifecycle")
        connection.execute("UPDATE managed_output_associations SET attempt_id='missing-attempt'")
        connection.commit()
    finally:
        connection.close()

    before = (root / "realm.sqlite3").read_bytes()
    report = RealmStore.inspect_realm(root)
    after = (root / "realm.sqlite3").read_bytes()

    assert before == after
    assert report["ok"] is False
    assert report["checks"]["schema"]["actual_format_id"] == CANONICAL_FORMAT_ID
    assert report["checks"]["schema"]["actual_version"] == SCHEMA_VERSION
    assert report["checks"]["schema"]["missing_columns"] == {"attempts": ["lease_id"]}
    assert report["checks"]["realm_identity"]["ok"] is False
    assert report["checks"]["foreign_keys"]["ok"] is False
    assert any(item["reason"] == "attempt_task_identity" for item in report["checks"]["relational"]["errors"])
    assert any(item["reason"] == "lifecycle_missing" for item in report["checks"]["relational"]["errors"])
    assert report["checks"]["reachable_cas"]["corrupt"]


def test_generic_settlement_associates_outputs_atomically_without_generation_rows(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        task, attempt = _attempt(service, key="generic")
        manifest = b"{}"
        output = _output(
            b"video",
            name="video",
            filename="original-video.mp4",
            output_port="video",
            group_key="declared",
            variant_key="original",
            ordinal=0,
            role="video",
            coverage="full",
        )
        manifest_output = _output(
            manifest,
            name="manifest",
            filename="manifest.json",
            output_port="manifest",
            group_key="declared",
            variant_key="manifest",
            role="manifest",
        )
        result = {"manifest_ref": {"object_id": _digest(manifest), "size": len(manifest)}}
        first = _settle(service, attempt, [manifest_output, output], key="generic-settle", result=result)
        assert _settle(service, attempt, [manifest_output, output], key="generic-settle", result=result) == first
        with pytest.raises(ConflictError):
            _settle(service, attempt, [manifest_output, output], key="generic-settle", result={"answer": 2})

        associations = service.managed_outputs(task["task"]["id"])
        video = next(item for item in associations if item["output_port"] == "video")
        assert video["filename"] == "original-video.mp4"
        assert video["manifest_ref"] == _digest(manifest)
        assert video["state"] == "available"
        assert service.store.conn.execute("SELECT COUNT(*) FROM managed_output_lifecycle").fetchone()[0] == 2
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='attempt.settle'").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_shots").fetchone()[0] == 0
    finally:
        service.close()


def test_managed_settlement_failure_is_fenced_and_rolls_back_before_publication(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        task, attempt = _attempt(service, key="rollback")
        output = _output(b"rollback", name="video", filename="rollback.mp4", output_port="video")
        base_result = {"manifest_ref": {"object_id": _digest(b"missing"), "size": 7}}
        with pytest.raises(ConflictError):
            _settle(service, attempt, [output], key="rollback-bad", result=base_result)
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM managed_output_associations").fetchone()[0] == 0
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        with pytest.raises(LeaseError):
            _settle(service, attempt, [output], key="rollback-stale", result=None, fence=attempt["fence"] - 1)
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
    finally:
        service.close()


def test_explicit_d1_generation_settlement_is_the_only_domain_row_path(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "d1", "name": "D1"}, idempotency_key="d1-project")
        source = service.ingest(project["id"], b"source", idempotency_key="d1-source")
        effect = {
            "effect_type": "generation.create_with_variant",
            "target_id": project["id"],
            "payload": {
                "generation_type": "video",
                "metadata": {"params": {"prompt": "smoke"}},
                "variant_type": "generated",
                "output_name": "video",
                "output_ordinal": 0,
                "primary_policy": "preserve",
            },
        }
        task, attempt = _attempt(service, project=project, input_object_ids=[source["data"]["digest"]], effect=effect, key="d1")
        _settle(service, attempt, [_output(b"d1-video", name="video")], key="d1-settle", effect=effect)
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_shots").fetchone()[0] == 0
        assert service.managed_outputs(task["task"]["id"])
    finally:
        service.close()
