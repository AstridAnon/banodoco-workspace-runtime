from __future__ import annotations

import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


CAPABILITY = "managed-output.fixture"


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(value: bytes, *, name: str, **fields) -> dict:
    result = {
        "name": name,
        "kind": "object",
        "digest": _digest(value),
        "media_type": "video/mp4",
        "size": len(value),
        "data_base64": base64.b64encode(value).decode("ascii"),
    }
    result.update(fields)
    return result


def _service(tmp_path, *, project=None, key="fixture"):
    root = tmp_path / key
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    if project is True:
        project = service.create_project({"slug": key, "name": key.title()}, idempotency_key=f"{key}-project")
    digest = _digest(CAPABILITY)
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": digest})
    service.register_executor({"executor_id": f"{key}-worker", "capabilities": [CAPABILITY]}, idempotency_key=f"{key}-executor")
    task_body = {"capability_id": CAPABILITY, "capability_digest": digest, "input_object_ids": [], "idempotency_key": f"{key}-task"}
    if project is not None:
        task_body["project"] = project["id"]
    task = service.create_task(task_body)
    attempt = service.claim_next({"executor_id": f"{key}-worker", "capability_ids": [CAPABILITY], "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key=f"{key}-claim")
    return service, task, attempt


def _settle(service, attempt, outputs, *, key, result=None):
    body = {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": outputs}
    if result is not None:
        body["result"] = result
    return service.settle_attempt(attempt["attempt_id"], body, idempotency_key=key)


def _coverage(mode="interval"):
    sampling = {"mode": mode, "range": {"start": 0, "end": 2}, "step_frames_rational": "1/1"}
    if mode == "interval":
        sampling["every"] = 1
    sampling["cards"] = [{"frame": 0, "time_seconds": 0, "time_rational": "0/1", "sample_reasons": ["interval"]}]
    return {"sampling": sampling}


def _regeneration(*, available=True):
    return {
        "available": available,
        "capability_id": CAPABILITY if available else None,
        "source_refs": [_digest(b"source")],
        "recipe_digest": _digest(b"recipe"),
        "exact_inputs": {"prompt": "fixed", "seed": 7},
    }


def test_public_managed_output_adoption_read_and_lifecycle_receipts(tmp_path):
    service, task, attempt = _service(tmp_path, key="public")
    try:
        manifest = _output(b"{}", name="manifest", filename="manifest.json", output_port="manifest", role="manifest")
        video = _output(
            b"video", name="video", filename="actual.mp4", output_port="video",
            selector={"group_key": "main", "variant_key": "original"}, ordinal=0,
            role="result", durability="durable", coverage=_coverage(), regeneration=_regeneration(),
        )
        result = {"manifest_ref": {"object_id": manifest["digest"], "size": manifest["size"]}}
        _settle(service, attempt, [manifest, video], key="public-settle", result=result)
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 0
        association = next(item for item in service.managed_outputs(task["task"]["id"]) if item["output_port"] == "video")
        assert association["run_id"] == task["run"]["id"]
        assert association["object_id"] == association["digest"] == video["digest"]
        assert association["manifest_ref"] == manifest["digest"]
        assert association["selector"] == {"group_key": "main", "variant_key": "original"}
        assert association["provenance"]["capability_id"] == CAPABILITY
        assert association["provenance"]["fence"] == attempt["fence"]
        assert service.managed_output(association["association_id"]) == association

        adopted = service.adopt_managed_output(
            association["association_id"],
            {"object_id": association["object_id"], "manifest_ref": association["manifest_ref"]},
            idempotency_key="public-adopt",
        )
        assert adopted["data"] == association and adopted["receipt"]["command_kind"] == "managed_output.adopt"
        assert service.adopt_managed_output(
            association["association_id"],
            {"object_id": association["object_id"], "manifest_ref": association["manifest_ref"]},
            idempotency_key="public-adopt",
        ) == adopted
        with pytest.raises(ConflictError):
            service.adopt_managed_output(association["association_id"], {"size": 999}, idempotency_key="public-adopt")

        pinned = service.update_managed_output_lifecycle(association["association_id"], {"operation": "pin", "expected_version": 1, "provenance": {"actor": "fixture"}}, idempotency_key="public-pin")
        assert pinned["data"]["state"] == "available" and pinned["data"]["pinned_at"]
        leased = service.update_managed_output_lifecycle(association["association_id"], {"operation": "lease", "expected_version": 2, "lease_owner": "fixture", "lease_seconds": 30}, idempotency_key="public-lease")
        assert leased["data"]["lease_id"]
        released = service.update_managed_output_lifecycle(association["association_id"], {"operation": "release", "expected_version": 3, "lease_id": leased["data"]["lease_id"]}, idempotency_key="public-release")
        assert released["data"]["lease_id"] is None
    finally:
        service.close()


def test_v1_coverage_and_regeneration_reject_legacy_or_latest_and_preserve_unavailable(tmp_path):
    service, _task, attempt = _service(tmp_path, key="contract")
    try:
        with pytest.raises(ValidationError):
            _settle(service, attempt, [_output(b"bad", name="bad", coverage="full")], key="bad-coverage")
        with pytest.raises(ValidationError):
            _settle(service, attempt, [_output(b"bad-every", name="bad-every", coverage={"sampling": {"mode": "clips", "range": {"start": 0, "end": 2}, "every": 1}})], key="bad-every")
        with pytest.raises(ValidationError):
            _settle(service, attempt, [_output(b"bad-latest", name="bad-latest", regeneration={**_regeneration(), "exact_inputs": {"source": "latest"}})], key="bad-latest")

        unavailable = _output(b"available-bytes", name="temporary", durability="temporary", coverage=_coverage("clips"), regeneration=_regeneration(available=False))
        _settle(service, attempt, [unavailable], key="valid-unavailable")
        stored = service.managed_outputs(_task["task"]["id"])[0]
        assert stored["coverage"]["sampling"]["mode"] == "clips"
        assert stored["coverage"]["sampling"]["range"] == {"start": 0, "end": 2}
        assert stored["regeneration"]["available"] is False
        assert stored["regeneration"]["exact_inputs"] == {"prompt": "fixed", "seed": 7}
    finally:
        service.close()


def test_temporary_lifecycle_expiry_reclaim_and_promotion_are_runtime_only(tmp_path):
    service, _task, attempt = _service(tmp_path, project=True, key="lifecycle")
    try:
        temporary = _output(b"temp", name="overview", durability="temporary", coverage=_coverage())
        durable = _output(b"promote", name="poster", durability="durable", coverage=_coverage())
        _settle(service, attempt, [temporary, durable], key="temporary-settle")
        associations = {item["output_port"]: item for item in service.managed_outputs(_task["task"]["id"])}
        promoted = service.update_managed_output_lifecycle(associations["poster"]["association_id"], {"operation": "promote", "expected_version": 1}, idempotency_key="promote")
        assert promoted["data"]["state"] == "promoted"
        association = associations["overview"]
        pinned = service.update_managed_output_lifecycle(association["association_id"], {"operation": "pin", "expected_version": 1}, idempotency_key="pin")
        with pytest.raises(ConflictError):
            service.update_managed_output_lifecycle(association["association_id"], {"operation": "expire", "expected_version": pinned["data"]["version"]}, idempotency_key="expire-pinned")
        unpinned = service.update_managed_output_lifecycle(association["association_id"], {"operation": "unpin", "expected_version": pinned["data"]["version"]}, idempotency_key="unpin")
        expired = service.update_managed_output_lifecycle(association["association_id"], {"operation": "expire", "expected_version": unpinned["data"]["version"]}, idempotency_key="expire")
        reclaimed = service.update_managed_output_lifecycle(association["association_id"], {"operation": "reclaim", "expected_version": expired["data"]["version"]}, idempotency_key="reclaim")
        assert reclaimed["data"]["state"] == "reclaimed"
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (temporary["digest"].removeprefix("sha256:"),)).fetchone()
    finally:
        service.close()
