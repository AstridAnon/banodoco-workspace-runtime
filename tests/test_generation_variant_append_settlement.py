from __future__ import annotations

import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService


CAPABILITY = "render.variant-append"


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(value: bytes, *, name: str = "generated_images") -> dict:
    return {
        "name": name,
        "kind": "object",
        "digest": _digest(value),
        "media_type": "image/png",
        "size": len(value),
        "data_base64": base64.b64encode(value).decode("ascii"),
    }


def _setup(service: RuntimeService, *, slug: str = "edit", effect_override: dict | None = None, mismatched_source: bool = False) -> dict:
    capability_digest = _digest(CAPABILITY)
    executor_id = f"worker-{slug}"
    service.register_executor(
        {"executor_id": executor_id, "capabilities": [CAPABILITY]},
        idempotency_key=f"executor-{slug}",
    )
    project = service.create_project(
        {"slug": slug, "name": slug.title()}, idempotency_key=f"project-{slug}"
    )
    source = service.ingest(project["id"], b"source-image", idempotency_key=f"source-{slug}")
    source_object_id = source["data"]["digest"]
    effect_source_object_id = source_object_id
    if mismatched_source:
        alternate = service.ingest(project["id"], b"other-source", idempotency_key=f"other-source-{slug}")
        effect_source_object_id = alternate["data"]["digest"]
    generation_id = f"generation-{slug}"
    service.create_generation(
        project["id"],
        {"generation_id": generation_id, "type": "image", "metadata": {"prompt": "source"}},
        idempotency_key=f"generation-{slug}",
    )
    source_variant_id = f"source-variant-{slug}"
    service.create_variant(
        generation_id,
        {
            "variant_id": source_variant_id,
            "object_id": source_object_id,
            "variant_type": "original",
            "metadata": {"role": "source"},
        },
        idempotency_key=f"variant-{slug}",
    )
    effect = {
        "effect_type": "generation.variant.append",
        "target_id": generation_id,
        "expected_version": 1,
        "payload": {
            "source_variant_id": source_variant_id,
            "source_object_id": effect_source_object_id,
            "variant_type": "magic_edit",
            "output_name": "generated_images",
            "output_ordinal": 0,
            "primary_policy": "preserve",
        },
    }
    admitted_effect = effect_override or effect
    task = service.create_task(
        {
            "capability_id": CAPABILITY,
            "capability_digest": capability_digest,
            "project": project["id"],
            "input_object_ids": [source_object_id],
            "settlement_effect": admitted_effect,
            "idempotency_key": f"task-{slug}",
        }
    )
    attempt = service.claim_next(
        {
            "executor_id": executor_id,
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=f"claim-{slug}",
    )
    return {
        "project": project,
        "source_object_id": source_object_id,
        "generation_id": generation_id,
        "source_variant_id": source_variant_id,
        "effect": admitted_effect,
        "task": task,
        "attempt": attempt,
    }


def _settle(service: RuntimeService, attempt: dict, outputs: list[dict], *, key: str, effect: dict):
    return service.settle_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"],
            "runtime_epoch": attempt["runtime_epoch"],
            "outputs": outputs,
            "effect": effect,
        },
        idempotency_key=key,
    )


def test_generation_variant_append_is_atomic_and_replays_deterministically(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        fixture = _setup(service)
        output = b"generated-image"
        first = _settle(service, fixture["attempt"], [_output(output)], key="settle", effect=fixture["effect"])
        replay = _settle(service, fixture["attempt"], [_output(output)], key="settle", effect=fixture["effect"])

        assert replay == first
        assert first["data"]["result"]["generation_variant"]["object_id"] == _digest(output)
        generation = service.get_generation(fixture["generation_id"])
        assert generation["version"] == 2
        variants = service.list_variants(fixture["generation_id"])["items"]
        assert len(variants) == 2
        appended = variants[1]
        assert appended["variant_type"] == "magic_edit"
        assert appended["object_id"] == _digest(output)
        assert service.store.conn.execute(
            "SELECT 1 FROM project_objects WHERE project_id=? AND digest=?",
            (fixture["project"]["id"], _digest(output).removeprefix("sha256:")),
        ).fetchone()
    finally:
        service.close()


def test_generation_variant_append_rejects_target_generation_from_another_project(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        target = _setup(service, slug="foreign")
        foreign_effect = {
            **target["effect"],
            "target_id": target["generation_id"],
            "payload": dict(target["effect"]["payload"]),
        }
        local = _setup(service, slug="local", effect_override=foreign_effect)
        before = service.store.conn.execute(
            "SELECT version, COUNT(*) AS variants FROM generations JOIN generation_variants ON generation_variants.generation_id=generations.id WHERE generations.id=?",
            (target["generation_id"],),
        ).fetchone()
        with pytest.raises(ConflictError, match="outside the task project"):
            _settle(service, local["attempt"], [_output(b"foreign-target-output")], key="foreign-settle", effect=foreign_effect)
        after = service.store.conn.execute(
            "SELECT version, COUNT(*) AS variants FROM generations JOIN generation_variants ON generation_variants.generation_id=generations.id WHERE generations.id=?",
            (target["generation_id"],),
        ).fetchone()
        assert tuple(after) == tuple(before)
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (local["task"]["task"]["id"],)).fetchone()[0] == "running"
    finally:
        service.close()


def test_generation_variant_append_rejects_source_variant_object_mismatch(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        fixture = _setup(service, mismatched_source=True)
        with pytest.raises(ConflictError, match="does not match source_object_id"):
            _settle(service, fixture["attempt"], [_output(b"mismatch-output")], key="mismatch-settle", effect=fixture["effect"])
        assert service.get_generation(fixture["generation_id"])["version"] == 1
        assert len(service.list_variants(fixture["generation_id"])["items"]) == 1
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (fixture["task"]["task"]["id"],)).fetchone()[0] == "running"
    finally:
        service.close()


def test_generation_variant_append_rejects_stale_generation_version_without_mutation(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        fixture = _setup(service)
        with service.store._transaction():
            service.store.conn.execute(
                "UPDATE generations SET version=2 WHERE id=?",
                (fixture["generation_id"],),
            )
        with pytest.raises(ConflictError, match="stale settlement effect target generation version"):
            _settle(service, fixture["attempt"], [_output(b"stale-output")], key="stale-settle", effect=fixture["effect"])
        assert service.get_generation(fixture["generation_id"])["version"] == 2
        assert len(service.list_variants(fixture["generation_id"])["items"]) == 1
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (fixture["task"]["task"]["id"],)).fetchone()[0] == "running"
    finally:
        service.close()


def test_generation_variant_append_rejects_wrong_output_cardinality_and_cleans_cas(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        fixture = _setup(service)
        left = b"left-output"
        right = b"right-output"
        with pytest.raises(ValidationError, match="exactly one settlement output"):
            _settle(service, fixture["attempt"], [_output(left), _output(right, name="other")], key="cardinality-settle", effect=fixture["effect"])
        for value in (left, right):
            digest = _digest(value).removeprefix("sha256:")
            assert not service.cas.path_for(digest).exists()
            assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert service.get_generation(fixture["generation_id"])["version"] == 1
        assert len(service.list_variants(fixture["generation_id"])["items"]) == 1
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (fixture["task"]["task"]["id"],)).fetchone()[0] == "running"
    finally:
        service.close()


def test_generation_variant_append_rolls_back_after_publication_failure(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    try:
        fixture = _setup(service)
        output = b"rollback-output"

        def fail_receipt(*args, **kwargs):
            raise RuntimeError("receipt failure")

        monkeypatch.setattr(service, "_command_record", fail_receipt)
        with pytest.raises(RuntimeError, match="receipt failure"):
            _settle(service, fixture["attempt"], [_output(output)], key="rollback-settle", effect=fixture["effect"])
        digest = _digest(output).removeprefix("sha256:")
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert service.get_generation(fixture["generation_id"])["version"] == 1
        assert len(service.list_variants(fixture["generation_id"])["items"]) == 1
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (fixture["task"]["task"]["id"],)).fetchone()[0] == "running"
    finally:
        service.close()
