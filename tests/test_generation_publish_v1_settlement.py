from __future__ import annotations

import base64
import hashlib
import json

import pytest

from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


CAPABILITY = "generation.publish.v1"


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(value: bytes, *, output_port: str, group_key: str, variant_key: str, ordinal: int, name: str | None = None, **fields) -> dict:
    result = {
        "name": name or output_port,
        "kind": "object",
        "digest": _digest(value),
        "media_type": "application/octet-stream",
        "size": len(value),
        "data_base64": base64.b64encode(value).decode("ascii"),
        "output_port": output_port,
        "group_key": group_key,
        "variant_key": variant_key,
        "ordinal": ordinal,
    }
    result.update(fields)
    return result


def _effect(project_id: str, *, policy: str = "reject", groups: list[dict] | None = None) -> dict:
    return {
        "effect_type": "generation.publish_v1",
        "target_id": project_id,
        "payload": {
            "version": 1,
            "modality": "video",
            "generation_type": "multi_output_render",
            "metadata": {"prompt": "bounded publish"},
            "partial_success_policy": policy,
            "groups": groups or [
                {
                    "group_key": "main",
                    "selectors": [
                        {"selector": "first", "ordinal": 0, "variant_key": "first", "output_port": "video"},
                        {"selector": "second", "ordinal": 1, "variant_key": "second", "output_port": "video"},
                    ],
                },
                {
                    "group_key": "audio",
                    "selectors": [
                        {"selector": "track", "ordinal": 0, "variant_key": "original", "output_port": "audio"},
                    ],
                },
            ],
        },
    }


def _fixture(tmp_path, *, effect_factory=_effect, slug="publish"):
    root = tmp_path / slug
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    digest = _digest(CAPABILITY.encode())
    service.register_executor(
        {"executor_id": f"{slug}-worker", "capabilities": [CAPABILITY]},
        idempotency_key=f"{slug}-executor",
    )
    project = service.create_project(
        {"slug": slug, "name": slug.title()}, idempotency_key=f"{slug}-project"
    )
    effect = effect_factory(project["id"])
    task = service.create_task(
        {
            "capability_id": CAPABILITY,
            "capability_digest": digest,
            "project": project["id"],
            "settlement_effect": effect,
            "idempotency_key": f"{slug}-task",
        }
    )
    attempt = service.claim_next(
        {
            "executor_id": f"{slug}-worker",
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=f"{slug}-claim",
    )
    return service, project, task, attempt, effect


def _settle(service, attempt, outputs, *, effect, key="settle", fence=None):
    return service.settle_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"] if fence is None else fence,
            "runtime_epoch": attempt["runtime_epoch"],
            "outputs": outputs,
            "effect": effect,
        },
        idempotency_key=key,
    )


def _derived_generation(task_id: str, group_key: str) -> str:
    return "generation-" + hashlib.sha256(
        canonical_json({"task_id": task_id, "group_key": group_key}).encode()
    ).hexdigest()


def _derived_variant(generation_id: str, ordinal: int, variant_key: str) -> str:
    return "variant-" + hashlib.sha256(
        canonical_json({"generation_id": generation_id, "ordinal": ordinal, "variant_key": variant_key}).encode()
    ).hexdigest()


def test_publish_v1_matches_out_of_order_groups_and_derives_domain_identity(tmp_path):
    service, project, task, attempt, effect = _fixture(tmp_path)
    try:
        outputs = [
            _output(b"audio", output_port="audio", group_key="audio", variant_key="original", ordinal=0),
            _output(b"extra", output_port="thumbnail", group_key="other", variant_key="preview", ordinal=0, generation_id="forged-generation"),
            _output(b"first", output_port="video", group_key="main", variant_key="first", ordinal=0, filename="first.mp4"),
            _output(b"second", output_port="video", group_key="main", variant_key="second", ordinal=1, filename="second.mp4"),
        ]
        settled = _settle(service, attempt, outputs, effect=effect)
        task_id = task["task"]["id"]
        assert settled["data"]["state"] == "succeeded"
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 2
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 3

        for group_key in ("main", "audio"):
            generation_id = _derived_generation(task_id, group_key)
            generation = service.get_generation(generation_id)
            assert generation["project_id"] == project["id"]
            assert generation["source_task_id"] == task_id
            assert generation["type"] == "multi_output_render"
            assert generation["metadata"] == effect["payload"]["metadata"]
        for group_key, ordinal, variant_key in (("main", 0, "first"), ("main", 1, "second"), ("audio", 0, "original")):
            generation_id = _derived_generation(task_id, group_key)
            variant_id = _derived_variant(generation_id, ordinal, variant_key)
            variant = service.get_variant(variant_id)
            assert variant["generation_id"] == generation_id
            assert variant["variant_type"] == variant_key

        associations = service.managed_outputs(task_id)
        selected = {(item["output_port"], item["group_key"], item["variant_key"], item["ordinal"]): item for item in associations}
        first = selected[("video", "main", "first", 0)]
        assert first["generation_id"] == _derived_generation(task_id, "main")
        assert first["provenance"]["selector"] == "first"
        assert selected[("video", "main", "second", 1)]["generation_id"] == _derived_generation(task_id, "main")
        assert selected[("audio", "audio", "original", 0)]["generation_id"] == _derived_generation(task_id, "audio")
        extra = selected[("thumbnail", "other", "preview", 0)]
        assert extra["generation_id"] is None
        assert "selector" not in extra["provenance"]
    finally:
        service.close()


def test_publish_v1_reject_missing_selector_rolls_back_everything(tmp_path):
    service, _project, task, attempt, effect = _fixture(tmp_path, slug="reject-missing")
    try:
        output = _output(b"first", output_port="video", group_key="main", variant_key="first", ordinal=0)
        with pytest.raises(ValidationError, match="requires every declared selector"):
            _settle(service, attempt, [output], effect=effect, key="reject-missing-settle")
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM managed_output_associations").fetchone()[0] == 0
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
    finally:
        service.close()


def test_publish_v1_allow_records_missing_members_without_empty_generations(tmp_path):
    def effect_factory(project_id):
        return _effect(
            project_id,
            policy="allow",
            groups=[
                {
                    "group_key": "main",
                    "selectors": [
                        {"selector": "present", "ordinal": 0, "variant_key": "present", "output_port": "video"},
                        {"selector": "missing", "ordinal": 1, "variant_key": "missing", "output_port": "video"},
                    ],
                },
                {
                    "group_key": "empty",
                    "selectors": [
                        {"selector": "none", "ordinal": 0, "variant_key": "none", "output_port": "audio"},
                    ],
                },
            ],
        )

    service, _project, task, attempt, effect = _fixture(tmp_path, effect_factory=effect_factory, slug="allow-partial")
    try:
        _settle(
            service,
            attempt,
            [_output(b"present", output_port="video", group_key="main", variant_key="present", ordinal=0)],
            effect=effect,
            key="allow-partial-settle",
        )
        task_value = service.task(task["task"]["id"])["task"]
        publication = task_value["result"]["generation_publish_v1"]
        assert len(publication["publications"]) == 2
        assert publication["publications"][0]["missing_selectors"] == [effect["payload"]["groups"][0]["selectors"][1]]
        assert publication["publications"][1]["published"] == []
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 1
    finally:
        service.close()


def test_publish_v1_rejects_wrong_shape_duplicates_and_project_target_at_admission(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "shape", "name": "Shape"}, idempotency_key="shape-project")
        base = _effect(project["id"])
        for index, bad in enumerate((
            {**base, "extra": True},
            {**base, "payload": {**base["payload"], "groups": [{"group_key": "main", "selectors": []}]}},
            {**base, "payload": {**base["payload"], "modality": "text"}},
            {**base, "payload": {**base["payload"], "modality": []}},
            {**base, "payload": {**base["payload"], "partial_success_policy": {}}},
        )):
            with pytest.raises(ValidationError):
                service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": bad, "idempotency_key": "shape-" + str(index)})
        duplicate = _effect(
            project["id"],
            groups=[{
                "group_key": "main",
                "selectors": [
                    {"selector": "one", "ordinal": 0, "variant_key": "same", "output_port": "video"},
                    {"selector": "two", "ordinal": 0, "variant_key": "same", "output_port": "audio"},
                ],
            }],
        )
        with pytest.raises(ValidationError, match="ordinal and variant_key"):
            service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": duplicate, "idempotency_key": "shape-duplicate"})
        full_duplicate = _effect(
            project["id"],
            groups=[{
                "group_key": "main",
                "selectors": [
                    {"selector": "one", "ordinal": 0, "variant_key": "same", "output_port": "video"},
                    {"selector": "two", "ordinal": 0, "variant_key": "same", "output_port": "video"},
                ],
            }],
        )
        with pytest.raises(ValidationError, match="must not contain duplicates"):
            service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": full_duplicate, "idempotency_key": "shape-full-duplicate"})
        foreign_project = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="shape-foreign-project")
        foreign = _effect(foreign_project["id"])
        with pytest.raises(ConflictError, match="target project does not match"):
            service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": foreign, "idempotency_key": "shape-foreign"})
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    finally:
        service.close()


def test_publish_v1_replay_conflict_and_stale_fence_are_atomic(tmp_path):
    service, _project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=lambda project_id: _effect(project_id, policy="allow"),
        slug="replay",
    )
    try:
        output = _output(b"stable", output_port="video", group_key="main", variant_key="first", ordinal=0)
        first = _settle(service, attempt, [output], effect=effect, key="replay-settle")
        assert _settle(service, attempt, [output], effect=effect, key="replay-settle") == first
        before = tuple(service.store.conn.execute("SELECT COUNT(*) FROM generations, generation_variants, managed_output_associations").fetchone())
        changed = _output(b"changed", output_port="video", group_key="main", variant_key="first", ordinal=0)
        with pytest.raises(ConflictError):
            _settle(service, attempt, [changed], effect=effect, key="replay-settle")
        after = tuple(service.store.conn.execute("SELECT COUNT(*) FROM generations, generation_variants, managed_output_associations").fetchone())
        assert after == before
    finally:
        service.close()

    service, _project, task, attempt, effect = _fixture(tmp_path, slug="stale-fence")
    try:
        output = _output(b"stale", output_port="video", group_key="main", variant_key="first", ordinal=0)
        with pytest.raises(LeaseError):
            _settle(service, attempt, [output], effect=effect, key="stale-fence-settle", fence=attempt["fence"] - 1)
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
    finally:
        service.close()


def test_generic_output_generation_id_remains_managed_only(tmp_path):
    service, project, task, attempt, _effect_value = _fixture(
        tmp_path,
        effect_factory=lambda _project_id: None,
        slug="generic",
    )
    try:
        output = _output(
            b"generic",
            output_port="video",
            group_key="default",
            variant_key="original",
            ordinal=0,
            generation_id="producer-forged-generation",
        )
        # The fixture admits no effect; the helper's claim is still valid.
        service.settle_attempt(
            attempt["attempt_id"],
            {
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"],
                "outputs": [output],
                "effect": None,
            },
            idempotency_key="generic-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        assert association["generation_id"] is None
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert project["id"] == association["project_id"]
    finally:
        service.close()
