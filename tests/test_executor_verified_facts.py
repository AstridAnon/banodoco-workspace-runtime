from __future__ import annotations

import copy

import pytest

from runtime_protocol.errors import ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


CAPABILITY = "render.facts"
DIGEST = "sha256:" + "a" * 64
VERIFIED_FACTS = {
    "exact": {
        "interpreter": "/opt/runtime/bin/python",
        "runtime_lock": "sha256:runtime-lock",
        "engine_lock": "sha256:engine-lock",
        "model_digest": "sha256:model",
        "custom_node_digest": "sha256:custom-node",
        "driver": "cuda-12.4/driver-550",
        "root": "sha256:runtime-root",
        "port": 8188,
    },
    "minimum": {"vram_bytes": 16 * 1024**3, "scratch_bytes": 8 * 1024**3},
}


def _register(service: RuntimeService, *, facts=VERIFIED_FACTS):
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": DIGEST})
    return service.register_executor(
        {
            "executor_id": "facts-worker",
            "capabilities": [
                {
                    "capability_id": CAPABILITY,
                    "definition_digest": DIGEST,
                    "status": "ready",
                    "required_resource_keys": [],
                    "estimated_scratch_bytes": 0,
                    "estimated_output_bytes": 0,
                }
            ],
            "verified_facts": facts,
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key="facts-worker-register",
    )


def _task(service: RuntimeService, key: str, required_facts):
    return service.create_task(
        {
            "capability_id": CAPABILITY,
            "capability_digest": DIGEST,
            "input_object_ids": [],
            "required_facts": required_facts,
            "idempotency_key": key,
        },
        enforce_readiness=True,
    )


def _claim(service: RuntimeService, key: str):
    return service.claim_next(
        {
            "executor_id": "facts-worker",
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=key,
    )


def test_matching_exact_and_minimum_facts_are_returned_and_claimed(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        registered = _register(service)
        assert registered["verified_facts"] == VERIFIED_FACTS
        admitted = _task(service, "matching", VERIFIED_FACTS)
        assert admitted["task"]["required_facts"] == VERIFIED_FACTS
        attempt = _claim(service, "matching-claim")
        assert attempt["task_id"] == admitted["task"]["id"]
        assert attempt["required_facts"] == VERIFIED_FACTS
    finally:
        service.close()


@pytest.mark.parametrize(
    ("kind", "key"),
    [
        ("exact", "interpreter"),
        ("exact", "runtime_lock"),
        ("exact", "engine_lock"),
        ("exact", "model_digest"),
        ("exact", "custom_node_digest"),
        ("exact", "driver"),
        ("exact", "root"),
        ("exact", "port"),
        ("minimum", "vram_bytes"),
        ("minimum", "scratch_bytes"),
    ],
)
def test_missing_or_mismatched_fact_stays_queued_with_deterministic_reason(tmp_path, kind, key):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        _register(service)
        required = copy.deepcopy(VERIFIED_FACTS)
        if kind == "minimum":
            required[kind][key] += 1
        elif key == "port":
            required[kind][key] = 8189
        else:
            required[kind][key] += "-wrong"
        admitted = _task(service, f"wrong-{kind}-{key}", required)
        assert admitted["task"]["waiting_reason"] == "waiting_for_executor_facts"
        waiting = _claim(service, f"wrong-{kind}-{key}-claim")
        assert waiting["task"]["state"] == "queued"
        assert waiting["task"]["waiting_reason"] == "waiting_for_executor_facts"
    finally:
        service.close()


def test_missing_verified_facts_fails_closed_only_for_fact_bound_tasks(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        _register(service, facts={"exact": {}, "minimum": {}})
        admitted = _task(service, "missing-facts", {"exact": {"driver": "cuda"}})
        assert admitted["task"]["waiting_reason"] == "waiting_for_executor_facts"
        waiting = _claim(service, "missing-facts-claim")
        assert waiting["waiting_reason"] == "waiting_for_executor_facts"
    finally:
        service.close()


def test_fact_maps_reject_backend_or_unknown_policy(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        service.register_capability({"capability_id": CAPABILITY, "definition_digest": DIGEST})
        with pytest.raises(ValidationError, match="unsupported facts"):
            _register(service, facts={"exact": {"backend": "wan2gp"}, "minimum": {}})
    finally:
        service.close()
