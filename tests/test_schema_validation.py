from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).parents[1]


def validate(schema_name: str, fixture_name: str, *, definition: str | None = None) -> None:
    schema = json.loads((ROOT / "contract/schemas" / schema_name).read_text())
    if definition:
        schema = {"$schema": schema["$schema"], "definitions": schema["definitions"], **schema["definitions"][definition]}
    instance = json.loads((ROOT / "conformance/fixtures" / fixture_name).read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda error: list(error.path))
    assert not errors, "\n".join(error.message for error in errors)


def test_core_fixtures_validate_against_closed_schemas() -> None:
    validate("handshake-response.json", "handshake.json")
    validate("project.json", "project.json")
    validate("managed-object.json", "managed-object.json")
    validate("task.json", "task.json")
    validate("event.json", "event.json")
    validate("worker.json", "settlement.json", definition="Settlement")


def test_closed_schemas_reject_unknown_fields() -> None:
    schema = json.loads((ROOT / "contract/schemas/project.json").read_text())
    instance = json.loads((ROOT / "conformance/fixtures/project.json").read_text())
    instance["product_private_field"] = True
    assert list(Draft202012Validator(schema).iter_errors(instance))


def test_settlement_schema_allows_bounded_inline_output_bytes() -> None:
    instance = json.loads((ROOT / "conformance/fixtures/settlement.json").read_text())
    payload = b"abcd"
    output = instance["outputs"][0]
    output["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    output["data_base64"] = base64.b64encode(payload).decode("ascii")
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    settlement = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Settlement"],
    }
    errors = list(Draft202012Validator(settlement).iter_errors(instance))
    assert not errors, "\n".join(error.message for error in errors)


def test_worker_schema_declares_continuation_waits_and_output_primary_contract() -> None:
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    claim_waiting = schema["definitions"]["ClaimWaiting"]["properties"]["waiting_reason"]
    assert {"waiting_for_dependencies", "dependency_failed", "dependency_cancelled"} <= set(claim_waiting["enum"])
    output = schema["definitions"]["Output"]["properties"]
    assert output["is_primary"] == {"type": "boolean"}
    assert output["role"]["maxLength"] == 255
