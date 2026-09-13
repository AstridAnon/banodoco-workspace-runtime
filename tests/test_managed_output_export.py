from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import ApiError, WorkspaceClient  # noqa: E402
from runtime_protocol.errors import ConflictError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _settled_service(root: Path, export_root: Path) -> tuple[RuntimeService, dict, dict, bytes, int]:
    RealmStore.initialize(root).close()
    service = RuntimeService(root, export_root=export_root)
    project = service.create_project({"slug": "exports", "name": "Exports"})
    capability_digest = _digest(b"rendering.export-v1")
    service.register_capability({"capability_id": "rendering.export", "definition_digest": capability_digest})
    service.register_executor(
        {"executor_id": "export-worker", "capabilities": ["rendering.export"]},
        idempotency_key="export-worker-register",
    )
    task = service.create_task({
        "capability_id": "rendering.export",
        "capability_digest": capability_digest,
        "project": project["id"],
        "idempotency_key": "export-task",
    })
    worker_identity = {"actor": "export-worker", "scopes": ["objects:write", "worker:execute"]}
    attempt = service.claim_next(
        {"executor_id": "export-worker", "capability_ids": ["rendering.export"], "runtime_epoch": service.health()["runtime_epoch"]},
        idempotency_key="export-claim",
        identity=worker_identity,
    )
    payload = b"retained-render-output"
    filename = "retained-render.bin"
    media_type = "application/octet-stream"
    binding = {
        "project_id": project["id"], "run_id": task["run"]["id"], "task_id": attempt["task_id"],
        "attempt_id": attempt["attempt_id"], "executor_id": "export-worker", "lease_id": attempt["lease_id"],
        "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "output_key": "render",
        "output_port": "render", "filename": filename, "digest": _digest(payload), "size": len(payload),
        "media_type": media_type,
    }
    service.ingest_object(
        payload, media_type=media_type, original_name=filename,
        idempotency_key=service._generic_output_idempotency_key(binding),
        identity=worker_identity, upload_binding=binding,
    )
    service.settle_attempt(
        attempt["attempt_id"], {
            "lease_id": attempt["lease_id"], "fence": attempt["fence"],
            "runtime_epoch": attempt["runtime_epoch"], "outputs": [{
                "name": "render", "kind": "object", "filename": filename, "output_port": "render",
                "digest": _digest(payload), "media_type": media_type, "size": len(payload),
                "role": "result", "durability": "durable", "producer": {"capability_id": "rendering.export"},
            }],
        },
        idempotency_key="export-settle",
        identity=worker_identity,
    )
    association = service.managed_outputs(task["task"]["id"])[0]
    production_epoch = int(attempt["runtime_epoch"])
    return service, association, task, payload, production_epoch


def test_export_preserves_completed_historical_provenance_after_restart(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    export_root = tmp_path / "exports"
    export_root.mkdir()
    first, association, task, payload, production_epoch = _settled_service(root, export_root)
    run_id = task["run"]["id"]
    association_id = association["association_id"]
    first.close()

    second = RuntimeService(root, export_root=export_root)
    try:
        assert second.health()["runtime_epoch"] != production_epoch
        result = second.export_managed_output(
            association_id,
            {"destination_filename": association["filename"], "expected": {"digest": association["digest"]}},
            idempotency_key="export-retained-output",
        )
        receipt = result["receipt"]
        exported = result["data"]
        assert (export_root / association["filename"]).read_bytes() == payload
        assert exported["runtime_epoch"] == production_epoch
        assert exported["lease_id"] == association["provenance"].get("lease_id", second.store.conn.execute("SELECT lease_id FROM attempts WHERE id=?", (association["attempt_id"],)).fetchone()[0])
        assert receipt["result"]["export_id"] == exported["export_id"]
        assert any(event["kind"] == "managed_output.exported" for event in second.events(run_id))

        replay = second.export_managed_output(
            association_id, {"destination_filename": association["filename"], "expected": {"digest": association["digest"]}}, idempotency_key="export-retained-output",
        )
        assert replay["data"] == exported
    finally:
        second.close()


def test_export_fails_closed_without_runtime_export_root(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    export_root = tmp_path / "exports"
    export_root.mkdir()
    service, association, _task, _payload, _epoch = _settled_service(root, export_root)
    service.close()
    service = RuntimeService(root)
    try:
        with pytest.raises(ConflictError, match="export root is not configured"):
            service.export_managed_output(
                association["association_id"], {"destination_filename": association["filename"]}, idempotency_key="export-without-root",
            )
    finally:
        service.close()


def test_generated_http_export_replay_conflict_and_durable_event(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    export_root = tmp_path / "exports"
    export_root.mkdir()
    first, association, task, payload, production_epoch = _settled_service(root, export_root)
    first.close()
    daemon = RuntimeDaemon(
        root, support_root=tmp_path / "support", export_root=export_root, port=0,
        production_worker_credentials=True,
    ).start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        output = client.get_managed_output(association["association_id"])
        result = client.export_managed_output(
            output.association_id,
            destination_filename=output.filename,
            idempotency_key="http-export",
            expected={"runtime_epoch": production_epoch, "digest": output.digest},
        )
        assert (export_root / output.filename).read_bytes() == payload
        assert result["runtime_epoch"] == production_epoch
        assert result.receipt["command_kind"] == "managed_output.export"

        replay = client.export_managed_output(
            output.association_id,
            destination_filename=output.filename,
            idempotency_key="http-export",
            expected={"runtime_epoch": production_epoch, "digest": output.digest},
        )
        assert replay["export_id"] == result["export_id"]

        with pytest.raises(ApiError) as changed:
            client.export_managed_output(
                output.association_id,
                destination_filename=output.filename,
                idempotency_key="http-export",
                expected={"runtime_epoch": production_epoch, "size": output.size + 1},
            )
        assert changed.value.status == 409

        with pytest.raises(ApiError) as overwrite:
            client.export_managed_output(
                output.association_id,
                destination_filename=output.filename,
                idempotency_key="http-export-overwrite",
            )
        assert overwrite.value.status == 409

        with pytest.raises(ApiError) as unsafe_name:
            client.export_managed_output(
                output.association_id,
                destination_filename=f"../{output.filename}",
                idempotency_key="http-export-unsafe-name",
            )
        assert unsafe_name.value.status == 409

        events, _ = client.list_run_events(task["run"]["id"])
        exported_events = [event for event in events if event.event_type == "managed_output.exported"]
        assert len(exported_events) == 1
        assert exported_events[0].payload["export_id"] == result["export_id"]
    finally:
        daemon.stop()
