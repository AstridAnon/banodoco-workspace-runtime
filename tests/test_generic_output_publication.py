from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _new_service(root: Path) -> RuntimeService:
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def _filmstrip_attempt(service: RuntimeService, project_id: str):
    definition = _digest(b"rendering.timeline_visualize-v1")
    service.register_capability(
        {"capability_id": "rendering.timeline_visualize", "definition_digest": definition}
    )
    service.register_executor(
        {"executor_id": "filmstrip-worker", "capabilities": ["rendering.timeline_visualize"]},
        idempotency_key="filmstrip-worker-register",
    )
    task = service.create_task(
        {
            "capability_id": "rendering.timeline_visualize",
            "capability_digest": definition,
            "project": project_id,
            "idempotency_key": f"filmstrip-task-{project_id}",
        }
    )
    return task, service.claim_next(
        {
            "executor_id": "filmstrip-worker",
            "capability_ids": ["rendering.timeline_visualize"],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=f"filmstrip-claim-{project_id}",
    )


def _descriptor(payload: bytes, *, name: str, filename: str, output_port: str, primary: bool, media_type: str):
    digest = _digest(payload)
    return {
        "name": name,
        "kind": "object",
        "filename": filename,
        "output_port": output_port,
        "digest": digest,
        "media_type": media_type,
        "size": len(payload),
        "role": "result" if primary else "auxiliary",
        "is_primary": primary,
        "durability": "durable" if primary else "temporary",
        "producer": {"capability_id": "rendering.timeline_visualize", "view": "filmstrip"},
        "provenance": {
            "render_run_id": "render-run-1",
            "timeline_id": "main",
            "video_digest": _digest(b"source-video"),
        },
    }


def _zip_payload() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps({"kind": "timeline_filmstrip"}))
        archive.writestr("filmstrip.html", "<html>filmstrip</html>")
    return stream.getvalue()


def _settle_body(attempt: dict, outputs: list[dict]) -> dict:
    return {
        "lease_id": attempt["lease_id"],
        "fence": attempt["fence"],
        "runtime_epoch": attempt["runtime_epoch"],
        "outputs": outputs,
    }


def test_generic_filmstrip_outputs_are_associated_by_fenced_settlement(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "filmstrip", "name": "Filmstrip"})
        _task, attempt = _filmstrip_attempt(service, project["id"])
        manifest = b'{"kind":"timeline_filmstrip_result"}'
        bundle = _zip_payload()
        outputs = [
            _descriptor(
                manifest,
                name="filmstrip_manifest",
                filename="filmstrip-manifest.json",
                output_port="filmstrip_manifest",
                primary=False,
                media_type="application/json",
            ),
            _descriptor(
                bundle,
                name="filmstrip_bundle",
                filename="filmstrip-bundle.zip",
                output_port="filmstrip_bundle",
                primary=True,
                media_type="application/zip",
            ),
        ]
        for payload, media_type in ((manifest, "application/json"), (bundle, "application/zip")):
            service.ingest_object(
                payload,
                media_type=media_type,
                idempotency_key="output-" + hashlib.sha256(payload).hexdigest(),
            )

        service.settle_attempt(
            attempt["attempt_id"],
            _settle_body(attempt, outputs),
            idempotency_key="filmstrip-settle",
        )

        assert service.task(_task["task"]["id"])["task"]["status"] == "completed"
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM project_objects WHERE project_id=?", (project["id"],)
        ).fetchone()[0] == 2
    finally:
        service.close()


def test_settlement_rejects_foreign_and_unrecognized_ownerless_objects(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        target = service.create_project({"slug": "target", "name": "Target"})
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"})

        foreign_payload = b"foreign-filmstrip-bundle"
        foreign_object = service.ingest(
            foreign["id"],
            foreign_payload,
            media_type="application/zip",
            idempotency_key="foreign-ingest",
        )["data"]
        # Even an output-shaped unscoped receipt cannot adopt an object that
        # is already owned by another project.
        service.ingest_object(
            foreign_payload,
            media_type="application/zip",
            idempotency_key="output-" + hashlib.sha256(foreign_payload).hexdigest(),
        )
        _task, attempt = _filmstrip_attempt(service, target["id"])
        foreign_output = _descriptor(
            foreign_payload,
            name="filmstrip_bundle",
            filename="filmstrip-bundle.zip",
            output_port="filmstrip_bundle",
            primary=True,
            media_type="application/zip",
        )
        assert foreign_output["digest"] == foreign_object["digest"]
        with pytest.raises(ConflictError, match="outside the task project"):
            service.settle_attempt(
                attempt["attempt_id"],
                _settle_body(attempt, [foreign_output]),
                idempotency_key="foreign-filmstrip-settle",
            )
        assert service.store.conn.execute(
            "SELECT 1 FROM project_objects WHERE project_id=? AND digest=?",
            (target["id"], foreign_object["digest"].removeprefix("sha256:")),
        ).fetchone() is None

        ownerless_payload = b"ownerless-cas-object"
        ownerless_object = service.ingest_object(
            ownerless_payload,
            media_type="application/zip",
            idempotency_key="not-an-output-upload",
        )["data"]
        ownerless_output = _descriptor(
            ownerless_payload,
            name="filmstrip_bundle",
            filename="filmstrip-bundle.zip",
            output_port="filmstrip_bundle",
            primary=True,
            media_type="application/zip",
        )
        assert ownerless_output["digest"] == ownerless_object["digest"]
        with pytest.raises(ConflictError, match="outside the task project"):
            service.settle_attempt(
                attempt["attempt_id"],
                _settle_body(attempt, [ownerless_output]),
                idempotency_key="unrecognized-filmstrip-settle",
            )
    finally:
        service.close()
