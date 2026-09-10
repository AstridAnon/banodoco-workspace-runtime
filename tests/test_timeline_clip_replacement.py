from __future__ import annotations

import json
import shutil
import subprocess
import urllib.request

import pytest

from banodoco_workspace_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService


def _media_bytes(duration: float = 5, *, kind: str = "video") -> bytes:
    if not shutil.which("ffmpeg"):
        pytest.skip("ffmpeg is required for media replacement fixtures")
    if kind == "video":
        inputs = ["-f", "lavfi", "-i", "color=c=blue:s=16x16:r=10"]
        codec = ["-an", "-c:v", "libx264", "-pix_fmt", "yuv420p"]
    else:
        inputs = ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=8000"]
        codec = ["-vn", "-c:a", "aac"]
    result = subprocess.run(
        ["ffmpeg", "-v", "error", *inputs, "-t", str(duration), *codec,
         "-movflags", "+frag_keyframe+empty_moov", "-f", "mp4", "pipe:1"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout


def _composition(asset_id: str = "old") -> tuple[dict, dict]:
    return (
        {
            "tracks": [{"id": "visual", "kind": "visual"}],
            "clips": [
                {"id": "target", "track": "visual", "clipType": "video", "asset": asset_id, "at": 2, "from": 1, "to": 4, "effects": [{"id": "grade"}]},
                {"id": "untouched", "track": "visual", "clipType": "text", "at": 8, "text": "keep me"},
            ],
            "metadata": {"keep": True},
        },
        {"assets": {asset_id: {"media_id": "sha256:" + "0" * 64, "type": "video/mp4"}}, "metadata": {"keep": True}},
    )


def _service_fixture(tmp_path, *, clip_type: str | None = None):
    service = RuntimeService(tmp_path / "realm")
    project = service.create_project({"slug": "replace", "name": "Replace"})
    config, registry = _composition()
    if clip_type is not None:
        config["clips"][0]["clipType"] = clip_type
    service.create_timeline_document(
        project["id"],
        {"timeline_id": "main", "slug": "main", "name": "Main", "config": config, "registry": registry},
        idempotency_key="timeline-create",
    )
    source = service.ingest(project["id"], _media_bytes(), media_type="video/mp4", idempotency_key="source")
    return service, project, config, registry, source["data"]["object_id"]


def test_replace_timeline_clip_is_atomic_cas_and_exactly_replayable(tmp_path):
    service, project, before_config, before_registry, source_id = _service_fixture(tmp_path)
    try:
        body = {"clip_id": "target", "source_object_id": source_id, "expected_version": 1, "timing": "preserve-duration"}
        replaced = service.replace_timeline_clip("main", body, idempotency_key="replace")
        assert replaced["receipt"]["command_kind"] == "timeline.clip.replace"
        assert replaced["receipt"]["event_ids"]
        assert replaced["data"]["config_version"] == 2
        assert replaced["data"]["config"]["clips"][0] == {**before_config["clips"][0], "asset": source_id}
        assert replaced["data"]["config"]["clips"][1] == before_config["clips"][1]
        assert replaced["data"]["registry"]["metadata"] == before_registry["metadata"]
        assert replaced["data"]["registry"]["assets"]["old"] == before_registry["assets"]["old"]
        assert service.replace_timeline_clip("main", body, idempotency_key="replace") == replaced

        with pytest.raises(ConflictError, match="different input"):
            service.replace_timeline_clip("main", {**body, "clip_id": "untouched"}, idempotency_key="replace")
        with pytest.raises(ConflictError, match="version conflict"):
            service.replace_timeline_clip("main", {**body, "expected_version": 1}, idempotency_key="stale")

        assert service._timeline_resource("main")["config_version"] == 2
        receipt_rows = service.store.conn.execute("SELECT * FROM command_idempotency WHERE command_kind='timeline.clip.replace'").fetchall()
        event_rows = service.store.conn.execute("SELECT * FROM timeline_events WHERE timeline_id='main' AND kind='timeline.clip.replaced'").fetchall()
        assert len(receipt_rows) == len(event_rows) == 1
    finally:
        service.close()


def test_replace_timeline_clip_rejects_cross_project_source(tmp_path):
    service, _, _, _, _ = _service_fixture(tmp_path)
    try:
        other = service.create_project({"slug": "other", "name": "Other"})
        foreign = service.ingest(other["id"], _media_bytes(duration=6), media_type="video/mp4", idempotency_key="foreign")["data"]["object_id"]
        with pytest.raises(NotFoundError, match="timeline project"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": foreign, "expected_version": 1}, idempotency_key="cross-project")
        assert service._timeline_resource("main")["config_version"] == 1
    finally:
        service.close()


def test_replace_timeline_clip_rejects_malformed_source_without_mutation(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        malformed = service.ingest(project["id"], b"not a media container", media_type="video/mp4", idempotency_key="malformed")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="malformed"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": malformed["data"]["object_id"], "expected_version": 1}, idempotency_key="malformed-replace")
        assert service._timeline_resource("main") == before
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id='main'").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.clip.replace'").fetchone()[0] == 0
    finally:
        service.close()


def test_replace_timeline_clip_rejects_tampered_cas_without_mutation(tmp_path):
    service, _, _, _, source_id = _service_fixture(tmp_path)
    try:
        digest = source_id.removeprefix("sha256:")
        service.cas.path_for(digest).write_bytes(b"tampered")
        before = service._timeline_resource("main")
        with pytest.raises(ConflictError, match="immutable"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": source_id, "expected_version": 1}, idempotency_key="tampered-replace")
        assert service._timeline_resource("main") == before
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='timeline.clip.replace'").fetchone()[0] == 0
    finally:
        service.close()


def test_replace_timeline_clip_rejects_wrong_stream_without_mutation(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        audio = service.ingest(project["id"], _media_bytes(kind="audio"), media_type="audio/mp4", idempotency_key="audio")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="stream"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": audio["data"]["object_id"], "expected_version": 1}, idempotency_key="wrong-stream")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


def test_replace_timeline_clip_rejects_too_short_source_without_mutation(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        short = service.ingest(project["id"], _media_bytes(duration=1), media_type="video/mp4", idempotency_key="short")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="too short"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": short["data"]["object_id"], "expected_version": 1}, idempotency_key="too-short")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


def test_replace_timeline_clip_requires_source_to_reach_authored_end(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path)
    try:
        source = service.ingest(project["id"], _media_bytes(duration=3.5), media_type="video/mp4", idempotency_key="end-short")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="too short"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": source["data"]["object_id"], "expected_version": 1}, idempotency_key="end-short-replace")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


def test_replace_timeline_clip_generic_visual_media_requires_video_stream(tmp_path):
    service, project, _, _, _ = _service_fixture(tmp_path, clip_type="media")
    try:
        source = service.ingest(project["id"], _media_bytes(kind="audio"), media_type="audio/mp4", idempotency_key="generic-audio")
        before = service._timeline_resource("main")
        with pytest.raises(ValidationError, match="stream"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": source["data"]["object_id"], "expected_version": 1}, idempotency_key="generic-audio-replace")
        assert service._timeline_resource("main") == before
    finally:
        service.close()


def test_replace_timeline_clip_replays_after_intervening_edit_and_reopen(tmp_path):
    service, project, _, _, source_id = _service_fixture(tmp_path)
    root = tmp_path / "realm"
    body = {"clip_id": "target", "source_object_id": source_id, "expected_version": 1}
    first = service.replace_timeline_clip("main", body, idempotency_key="replay")
    current = service.get_document(project["id"], "timeline:main")
    edited = json.loads(json.dumps(current["content"]))
    edited["metadata"] = {"intervening": True}
    service.update_document(project["id"], "timeline:main", {"expected_version": current["version"], "content": edited}, idempotency_key="intervening-edit")
    service.close()
    reopened = RuntimeService(root)
    try:
        assert reopened.replace_timeline_clip("main", body, idempotency_key="replay") == first
        assert reopened._timeline_resource("main")["config_version"] == 3
        assert reopened.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE kind='timeline.clip.replaced'").fetchone()[0] == 1
    finally:
        reopened.close()


def test_replace_timeline_clip_public_http_route(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("HTTP", slug="http", idempotency_key="project")
        config, registry = _composition()
        client.create_timeline_document(project.project_id, "main", config=config, registry=registry, idempotency_key="timeline")
        source = client.ingest_project_object(project.project_id, _media_bytes(), media_type="video/mp4", idempotency_key="source")
        request = urllib.request.Request(
            f"{daemon.endpoint}/v1/timelines/main/replace-clip",
            data=json.dumps({"clip_id": "target", "source_object_id": source.object_id, "expected_version": 1}).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {daemon.token}", "Content-Type": "application/json", "Idempotency-Key": "replace"},
        )
        with urllib.request.urlopen(request) as response:
            value = json.loads(response.read())
        assert value["data"]["config"]["clips"][0]["asset"] == source.object_id
        assert value["receipt"]["command_kind"] == "timeline.clip.replace"
    finally:
        daemon.stop()
