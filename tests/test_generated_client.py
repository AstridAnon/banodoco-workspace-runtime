from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import ApiError, ClaimWaiting, WorkspaceClient


def test_generated_client_smoke_and_scoped_handshake() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        if path == "/v1/health":
            return 200, {}, json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1}).encode()
        if path == "/v1/handshake":
            return 200, {}, json.dumps({"protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "session_id": "session-1", "actor_id": "actor-1", "realm_id": "realm-1", "scopes": ["realm:read", "project:write"]}).encode()
        if path == "/v1/projects" and method == "POST":
            return 201, {}, json.dumps({"data": {"project_id": "project-1", "realm_id": "realm-1", "name": "Neutral", "version": 1, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}, "receipt": {"receipt_id": "runtime-command-1", "command_kind": "project.create", "idempotency_key": "create-1", "request_hash": "sha256:" + "a" * 64, "project_id": "project-1", "project_seq": [1, 1], "event_ids": [], "result": {}, "created_at": "2026-01-01T00:00:00Z"}}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    assert client.health()["protocol"] == "workspace.v1"
    session = client.handshake("second-product", "0.1.0", ["realm:read", "project:write"])
    assert session.realm_id == "realm-1"
    project = client.create_project("Neutral", idempotency_key="create-1")
    assert project.project_id == "project-1"
    assert project.receipt["command_kind"] == "project.create"
    assert calls[-1][2]["Authorization"] == "Bearer token"
    assert calls[-1][2]["Idempotency-Key"] == "create-1"


def test_object_byte_range_etag_and_head_are_preserved() -> None:
    payload = b"0123456789"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers))
        assert headers["Range"] == "bytes=2-5"
        result = {"ETag": f'"{digest}"', "Content-Range": "bytes 2-5/10", "Accept-Ranges": "bytes"}
        return 206, result, payload[2:6] if method == "GET" else b""

    client = WorkspaceClient("http://runtime", transport=transport)
    result = client.get_object("obj-1", byte_range=(2, 5))
    assert result.status == 206 and result.data == b"2345"
    assert result.etag == f'"{digest}"' and result.content_range == "bytes 2-5/10"
    head = client.head_object("obj-1", byte_range=(2, 5))
    assert head.status == 206 and calls[-1][0] == "HEAD"


def test_invalid_range_is_rejected_before_transport() -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (_ for _ in ()).throw(AssertionError("called")))
    try:
        client.get_object("obj", byte_range=(5, 2))
    except ValueError as exc:
        assert "range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_generated_run_events_preserve_event_page_contract() -> None:
    event = {
        "event_id": "1", "sequence": 1, "cursor": "1",
        "event_type": "task.admitted", "aggregate_type": "run",
        "aggregate_id": "run-1", "payload": {},
        "occurred_at": "2026-01-01T00:00:00Z",
    }

    def transport(method, path, headers, body):
        assert method == "GET" and path == "/v1/runs/run-1/events"
        return 200, {}, json.dumps({"items": [event], "next_cursor": None}).encode()

    items, cursor = WorkspaceClient("http://runtime", transport=transport).list_run_events("run-1")
    assert items[0].event_id == "1"
    assert cursor is None


def test_api_error_preserves_conflict_and_version_details() -> None:
    def transport(*args):
        return 409, {}, json.dumps({"code": "version_conflict", "message": "stale", "request_id": "req-1", "details": {"expected": 2, "actual": 3}}).encode()

    try:
        WorkspaceClient("http://runtime", transport=transport).get_project("p")
    except ApiError as exc:
        assert exc.status == 409 and exc.code == "version_conflict" and exc.details["actual"] == 3
    else:
        raise AssertionError("expected ApiError")


def test_client_correlates_transport_timeout_and_http_failure() -> None:
    observed_request_ids = []

    def timed_out(_method, _path, headers, _body):
        observed_request_ids.append(headers["X-Request-ID"])
        raise TimeoutError("late")

    with pytest.raises(ApiError) as timeout_error:
        WorkspaceClient("http://runtime", transport=timed_out, timeout=0.25).health()
    assert timeout_error.value.code == "transport_timeout"
    assert timeout_error.value.request_id == observed_request_ids[0]

    def rejected(_method, _path, headers, _body):
        observed_request_ids.append(headers["X-Request-ID"])
        return 503, {}, json.dumps({"code": "registration_failed", "message": "terminal"}).encode()

    with pytest.raises(ApiError) as rejected_error:
        WorkspaceClient("http://runtime", transport=rejected).health()
    assert rejected_error.value.code == "registration_failed"
    assert rejected_error.value.request_id == observed_request_ids[1]


def test_client_applies_bounded_timeout_to_stdlib_transport(monkeypatch) -> None:
    observed = {}

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1}).encode()

    def urlopen(request, *, timeout):
        observed["timeout"] = timeout
        observed["request_id"] = request.headers["X-request-id"]
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    client = WorkspaceClient("http://runtime", timeout=1.5)
    assert client.health().status == "ok"
    assert observed["timeout"] == 1.5
    assert observed["request_id"].startswith("request-")
    with pytest.raises(ValueError, match="finite and positive"):
        WorkspaceClient("http://runtime", timeout=0)


def test_claim_capability_unavailable_is_typed_waiting_result() -> None:
    digest = "sha256:" + "a" * 64
    task = {
        "task_id": "task-1", "run_id": "run-1", "state": "queued", "version": 1,
        "capability_id": "render.gpu", "capability_digest": digest,
        "idempotency_key": "admit-1", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "runtime_epoch": 1,
        "waiting_reason": "capability_unavailable",
    }

    def transport(method, path, headers, body):
        assert method == "POST" and path == "/v1/tasks/claim"
        return 200, {}, json.dumps({"task": task, "waiting_reason": "capability_unavailable"}).encode()

    result = WorkspaceClient("http://runtime", transport=transport).claim_task(
        executor_id="worker-1", capability_ids=["render.gpu"],
        idempotency_key="claim-1", runtime_epoch=1,
    )
    assert isinstance(result, ClaimWaiting)
    assert result.waiting_reason == "capability_unavailable"
    assert result.task.task_id == "task-1"


def test_generator_is_reproducible() -> None:
    root = Path(__file__).parents[1]
    subprocess.run([sys.executable, str(root / "generators" / "generate.py")], check=True, cwd=root)
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--check"], check=True, cwd=root)


def test_python_client_source_is_tracked_and_generated_check_is_not_self_referential(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    component = json.loads((root / "contract" / "component-manifest.json").read_text())
    python_component = next(item for item in component["clients"] if item["generator"] == "GENERATOR-PYTHON-INREPO")
    template = root / "generators" / "python_client_template.py"
    output = root / "packages" / "python" / "banodoco_workspace_client" / "generated.py"
    assert (root / python_component["source"]).is_file()
    assert (root / python_component["output"]).resolve() == output.resolve()
    assert template.is_file()
    assert "__SCHEMA_DIGEST__" in template.read_text()
    original = output.read_bytes()
    isolated = tmp_path / "generated.py"
    isolated.write_bytes(original + b"\n# mutation\n")
    check = subprocess.run(
        [sys.executable, str(root / "generators" / "generate.py"), "--check", "--python-output", str(isolated)],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert check.returncode != 0
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--python-output", str(isolated)], check=True, cwd=root)
    assert isolated.read_bytes() == output.read_bytes() == original
