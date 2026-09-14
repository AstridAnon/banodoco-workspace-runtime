from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from banodoco_workspace_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


def _request(endpoint: str, token: str, method: str, object_id: str, range_header: str):
    request = urllib.request.Request(
        f"{endpoint}/v1/objects/{object_id}",
        method=method,
        headers={"Authorization": f"Bearer {token}", "Range": range_header},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


@pytest.fixture()
def ranged_object(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Ranges", idempotency_key="range-project", slug="ranges")
        obj = client.ingest_project_object(
            project.project_id,
            b"0123456789",
            media_type="application/octet-stream",
            idempotency_key="range-object",
            filename="range.bin",
        )
        yield daemon, obj.object_id
    finally:
        daemon.stop()


def test_suffix_oversized_and_explicit_ranges_preserve_get_head_identity(ranged_object) -> None:
    daemon, object_id = ranged_object
    status, headers, body = _request(daemon.endpoint, daemon.token, "GET", object_id, "bytes=-3")
    assert status == 206 and body == b"789"
    assert headers["Content-Range"] == "bytes 7-9/10"
    assert headers["Accept-Ranges"] == "bytes"
    etag = headers["ETag"]

    status, headers, body = _request(daemon.endpoint, daemon.token, "HEAD", object_id, "bytes=-3")
    assert status == 206 and body == b""
    assert headers["Content-Length"] == "3"
    assert headers["Content-Range"] == "bytes 7-9/10"
    assert headers["ETag"] == etag

    status, headers, body = _request(daemon.endpoint, daemon.token, "GET", object_id, "bytes=-99")
    assert status == 206 and body == b"0123456789"
    assert headers["Content-Range"] == "bytes 0-9/10"
    assert headers["Content-Length"] == "10"

    status, headers, body = _request(daemon.endpoint, daemon.token, "GET", object_id, "bytes=7-")
    assert status == 206 and body == b"789"
    assert headers["Content-Range"] == "bytes 7-9/10"

    status, headers, body = _request(daemon.endpoint, daemon.token, "GET", object_id, "bytes=2-5")
    assert status == 206 and body == b"2345"
    assert headers["Content-Range"] == "bytes 2-5/10"


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("range_header", ["bytes=-0", "bytes=-", "bytes=99-", "bytes=0-1,4-5", "items=0-1", "bytes=999999999999-"])
def test_zero_and_malformed_ranges_are_unsatisfiable(ranged_object, method: str, range_header: str) -> None:
    daemon, object_id = ranged_object
    status, headers, _body = _request(daemon.endpoint, daemon.token, method, object_id, range_header)
    assert status == 416
    assert headers["Content-Range"] == "bytes */10"
