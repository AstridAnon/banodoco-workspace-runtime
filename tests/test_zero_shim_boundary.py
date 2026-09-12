"""Adversarial checks for the installed neutral runtime boundary."""

import inspect
import sys
from pathlib import Path

import pytest

from banodoco_local import cli
from banodoco_local.bootstrap import SourceProfile
from banodoco_local.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.backup import verify_backup


def test_cli_accepts_only_canonical_spellings():
    parse = cli.parser().parse_args
    parse(["backup", "--destination", "backup"])
    parse(["prepare-reboot", "--attempt-id", "a", "--lease-id", "l", "--fence", "1", "--runtime-epoch", "1"])
    parse(["recovery", "--expected-realm-id", "realm", "--expected-version", "1", "--non-interactive"])
    for argv in (
        ["backup", "--out", "backup"],
        ["prepare"],
        ["recover"],
        ["recovery", "--realm-id", "realm", "--expected-version", "1", "--non-interactive"],
        ["migrate", "--source", "source", "--archive", "archive", "--destination", "destination"],
        ["rehearse", "--source", "source", "--archive", "archive", "--destination", "destination"],
        ["migrate", "--source-root", "source", "--archive-root", "archive", "--destination-root", "destination"],
    ):
        with pytest.raises(SystemExit):
            parse(argv)


def test_backup_verifier_has_no_live_legacy_switch():
    assert "allow_legacy" not in inspect.signature(verify_backup).parameters


def test_http_surface_has_no_removed_route_aliases():
    source = Path(__file__).parents[1].joinpath("runtime_protocol", "server.py").read_text()
    for removed in (
        'path in (["health"]',
        'path in (["v1", "workers"]',
        'path in (["v1", "recovery", "reboot"], ["v1", "runtime", "reboot"]',
        'path in (["v1", "recovery", "resume"], ["v1", "runtime", "resume"]',
    ):
        assert removed not in source
    assert "self.runtime.claim(task_id" not in source
    assert "self.runtime.heartbeat(task_id" not in source


def test_connect_uses_installed_client_without_mutating_import_path(monkeypatch):
    class FakeClient:
        def __init__(self, endpoint, credential):
            self.endpoint = endpoint
            self.credential = credential

    monkeypatch.setitem(sys.modules, "banodoco_workspace_client", type("M", (), {"WorkspaceClient": FakeClient}))
    boundary = LocalRuntimeBoundary()
    boundary.configure_source(
        SourceProfile(
            profile="astrid",
            runtime_checkout="/checkout-that-must-not-be-consulted",
            source_checkout="/source-provenance-only",
            runtime_command=(),
            runtime_environment="",
            protocol_version="workspace.v1",
            schema_version="workspace-schema-v1",
            capability_digest="digest",
        )
    )
    before = list(sys.path)
    connection = boundary.connect(endpoint="http://127.0.0.1:1", credential="token")
    assert list(sys.path) == before
    assert connection._client.endpoint == "http://127.0.0.1:1"


def test_start_does_not_inject_checkout_into_child(monkeypatch, tmp_path):
    captured = {}

    class FakeProcess:
        pid = 123

        def poll(self):
            return None

    def fake_popen(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return FakeProcess()

    boundary = LocalRuntimeBoundary()
    monkeypatch.setattr("banodoco_local.runtime_boundary.subprocess.Popen", fake_popen)
    monkeypatch.setattr(boundary, "_wait_endpoint", lambda _support, _process: "http://127.0.0.1:1")
    monkeypatch.setattr(boundary, "_read_discovery", lambda _support: {"process_birth_id": "birth"})
    source_checkout = tmp_path / "product-source"
    source_checkout.mkdir()
    profile = SourceProfile(
        profile="astrid",
        runtime_checkout=str(tmp_path / "runtime-checkout-that-must-not-be-used"),
        source_checkout=str(source_checkout),
        runtime_command=(sys.executable, "-c", "pass"),
        runtime_environment="",
        protocol_version="workspace.v1",
        schema_version="workspace-schema-v1",
        capability_digest="digest",
    )
    owner_lock = tmp_path / "support" / "owner.lock"
    boundary.start(realm_id="realm", realm_root=tmp_path / "realm", owner_lock=owner_lock, source_profile=profile)
    assert "cwd" not in captured["kwargs"]
    assert "env" not in captured["kwargs"]
    assert "PYTHONPATH" not in captured["kwargs"]
