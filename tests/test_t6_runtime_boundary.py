from __future__ import annotations

import json
import urllib.request

from runtime_protocol import cli
from runtime_protocol.store import RealmStore
from runtime_protocol.daemon import RuntimeDaemon


def test_cli_explicit_create_provisions_only_the_canonical_root(tmp_path, capsys):
    root = tmp_path / "realm"
    assert cli.main(["create", "--root", str(root), "--realm-id", "cli-realm"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {"root": str(root.resolve()), "realm_id": "cli-realm", "state": "created"}
    store = RealmStore(root)
    try:
        assert store.realm["id"] == "cli-realm"
    finally:
        store.close()


def test_cli_exposes_verified_replace_and_server_route():
    parsed = cli._parser().parse_args(["replace", "--root", "/tmp/runtime", "--backup", "/tmp/backup"])
    assert parsed.command == "replace"
    assert parsed.backup == "/tmp/backup"


def test_server_replace_route_uses_the_daemon_boundary(tmp_path):
    authority = tmp_path / "authority"
    authority.mkdir()
    active = authority / "active"
    RealmStore.initialize(active).close()
    daemon = RuntimeDaemon(active, support_root=tmp_path / "support", production_worker_credentials=True).start()
    backup = tmp_path / "backup"
    candidate = authority / "candidate"
    try:
        daemon.service.backup(backup)
        daemon.service.restore(backup, candidate)
        request = urllib.request.Request(
            daemon.endpoint + "/v1/replace",
            data=json.dumps({"candidate": str(candidate)}).encode(),
            headers={"Authorization": "Bearer " + daemon.token, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read())
        assert result["state"] == "complete"
    finally:
        daemon.stop()
