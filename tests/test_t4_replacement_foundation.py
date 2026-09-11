from __future__ import annotations

import json

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


def _fresh(root):
    RealmStore.initialize(root).close()


def test_verified_candidate_replaces_owner_with_fresh_epoch_credentials_and_quarantine(tmp_path):
    active_root = tmp_path / "active"
    support_root = tmp_path / "support"
    _fresh(active_root)
    daemon = RuntimeDaemon(active_root, support_root=support_root, production_worker_credentials=True).start()
    old_service = daemon.service
    old_epoch = old_service.health()["runtime_epoch"]
    old_token = daemon.token
    backup = tmp_path / "backup"
    candidate = tmp_path / "candidate"
    try:
        old_service.backup(backup)
        old_service.restore(backup, candidate)
        result = daemon.activate_candidate(candidate)
        assert result["state"] == "complete"
        assert result["runtime_epoch"] > old_epoch
        assert result["runtime_instance_id"] != result["superseded_root"]
        assert daemon.token != old_token
        assert daemon.service is not old_service
        assert old_service.store.conn is None
        assert active_root.is_dir()
        assert not candidate.exists()
        assert (tmp_path / result["superseded_root"].split("/")[-1]).is_dir()
        assert json.loads((support_root / "replacement-state.json").read_text())["state"] == "complete"
        catalog = daemon.catalog.read()
        row = next(item for item in catalog["realms"] if item["realm_id"] == daemon.service.realm["id"])
        assert row["data_root"] == str(active_root)
        assert row["runtime_epoch"] == result["runtime_epoch"]
        assert row["runtime_instance_id"] == result["runtime_instance_id"]
        assert row["readiness"] == "ready"
    finally:
        daemon.stop()


def test_failed_replacement_rolls_back_and_leaves_recoverable_state(tmp_path, monkeypatch):
    active_root = tmp_path / "active"
    support_root = tmp_path / "support"
    _fresh(active_root)
    daemon = RuntimeDaemon(active_root, support_root=support_root, production_worker_credentials=True).start()
    backup = tmp_path / "backup"
    candidate = tmp_path / "candidate"
    original_start = daemon._start
    failed = False

    def fail_once(*, rotate_credentials=False):
        nonlocal failed
        if rotate_credentials and not failed:
            failed = True
            raise RuntimeError("injected replacement startup interruption")
        return original_start(rotate_credentials=rotate_credentials)

    monkeypatch.setattr(daemon, "_start", fail_once)
    try:
        daemon.service.backup(backup)
        daemon.service.restore(backup, candidate)
        try:
            daemon.activate_candidate(candidate)
        except RuntimeError as exc:
            assert "interruption" in str(exc)
        else:  # pragma: no cover - the injected interruption is required
            raise AssertionError("replacement did not exercise the injected interruption")
        state = json.loads((support_root / "replacement-state.json").read_text())
        assert state["state"] == "rolled_back"
        assert active_root.is_dir()
        assert candidate.is_dir()
        assert daemon.service is not None
        assert daemon.service.health()["status"] == "ok"
        assert any(path.name.startswith(".active.superseded-") for path in tmp_path.iterdir()) is False
    finally:
        daemon.stop()
