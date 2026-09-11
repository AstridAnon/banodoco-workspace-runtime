from __future__ import annotations

from pathlib import Path

from runtime_protocol.daemon import RuntimeDaemon
import runtime_protocol.daemon as daemon_module
from runtime_protocol.store import RealmStore


def test_activation_anchors_last_rename_to_validated_parent(tmp_path: Path, monkeypatch):
    """A parent swap at the publication rename cannot redirect activation writes."""
    authority = tmp_path / "authority"
    authority.mkdir()
    active_root = authority / "active"
    RealmStore.initialize(active_root).close()
    daemon = RuntimeDaemon(active_root, support_root=tmp_path / "support", production_worker_credentials=True).start()
    backup = tmp_path / "backup"
    daemon.service.backup(backup)
    candidate = authority / "candidate"
    daemon.service.restore(backup, candidate)
    outside = tmp_path / "outside"
    outside.mkdir()
    original_rename = daemon_module.os.rename
    swapped = False

    def hostile_rename(source, destination, **kwargs):
        nonlocal swapped
        if destination == "active" and source == "candidate" and not swapped:
            swapped = True
            real_parent = tmp_path / "authority-real"
            authority.rename(real_parent)
            authority.symlink_to(outside, target_is_directory=True)
            try:
                return original_rename(source, destination, **kwargs)
            finally:
                authority.unlink()
                real_parent.rename(authority)
        return original_rename(source, destination, **kwargs)

    monkeypatch.setattr(daemon_module.os, "rename", hostile_rename)
    try:
        result = daemon.activate_candidate(candidate)
        assert swapped
        assert result["state"] == "complete"
        assert daemon.service.health()["status"] == "ok"
        assert not any(outside.iterdir())
        assert active_root.is_dir()
    finally:
        daemon.stop()
