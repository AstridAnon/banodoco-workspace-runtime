from __future__ import annotations

from pathlib import Path
import threading

import pytest

import runtime_protocol.backup as backup_module
from runtime_protocol.dirfd import atomic_json_write
from runtime_protocol.dirfd import capture_parent, close_pinned
from runtime_protocol.catalog import RealmCatalog
from runtime_protocol.service import RuntimeService
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import RealmStore


def _service(root, **kwargs):
    RealmStore.initialize(root).close()
    return RuntimeService(root, **kwargs)


def _swap_on_final_rename(monkeypatch, module, parent: Path, outside: Path, target_name: str, *, mode: str):
    original = module.os.rename
    swapped = False
    real_parent = parent.with_name(parent.name + "-real")

    def hostile(source, destination, **kwargs):
        nonlocal swapped
        if destination == target_name and str(source).startswith(f".{target_name}.") and not swapped:
            swapped = True
            parent.rename(real_parent)
            if mode == "symlink":
                parent.symlink_to(outside, target_is_directory=True)
            else:
                parent.mkdir()
        return original(source, destination, **kwargs)

    monkeypatch.setattr(module.os, "rename", hostile)
    return lambda: (swapped, real_parent)


@pytest.mark.parametrize("mode", ["symlink", "replacement"])
def test_runtime_backup_last_rename_is_parent_pinned(tmp_path, monkeypatch, mode):
    active = _service(tmp_path / "active")
    parent = tmp_path / "backup-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    state = _swap_on_final_rename(monkeypatch, backup_module, parent, outside, "backup", mode=mode)
    try:
        with pytest.raises(ConflictError, match="identity|symlink|parent"):
            active.backup(parent / "backup")
        swapped, real_parent = state()
        assert swapped and (real_parent / "backup").is_dir()
        assert not any(outside.iterdir())
        assert active.health()["status"] == "ok"
    finally:
        active.close()


@pytest.mark.parametrize("mode", ["symlink", "replacement"])
def test_runtime_restore_last_rename_is_parent_pinned(tmp_path, monkeypatch, mode):
    active = _service(tmp_path / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    parent = tmp_path / "restore-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    state = _swap_on_final_rename(monkeypatch, backup_module, parent, outside, "candidate", mode=mode)
    try:
        with pytest.raises(ConflictError, match="identity|symlink|parent"):
            active.restore(backup, parent / "candidate")
        swapped, real_parent = state()
        assert swapped and (real_parent / "candidate").is_dir()
        assert not any(outside.iterdir())
        assert active.health()["status"] == "ok"
    finally:
        active.close()


def test_atomic_publication_survives_concurrent_parent_swap_loop(tmp_path):
    """Repeated swaps may reject a write, but never redirect bytes outside the pin."""
    parent = tmp_path / "evidence-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    real_parent = tmp_path / "evidence-parent-real"
    stop = threading.Event()

    def swap_loop():
        def restore(index, suffix):
            try:
                real_parent.rename(parent)
            except OSError:
                # A writer can create the lexical name after the symlink is
                # removed but before the original inode is restored.
                race_parent = tmp_path / f"evidence-parent-race-{index}-{suffix}"
                parent.rename(race_parent)
                real_parent.rename(parent)

        for index in range(40):
            if stop.is_set():
                return
            if parent.is_symlink():
                parent.unlink()
                restore(index, "restore")
            else:
                parent.rename(real_parent)
                try:
                    parent.symlink_to(outside, target_is_directory=True)
                    parent.unlink()
                except FileExistsError:
                    # A writer may intentionally recreate a missing parent in
                    # this tiny window. Keep those bytes in an isolated race
                    # directory and restore the original parent inode.
                    race_parent = tmp_path / f"evidence-parent-race-{index}"
                    parent.rename(race_parent)
                restore(index, "normal")

    worker = threading.Thread(target=swap_loop)
    worker.start()
    try:
        for index in range(40):
            try:
                atomic_json_write(parent / f"receipt-{index}.json", b"{}\n")
            except (ConflictError, OSError):
                pass
    finally:
        stop.set()
        worker.join(timeout=5)
        if parent.is_symlink():
            parent.unlink()
            real_parent.rename(parent)
    assert not any(outside.iterdir())
    assert all(path.is_file() for path in parent.iterdir())


def test_backup_verification_read_is_pinned_against_parent_replacement(tmp_path):
    active = _service(tmp_path / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    identity = capture_parent(backup)
    parent = backup.parent
    replacement = parent.with_name(parent.name + "-replacement")
    try:
        parent.rename(replacement)
        parent.mkdir()
        with pytest.raises(ConflictError, match="identity|parent|symlink"):
            backup_module.verify_backup(backup, directory_identity=identity)
        assert active.health()["status"] == "ok"
    finally:
        close_pinned(identity)
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
        if replacement.exists():
            replacement.rename(parent)
        active.close()


def test_backup_manifest_file_replacement_at_read_syscall_fails_closed(tmp_path, monkeypatch):
    active = _service(tmp_path / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    original_open = backup_module.os.open
    replaced = False

    def hostile(name, flags, *args, **kwargs):
        nonlocal replaced
        if name == "manifest.json" and not replaced:
            replaced = True
            (backup / "manifest.json").write_text("{}", encoding="utf-8")
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(backup_module.os, "open", hostile)
    try:
        with pytest.raises(ConflictError):
            backup_module.verify_backup(backup)
        assert replaced and active.health()["status"] == "ok"
    finally:
        active.close()


def test_catalog_read_rejects_ordinary_parent_replacement(tmp_path):
    parent = tmp_path / "support"
    parent.mkdir()
    catalog_path = parent / "catalog.json"
    catalog = RealmCatalog(catalog_path)
    catalog.register(realm_id="realm-1", display_name="Realm", data_root=str(tmp_path / "realm"))
    replacement = parent.with_name(parent.name + "-replacement")
    parent.rename(replacement)
    parent.mkdir()
    try:
        with pytest.raises(ConflictError, match="identity|parent|symlink"):
            catalog.read()
    finally:
        parent.rmdir()
        replacement.rename(parent)
