import json
import threading

import pytest

import runtime_protocol.backup as backup_module
import runtime_protocol.store as store_module
from runtime_protocol.backup import verify_backup
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, LeaseError, OwnerBusyError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def test_fresh_creation_invalid_identity_leaves_no_final_or_staged_root(tmp_path):
    root = tmp_path / "realm"
    with pytest.raises(ValidationError):
        RealmStore.initialize(root, display_name="   ")
    assert not root.exists()
    assert not list(tmp_path.glob(".realm.create-*"))


def test_fresh_creation_interruption_leaves_no_partial_final_root(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    original_open = RealmStore._open

    def interrupt(store, *, fresh=False):
        if fresh:
            raise RuntimeError("injected creation interruption")
        return original_open(store, fresh=fresh)

    monkeypatch.setattr(RealmStore, "_open", interrupt)
    with pytest.raises(RuntimeError, match="creation interruption"):
        RealmStore.initialize(root)
    assert not root.exists()
    assert not list(tmp_path.glob(".realm.create-*"))


def test_fresh_creation_post_rename_fsync_rolls_back_and_is_retryable(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    original_fsync = store_module.os.fsync
    injected = False

    def interrupt_after_publication(fd):
        nonlocal injected
        if root.exists() and not injected:
            injected = True
            raise OSError("injected parent fsync interruption")
        return original_fsync(fd)

    monkeypatch.setattr(store_module.os, "fsync", interrupt_after_publication)
    with pytest.raises(OSError, match="parent fsync interruption"):
        RealmStore.initialize(root)
    assert injected
    assert not root.exists()
    assert not list(tmp_path.glob(".realm.create-*"))

    monkeypatch.setattr(store_module.os, "fsync", original_fsync)
    retry = RealmStore.initialize(root, realm_id="retry-realm", display_name="Retry Realm")
    try:
        assert retry.realm["id"] == "retry-realm"
        assert retry.realm["display_name"] == "Retry Realm"
    finally:
        retry.close()


def test_fresh_creation_keeps_owner_custody_through_publication(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    original_fsync = store_module.os.fsync
    interposed = threading.Event()
    outcome = []

    def interpose_competing_opener(fd):
        if root.exists() and not interposed.is_set():
            interposed.set()
            try:
                RealmStore(root)
            except Exception as exc:
                outcome.append((type(exc), str(exc)))
            else:  # pragma: no cover - the owner lock must remain held
                outcome.append((None, "other_owner_acquired"))
        return original_fsync(fd)

    monkeypatch.setattr(store_module.os, "fsync", interpose_competing_opener)
    creator = RealmStore.initialize(root, realm_id="custody-realm", display_name="Custody Realm")
    try:
        assert interposed.is_set()
        assert outcome == [(OwnerBusyError, "another runtime daemon owns this realm")]
        project = creator.create_project("owner-write", "Owner Write", idempotency_key="owner-write")
        assert creator.get_project(project["id"])["name"] == "Owner Write"
    finally:
        creator.close()


def test_direct_generation_publication_remains_refused(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        refusal = "direct generation publication is disabled"
        with pytest.raises(ConflictError, match=refusal):
            service.create_generation("project", {})
        with pytest.raises(ConflictError, match="direct variant publication is disabled"):
            service.create_variant("generation", {})
    finally:
        service.close()


def test_backup_candidate_is_verified_before_publication(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        def reject_candidate(*args, **kwargs):
            raise ConflictError("injected private verifier failure")

        monkeypatch.setattr(backup_module, "_inspect_consolidated_realm", reject_candidate)
        destination = tmp_path / "backup"
        with pytest.raises(ConflictError, match="private verifier"):
            service.backup(destination)
        assert not destination.exists()
        assert not list(tmp_path.glob(".backup.*"))
    finally:
        service.close()


def test_replacement_epoch_floor_survives_restarts_and_fences_stale_worker(tmp_path):
    active = tmp_path / "active"
    support = tmp_path / "support"
    RealmStore.initialize(active).close()
    daemon = RuntimeDaemon(active, support_root=support, production_worker_credentials=True).start()
    old_epoch = daemon.service.health()["runtime_epoch"]
    backup = tmp_path / "old-backup"
    try:
        daemon.service.backup(backup)
        daemon.stop()
        daemon.start()
        daemon.stop()
        daemon.start()
        live_epoch = daemon.service.health()["runtime_epoch"]
        assert live_epoch > old_epoch
        candidate = tmp_path / "candidate"
        daemon.service.restore(backup, candidate)
        result = daemon.activate_candidate(candidate)
        assert result["runtime_epoch"] > live_epoch
        with pytest.raises(LeaseError, match="stale runtime epoch"):
            daemon.service.register_executor(
                {"executor_id": "stale-worker", "capabilities": [], "runtime_epoch": old_epoch},
                idempotency_key="stale-worker",
            )
        floor = json.loads((support / "runtime-epoch-floor.json").read_text())
        assert floor["runtime_epoch_floor"] == result["runtime_epoch"]
    finally:
        daemon.stop()


def test_older_snapshot_offline_replacement_preserves_external_support_custody(tmp_path):
    active = tmp_path / "active"
    support = tmp_path / "support"
    RealmStore.initialize(active).close()
    daemon = RuntimeDaemon(active, support_root=support, production_worker_credentials=True).start()
    backup = tmp_path / "older-backup"
    try:
        daemon.service.backup(backup)
        backup_key = (support / "backup-auth.key").read_bytes()
        old_epoch = daemon.service.health()["runtime_epoch"]
        daemon.stop()
        daemon.start()
        daemon.stop()
        daemon.start()
        live_epoch = daemon.service.health()["runtime_epoch"]
        assert live_epoch > old_epoch
        daemon.stop()

        result = daemon.replace_from_backup(backup)
        assert result["offline"] is True
        assert result["runtime_epoch"] > live_epoch
        assert (support / "backup-auth.key").read_bytes() == backup_key
        assert (support / "credentials" / "owner.token").is_file()
        floor = json.loads((support / "runtime-epoch-floor.json").read_text())
        assert floor["runtime_epoch_floor"] == result["runtime_epoch"]
        catalog = json.loads((support / "catalog.json").read_text())
        row = next(item for item in catalog["realms"] if item["realm_id"] == result["realm_id"])
        assert row["data_root"] == str(active)
        assert row["runtime_epoch"] == result["runtime_epoch"]
        assert row["readiness"] == "ready"
    finally:
        daemon.stop()


def test_offline_replacement_verifies_backup_without_admitting_damaged_root(tmp_path):
    source = tmp_path / "source"
    RealmStore.initialize(source).close()
    source_service = RuntimeService(source)
    backup = tmp_path / "backup"
    try:
        source_service.backup(backup)
    finally:
        source_service.close()

    damaged = tmp_path / "damaged"
    RealmStore.initialize(damaged).close()
    (damaged / "realm.sqlite3").write_bytes(b"damaged-active-root")
    daemon = RuntimeDaemon(damaged, support_root=tmp_path / "support", production_worker_credentials=True)
    result = daemon.replace_from_backup(backup)
    try:
        assert result["offline"] is True
        assert daemon.service.health()["status"] == "ok"
        superseded = tmp_path / result["superseded_root"].split("/")[-1]
        assert (superseded / "realm.sqlite3").read_bytes() == b"damaged-active-root"
        state = json.loads((tmp_path / "support" / "replacement-state.json").read_text())
        assert state["state"] == "complete"
    finally:
        daemon.stop()


def test_backup_manifest_has_no_transitional_metadata_aliases(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        backup = tmp_path / "backup"
        result = service.backup(backup)
        manifest = result["manifest"]
        assert set(manifest).isdisjoint({"schema_version", "realm_id", "display_name"})
        assert verify_backup(backup)["manifest"]["realm"]["id"] == service.realm["id"]
    finally:
        service.close()
