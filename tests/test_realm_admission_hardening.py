from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from runtime_protocol.backup import verify_restore_candidate
from runtime_protocol.cli import main as runtime_main
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, RealmAdmissionError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _tree_bytes(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def test_corrupt_startup_fails_before_credentials_catalog_discovery_or_server(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    root.mkdir()
    database = root / "realm.sqlite3"
    database.write_bytes(b"not a sqlite database")

    daemon = RuntimeDaemon(root, support_root=support)
    assert not support.exists()
    with pytest.raises(RealmAdmissionError) as error:
        daemon.start()

    assert error.value.code == "realm_admission_failed"
    assert error.value.details["state"] == "unhealthy"
    assert error.value.details["checks"]["sqlite_integrity"]["ok"] is False
    assert database.read_bytes() == b"not a sqlite database"
    assert not Path(str(database) + "-wal").exists()
    assert not Path(str(database) + "-shm").exists()
    assert daemon.httpd is None
    assert not (support / "credentials").exists()
    assert not (support / "catalog.json").exists()
    assert not (support / "discovery.json").exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sidecar_without_main_database_fails_closed_without_discarding_it(tmp_path, suffix):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    root.mkdir()
    sidecar = root / f"realm.sqlite3{suffix}"
    sidecar.write_bytes(b"orphaned committed-state fixture")
    before = sidecar.read_bytes()

    report = RealmStore.inspect_realm(root)
    assert report["state"] == "unhealthy"
    assert report["checks"]["sqlite_integrity"]["reason"] == "unreadable"
    with pytest.raises(RealmAdmissionError):
        RuntimeDaemon(root, support_root=support).start()

    assert not (root / "realm.sqlite3").exists()
    assert sidecar.read_bytes() == before
    assert not support.exists()


def test_malformed_doctor_is_structured_bounded_and_non_mutating(tmp_path, capsys):
    root = tmp_path / "realm"
    root.mkdir()
    (root / "realm.sqlite3").write_bytes(b"malformed")
    before = _tree_bytes(root)

    report = RealmStore.inspect_realm(root)
    assert report["state"] == "unhealthy"
    assert report["checks"]["sqlite_integrity"]["reason"] in {"malformed", "unreadable"}
    assert RealmStore.inspect_realm(root, timeout_seconds=0)["checks"]["sqlite_integrity"]["reason"] == "timeout"
    assert runtime_main(["doctor", "--root", str(root), "--json"]) == 1
    cli_report = json.loads(capsys.readouterr().out)
    assert cli_report["state"] == "unhealthy"
    assert cli_report["checks"]["sqlite_integrity"]["ok"] is False
    assert _tree_bytes(root) == before


def test_preflight_migrates_only_its_isolated_copy_before_rejecting_bad_schema(tmp_path):
    root = tmp_path / "realm"
    service = RuntimeService(root)
    service.close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("DROP TABLE executors")
        connection.execute("DELETE FROM schema_migrations WHERE version=23")
        connection.commit()
    finally:
        connection.close()
    database = root / "realm.sqlite3"
    before = database.read_bytes()

    report = RealmStore.inspect_realm(root, allow_migration=True)
    assert report["ok"] is False
    assert "executors" in report["checks"]["schema"]["missing_tables"]
    assert database.read_bytes() == before
    with pytest.raises(RealmAdmissionError):
        RealmStore(root)
    assert database.read_bytes() == before

    immutable = sqlite3.connect(f"file:{database}?immutable=1", uri=True)
    try:
        assert immutable.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 22
    finally:
        immutable.close()


def test_existing_realm_missing_attempts_table_fails_admission(tmp_path):
    root = tmp_path / "realm"
    RuntimeService(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("DROP TABLE attempts")
        connection.commit()
    finally:
        connection.close()

    report = RealmStore.inspect_realm(root, allow_migration=True)
    assert report["ok"] is False
    assert report["checks"]["schema"]["ok"] is False
    assert "attempts" in report["checks"]["schema"]["missing_tables"]
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert error.value.code == "realm_admission_failed"


def test_existing_realm_missing_required_column_fails_admission_with_schema_details(tmp_path):
    root = tmp_path / "realm"
    RuntimeService(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("ALTER TABLE attempts DROP COLUMN lease_id")
        connection.commit()
    finally:
        connection.close()

    report = RealmStore.inspect_realm(root, allow_migration=True)
    assert report["ok"] is False
    assert report["issues"] == ["schema"]
    assert report["checks"]["schema"] == {
        "ok": False,
        "expected_version": 23,
        "actual_version": 23,
        "missing_tables": [],
        "missing_columns": {"attempts": ["lease_id"]},
    }
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert error.value.code == "realm_admission_failed"
    assert error.value.details["checks"]["schema"]["missing_columns"] == {"attempts": ["lease_id"]}


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("missing", "realm_identity_missing"),
        ("ambiguous", "realm_identity_ambiguous"),
    ],
)
def test_existing_realm_requires_one_unambiguous_identity(tmp_path, mutation, reason):
    root = tmp_path / "realm"
    RuntimeService(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        if mutation == "missing":
            connection.execute("DELETE FROM realm_lifecycle")
            connection.execute("DELETE FROM realm")
        else:
            connection.execute(
                "INSERT INTO realm(id, display_name, created_at, updated_at) VALUES ('second-realm', 'Second', datetime('now'), datetime('now'))"
            )
        connection.commit()
    finally:
        connection.close()

    report = RealmStore.inspect_realm(root, allow_migration=True)
    assert report["ok"] is False
    assert report["checks"]["realm_identity"]["ok"] is False
    assert report["checks"]["realm_identity"]["reason"] == reason
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert error.value.code == "realm_admission_failed"


def test_runtime_strict_identity_admission_rejects_before_open_and_preserves_bytes(tmp_path):
    root = tmp_path / "realm"
    RuntimeService(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("DELETE FROM realm_lifecycle")
        connection.execute("DELETE FROM realm")
        connection.execute("DELETE FROM schema_migrations WHERE version=23")
        connection.commit()
    finally:
        connection.close()
    before = _tree_bytes(root)

    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)

    assert error.value.details["checks"]["realm_identity"]["reason"] == "realm_identity_missing"
    assert _tree_bytes(root) == before
    immutable = sqlite3.connect(f"file:{root / 'realm.sqlite3'}?immutable=1", uri=True)
    try:
        assert immutable.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 22
    finally:
        immutable.close()


def test_wal_only_commit_survives_owned_backup_and_restore(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        service.store.conn.execute("PRAGMA wal_autocheckpoint=0")
        project = service.create_project({"slug": "wal-only", "name": "WAL only", "metadata": {}})
        wal = Path(str(service.store.db_path) + "-wal")
        assert wal.stat().st_size > 0

        main_only = sqlite3.connect(f"file:{service.store.db_path}?immutable=1", uri=True)
        try:
            assert main_only.execute("SELECT 1 FROM projects WHERE id=?", (project["id"],)).fetchone() is None
        finally:
            main_only.close()

        backup = tmp_path / "backup"
        service.backup(backup)
        restored = tmp_path / "restored"
        service.restore(backup, restored)
        restored_db = sqlite3.connect(f"file:{restored / 'realm.sqlite3'}?immutable=1", uri=True)
        try:
            assert restored_db.execute("SELECT name FROM projects WHERE id=?", (project["id"],)).fetchone()[0] == "WAL only"
        finally:
            restored_db.close()
        for suffix in ("-wal", "-shm", "-journal"):
            assert not Path(str(restored / "realm.sqlite3") + suffix).exists()
    finally:
        service.close()


def test_candidate_verification_is_byte_safe_and_rejects_unmanifested_sidecars(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        backup = tmp_path / "backup"
        candidate = tmp_path / "candidate"
        service.backup(backup)
        service.restore(backup, candidate)
        before = _tree_bytes(candidate)
        assert verify_restore_candidate(candidate)["doctor"]["ok"] is True
        assert _tree_bytes(candidate) == before

        sidecar = Path(str(candidate / "realm.sqlite3") + "-wal")
        sidecar.write_bytes(b"unmanifested")
        sidecar_before = _tree_bytes(candidate)
        with pytest.raises(ConflictError, match="unmanifested SQLite sidecar"):
            verify_restore_candidate(candidate)
        assert _tree_bytes(candidate) == sidecar_before
    finally:
        service.close()


def test_executor_descriptor_upserts_and_rolls_back_partial_visibility(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    old_digest = "sha256:" + "a" * 64
    new_digest = "sha256:" + "c" * 64
    try:
        service.register_capability({"capability_id": "render.atomic", "definition_digest": old_digest, "status": "unavailable"})
        service.register_executor(
            {
                "executor_id": "worker",
                "capabilities": [{"capability_id": "render.atomic", "definition_digest": new_digest, "status": "ready"}],
            },
            idempotency_key="register-upsert",
        )
        capability = service.store.list_capabilities()[0]
        assert capability["definition_digest"] == new_digest
        assert capability["status"] == "ready"

        original_register = service.store.register_capability

        def fail_after_descriptor(capability_id, definition_digest, **kwargs):
            value = original_register(capability_id, definition_digest, **kwargs)
            if capability_id == "render.partial":
                raise ValidationError("forced terminal registration failure")
            return value

        monkeypatch.setattr(service.store, "register_capability", fail_after_descriptor)
        with pytest.raises(ValidationError, match="terminal registration failure"):
            service.register_executor(
                {
                    "executor_id": "failed-worker",
                    "capabilities": [{"capability_id": "render.partial", "definition_digest": "sha256:" + "b" * 64}],
                },
                idempotency_key="register-failure",
            )
        assert service.store.conn.execute("SELECT 1 FROM capabilities WHERE id='render.partial'").fetchone() is None
        assert service.store.conn.execute("SELECT 1 FROM executors WHERE id='failed-worker'").fetchone() is None
    finally:
        service.close()


def test_capability_catalog_read_waits_for_atomic_executor_registration(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    first_descriptor_written = threading.Event()
    release_registration = threading.Event()
    reader_started = threading.Event()
    reader_done = threading.Event()
    failures = []
    result = {}
    original_register = service.store.register_capability

    def pause_after_first(capability_id, definition_digest, **kwargs):
        value = original_register(capability_id, definition_digest, **kwargs)
        if capability_id == "render.first":
            first_descriptor_written.set()
            if not release_registration.wait(2):
                raise AssertionError("test registration release timed out")
        return value

    monkeypatch.setattr(service.store, "register_capability", pause_after_first)

    def register():
        try:
            service.register_executor(
                {
                    "executor_id": "atomic-worker",
                    "capabilities": [
                        {"capability_id": "render.first", "definition_digest": "sha256:" + "1" * 64},
                        {"capability_id": "render.second", "definition_digest": "sha256:" + "2" * 64},
                    ],
                },
                idempotency_key="register-atomic",
            )
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def read_catalog():
        reader_started.set()
        result["page"] = service.list_capabilities()
        reader_done.set()

    registration_thread = threading.Thread(target=register)
    reader_thread = threading.Thread(target=read_catalog)
    try:
        registration_thread.start()
        assert first_descriptor_written.wait(2)
        reader_thread.start()
        assert reader_started.wait(2)
        assert not reader_done.wait(0.1)
        release_registration.set()
        registration_thread.join(2)
        reader_thread.join(2)
        assert not failures
        assert reader_done.is_set()
        assert {item["capability_id"] for item in result["page"]["items"]} == {"render.first", "render.second"}
    finally:
        release_registration.set()
        registration_thread.join(2)
        reader_thread.join(2)
        service.close()


def test_health_degradation_revokes_mutations_and_http_errors_are_request_correlated(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        result = daemon.service.ingest_object(b"health-corruption", idempotency_key="health-object")
        digest = result["data"]["digest"].removeprefix("sha256:")
        (daemon.service.store.cas_root / digest[:2] / digest[2:]).write_bytes(b"corrupt")
        assert daemon.service.health()["status"] == "degraded"
        assert daemon.service.doctor()["ok"] is False
        project_count = daemon.service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        with pytest.raises(RealmAdmissionError) as mutation_error:
            daemon.service.create_project({"slug": "must-not-commit", "name": "Must not commit", "metadata": {}})
        assert mutation_error.value.code == "realm_admission_failed"
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == project_count

        request = urllib.request.Request(
            daemon.endpoint + "/v1/executors",
            data=b"{}",
            method="POST",
            headers={
                "Authorization": f"Bearer {daemon.worker_token}",
                "Content-Type": "application/json",
                "Content-Length": "2",
                "X-Request-ID": "registration-test-request",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        payload = json.loads(error.value.read().decode("utf-8"))
        assert payload["code"] == "protocol_error"
        assert payload["request_id"] == "registration-test-request"
        assert error.value.headers["X-Request-ID"] == payload["request_id"]
    finally:
        daemon.stop()


def test_writer_holds_admission_fence_through_commit_during_degradation(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    writer_in_body = threading.Event()
    release_writer = threading.Event()
    health_attempting_fence = threading.Event()
    health_acquired_fence = threading.Event()
    health_done = threading.Event()
    writer_done = threading.Event()
    failures = []
    results = {}

    class ObservedMutex:
        def __init__(self, mutex):
            self.mutex = mutex

        def __enter__(self):
            if threading.current_thread().name == "degradation-report":
                health_attempting_fence.set()
            self.mutex.acquire()
            if threading.current_thread().name == "degradation-report":
                health_acquired_fence.set()
            return self

        def __exit__(self, *_):
            self.mutex.release()

    service.store._mutex = ObservedMutex(service.store._mutex)
    original_create_project = service.store.create_project

    def pause_after_service_admission(*args, **kwargs):
        writer_in_body.set()
        if not release_writer.wait(2):
            raise AssertionError("writer release timed out")
        return original_create_project(*args, **kwargs)

    monkeypatch.setattr(service.store, "create_project", pause_after_service_admission)

    def write_project():
        try:
            results["project"] = service.create_project(
                {"slug": "fenced-writer", "name": "Fenced writer", "metadata": {}}
            )
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            writer_done.set()

    def report_degradation():
        try:
            results["health"] = service.health()
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            health_done.set()

    writer = threading.Thread(target=write_project, name="fenced-writer")
    health = threading.Thread(target=report_degradation, name="degradation-report")
    try:
        corrupt = service.ingest_object(b"fence-corruption", idempotency_key="fence-object")
        digest = corrupt["data"]["digest"].removeprefix("sha256:")
        (service.store.cas_root / digest[:2] / digest[2:]).write_bytes(b"corrupt")

        writer.start()
        assert writer_in_body.wait(2)
        health.start()
        assert health_attempting_fence.wait(2)
        assert not health_acquired_fence.wait(0.1)
        assert not health_done.is_set()

        release_writer.set()
        writer.join(2)
        health.join(2)

        assert not failures
        assert writer_done.is_set() and health_done.is_set()
        assert results["project"]["slug"] == "fenced-writer"
        assert results["health"]["status"] == "degraded"
        project_count = service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        with pytest.raises(RealmAdmissionError):
            service.create_project({"slug": "after-degradation", "name": "After degradation", "metadata": {}})
        assert service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == project_count
    finally:
        release_writer.set()
        writer.join(2)
        health.join(2)
        service.close()
