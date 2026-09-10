"""Serialized live Astrid migration (B12).

The ordinary migrator is deliberately source-scoped and the rehearsal is
disposable.  This module composes those two primitives for the one selected
realm migration: a caller must provide fresh, mutually distinct authorizations
and an explicit writer-stop boundary.  Destination writes happen in a fresh
runtime realm; the selected realm is changed only by the verified activation
swap, and rollback/reactivation use the same durable journal.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, replace
import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .boundary import verify_backup, verify_restore_candidate, capture_parent as _capture_parent, close_pinned as _close_pinned, ensure_directory as _ensure_directory, ensure_parent_at as _ensure_parent_at, pin_directory as _pin_directory, copy_file_at as _copy_file_at, mkdir_temp_at as _mkdir_temp_at, remove_tree_at as _remove_tree_at, validate_created_parent as _validate_created_parent, validate_parent as _validate_parent, canonical_json, RealmCatalog

from .migrator import MigrationConfig, MigrationError, Migrator, _sha256_file, _tree_size
from .capacity import CapacityPlan, CapacityReservation, StorageDomain, capture_activation_path, capture_write_path, revalidate_activation_path, revalidate_write_path, close_activation_path
from .rehearsal import MigrationJournal, RuntimeServiceAdapter, _tree_digest, _write_json


LIVE_AUTHORIZATION_IDS = (
    "AUTH-LIVE-INPUT-B12",
    "AUTH-WRITER-STOP-B12",
    "AUTH-LIVE-MIGRATION-B12",
    "AUTH-ACTIVATION-B12",
    "AUTH-ROLLBACK-B12",
    "AUTH-REACTIVATION-B12",
)

_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _database_snapshot_sha256(path: Path, *, connection: sqlite3.Connection, owner_lock: Any) -> str:
    """Hash a consistent SQLite snapshot, including committed WAL state.

    Hashing only the main database file is not sufficient while the runtime is
    in WAL mode: a committed mutation can still be present exclusively in the
    ``-wal`` file. SQLite's backup API reads one consistent view of the
    database plus its WAL/SHM sidecars. The destination is a private temporary
    snapshot, so checking terminal identity never checkpoints or otherwise
    mutates the live runtime.
    """
    path = _absolute_path(path)
    parent_identity = _capture_parent(path)
    parent_fd = int(parent_identity.get("_parent_fd"))
    source = connection
    temporary_name = None
    temporary_fd = -1
    cwd_fd = -1
    try:
        temporary_name, temporary_fd = _mkdir_temp_at(parent_fd, ".b12-db-snapshot-")
        cwd_fd = os.open(".", _DIR_FLAGS)
        try:
            # SQLite accepts a relative URI/path, but only while cwd is the
            # retained parent. No pathname is resolved through a replaceable
            # parent after capture.
            os.fchdir(parent_fd)
            target = sqlite3.connect(str(Path(temporary_name) / "snapshot.sqlite3"), timeout=10)
            try:
                with owner_lock:
                    source.backup(target)
                    target.commit()
            finally:
                target.close()
        finally:
            os.fchdir(cwd_fd)
            os.close(cwd_fd)
            cwd_fd = -1
        snapshot_fd = os.open("snapshot.sqlite3", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=temporary_fd)
        try:
            digest = hashlib.sha256()
            while True:
                block = os.read(snapshot_fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
            return digest.hexdigest()
        finally:
            os.close(snapshot_fd)
    finally:
        if cwd_fd >= 0:
            try:
                os.fchdir(cwd_fd)
            finally:
                os.close(cwd_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                _remove_tree_at(parent_fd, temporary_name)
                os.fsync(parent_fd)
            except OSError:
                pass
        _close_pinned(parent_identity)


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _database_semantic_sha256(path: Path, *, immutable: bool = False) -> str:
    """Hash durable realm data while excluding the boot/session control row."""
    # Semantic verification is read-only. Opening a backup with a writable
    # default connection can create `-wal`/`-shm` siblings after the backup
    # has already passed its consolidated-file check.
    query = "immutable=1" if immutable else "mode=ro"
    connection = sqlite3.connect(f"file:{path}?{query}", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        # Runtime startup refreshes capability metadata and SQLite sequence
        # counters; those control-plane details are not migration content.
        # Keep every realm/project/event/media row so a post-reconciliation
        # user mutation still changes this digest.
        ignored = {"runtime_lifecycle", "capabilities", "sqlite_sequence"}
        tables = [str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name") if row[0] not in ignored]
        value = {table: [dict(row) for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')] for table in tables}
    finally:
        connection.close()
    return _canonical_digest(value)


def _semantic_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in snapshot.items() if key != "database_sha256"}


def _absolute_path(value: str | Path) -> Path:
    """Normalize a path lexically without resolving symlinks."""
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _has_symlink_component(path: str | Path) -> bool:
    path = _absolute_path(path)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def issue_live_authorizations(*, source_manifest_sha256: str | None = None, selected_realm_id: str | None = None, ttl_seconds: int = 3600) -> dict[str, dict[str, Any]]:
    """Create a fresh set of B12 command authorizations.

    The returned values are operator input, not durable authority.  The live
    runner records only a SHA-256 of each nonce in its journal, so credentials
    never enter migration evidence.
    """
    if ttl_seconds <= 0:
        raise ValueError("authorization TTL must be positive")
    if not isinstance(source_manifest_sha256, str) or not source_manifest_sha256.strip():
        raise ValueError("B12 authorizations require an exact source manifest")
    if not isinstance(selected_realm_id, str) or not selected_realm_id.strip():
        raise ValueError("B12 authorizations require a concrete selected realm")
    expires_at = time.time() + ttl_seconds
    result = {}
    for authorization_id in LIVE_AUTHORIZATION_IDS:
        result[authorization_id] = {
            "authorization_id": authorization_id,
            "scope": authorization_id.removeprefix("AUTH-").lower(),
            "nonce": secrets.token_urlsafe(32),
            "source_manifest_sha256": source_manifest_sha256,
            "selected_realm_id": selected_realm_id,
            "expires_at": expires_at,
        }
    return result


@dataclass(frozen=True)
class LiveMigration:
    """Execute B12 against a selected runtime and an immutable source root."""

    config: MigrationConfig
    active_runtime: Any
    authorizations: Mapping[str, Mapping[str, Any]]
    writer_stop: Callable[[], Any]
    fault_injector: Callable[[str], None] | None = None
    crash_at: str | None = None

    def __post_init__(self) -> None:
        missing = [item for item in LIVE_AUTHORIZATION_IDS if item not in self.authorizations]
        if missing:
            raise MigrationError(f"B12 requires fresh authorizations: {', '.join(missing)}")
        nonces = []
        for authorization_id in LIVE_AUTHORIZATION_IDS:
            value = self.authorizations[authorization_id]
            if not isinstance(value, Mapping):
                raise MigrationError(f"invalid authorization instance {authorization_id}")
            if value.get("authorization_id") != authorization_id or not value.get("nonce"):
                raise MigrationError(f"invalid authorization instance {authorization_id}")
            if not isinstance(value.get("selected_realm_id"), str) or not value.get("selected_realm_id", "").strip():
                raise MigrationError(f"{authorization_id} requires a concrete selected realm")
            if not isinstance(value.get("source_manifest_sha256"), str) or not value.get("source_manifest_sha256", "").strip():
                raise MigrationError(f"{authorization_id} requires an exact source manifest")
            nonces.append(str(value["nonce"]))
        if len(set(nonces)) != len(nonces):
            raise MigrationError("B12 authorizations must use distinct nonces")
        realms = {str(self.authorizations[item]["selected_realm_id"]) for item in LIVE_AUTHORIZATION_IDS}
        sources = {str(self.authorizations[item]["source_manifest_sha256"]) for item in LIVE_AUTHORIZATION_IDS}
        if len(realms) != 1 or len(sources) != 1:
            raise MigrationError("B12 authorizations must share one realm and source manifest")
        if self.config.destination_root == Path(self.active_runtime.store.root).resolve():
            raise MigrationError("B12 destination must be separate from the selected realm")
        if self.config.dry_run:
            raise MigrationError("B12 live runner does not accept dry_run; use Migrator for dry-run")

    @staticmethod
    def _nonce_digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(str(value["nonce"]).encode("utf-8")).hexdigest()

    def _validate_authorization(self, authorization_id: str, *, source_manifest_sha256: str | None, realm_id: str) -> dict[str, Any]:
        value = self.authorizations[authorization_id]
        expected_scope = authorization_id.removeprefix("AUTH-").lower()
        if value.get("scope") != expected_scope:
            raise MigrationError(f"{authorization_id} scope does not match the requested operation")
        if not isinstance(value.get("selected_realm_id"), str) or value.get("selected_realm_id") != realm_id:
            raise MigrationError(f"{authorization_id} selected realm does not match the active realm")
        bound_source = value.get("source_manifest_sha256")
        if not isinstance(bound_source, str) or not bound_source.strip() or not isinstance(source_manifest_sha256, str) or not source_manifest_sha256.strip() or bound_source != source_manifest_sha256:
            raise MigrationError(f"{authorization_id} source manifest does not match the frozen source")
        try:
            expires_at = float(value.get("expires_at", 0))
            if not math.isfinite(expires_at):
                raise MigrationError(f"{authorization_id} has an invalid expiry")
            if expires_at <= time.time():
                raise MigrationError(f"{authorization_id} has expired")
        except (TypeError, ValueError) as exc:
            raise MigrationError(f"{authorization_id} has an invalid expiry") from exc
        return dict(value)

    def _requested_source_manifest(self) -> str:
        values = {self.authorizations[item].get("source_manifest_sha256") for item in LIVE_AUTHORIZATION_IDS}
        if len(values) != 1:
            raise MigrationError("B12 authorizations do not share one exact source manifest")
        value = next(iter(values))
        if not isinstance(value, str) or not value.strip():
            raise MigrationError("B12 authorizations require an exact source manifest")
        return value

    def _consume_authorization(self, authorization_id: str, *, source_manifest_sha256: str, realm_id: str, journal: MigrationJournal) -> dict[str, Any]:
        value = self._validate_authorization(authorization_id, source_manifest_sha256=source_manifest_sha256, realm_id=realm_id)
        effect_name = f"authorization:{authorization_id}"
        digest = self._nonce_digest(value)
        existing = journal.effects().get(effect_name)
        if existing:
            payload = existing.get("payload", {})
            if (payload.get("nonce_sha256") != digest or
                    payload.get("source_manifest_sha256") != source_manifest_sha256 or
                    payload.get("selected_realm_id") != realm_id):
                raise MigrationError(f"{authorization_id} replay conflicts with the durable journal")
            return existing
        journal.effect(effect_name, authorization_id=authorization_id, nonce_sha256=digest, source_manifest_sha256=source_manifest_sha256, selected_realm_id=realm_id)
        return journal.effects()[effect_name]

    def _writer_boundary(self, stack: ExitStack) -> dict[str, Any]:
        if not callable(self.writer_stop):
            raise MigrationError("B12 requires an explicit writer-stop boundary")
        boundary = self.writer_stop()
        if hasattr(boundary, "__enter__") and hasattr(boundary, "__exit__"):
            value = stack.enter_context(boundary)
        else:
            value = boundary
        if not isinstance(value, Mapping) or value.get("stopped") is not True:
            raise MigrationError("writer-stop boundary must return stopped=true")
        return {str(key): item for key, item in value.items() if key not in {"token", "nonce", "authorization"}} | {"stopped": True}

    def _capacity(self, inventory: Mapping[str, Any], evidence_root: Path) -> dict[str, Any]:
        source_bytes = _tree_size(self.config.source_root)
        estimated_cas = int(inventory.get("estimated_cas_bytes", 0))
        # Peak accounting is intentionally conservative.  The source remains
        # live while the archive, active rollback backup, destination, its
        # backup, rollback candidate, activation temporary, CAS, evidence,
        # and safety margin coexist.  Compact mode deliberately does not
        # reserve the two separately materialized live candidate trees: the
        # signed destination backup is copied into the activation temporary by
        # the activation boundary itself.
        archive_bytes = max(source_bytes, _tree_size(self.config.archive_root) if self.config.archive_root.exists() else 0)
        active_backup_bytes = _tree_size(self.active_runtime.store.root)
        destination_bytes = max(_tree_size(self.config.destination_root) if self.config.destination_root.exists() else 0, source_bytes + estimated_cas)
        destination_backup_bytes = destination_bytes
        candidate_bytes = destination_bytes if self.config.redundancy == "extreme" else 0
        rollback_bytes = active_backup_bytes
        reactivation_bytes = destination_bytes if self.config.redundancy == "extreme" else 0
        activation_temp_bytes = max(destination_bytes, active_backup_bytes)
        # The evidence directory is empty on a fresh run, but the journey
        # necessarily writes multiple fsynced receipts and journals before it
        # reaches the terminal state. Reserve a concrete export allowance so
        # an empty preflight cannot claim that evidence costs zero bytes.
        evidence_bytes = max(_tree_size(evidence_root), 1024 * 1024)
        if self.config.capacity_margin_bytes is not None:
            margin = self.config.capacity_margin_bytes
        elif self.config.redundancy == "compact":
            margin = int(source_bytes * 0.2)
        else:
            margin = max(int(source_bytes * 0.2), 10 * 1024**3)
        components = {"redundancy": self.config.redundancy, "source_bytes": source_bytes, "archive_bytes": archive_bytes, "active_backup_bytes": active_backup_bytes, "destination_bytes": destination_bytes, "destination_backup_bytes": destination_backup_bytes, "candidate_bytes": candidate_bytes, "rollback_bytes": rollback_bytes, "reactivation_bytes": reactivation_bytes, "activation_temp_bytes": activation_temp_bytes, "cas_bytes": estimated_cas, "evidence_bytes": evidence_bytes, "margin_bytes": margin}
        # Every output is charged to the filesystem where that output is
        # written.  A shared filesystem therefore gets one aggregate pool;
        # split filesystems are independently fail-closed.
        archive_parent = self.config.archive_root.parent
        allocations = (
            ("source", self.config.source_root, 0),
            ("archive", self.config.archive_root, archive_bytes),
            ("active_backup", archive_parent / f"{self.config.archive_root.name}-live-pre-migration-backup", active_backup_bytes),
            ("destination", self.config.destination_root, destination_bytes),
            ("destination_backup", archive_parent / f"{self.config.archive_root.name}-live-destination-backup", destination_backup_bytes),
            ("candidate", archive_parent / f"{self.config.archive_root.name}-live-candidate", candidate_bytes),
            ("rollback", archive_parent / f"{self.config.archive_root.name}-live-rollback", rollback_bytes),
            ("reactivation", archive_parent / f"{self.config.archive_root.name}-live-reactivated", reactivation_bytes),
            ("activation_temp", self.active_runtime.store.root.parent / ".b12-activation-temp", activation_temp_bytes),
            ("evidence", evidence_root, evidence_bytes),
            ("active_runtime", self.active_runtime.store.root, 0),
        )
        plan = CapacityPlan.from_allocations(allocations, margin_bytes=margin)
        # Retain the locked plan for the current journey.  The durable receipt
        # is still plain JSON; interrupted replay reconstructs it below.
        object.__setattr__(self, "_capacity_plan", plan)
        receipt = plan.receipt(packet="B12.1", components=components)
        receipt["domain_count"] = len(receipt["domains"])
        receipt["reservation_scope"] = "filesystem-device-and-mount"
        if not receipt["reserved"]:
            raise MigrationError("B12.1 capacity reservation is insufficient")
        return receipt

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MigrationError(f"B12 durable artifact is unreadable: {path}") from exc
        if not isinstance(value, dict):
            raise MigrationError(f"B12 durable artifact is not an object: {path}")
        return value

    @staticmethod
    def _existing_effect(journal: MigrationJournal, name: str) -> dict[str, Any] | None:
        return journal.effects().get(name)

    @staticmethod
    def _path_exists(path: Path) -> bool:
        # Path.exists() is false for a dangling symlink.  A destination must
        # be genuinely absent, not merely absent after link resolution.
        return os.path.lexists(str(path))

    def _fresh_destination(self, destination: Path) -> None:
        if _has_symlink_component(destination):
            raise MigrationError("B12 destination must be fresh and must not contain a symlink component")
        if self._path_exists(destination):
            raise MigrationError("B12 destination must be a fresh, non-symlink path")
        if destination.is_symlink():
            raise MigrationError("B12 destination must not be a symlink")

    def _bind_request(self, journal: MigrationJournal, *, realm_id: str, source_manifest_sha256: str, evidence_root: Path) -> dict[str, Any]:
        binding = {
            "realm_id": realm_id,
            "source_manifest_sha256": source_manifest_sha256,
            "source_root": str(self.config.source_root.resolve()),
            "archive_root": str(self.config.archive_root.resolve()),
            "destination_root": str(self.config.destination_root.resolve()),
            "evidence_root": str(evidence_root.resolve()),
            "redundancy": self.config.redundancy,
            "authorization_nonce_sha256": {
                authorization_id: self._nonce_digest(self.authorizations[authorization_id])
                for authorization_id in LIVE_AUTHORIZATION_IDS
            },
        }
        current = journal._read()
        recorded = current.get("binding")
        if recorded is not None:
            # Journals written before the redundancy field are immutable
            # legacy/extreme requests.  They may be replayed explicitly as
            # extreme, but compact must use a new evidence root rather than
            # silently rebinding the prepared journal.
            if "redundancy" not in recorded:
                if self.config.redundancy == "compact":
                    raise MigrationError("legacy B12 journal requires --redundancy extreme or a new evidence root")
                legacy_binding = dict(binding)
                legacy_binding.pop("redundancy")
                if recorded != legacy_binding:
                    raise MigrationError("B12 replay conflicts with the durable legacy request binding")
                return dict(recorded)
            if recorded != binding:
                raise MigrationError("B12 replay conflicts with the durable request binding")
            return dict(recorded)
        if recorded is None:
            journal.bind(**binding)
        return binding

    def _terminal_replay(self, journal: MigrationJournal, *, realm_id: str) -> dict[str, Any]:
        current = journal._read()
        binding = current.get("binding")
        if not isinstance(binding, Mapping):
            raise MigrationError("B12 terminal journal has no durable request binding")
        recorded_redundancy = binding.get("redundancy", "extreme")
        if recorded_redundancy != self.config.redundancy:
            raise MigrationError("B12 terminal replay redundancy conflicts with its durable journal")
        if binding.get("realm_id") != realm_id or binding.get("destination_root") != str(self.config.destination_root.resolve()):
            raise MigrationError("B12 terminal replay conflicts with realm or destination binding")
        if binding.get("source_root") != str(self.config.source_root.resolve()) or binding.get("archive_root") != str(self.config.archive_root.resolve()):
            raise MigrationError("B12 terminal replay conflicts with source or archive binding")
        try:
            source_manifest = Migrator(self.config, None).inventory()["source_manifest_sha256"]
        except Exception as exc:
            raise MigrationError("B12 terminal replay could not verify the frozen source") from exc
        if binding.get("source_manifest_sha256") != source_manifest:
            raise MigrationError("B12 terminal replay conflicts with the frozen source manifest")
        expected_nonces = binding.get("authorization_nonce_sha256")
        if not isinstance(expected_nonces, Mapping):
            raise MigrationError("B12 terminal journal has no authorization binding")
        for authorization_id in LIVE_AUTHORIZATION_IDS:
            value = self.authorizations.get(authorization_id)
            self._validate_authorization(authorization_id, source_manifest_sha256=source_manifest, realm_id=realm_id)
            if not isinstance(value, Mapping) or self._nonce_digest(value) != expected_nonces.get(authorization_id):
                raise MigrationError(f"{authorization_id} replay conflicts with the durable authorization")
        writer_effect = journal.effects().get("writer-stop")
        if not writer_effect:
            raise MigrationError("B12 terminal journal has no durable writer-stop completion")
        writer_payload = writer_effect.get("payload", {})
        if writer_payload.get("realm_id") != realm_id or writer_payload.get("source_manifest_sha256") != source_manifest or writer_payload.get("receipt", {}).get("stopped") is not True:
            raise MigrationError("B12 terminal writer-stop receipt is not bound to the selected source")
        completion_path = Path(str(writer_payload.get("completion_path", "")))
        if _has_symlink_component(completion_path) or not completion_path.is_file() or writer_payload.get("completion_sha256") != _sha256_file(completion_path):
            raise MigrationError("B12 terminal writer-stop completion is missing or changed")
        entries = current.get("entries", [])
        identity = entries[-1].get("identity") if entries else None
        if not isinstance(identity, Mapping) or identity.get("realm_id") != realm_id or identity.get("source_manifest_sha256") != source_manifest or identity.get("destination_root") != str(self.active_runtime.store.root):
            raise MigrationError("B12 terminal journal has an invalid final identity binding")
        final_effect = journal.effects().get("final-identity")
        if not final_effect or final_effect.get("payload", {}).get("identity") != dict(identity):
            raise MigrationError("B12 terminal journal final identity effect is missing or conflicting")
        try:
            identity_epoch = int(identity.get("runtime_epoch"))
        except (TypeError, ValueError) as exc:
            raise MigrationError("B12 terminal final identity has no valid runtime epoch") from exc
        current_epoch = int(self.active_runtime.health()["runtime_epoch"])
        same_session = identity.get("runtime_session_id") == getattr(self.active_runtime, "runtime_session_id", None)
        if same_session or current_epoch <= identity_epoch:
            if identity.get("active_database_sha256") != _database_snapshot_sha256(self.active_runtime.store.db_path, connection=self.active_runtime.store.conn, owner_lock=self.active_runtime.store._mutex):
                raise MigrationError("B12 terminal replay conflicts with the active final identity")
        elif identity.get("active_database_semantic_sha256") != _database_semantic_sha256(self.active_runtime.store.db_path):
            raise MigrationError("B12 terminal replay conflicts with the active durable database state")
        doctor = self.active_runtime.doctor()
        if not doctor.get("ok"):
            raise MigrationError("B12 terminal replay current runtime failed doctor")
        snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
        if identity.get("active_semantic_snapshot_sha256") != _canonical_digest(_semantic_snapshot(snapshot)):
            raise MigrationError("B12 terminal replay conflicts with the active semantic state")
        if identity.get("active_cas_manifest_sha256") != self._cas_manifest_digest(snapshot):
            raise MigrationError("B12 terminal replay conflicts with active CAS content")
        archive_root = self.config.archive_root
        active_backup_root = archive_root.parent / f"{archive_root.name}-live-pre-migration-backup"
        destination_backup_root = archive_root.parent / f"{archive_root.name}-live-destination-backup"
        for path, key in ((active_backup_root, "source_backup_manifest_sha256"), (destination_backup_root, "destination_backup_manifest_sha256")):
            if _has_symlink_component(path) or not path.is_dir():
                raise MigrationError(f"B12 terminal replay is missing backup {path}")
            try:
                verified_backup = verify_backup(path)
            except Exception as exc:
                raise MigrationError(f"B12 terminal replay backup verification failed: {path}") from exc
            backup_binding = verified_backup["manifest"].get("destination_binding") or {}
            if backup_binding.get("selected_realm_id") != realm_id or backup_binding.get("source_manifest_sha256") != source_manifest:
                raise MigrationError(f"B12 terminal replay backup binding changed: {path}")
            if identity.get(key) != _sha256_file(path / "manifest.json"):
                raise MigrationError(f"B12 terminal replay backup manifest changed: {path}")
        artifacts = self._runtime_artifact_identity(self.active_runtime, source_manifest_sha256=source_manifest, expected_activation_manifest_sha256=identity.get("activation_manifest_sha256"))
        if identity.get("catalog_identity") != artifacts["catalog"]:
            raise MigrationError("B12 terminal replay catalog identity changed")
        release = journal.effects().get("capacity-release")
        if not release or release.get("payload", {}).get("reservation_id") != journal.effects().get("capacity-reservation", {}).get("payload", {}).get("reservation_id"):
            raise MigrationError("B12 terminal capacity reservation was not durably released")
        self._cleanup_compact_quarantines(self.active_runtime)
        return {"packet": "B12", "journal": current, "identity": dict(identity), "idempotent": True}

    def _backup_or_reuse(self, runtime: Any, destination: Path, *, binding: Mapping[str, Any], journal: MigrationJournal, effect_name: str, seam: str) -> dict[str, Any]:
        if _has_symlink_component(destination):
            raise MigrationError(f"B12 {effect_name} path contains a symlink component")
        existing = self._existing_effect(journal, effect_name)
        if existing:
            payload = existing.get("payload", {})
            if payload.get("path") != str(destination) or payload.get("realm_id") != binding.get("selected_realm_id"):
                raise MigrationError(f"B12 {effect_name} conflicts with the durable effect")
            try:
                verified = verify_backup(destination)
            except Exception as exc:
                raise MigrationError(f"B12 durable backup effect is not reusable: {destination}") from exc
            actual_binding = verified["manifest"].get("destination_binding") or {}
            if not self._backup_binding_compatible(actual_binding, binding):
                raise MigrationError(f"B12 durable backup binding changed on disk: {destination}")
            if payload.get("manifest_sha256") != _sha256_file(destination / "manifest.json"):
                raise MigrationError(f"B12 durable backup effect changed on disk: {destination}")
            return verified
        if self._path_exists(destination):
            try:
                verified = verify_backup(destination)
            except Exception as exc:
                raise MigrationError(f"B12 existing backup is not a verified reusable artifact: {destination}") from exc
            actual = verified["manifest"].get("destination_binding") or {}
            if not self._backup_binding_compatible(actual, binding):
                raise MigrationError(f"B12 existing backup has a conflicting binding: {destination}")
        else:
            reservation = getattr(self, "_capacity_reservation", None)
            if reservation is not None:
                reservation.recheck()
            write_identity = capture_write_path(destination)
            journal._inject(f"before_{seam}")
            # The injection seam is intentionally inside the reservation:
            # tests and operators can model a hostile rename/symlink/device
            # swap here, and no backup bytes may be written until both the
            # capacity lease and the exact parent identity are revalidated.
            if reservation is not None:
                reservation.recheck()
            revalidate_write_path(destination, write_identity)
            try:
                verified = runtime.backup(destination, binding=dict(binding), destination_identity=write_identity)
                journal._inject(f"after_{seam}")
            finally:
                close_activation_path(write_identity)
        journal.effect(effect_name, path=str(destination), manifest_sha256=_sha256_file(destination / "manifest.json"), realm_id=binding.get("selected_realm_id"))
        return verified

    @staticmethod
    def _backup_binding_compatible(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
        """Compare immutable backup identity without binding volatile truth rows."""
        for key in ("packet", "kind", "selected_realm_id", "source_manifest_sha256"):
            if actual.get(key) != expected.get(key):
                return False
        actual_reconciliation = actual.get("reconciliation")
        expected_reconciliation = expected.get("reconciliation")
        if not isinstance(actual_reconciliation, Mapping) or not isinstance(expected_reconciliation, Mapping):
            return actual_reconciliation == expected_reconciliation
        # ``destination_truth`` carries paths, database bytes, and runtime
        # generated ids.  The immutable reconciliation contract is the source
        # mapping, counts, blockers, and success bit around that observation.
        for key, value in expected_reconciliation.items():
            if key == "destination_truth":
                continue
            if actual_reconciliation.get(key) != value:
                return False
        return actual_reconciliation.get("ok") is True

    def _restore_or_reuse(self, backup: Path, destination: Path, *, journal: MigrationJournal, effect_name: str, realm_id: str, seam: str, source_manifest_sha256: str | None = None) -> dict[str, Any]:
        if _has_symlink_component(backup):
            raise MigrationError(f"B12 {effect_name} backup contains a symlink component")
        if _has_symlink_component(destination):
            raise MigrationError(f"B12 {effect_name} destination contains a symlink component")
        existing = self._existing_effect(journal, effect_name)
        if existing:
            payload = existing.get("payload", {})
            if payload.get("destination") != str(destination) or payload.get("realm_id") != realm_id:
                raise MigrationError(f"B12 {effect_name} conflicts with the durable effect")
            candidate_identity = _capture_parent(destination)
            try:
                verification = verify_restore_candidate(destination, directory_identity=candidate_identity)
            except Exception as exc:
                raise MigrationError(f"B12 durable restore effect is not reusable: {destination}") from exc
            finally:
                _close_pinned(candidate_identity)
            if payload.get("source_manifest_sha256") != verification["handoff"].get("source_manifest_sha256"):
                raise MigrationError(f"B12 durable restore effect changed source binding: {destination}")
            self._assert_restore_binding(verification, realm_id=realm_id, source_manifest_sha256=source_manifest_sha256)
            return {"destination": str(destination), "realm_id": realm_id, "verification": verification}
        if self._path_exists(destination):
            candidate_identity = _capture_parent(destination)
            try:
                verification = verify_restore_candidate(destination, directory_identity=candidate_identity)
            except Exception as exc:
                raise MigrationError(f"B12 existing restore candidate is not reusable: {destination}") from exc
            finally:
                _close_pinned(candidate_identity)
        else:
            reservation = getattr(self, "_capacity_reservation", None)
            if reservation is not None:
                reservation.recheck()
            write_identity = capture_write_path(destination)
            source_identity = None
            try:
                source_identity = _capture_parent(backup)
                journal._inject(f"before_{seam}")
                if reservation is not None:
                    reservation.recheck()
                revalidate_write_path(destination, write_identity)
                self.active_runtime.restore(backup, destination, destination_identity=write_identity, source_identity=source_identity)
                journal._inject(f"after_{seam}")
                verification = verify_restore_candidate(destination, directory_identity=write_identity)
            finally:
                close_activation_path(write_identity)
                if source_identity is not None:
                    _close_pinned(source_identity)
        if verification["manifest"].get("realm_id") != realm_id:
            raise MigrationError(f"B12 restore candidate has the wrong realm: {destination}")
        self._assert_restore_binding(verification, realm_id=realm_id, source_manifest_sha256=source_manifest_sha256)
        journal.effect(effect_name, destination=str(destination), realm_id=realm_id, source_manifest_sha256=verification["handoff"].get("source_manifest_sha256"), database_sha256=verification.get("database_sha256"))
        return {"destination": str(destination), "realm_id": realm_id, "verification": verification}

    @staticmethod
    def _assert_restore_binding(verification: Mapping[str, Any], *, realm_id: str, source_manifest_sha256: str | None) -> None:
        manifest = verification.get("manifest")
        if not isinstance(manifest, Mapping) or manifest.get("realm_id") != realm_id:
            raise MigrationError("B12 restore candidate has an invalid backup realm binding")
        if source_manifest_sha256 is None:
            return
        binding = manifest.get("destination_binding")
        if not isinstance(binding, Mapping) or binding.get("selected_realm_id") != realm_id or binding.get("source_manifest_sha256") != source_manifest_sha256:
            raise MigrationError("B12 restore candidate has a conflicting source binding")

    @staticmethod
    def _cas_manifest_digest(snapshot: Mapping[str, Any]) -> str:
        objects = [
            {key: item.get(key) for key in ("digest", "size", "sha256")}
            for item in snapshot.get("cas_objects", [])
            if isinstance(item, Mapping)
        ]
        return _canonical_digest(sorted(objects, key=lambda item: str(item.get("digest"))))

    @staticmethod
    def _cas_content_map(root: Path) -> dict[str, str]:
        cas_root = _absolute_path(root) / "cas" / "sha256"
        result = {}
        if cas_root.is_dir():
            for path in cas_root.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    result[path.parent.name + path.name] = _sha256_file(path)
        return result

    def _verify_root_against_backup(self, root: Path, backup: Path, *, realm_id: str) -> None:
        if _has_symlink_component(root) or _has_symlink_component(backup):
            raise MigrationError("B12 destination verification path contains a symlink component")
        try:
            verified = verify_backup(backup)
        except Exception as exc:
            raise MigrationError(f"B12 destination backup cannot be verified: {backup}") from exc
        if verified["manifest"].get("realm_id") != realm_id:
            raise MigrationError("B12 destination backup realm identity changed")
        if _database_semantic_sha256(root / "realm.sqlite3") != _database_semantic_sha256(backup / "realm.sqlite3", immutable=True):
            raise MigrationError("B12 destination changed after reconciliation")
        expected = {str(item["digest"]): str(item["sha256"]) for item in verified["cas_manifest"].get("objects", [])}
        if self._cas_content_map(root) != expected:
            raise MigrationError("B12 destination CAS changed after reconciliation")
        # The semantic comparison above already binds every durable row,
        # including realm identity.  Inspect an isolated WAL-aware copy here;
        # reopening the stopped destination through RealmStore would run
        # migrations and create SQLite sidecars during verification.
        report = type(self.active_runtime.store).inspect_realm(root)
        if not report.get("ok"):
            raise MigrationError("B12 destination failed its final doctor check")

    def _active_matches_candidate(self, candidate: Path, realm_id: str) -> bool:
        """Recognize an already-completed activation after process restart.

        Runtime startup legitimately rewrites its epoch/session control rows,
        so a raw SQLite byte comparison would miss a swap that happened just
        before a crash and would perform the activation a second time. Compare
        the candidate's authenticated realm content instead.
        """
        try:
            if _has_symlink_component(candidate) or candidate.is_symlink():
                return False
            verify_restore_candidate(candidate)
            if self.active_runtime.realm["id"] != realm_id or not self.active_runtime.doctor().get("ok"):
                return False
            if _database_semantic_sha256(self.active_runtime.store.db_path) != _database_semantic_sha256(candidate / "realm.sqlite3"):
                return False
            return self._cas_content_map(_absolute_path(self.active_runtime.store.root)) == self._cas_content_map(candidate)
        except Exception:
            return False

    def _active_matches_backup(self, backup: Path, realm_id: str) -> bool:
        """Recognize an activation completed directly from a signed backup."""
        try:
            if _has_symlink_component(backup):
                return False
            verified = verify_backup(backup)
            manifest = verified["manifest"]
            if manifest.get("realm_id") != realm_id or self.active_runtime.realm["id"] != realm_id or not self.active_runtime.doctor().get("ok"):
                return False
            if _database_semantic_sha256(self.active_runtime.store.db_path) != _database_semantic_sha256(backup / "realm.sqlite3", immutable=True):
                return False
            expected = {str(item["digest"]): str(item["sha256"]) for item in verified["cas_manifest"].get("objects", [])}
            return self._cas_content_map(_absolute_path(self.active_runtime.store.root)) == expected
        except Exception:
            return False

    def _runtime_artifact_identity(self, runtime: Any, *, source_manifest_sha256: str, expected_activation_manifest_sha256: str | None = None) -> dict[str, Any]:
        """Verify the control-plane artifacts that a terminal replay relies on."""
        root = _absolute_path(runtime.store.root)
        activation_path = root / "activation-manifest.json"
        if _has_symlink_component(activation_path) or not activation_path.is_file():
            raise MigrationError("B12 terminal replay is missing the activation manifest")
        try:
            activation = self._read_json(activation_path)
        except MigrationError:
            raise
        if activation.get("format_version") not in {1, 2} or activation.get("state") != "activated" or _absolute_path(activation.get("destination_root", "")) != _absolute_path(self.config.destination_root):
            raise MigrationError("B12 terminal activation manifest has an invalid identity")
        source_archive = Path(str(activation.get("source_archive", "")))
        if _absolute_path(source_archive) != _absolute_path(self.config.archive_root):
            raise MigrationError("B12 terminal activation manifest archive identity changed")
        source_archive_manifest = source_archive / "manifest.json"
        if _has_symlink_component(source_archive_manifest) or not source_archive_manifest.is_file():
            raise MigrationError("B12 terminal activation manifest source archive is missing")
        if activation.get("source_archive_sha256") != _sha256_file(source_archive_manifest):
            raise MigrationError("B12 terminal activation manifest source archive changed")
        try:
            source_archive_payload = self._read_json(source_archive_manifest)
        except MigrationError:
            raise MigrationError("B12 terminal activation manifest source archive is unreadable")
        if source_archive_payload.get("source_manifest_sha256") != source_manifest_sha256:
            raise MigrationError("B12 terminal activation manifest source identity changed")
        # New manifests may also carry the source binding at the activation
        # layer.  Accept older migrator output only when its authenticated
        # archive manifest supplies the exact same binding above.
        if activation.get("source_manifest_sha256") is not None and activation.get("source_manifest_sha256") != source_manifest_sha256:
            raise MigrationError("B12 terminal activation manifest source identity changed")
        reconciliation = activation.get("reconciliation")
        if not isinstance(reconciliation, Mapping) or reconciliation.get("ok") is not True:
            raise MigrationError("B12 terminal activation manifest source identity changed")
        activation_sha256 = _sha256_file(activation_path)
        if expected_activation_manifest_sha256 is not None and activation_sha256 != expected_activation_manifest_sha256:
            raise MigrationError("B12 terminal activation manifest bytes changed")
        catalog_identity: dict[str, Any] = {"status": "not_configured", "sha256": None}
        if runtime.support_root is not None:
            catalog_path = _absolute_path(runtime.support_root) / "catalog.json"
            if _has_symlink_component(catalog_path) or not catalog_path.is_file():
                raise MigrationError("B12 terminal catalog is missing")
            try:
                catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise MigrationError("B12 terminal catalog is unreadable") from exc
            rows = [row for row in catalog.get("realms", []) if isinstance(row, Mapping) and row.get("realm_id") == runtime.realm["id"]]
            if catalog.get("selected_realm_id") != runtime.realm["id"] or len(rows) != 1:
                raise MigrationError("B12 terminal catalog selection or realm identity changed")
            if _absolute_path(rows[0].get("data_root", "")) != root:
                raise MigrationError("B12 terminal catalog data root changed")
            catalog_identity = {"status": "ready", "sha256": _sha256_file(catalog_path), "selected_realm_id": runtime.realm["id"], "data_root": str(root)}
        return {"activation_manifest_sha256": activation_sha256, "activation_state": activation.get("state"), "catalog": catalog_identity}

    def _revalidate_destination(self, config: MigrationConfig, inventory: Mapping[str, Any], destination: Any, *, source_manifest_sha256: str) -> dict[str, Any]:
        """Read and reconcile destination truth immediately before activation."""
        current_inventory = Migrator(config, None).inventory()
        if current_inventory.get("source_manifest_sha256") != source_manifest_sha256:
            raise MigrationError("B12 source manifest changed before activation")
        verifier = Migrator(config, RuntimeServiceAdapter(destination))
        # Re-run the migration kernel against its idempotent destination
        # operations.  This reconstructs source->destination identity maps,
        # then performs a fresh exact reconciliation from runtime truth; a
        # direct snapshot-only check cannot validate task/generation mappings.
        try:
            reconciliation = verifier.migrate().get("reconciliation")
        except Exception as exc:
            # Reconciliation is a migration boundary, so an idempotency or
            # identity conflict discovered while replaying the kernel must be
            # surfaced as a failed reconciliation rather than leaking an
            # implementation-specific adapter exception.
            raise MigrationError("B12.2 destination reconciliation changed before activation") from exc
        if not isinstance(reconciliation, Mapping) or not reconciliation.get("ok"):
            raise MigrationError("B12.2 destination reconciliation changed before activation")
        doctor = destination.doctor()
        if not doctor.get("ok") or destination.realm["id"] != str(self.active_runtime.realm["id"]):
            raise MigrationError("B12.2 destination failed its final integrity or realm check")
        return dict(reconciliation)

    def _destination_truth(self, destination: Any) -> dict[str, Any]:
        """Capture the durable destination identity at a write boundary."""
        snapshot = RuntimeServiceAdapter(destination).destination_snapshot()
        return {
            "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)),
            "cas_manifest_sha256": self._cas_manifest_digest(snapshot),
            "database_semantic_sha256": _database_semantic_sha256(destination.store.db_path),
            "realm_id": str(destination.realm["id"]),
        }

    def _assert_active_baseline(self, journal: MigrationJournal, active: Any) -> None:
        effect = journal.effects().get("active-baseline")
        if not effect:
            raise MigrationError("B12 active baseline is missing before activation")
        payload = effect.get("payload", {})
        snapshot = RuntimeServiceAdapter(active).destination_snapshot()
        if payload.get("semantic_snapshot_sha256") != _canonical_digest(_semantic_snapshot(snapshot)):
            raise MigrationError("B12 active runtime changed after the writer-stop boundary")

    def _cleanup_compact_quarantines(self, active: Any) -> None:
        """Remove residual compact activation quarantines through a pinned parent.

        A process can die after publishing a new active root but before the
        adapter finishes removing its old-root quarantine. Replay/reuse must
        clean that residue without resolving the replaceable active path again.
        Extreme mode retains these historical trees and never enters this
        helper.
        """
        if self.config.redundancy != "compact":
            return
        target = Path(os.path.abspath(os.fspath(active.store.root)))
        identity = capture_activation_path(target)
        parent_fd = int(identity.get("_parent_fd", -1))
        if parent_fd < 0:
            close_activation_path(identity)
            raise MigrationError("B12 compact quarantine cleanup has no retained parent descriptor")
        quarantine_pattern = re.compile(rf"\.{re.escape(target.name)}\.inactive-(?:active|rolled_back|reactivated)-[0-9]+$")
        marker_pattern = re.compile(rf"\.{re.escape(target.name)}\.inactive-(?:active|rolled_back|reactivated)-[0-9]+\.b12-owner$")
        try:
            revalidate_activation_path(target, identity)
            try:
                marker_names = {}
                for name in os.listdir(parent_fd):
                    if not marker_pattern.fullmatch(name):
                        continue
                    try:
                        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISREG(entry.st_mode):
                        continue
                    marker_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
                    try:
                        marker_data = bytearray()
                        while True:
                            block = os.read(marker_fd, 1024 * 1024)
                            if not block:
                                break
                            marker_data.extend(block)
                    finally:
                        os.close(marker_fd)
                    try:
                        marker = json.loads(bytes(marker_data).decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        continue
                    quarantine_name = name.removesuffix(".b12-owner")
                    quarantine_suffix = quarantine_name.removeprefix(f".{target.name}.inactive-")
                    state = quarantine_suffix.rsplit("-", 1)[0]
                    expected_token = hashlib.sha256(f"{active.realm['id']}:{quarantine_name}:{state}".encode("utf-8")).hexdigest()
                    if not isinstance(marker, Mapping) or marker.get("format_version") != 1 or marker.get("kind") != "b12-compact-quarantine" or marker.get("quarantine") != quarantine_name or marker.get("target_name") != target.name or marker.get("state") != state or marker.get("realm_id") != active.realm["id"] or marker.get("token") != expected_token:
                        continue
                    marker_names[quarantine_name] = name
                names = []
                for quarantine_name, marker_name in sorted(marker_names.items()):
                    try:
                        entry = os.stat(quarantine_name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        os.unlink(marker_name, dir_fd=parent_fd)
                        continue
                    # Only adapter-created directory quarantines qualify. A
                    # similarly named file or symlink is not runtime-owned and
                    # remains untouched.
                    if stat.S_ISDIR(entry.st_mode) and quarantine_pattern.fullmatch(quarantine_name):
                        names.append((quarantine_name, marker_name))
            except OSError as exc:
                raise MigrationError("B12 compact quarantine cleanup could not inspect its pinned parent") from exc
            for name, marker_name in names:
                revalidate_activation_path(target, identity)
                try:
                    _remove_tree_at(parent_fd, name)
                    os.unlink(marker_name, dir_fd=parent_fd)
                except (OSError, MigrationError) as exc:
                    raise MigrationError(f"B12 compact quarantine cleanup failed: {name}") from exc
            revalidate_activation_path(target, identity)
        finally:
            close_activation_path(identity)

    def _assert_destination_baseline(self, destination: Any, payload: Mapping[str, Any]) -> None:
        current = self._destination_truth(destination)
        if any(payload.get(key) != current.get(key) for key in ("semantic_snapshot_sha256", "cas_manifest_sha256", "database_semantic_sha256", "realm_id")):
            raise MigrationError("B12 destination changed after its final reconciliation")

    def run(self) -> dict[str, Any]:
        active = self.active_runtime
        realm_id = str(active.realm["id"])
        evidence_root = (self.config.evidence_root or self.config.destination_root.parent / "migration-evidence-b12").resolve()
        evidence_identity = _ensure_directory(evidence_root)
        _close_pinned(evidence_identity)
        journal = MigrationJournal(evidence_root / "migration-journal-b12.json", fault_injector=self.fault_injector, crash_at=self.crash_at)
        current = journal._read()
        if current["state"] == "reactivated":
            return self._terminal_replay(journal, realm_id=realm_id)
        if current["state"] not in {"prepared", "active", "rolled_back"}:
            raise MigrationError("B12 live migration journal is interrupted; inspect it before resuming")
        if current["state"] == "prepared" and current.get("binding") is None:
            self._fresh_destination(self.config.destination_root)
        archive_root = self.config.archive_root
        active_backup_root = archive_root.parent / f"{archive_root.name}-live-pre-migration-backup"
        destination_backup_root = archive_root.parent / f"{archive_root.name}-live-destination-backup"
        rollback_root = archive_root.parent / f"{archive_root.name}-live-rollback"
        candidate_root = (archive_root.parent / f"{archive_root.name}-live-candidate" if self.config.redundancy == "extreme" else None)
        reactivation_root = (archive_root.parent / f"{archive_root.name}-live-reactivated" if self.config.redundancy == "extreme" else None)
        with ExitStack() as stack:
            requested_source_manifest = self._requested_source_manifest()
            # Bind the operator inputs before invoking the external writer-stop
            # authority.  A stop completion is therefore never detached from
            # its realm/source request, even if the process dies immediately
            # after the callback returns.
            for authorization_id in LIVE_AUTHORIZATION_IDS:
                self._validate_authorization(authorization_id, source_manifest_sha256=requested_source_manifest, realm_id=realm_id)
            binding = self._bind_request(journal, realm_id=realm_id, source_manifest_sha256=requested_source_manifest, evidence_root=evidence_root)
            writer_effect = self._existing_effect(journal, "writer-stop")
            writer_completion_path = evidence_root / "writer-stop-completion-b12.json"
            if writer_effect:
                writer_payload = writer_effect.get("payload", {})
                if writer_payload.get("realm_id") != realm_id or writer_payload.get("source_manifest_sha256") != requested_source_manifest or writer_payload.get("receipt", {}).get("stopped") is not True:
                    raise MigrationError("B12 durable writer-stop completion conflicts with this request")
                writer_receipt = dict(writer_payload["receipt"])
                if writer_payload.get("completion_sha256") != _sha256_file(writer_completion_path):
                    raise MigrationError("B12 durable writer-stop completion file changed")
            else:
                if writer_completion_path.is_file():
                    completion = self._read_json(writer_completion_path)
                    if completion.get("realm_id") != realm_id or completion.get("source_manifest_sha256") != requested_source_manifest or completion.get("receipt", {}).get("stopped") is not True:
                        raise MigrationError("B12 durable writer-stop completion file conflicts with this request")
                    writer_receipt = dict(completion["receipt"])
                else:
                    writer_receipt = self._writer_boundary(stack)
                    _write_json(writer_completion_path, {"packet": "B12.1", "realm_id": realm_id, "source_manifest_sha256": requested_source_manifest, "receipt": writer_receipt})
                journal.effect("writer-stop", realm_id=realm_id, source_manifest_sha256=requested_source_manifest, receipt=writer_receipt, completion_path=str(writer_completion_path), completion_sha256=_sha256_file(writer_completion_path))
            probe = Migrator(self.config, None)
            inventory = probe.inventory()
            source_manifest_sha256 = inventory["source_manifest_sha256"]
            if source_manifest_sha256 != requested_source_manifest:
                raise MigrationError("B12 source manifest changed at the writer-stop boundary")
            self._consume_authorization("AUTH-LIVE-INPUT-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            self._consume_authorization("AUTH-WRITER-STOP-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            capacity_path = evidence_root / "capacity-receipt-b12.json"
            capacity_effect = self._existing_effect(journal, "capacity-receipt")
            if capacity_effect:
                capacity = self._read_json(capacity_path)
                if capacity_effect.get("payload", {}).get("receipt_sha256") != _sha256_file(capacity_path) or capacity.get("reserved") is not True:
                    raise MigrationError("B12 durable capacity receipt is missing or changed")
                plan = CapacityPlan({}, int(capacity.get("margin_bytes", 0)))
                for record in capacity.get("domains", []):
                    if not isinstance(record, Mapping) or not record.get("domain_id"):
                        raise MigrationError("B12 durable capacity receipt has no storage-domain identity")
                    domain = StorageDomain.identify(record.get("probe_path", ""))
                    if domain.key != record.get("domain_id") or int(domain.device) != int(record.get("device")) or domain.mount != record.get("mount"):
                        raise MigrationError("B12 durable capacity receipt storage domain changed")
                    domain.roots = {str(key): int(value) for key, value in dict(record.get("roots", {})).items()}
                    domain.required_bytes = int(record.get("required_bytes"))
                    plan.domains[domain.key] = domain
            else:
                capacity = self._capacity(inventory, evidence_root)
                plan = self._capacity_plan
            reservation_effect = self._existing_effect(journal, "capacity-reservation")
            if reservation_effect:
                reservation_payload = reservation_effect.get("payload", {})
                if reservation_payload.get("required_bytes") != capacity["required_bytes"] or reservation_payload.get("domain_ids") != sorted(plan.domains):
                    raise MigrationError("B12 capacity reservation conflicts with its durable receipt")
                reservation_id = str(reservation_payload["reservation_id"])
            else:
                reservation_id = secrets.token_urlsafe(18)
            reservation = CapacityReservation.acquire(plan=plan, reservation_id=reservation_id)
            object.__setattr__(self, "_capacity_reservation", reservation)
            stack.callback(reservation.release)
            immediate_free = reservation.recheck()
            if not capacity_effect:
                # The receipt is itself a lifecycle write; publish it only
                # after the storage-domain lock and immediate free-space
                # recheck have succeeded.
                _write_json(capacity_path, capacity)
                journal.effect("capacity-receipt", path=str(capacity_path), receipt_sha256=_sha256_file(capacity_path), required_bytes=capacity["required_bytes"], available_bytes=capacity["available_bytes"])
            if reservation_effect:
                if reservation_effect.get("payload", {}).get("recheck_available_bytes") is None:
                    raise MigrationError("B12 capacity reservation receipt is incomplete")
            else:
                journal.effect("capacity-reservation", path=str(reservation.path) if reservation.path else None, domain_ids=sorted(plan.domains), reservation_id=reservation_id, required_bytes=int(capacity["required_bytes"]), recheck_available_bytes=immediate_free)
            if current["state"] == "prepared":
                freeze_path = evidence_root / "source-freeze-b12.json"
                freeze_effect = self._existing_effect(journal, "source-freeze")
                if freeze_effect:
                    freeze = self._read_json(freeze_path)
                    if freeze.get("source_manifest_sha256") != source_manifest_sha256 or freeze.get("source_facts_sha256") != inventory["source_facts_sha256"] or freeze.get("writer", {}).get("stopped") is not True:
                        raise MigrationError("B12 durable source freeze is not bound to the writer-stop receipt")
                    byte_path = evidence_root / "source-byte-manifest-b12.json"
                    byte_manifest = self._read_json(byte_path)
                    if byte_manifest.get("source_manifest_sha256") != source_manifest_sha256 or byte_manifest.get("source_facts_sha256") != inventory["source_facts_sha256"] or byte_manifest.get("files_sha256") != inventory["files_sha256"] or byte_manifest.get("database_sha256") != inventory["database_sha256"]:
                        raise MigrationError("B12 durable source byte manifest changed")
                else:
                    freeze = {"packet": "B12.1", "state": "frozen", "source_manifest_sha256": source_manifest_sha256, "source_tree_sha256": _tree_digest(self.config.source_root), "source_facts_sha256": inventory["source_facts_sha256"], "writer": writer_receipt, "created_at": time.time()}
                if not freeze_effect:
                    _write_json(freeze_path, freeze)
                    byte_manifest = {"packet": "B12.1", "source_manifest_sha256": source_manifest_sha256, "source_facts_sha256": inventory["source_facts_sha256"], "database_sha256": inventory["database_sha256"], "files": inventory["files"], "files_sha256": inventory["files_sha256"], "created_at": time.time()}
                    _write_json(evidence_root / "source-byte-manifest-b12.json", byte_manifest)
                    journal.effect("source-freeze", path=str(freeze_path), source_manifest_sha256=source_manifest_sha256, source_byte_manifest_sha256=inventory["files_sha256"])
                writer_path = evidence_root / "writer-freeze-receipt-b12.json"
                if not self._existing_effect(journal, "writer-freeze-receipt"):
                    _write_json(writer_path, freeze | {"authorization_id": "AUTH-WRITER-STOP-B12"})
                    journal.effect("writer-freeze-receipt", path=str(writer_path), source_manifest_sha256=source_manifest_sha256)
                dry_path = evidence_root / "dry-run-receipt-b12.json"
                dry_effect = self._existing_effect(journal, "dry-run-receipt")
                if dry_effect:
                    dry_run = self._read_json(dry_path)["report"]
                else:
                    dry_config = replace(self.config, dry_run=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
                    dry_run = Migrator(dry_config, None).migrate()
                    _write_json(dry_path, {"packet": "B12.1", "source_manifest_sha256": source_manifest_sha256, "report": dry_run})
                    journal.effect("dry-run-receipt", path=str(dry_path), source_manifest_sha256=source_manifest_sha256)
                reservation.recheck()
                active_binding = {"packet": "B12.1", "kind": "rollback-archive", "selected_realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256}
                active_backup = self._backup_or_reuse(active, active_backup_root, binding=active_binding, journal=journal, effect_name="pre-migration-backup", seam="active_backup")
                baseline_effect = self._existing_effect(journal, "active-baseline")
                if not baseline_effect:
                    baseline_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                    baseline_payload = {"semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(baseline_snapshot)), "database_sha256": _database_snapshot_sha256(active.store.db_path, connection=active.store.conn, owner_lock=active.store._mutex), "realm_id": realm_id}
                    journal.effect("active-baseline", **baseline_payload)
                self._consume_authorization("AUTH-LIVE-MIGRATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)

                if _has_symlink_component(self.config.destination_root):
                    raise MigrationError("B12 destination must not contain a symlink component")
                reservation.recheck()
                # Create/open the destination root relative to its retained
                # parent, and keep cwd pinned while the runtime performs its
                # startup migrations and control writes.
                destination_pin = _capture_parent(self.config.destination_root, require_fresh_target=not os.path.lexists(str(self.config.destination_root)))
                destination_parent_fd = -1
                destination_root_fd = -1
                try:
                    destination_parent_fd, destination_name = _ensure_parent_at(self.config.destination_root, destination_pin)
                    _validate_parent(self.config.destination_root, destination_pin, allow_parent_appeared=True)
                    destination_exists = os.path.lexists(str(self.config.destination_root))
                    if not destination_exists:
                        try:
                            os.mkdir(destination_name, 0o700, dir_fd=destination_parent_fd)
                        except FileExistsError:
                            raise MigrationError("B12 destination appeared before runtime initialization")
                    _validate_created_parent(self.config.destination_root, destination_pin, destination_parent_fd)
                    # Retain the newly created/existing root itself before
                    # invoking the runtime. Opening it with O_NOFOLLOW closes
                    # the final name-to-inode gap after the mkdir seam; cwd is
                    # then pinned to this descriptor for all startup writes.
                    destination_root_fd = os.open(destination_name, _DIR_FLAGS, dir_fd=destination_parent_fd)
                    root_stat = os.fstat(destination_root_fd)
                    named_stat = os.stat(destination_name, dir_fd=destination_parent_fd, follow_symlinks=False)
                    if (int(root_stat.st_dev), int(root_stat.st_ino), int(root_stat.st_mode)) != (int(named_stat.st_dev), int(named_stat.st_ino), int(named_stat.st_mode)):
                        raise MigrationError("B12 destination root identity changed before runtime initialization")
                    cwd_fd = os.open(".", _DIR_FLAGS)
                    try:
                        os.fchdir(destination_root_fd)
                        try:
                            destination = type(active)(Path("."), display_name=active.realm["display_name"], realm_id=realm_id)
                        except Exception as exc:
                            # A resumed destination is an authenticated
                            # migration artifact, not a fresh service. Let
                            # reconciliation report that its durable state
                            # changed instead of leaking a startup admission
                            # failure through the B12 protocol. Any failure
                            # at this seam means the retained destination is
                            # no longer a valid migration artifact.
                            raise MigrationError("B12 destination changed before reconciliation") from exc
                    finally:
                        os.fchdir(cwd_fd)
                        os.close(cwd_fd)
                finally:
                    if destination_root_fd >= 0:
                        os.close(destination_root_fd)
                    if destination_parent_fd >= 0 and destination_parent_fd != destination_pin.get("_parent_fd"):
                        os.close(destination_parent_fd)
                    _close_pinned(destination_pin)
                destination_adapter = RuntimeServiceAdapter(destination)
                try:
                    migration_effect = self._existing_effect(journal, "migration-receipt")
                    migration_baseline_effect = self._existing_effect(journal, "migration-baseline")
                    destination_baseline_effect = self._existing_effect(journal, "destination-baseline")
                    # Validate every durable destination checkpoint before
                    # replaying the migration kernel.  Otherwise a deleted or
                    # edited destination row could be silently recreated by
                    # idempotent import during resume.
                    if migration_effect and not migration_baseline_effect:
                        raise MigrationError("B12 migration baseline is missing before reconciliation")
                    if migration_baseline_effect:
                        self._assert_destination_baseline(destination, migration_baseline_effect.get("payload", {}))
                    if destination_baseline_effect:
                        self._assert_destination_baseline(destination, destination_baseline_effect.get("payload", {}))
                    if migration_effect:
                        migration = self._read_json(evidence_root / "migration-receipt-b12.json")["report"]
                    else:
                        live_config = replace(self.config, require_destination_verification=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
                        journal._inject("before_migration")
                        reservation.recheck()
                        migration = Migrator(live_config, destination_adapter).migrate()
                        migration_baseline = self._destination_truth(destination)
                        journal.effect("migration-baseline", **migration_baseline)
                        journal._inject("after_migration")
                        self._assert_destination_baseline(destination, migration_baseline)
                        reservation.recheck()
                        _write_json(evidence_root / "migration-receipt-b12.json", {"packet": "B12.2", "migration_epoch": 1, "report": migration})
                        journal.effect("migration-receipt", path=str(evidence_root / "migration-receipt-b12.json"), source_manifest_sha256=source_manifest_sha256)
                    live_config = replace(self.config, require_destination_verification=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
                    reconciliation = self._revalidate_destination(live_config, inventory, destination, source_manifest_sha256=source_manifest_sha256)
                    if not reconciliation.get("ok"):
                        raise MigrationError("B12.2 reconciliation failed")
                    destination_baseline = self._destination_truth(destination)
                    baseline_effect = self._existing_effect(journal, "destination-baseline")
                    if baseline_effect:
                        if baseline_effect.get("payload") != destination_baseline:
                            # A crash/resume may reopen the destination and
                            # refresh only runtime control metadata; semantic
                            # content must still match the original receipt.
                            self._assert_destination_baseline(destination, baseline_effect.get("payload", {}))
                        destination_baseline = baseline_effect.get("payload", {})
                    else:
                        journal.effect("destination-baseline", **destination_baseline)
                    destination_binding = {"packet": "B12.2", "kind": "destination", "selected_realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "reconciliation": reconciliation}
                    reservation.recheck()
                    destination_backup = self._backup_or_reuse(destination, destination_backup_root, binding=destination_binding, journal=journal, effect_name="destination-backup", seam="destination_backup")
                    self._assert_destination_baseline(destination, destination_baseline)
                finally:
                    destination.close()

                reservation.recheck()
                # The extreme path retains the historical standalone restore
                # candidate. Compact verifies the signed destination backup
                # and lets activate_destination copy it into its own
                # descriptor-pinned activation temporary, where the handoff
                # is written and verified.
                if self.config.redundancy == "extreme":
                    assert candidate_root is not None
                    candidate_result = self._restore_or_reuse(destination_backup_root, candidate_root, journal=journal, effect_name="candidate-restore", realm_id=realm_id, seam="candidate_restore", source_manifest_sha256=source_manifest_sha256)
                    destination_activation_manifest = self.config.destination_root / "activation-manifest.json"
                    if _has_symlink_component(destination_activation_manifest):
                        raise MigrationError("B12 destination activation manifest contains a symlink component")
                    if destination_activation_manifest.is_file() and not (candidate_root / "activation-manifest.json").is_file():
                        source_pin, source_fd, _ = _pin_directory(self.config.destination_root)
                        candidate_pin, candidate_fd, _ = _pin_directory(candidate_root)
                        try:
                            _copy_file_at(source_fd, "activation-manifest.json", candidate_fd, "activation-manifest.json")
                            os.fsync(candidate_fd)
                        finally:
                            os.close(source_fd)
                            os.close(candidate_fd)
                            _close_pinned(source_pin)
                            _close_pinned(candidate_pin)
                    candidate_verification = verify_restore_candidate(candidate_root)
                    candidate_result = candidate_result | {"verification": candidate_verification}
                    destination_binding = candidate_verification["manifest"].get("destination_binding") or {}
                    if (destination_binding.get("packet") != "B12.2" or destination_binding.get("selected_realm_id") != realm_id or destination_binding.get("source_manifest_sha256") != source_manifest_sha256):
                        raise MigrationError("B12.3 destination backup is not bound to the selected live migration")
                    candidate_db = candidate_verification["database_sha256"]
                else:
                    destination_verification = verify_backup(destination_backup_root)
                    destination_binding = destination_verification["manifest"].get("destination_binding") or {}
                    if (destination_binding.get("packet") != "B12.2" or destination_binding.get("selected_realm_id") != realm_id or destination_binding.get("source_manifest_sha256") != source_manifest_sha256):
                        raise MigrationError("B12.3 destination backup is not bound to the selected live migration")
                    candidate_result = {"destination": str(destination_backup_root), "source": "signed-destination-backup", "verification": destination_verification}
                    candidate_verification = destination_verification
                    candidate_db = destination_verification["manifest"]["database_sha256"]
                # Recheck the original destination itself: a mutation after
                # reconciliation/backup must not be hidden by an unchanged
                # activation source.
                self._verify_root_against_backup(self.config.destination_root, destination_backup_root, realm_id=realm_id)
                self._consume_authorization("AUTH-ACTIVATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
                self._cleanup_compact_quarantines(active)
                activation_effect = self._existing_effect(journal, "active-activation")
                if activation_effect:
                    activation_payload = activation_effect.get("payload", {})
                    if self.config.redundancy == "extreme":
                        reusable = activation_payload.get("candidate") == str(candidate_root) and candidate_root is not None and not _has_symlink_component(candidate_root) and self._active_matches_candidate(candidate_root, realm_id)
                    else:
                        reusable = activation_payload.get("candidate") == str(destination_backup_root) and self._active_matches_backup(destination_backup_root, realm_id)
                    if not reusable:
                        raise MigrationError("B12 durable active activation is not reusable")
                    activated = activation_effect["payload"]["activation"]
                elif ((self.config.redundancy == "extreme" and candidate_root is not None and self._active_matches_candidate(candidate_root, realm_id)) or (self.config.redundancy == "compact" and self._active_matches_backup(destination_backup_root, realm_id))):
                    activation_source = candidate_root if self.config.redundancy == "extreme" else destination_backup_root
                    activated = {"state": "active", "reused": True, "candidate": str(activation_source)}
                    journal.effect("active-activation", candidate=str(activation_source), state="active", activation=activated, database_sha256=candidate_db)
                else:
                    self._assert_active_baseline(journal, active)
                    # Capture the configured authority before the crash seam;
                    # the post-seam revalidation must run before any health or
                    # verification read can follow a swapped root.
                    reservation.recheck()
                    target_identity = capture_activation_path(active.store.root)
                    journal._inject("before_active_activation")
                    reservation.recheck()
                    revalidate_activation_path(active.store.root, target_identity)
                    self._assert_active_baseline(journal, active)
                    self._verify_root_against_backup(self.config.destination_root, destination_backup_root, realm_id=realm_id)
                    reservation.recheck()
                    revalidate_activation_path(active.store.root, target_identity)
                    activation_source = candidate_root if self.config.redundancy == "extreme" else destination_backup_root
                    activated = RuntimeServiceAdapter(active).activate_destination(activation_source, state="active", target_identity=target_identity, activation_manifest_source=(self.config.destination_root / "activation-manifest.json" if self.config.redundancy == "compact" else None), retain_quarantine=self.config.redundancy != "compact")
                    journal._inject("after_active_activation")
                    journal.effect("active-activation", candidate=str(activation_source), state="active", activation=activated, database_sha256=candidate_db)
                active_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                active_entry = journal.transition("active", source_manifest_sha256=source_manifest_sha256, destination=str(self.config.destination_root), destination_backup=str(destination_backup_root), activation=activated, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=1)
                _write_json(evidence_root / "activated-destination-b12-active.json", {"packet": "B12.3", "state": "active", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 1, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})
            else:
                active_entry = current
                source_manifest_sha256 = str(current["binding"]["source_manifest_sha256"])
                active_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                freeze = capacity = dry_run = migration = reconciliation = active_backup = destination_backup = None
                activated = None

            if journal._read()["state"] == "active":
                self._consume_authorization("AUTH-ROLLBACK-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
                reservation.recheck()
                rollback_result = self._restore_or_reuse(active_backup_root, rollback_root, journal=journal, effect_name="rollback-restore", realm_id=realm_id, seam="rollback_restore", source_manifest_sha256=source_manifest_sha256)
                rollback_verification = rollback_result["verification"]
                self._cleanup_compact_quarantines(active)
                rollback_effect = self._existing_effect(journal, "rollback-activation")
                if rollback_effect:
                    rollback_payload = rollback_effect.get("payload", {})
                    if (rollback_payload.get("candidate") != str(rollback_root) or _has_symlink_component(rollback_root) or not self._active_matches_candidate(rollback_root, realm_id)):
                        raise MigrationError("B12 durable rollback activation is not reusable")
                    rolled_back = rollback_effect["payload"]["activation"]
                elif self._active_matches_candidate(rollback_root, realm_id):
                    rolled_back = {"state": "rolled_back", "reused": True, "candidate": str(rollback_root)}
                    journal.effect("rollback-activation", candidate=str(rollback_root), state="rolled_back", activation=rolled_back, database_sha256=rollback_verification["database_sha256"])
                else:
                    reservation.recheck()
                    target_identity = capture_activation_path(active.store.root)
                    journal._inject("before_rollback_activation")
                    reservation.recheck()
                    revalidate_activation_path(active.store.root, target_identity)
                    rolled_back = RuntimeServiceAdapter(active).activate_destination(rollback_root, state="rolled_back", target_identity=target_identity, retain_quarantine=self.config.redundancy != "compact")
                    journal._inject("after_rollback_activation")
                    journal.effect("rollback-activation", candidate=str(rollback_root), state="rolled_back", activation=rolled_back, database_sha256=rollback_verification["database_sha256"])
                rollback_entry = journal.transition("rolled_back", predecessor=active_entry["entries"][-1], activation=rolled_back, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=2)
                _write_json(evidence_root / "activated-destination-b12-rollback.json", {"packet": "B12.3", "state": "rolled_back", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 2, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})
            else:
                rollback_entry = current
                rolled_back = None

            if journal._read()["state"] == "rolled_back":
                self._consume_authorization("AUTH-REACTIVATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
                reservation.recheck()
                if self.config.redundancy == "extreme":
                    assert reactivation_root is not None
                    reactivation_result = self._restore_or_reuse(destination_backup_root, reactivation_root, journal=journal, effect_name="reactivation-restore", realm_id=realm_id, seam="reactivation_restore", source_manifest_sha256=source_manifest_sha256)
                    reactivation_verification = reactivation_result["verification"]
                else:
                    reactivation_verification = verify_backup(destination_backup_root)
                    reactivation_result = {"destination": str(destination_backup_root), "source": "signed-destination-backup", "verification": reactivation_verification}
                self._cleanup_compact_quarantines(active)
                reactivation_effect = self._existing_effect(journal, "reactivation-activation")
                if reactivation_effect:
                    reactivation_payload = reactivation_effect.get("payload", {})
                    if self.config.redundancy == "extreme":
                        reusable = reactivation_payload.get("candidate") == str(reactivation_root) and reactivation_root is not None and not _has_symlink_component(reactivation_root) and self._active_matches_candidate(reactivation_root, realm_id)
                    else:
                        reusable = reactivation_payload.get("candidate") == str(destination_backup_root) and self._active_matches_backup(destination_backup_root, realm_id)
                    if not reusable:
                        raise MigrationError("B12 durable reactivation activation is not reusable")
                    reactivated = reactivation_effect["payload"]["activation"]
                elif ((self.config.redundancy == "extreme" and reactivation_root is not None and self._active_matches_candidate(reactivation_root, realm_id)) or (self.config.redundancy == "compact" and self._active_matches_backup(destination_backup_root, realm_id))):
                    activation_source = reactivation_root if self.config.redundancy == "extreme" else destination_backup_root
                    reactivated = {"state": "reactivated", "reused": True, "candidate": str(activation_source)}
                    database_sha256 = reactivation_verification.get("database_sha256") or reactivation_verification["manifest"].get("database_sha256")
                    journal.effect("reactivation-activation", candidate=str(activation_source), state="reactivated", activation=reactivated, database_sha256=database_sha256)
                else:
                    reservation.recheck()
                    target_identity = capture_activation_path(active.store.root)
                    journal._inject("before_reactivation_activation")
                    reservation.recheck()
                    revalidate_activation_path(active.store.root, target_identity)
                    activation_source = reactivation_root if self.config.redundancy == "extreme" else destination_backup_root
                    reactivated = RuntimeServiceAdapter(active).activate_destination(activation_source, state="reactivated", target_identity=target_identity, activation_manifest_source=(self.config.destination_root / "activation-manifest.json" if self.config.redundancy == "compact" else None), retain_quarantine=self.config.redundancy != "compact")
                    journal._inject("after_reactivation_activation")
                    database_sha256 = reactivation_verification.get("database_sha256") or reactivation_verification["manifest"].get("database_sha256")
                    journal.effect("reactivation-activation", candidate=str(activation_source), state="reactivated", activation=reactivated, database_sha256=database_sha256)
                final_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                if not active.doctor().get("ok"):
                    raise MigrationError("B12.4 final runtime failed integrity verification")
                artifacts = self._runtime_artifact_identity(active, source_manifest_sha256=source_manifest_sha256)
                identity = {"packet": "B12.4", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "destination_root": str(active.store.root), "runtime_epoch": active.health()["runtime_epoch"], "runtime_session_id": active.runtime_session_id, "activation_epoch": 3, "source_backup_manifest_sha256": _sha256_file(active_backup_root / "manifest.json"), "destination_backup_manifest_sha256": _sha256_file(destination_backup_root / "manifest.json"), "active_database_sha256": _database_snapshot_sha256(active.store.db_path, connection=active.store.conn, owner_lock=active.store._mutex), "active_database_semantic_sha256": _database_semantic_sha256(active.store.db_path), "active_semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(final_snapshot)), "active_cas_manifest_sha256": self._cas_manifest_digest(final_snapshot), "activation_manifest_sha256": artifacts["activation_manifest_sha256"], "catalog_identity": artifacts["catalog"], "active_snapshot_counts": {key: len(value) for key, value in final_snapshot.items() if isinstance(value, list)}}
                _write_json(evidence_root / "activated-destination-b12-reactivated.json", {"packet": "B12.3", "state": "reactivated", **{key: identity[key] for key in ("realm_id", "source_manifest_sha256", "activation_epoch", "runtime_epoch", "active_database_sha256")}})
                journal.effect("final-identity", identity=identity)
                journal.effect("capacity-release", reservation_id=reservation.reservation_id, reason="terminal")
                reservation.release()
                final = journal.transition("reactivated", predecessor=rollback_entry["entries"][-1], activation=reactivated, identity=identity, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=3)
                _write_json(evidence_root / "activated-destination-b12.json", identity)
                return {"packet": "B12", "source_freeze": freeze, "capacity": capacity, "dry_run": dry_run, "migration": migration, "reconciliation": reconciliation, "active_backup": active_backup, "destination_backup": destination_backup, "journal": final, "activation": activated, "rollback": rolled_back, "reactivation": reactivated, "identity": identity, "active_snapshot": active_snapshot, "final_snapshot": final_snapshot}
            raise MigrationError("B12 live migration did not reach a resumable terminal state")


def run_live_migration(config: MigrationConfig, active_runtime: Any, authorizations: Mapping[str, Mapping[str, Any]], *, writer_stop: Callable[[], Any], fault_injector: Callable[[str], None] | None = None, crash_at: str | None = None) -> dict[str, Any]:
    """Run the serialized B12 flow against a selected disposable runtime."""
    return LiveMigration(config, active_runtime, authorizations, writer_stop, fault_injector=fault_injector, crash_at=crash_at).run()


__all__ = ["LIVE_AUTHORIZATION_IDS", "LiveMigration", "issue_live_authorizations", "run_live_migration"]
