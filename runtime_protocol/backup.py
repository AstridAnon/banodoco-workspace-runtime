"""Consistent local backup, verification, restore, and structured export.

Backups are self-contained directories.  SQLite is copied with the online
backup API while the realm writer is held, and every append-only CAS object is
copied alongside a digest manifest.  Restore never replaces an existing realm;
it prepares a new directory and atomically renames it into place only after
SQLite, foreign keys, and every CAS hash pass verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from pathlib import Path
import stat
from typing import Any, Mapping

from .errors import ConflictError, NotFoundError, ValidationError
from .util import canonical_json, now
from .dirfd import (
    absolute_path,
    capture_parent,
    close_pinned,
    copy_file_at,
    copy_tree_at,
    ensure_parent_at,
    mkdir_chain_at,
    mkdir_temp_at,
    open_directory_chain,
    pin_directory,
    remove_tree_at,
    validate_created_parent,
    validate_parent,
    write_bytes_at,
)


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _open_relative(root_fd: int, relative: str | Path, *, directory: bool = False) -> int:
    """Open a relative file/dir without resolving a path from the process cwd."""
    relative = Path(relative)
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValidationError("invalid descriptor-relative path")
    parts = list(relative.parts)
    current = root_fd
    opened: list[int] = []
    try:
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = (os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if (directory or not final) else 0) | getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(part, flags, dir_fd=current)
            if current != root_fd:
                opened.append(current)
            current = fd
        for fd in opened:
            os.close(fd)
        return current
    except Exception:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass
        if current != root_fd:
            try:
                os.close(current)
            except OSError:
                pass
        raise


def _sha256_at(root_fd: int, relative: str | Path) -> tuple[str, int]:
    fd = _open_relative(root_fd, relative)
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise ConflictError(f"backup entry is not a regular file: {relative}")
        os.lseek(fd, 0, os.SEEK_SET)
        return _sha256_fd(fd), int(value.st_size)
    finally:
        os.close(fd)


def _json_at(root_fd: int, name: str) -> dict:
    fd = _open_relative(root_fd, name)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        data = b""
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data += chunk
        value = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise ConflictError(f"backup artifact is invalid: {name}") from exc
    finally:
        os.close(fd)
    if not isinstance(value, dict):
        raise ConflictError(f"backup artifact must be an object: {name}")
    return value


def _file_record_at(root_fd: int, name: str) -> dict:
    digest, size = _sha256_at(root_fd, name)
    return {"sha256": digest, "size": size}


def _authenticated_digest(payload: dict) -> str:
    """Digest a JSON object using the runtime's canonical wire encoding."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _auth_payload(value: dict) -> dict:
    return {key: item for key, item in value.items() if key not in {"manifest_sha256", "manifest_hmac", "handoff_sha256", "handoff_hmac"}}


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:32]


def _provision_key(path: Path, *, rotate: bool = False) -> bytes:
    """Provision a private operator key outside the backup directory."""
    path = absolute_path(path)
    if not rotate:
        identity = capture_parent(path)
        fd = -1
        try:
            validate_parent(path, identity, allow_parent_appeared=True)
            fd = _open_relative(int(identity["_parent_fd"]), path.relative_to(Path(str(identity["parent"]))))
        except FileNotFoundError:
            pass
        else:
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ConflictError("backup authentication key is not a regular file")
                key = b""
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    key += chunk
                validate_parent(path, identity, allow_parent_appeared=True)
            finally:
                os.close(fd)
                close_pinned(identity)
            if len(key) < 32:
                raise ConflictError("backup authentication key is too short")
            return key
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            close_pinned(identity)
    key = os.urandom(32)
    identity = capture_parent(path)
    try:
        parent_fd, name = ensure_parent_at(path, identity)
        try:
            validate_parent(path, identity, allow_parent_appeared=True)
            write_bytes_at(parent_fd, name, key, mode=stat.S_IRUSR | stat.S_IWUSR)
            os.fsync(parent_fd)
        finally:
            if parent_fd != identity.get("_parent_fd"):
                os.close(parent_fd)
    finally:
        close_pinned(identity)
    return key


def provision_backup_key(path: str | Path, *, rotate: bool = False) -> dict:
    """Provision/rotate a backup key without placing it in any backup.

    Rotation intentionally leaves existing backups bound to their old key;
    operators can verify those backups by supplying the retained old key via
    ``verify_backup(..., key=...)``.
    """
    key = _provision_key(Path(path), rotate=rotate)
    return {"path": str(Path(path).expanduser().resolve()), "key_id": _key_id(key), "algorithm": "hmac-sha256"}


def _resolve_key(manifest: dict, *, key: bytes | None = None, key_path: str | Path | None = None) -> bytes:
    if key is not None:
        value = bytes(key)
    else:
        auth = manifest.get("authentication")
        if not isinstance(auth, dict):
            raise ConflictError("backup authentication metadata is missing")
        candidate = key_path or auth.get("key_path")
        if not candidate:
            raise ConflictError("backup authentication key is not provisioned")
        path = absolute_path(str(candidate))
        identity = capture_parent(path)
        fd = -1
        try:
            validate_parent(path, identity, allow_parent_appeared=True)
            parent = Path(str(identity["parent"]))
            fd = _open_relative(int(identity["_parent_fd"]), path.relative_to(parent))
            key_stat = os.fstat(fd)
            if not stat.S_ISREG(key_stat.st_mode):
                raise ConflictError("backup authentication key is unavailable")
            value = b""
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                value += chunk
            validate_parent(path, identity, allow_parent_appeared=True)
        except FileNotFoundError as exc:
            raise ConflictError("backup authentication key is unavailable") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            close_pinned(identity)
    if len(value) < 32:
        raise ConflictError("backup authentication key is too short")
    auth = manifest.get("authentication")
    if not isinstance(auth, dict) or auth.get("algorithm") != "hmac-sha256" or auth.get("key_id") != _key_id(value):
        raise ConflictError("backup authentication key does not match manifest realm")
    return value


def _manifest_mac(manifest: dict, key: bytes) -> str:
    return hmac.new(key, canonical_json(_auth_payload(manifest)).encode("utf-8"), hashlib.sha256).hexdigest()


def _manifest_digest_payload(manifest: dict) -> dict:
    return {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "manifest_hmac"}}


def _handoff_digest_payload(handoff: dict) -> dict:
    return {key: value for key, value in handoff.items() if key not in {"handoff_sha256", "handoff_hmac"}}


def _object_path(cas_root: Path, digest: str) -> Path:
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValidationError("invalid CAS digest")
    return cas_root / digest[:2] / digest[2:]


def cas_manifest(store, *, cas_root: Path | None = None, cas_root_fd: int | None = None) -> dict:
    root = Path(cas_root or store.cas_root)
    own_cas_fd = cas_root_fd is None
    if cas_root_fd is None:
        # Preserve the public helper while ensuring even this entry point uses
        # one retained descriptor for every object read.
        cas_root_fd = open_directory_chain(root)
    rows = store.conn.execute("SELECT digest, size, media_type, original_name, created_at FROM objects ORDER BY digest").fetchall()
    try:
        objects = []
        for row in rows:
            digest = row["digest"]
            try:
                actual_hash, actual_size = _sha256_at(cas_root_fd, f"{digest[:2]}/{digest[2:]}")
            except OSError as exc:
                raise NotFoundError("CAS object is missing", details={"digest": digest}) from exc
            if actual_hash != digest or actual_size != int(row["size"]):
                raise ConflictError("CAS object failed backup verification", details={"digest": digest, "actual_digest": actual_hash, "actual_size": actual_size})
            objects.append({"digest": digest, "size": actual_size, "sha256": actual_hash, "media_type": row["media_type"], "original_name": row["original_name"], "created_at": row["created_at"]})
        payload = {"format_version": 1, "objects": objects}
        encoded = canonical_json(payload).encode()
        return payload | {"manifest_sha256": hashlib.sha256(encoded).hexdigest()}
    finally:
        if own_cas_fd:
            os.close(cas_root_fd)


def _verify_cas_manifest(root_fd: int, manifest: dict) -> None:
    expected_manifest_hash = manifest.get("manifest_sha256")
    payload = {"format_version": manifest.get("format_version"), "objects": manifest.get("objects", [])}
    if expected_manifest_hash != hashlib.sha256(canonical_json(payload).encode()).hexdigest():
        raise ConflictError("CAS manifest hash mismatch")
    cas_root_fd = _open_relative(root_fd, "cas/sha256", directory=True)
    try:
        for obj in payload["objects"]:
            digest = str(obj.get("digest", ""))
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ConflictError("backup CAS manifest contains an invalid digest")
            try:
                actual_hash, actual_size = _sha256_at(cas_root_fd, f"{digest[:2]}/{digest[2:]}")
            except OSError as exc:
                raise ConflictError("backup CAS object is missing", details={"digest": digest}) from exc
            if actual_size != int(obj["size"]) or actual_hash != obj["sha256"] or obj["sha256"] != digest:
                raise ConflictError("backup CAS object failed verification", details={"digest": obj.get("digest")})
    finally:
        os.close(cas_root_fd)


def _connection_from_fd(root_fd: int, name: str) -> sqlite3.Connection:
    """Open SQLite through a duplicated, already-pinned descriptor.

    ``immutable`` prevents SQLite from consulting sibling WAL/journal paths;
    the URI is only a kernel descriptor alias and never resolves the lexical
    backup pathname.
    """
    fd = _open_relative(root_fd, name)
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise ConflictError(f"backup SQLite entry is not a regular file: {name}")
        sqlite_fd = os.dup(fd)
        try:
            connection = sqlite3.connect(f"file:/dev/fd/{sqlite_fd}?immutable=1", uri=True)
            os.close(sqlite_fd)
            return connection
        except Exception:
            os.close(sqlite_fd)
            raise
    finally:
        os.close(fd)


def _reject_sqlite_sidecars(root_fd: int, *, label: str) -> None:
    """Enforce the consolidated backup/candidate database contract.

    Live realms may legitimately carry WAL state and startup admission keeps
    it. Backups and their restore candidates are different: the online backup
    API has already folded committed state into one authenticated database.
    Accepting an unmanifested sidecar here would make later activation observe
    bytes that verification deliberately ignored.
    """
    for suffix in ("-wal", "-shm", "-journal"):
        name = "realm.sqlite3" + suffix
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ConflictError(f"{label} contains an unmanifested SQLite sidecar", details={"file": name})


def _inspect_consolidated_realm(root_fd: int) -> tuple[dict, dict]:
    """Run the full RealmStore doctor logic over an immutable descriptor DB."""
    from .store import RealmStore

    connection = _connection_from_fd(root_fd, "realm.sqlite3")
    connection.row_factory = sqlite3.Row
    inspector = object.__new__(RealmStore)
    # Keep CAS reads rooted at the retained directory descriptor. This is a
    # read-only /dev/fd alias; no candidate pathname is reopened.
    inspector.root = Path(f"/dev/fd/{root_fd}")
    inspector.db_path = inspector.root / "realm.sqlite3"
    inspector.cas_root = inspector.root / "cas" / "sha256"
    try:
        inspector._cas_root_fd = _open_relative(root_fd, "cas/sha256", directory=True)
    except FileNotFoundError:
        inspector._cas_root_fd = -1
    inspector.conn = connection
    inspector._mutex = threading.RLock()
    try:
        report = inspector.integrity_report()
        if not report.get("ok"):
            raise ConflictError("realm failed integrity checks", details=report)
        realm = inspector.realm
        return report, realm
    finally:
        connection.close()
        if inspector._cas_root_fd >= 0:
            os.close(inspector._cas_root_fd)


def verify_backup(backup_dir: str | Path, *, key: bytes | None = None, key_path: str | Path | None = None, directory_identity: Mapping[str, Any] | None = None) -> dict:
    """Verify a backup while retaining its lexical parent for the whole read."""
    root = absolute_path(backup_dir)
    own_identity = directory_identity is None
    identity = directory_identity or capture_parent(root)
    try:
        return _verify_backup_pinned(root, key=key, key_path=key_path, directory_identity=identity)
    finally:
        if own_identity:
            close_pinned(identity)


def _verify_backup_pinned(backup_dir: str | Path, *, key: bytes | None = None, key_path: str | Path | None = None, directory_identity: Mapping[str, Any]) -> dict:
    root = absolute_path(backup_dir)
    backup_fd = -1
    try:
        try:
            validate_parent(root, directory_identity, allow_parent_appeared=bool(directory_identity.get("parent_was_missing")))
            parent_fd = int(directory_identity["_parent_fd"])
            parent_path = Path(str(directory_identity["parent"]))
            relative = root.relative_to(parent_path)
            backup_fd = _open_relative(parent_fd, relative, directory=True)
            _reject_sqlite_sidecars(backup_fd, label="backup")
            manifest = _json_at(backup_fd, "manifest.json")
        except FileNotFoundError as exc:
            raise NotFoundError("backup is incomplete", details={"backup": str(root)}) from exc
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise ConflictError("backup manifest is invalid") from exc
        if not isinstance(manifest, dict):
            raise ConflictError("backup manifest must be an object")
        format_version = manifest.get("format_version")
        if format_version == 2:
            digest = manifest.get("manifest_sha256")
            mac = manifest.get("manifest_hmac")
            if not isinstance(digest, str) or not hmac.compare_digest(digest, _authenticated_digest(_manifest_digest_payload(manifest))):
                raise ConflictError("backup manifest authentication failed (public digest mismatch)")
            auth_key = _resolve_key(manifest, key=key, key_path=key_path)
            if not isinstance(mac, str) or not hmac.compare_digest(mac, _manifest_mac(manifest, auth_key)):
                raise ConflictError("backup manifest authentication failed")
            realm_meta = manifest.get("realm")
            schema_meta = manifest.get("schema")
            files = manifest.get("files")
            if not isinstance(realm_meta, dict) or not realm_meta.get("id") or not isinstance(schema_meta, dict) or not isinstance(schema_meta.get("version"), int) or not isinstance(files, dict):
                raise ConflictError("backup manifest metadata is incomplete")
            if manifest.get("realm_id") != realm_meta["id"] or manifest.get("schema_version") != schema_meta["version"]:
                raise ConflictError("backup manifest metadata aliases mismatch")
            for name in ("realm.sqlite3", "cas-manifest.json"):
                record = files.get(name)
                actual_hash, actual_size = _sha256_at(backup_fd, name)
                if not isinstance(record, dict) or record.get("sha256") != actual_hash or int(record.get("size", -1)) != actual_size:
                    raise ConflictError("backup file digest mismatch", details={"file": name})
        elif format_version == 1:
            raise ConflictError("legacy backup format requires explicit migration")
        else:
            raise ConflictError("unsupported backup format", details={"format_version": format_version})
        if manifest.get("database_sha256") != _sha256_at(backup_fd, "realm.sqlite3")[0]:
            raise ConflictError("backup SQLite hash mismatch")
        try:
            cas = _json_at(backup_fd, "cas-manifest.json")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise ConflictError("backup CAS manifest is invalid") from exc
        if manifest.get("cas_manifest_sha256") != cas.get("manifest_sha256"):
            raise ConflictError("backup CAS manifest hash mismatch")
        _verify_cas_manifest(backup_fd, cas)
        report, realm = _inspect_consolidated_realm(backup_fd)
        if not realm or realm["id"] != manifest.get("realm_id"):
            raise ConflictError("backup realm identity mismatch")
        validate_parent(root, directory_identity, allow_parent_appeared=bool(directory_identity.get("parent_was_missing")))
        return {"manifest": manifest, "cas_manifest": cas, "doctor": report}
    finally:
        if backup_fd >= 0:
            os.close(backup_fd)


def verify_restore_candidate(candidate_dir: str | Path, *, directory_identity: Mapping[str, Any] | None = None) -> dict:
    """Verify a restored realm against its immutable backup handoff.

    This must run immediately before every activation and reuse.  In
    particular, a database edit (including an extra project) changes the
    candidate digest and is rejected before the active realm is touched.
    """
    root = absolute_path(candidate_dir)
    own_identity = directory_identity is None
    directory_identity = directory_identity or capture_parent(root)
    candidate_fd = -1
    source_fd = -1
    source_identity = None
    try:
        validate_parent(root, directory_identity, allow_parent_appeared=bool(directory_identity.get("parent_was_missing")))
        parent_fd = int(directory_identity.get("_parent_fd"))
        parent_path = Path(str(directory_identity["parent"]))
        if root.parent == parent_path:
            candidate_fd = os.open(root.name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        else:
            relative = root.relative_to(parent_path)
            candidate_fd = os.open(str(relative), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        if not stat.S_ISDIR(os.fstat(candidate_fd).st_mode):
            raise ConflictError("restore candidate is not an ordinary directory")
        _reject_sqlite_sidecars(candidate_fd, label="restore candidate")
        try:
            handoff = _json_at(candidate_fd, "activation-handoff.json")
            candidate_db_hash, _ = _sha256_at(candidate_fd, "realm.sqlite3")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise ConflictError("restore candidate is incomplete or invalid") from exc
        source_backup = absolute_path(str(handoff.get("source_backup", "")))
        source_identity, source_fd, _ = pin_directory(source_backup)
        verified = verify_backup(source_backup, directory_identity=source_identity)
        source_manifest = verified["manifest"]
        if handoff.get("format_version") != 2:
            raise ConflictError("legacy restore handoff requires explicit migration")
        handoff_digest = handoff.get("handoff_sha256")
        handoff_mac = handoff.get("handoff_hmac")
        auth_key = _resolve_key(source_manifest)
        if not isinstance(handoff_digest, str) or not hmac.compare_digest(handoff_digest, _authenticated_digest(_handoff_digest_payload(handoff))):
            raise ConflictError("restore handoff authentication failed")
        if not isinstance(handoff_mac, str) or not auth_key or not hmac.compare_digest(handoff_mac, hmac.new(auth_key, canonical_json(_auth_payload(handoff)).encode("utf-8"), hashlib.sha256).hexdigest()):
            raise ConflictError("restore handoff authentication failed")
        source_manifest_hash, _ = _sha256_at(source_fd, "manifest.json")
        if handoff.get("source_manifest_sha256") != source_manifest_hash:
            raise ConflictError("restore handoff source manifest mismatch")
        if handoff.get("realm_id") != source_manifest.get("realm_id"):
            raise ConflictError("restore candidate realm does not match its backup")
        if handoff.get("candidate_database_sha256") != candidate_db_hash or candidate_db_hash != source_manifest.get("database_sha256"):
            raise ConflictError("restore candidate SQLite bytes differ from its verified backup")
        expected_objects = {str(item["digest"]): item for item in verified["cas_manifest"].get("objects", [])}
        actual_objects = {}
        cas_fd = os.open("cas", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=candidate_fd)
        sha_fd = os.open("sha256", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=cas_fd)
        try:
            for entry in os.scandir(sha_fd):
                if not entry.is_dir(follow_symlinks=False):
                    continue
                prefix = entry.name
                prefix_fd = os.open(prefix, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=sha_fd)
                try:
                    for obj in os.scandir(prefix_fd):
                        if obj.is_file(follow_symlinks=False):
                            actual_objects[prefix + obj.name] = (prefix, obj.name)
                finally:
                    os.close(prefix_fd)
        finally:
            os.close(sha_fd)
            os.close(cas_fd)
        if set(actual_objects) != set(expected_objects):
            raise ConflictError("restore candidate CAS object set differs from its verified backup")
        cas_fd = os.open("cas", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=candidate_fd)
        sha_fd = os.open("sha256", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=cas_fd)
        try:
            for digest, item in expected_objects.items():
                prefix, name = actual_objects[digest]
                obj_fd = os.open(prefix, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=sha_fd)
                try:
                    actual_hash, actual_size = _sha256_at(obj_fd, name)
                finally:
                    os.close(obj_fd)
                if actual_size != int(item["size"]) or actual_hash != item["sha256"]:
                    raise ConflictError("restore candidate CAS bytes differ from its verified backup", details={"digest": digest})
        finally:
            os.close(sha_fd)
            os.close(cas_fd)
        report, realm = _inspect_consolidated_realm(candidate_fd)
        if not realm or realm["id"] != source_manifest.get("realm_id"):
            raise ConflictError("restore candidate realm identity mismatch")
        validate_parent(root, directory_identity, allow_parent_appeared=bool(directory_identity.get("parent_was_missing")))
        return {"handoff": handoff, "manifest": source_manifest, "doctor": report, "database_sha256": candidate_db_hash, "cas_manifest_sha256": verified["cas_manifest"].get("manifest_sha256")}
    finally:
        if candidate_fd >= 0:
            os.close(candidate_fd)
        if source_fd >= 0:
            os.close(source_fd)
        if source_identity is not None:
            close_pinned(source_identity)
        if own_identity:
            close_pinned(directory_identity)


def create_backup(store, destination: str | Path, *, binding: dict | None = None, key: bytes | None = None, key_path: str | Path | None = None, destination_identity: Mapping[str, Any] | None = None) -> dict:
    if getattr(store, "_lock_file", None) is None:
        raise ConflictError("backup requires the owning realm connection")
    destination = absolute_path(destination)
    if os.path.lexists(str(destination)):
        raise ConflictError("backup destination already exists", details={"destination": str(destination)})
    own_destination_identity = destination_identity is None
    destination_identity = destination_identity or capture_parent(destination, require_fresh_target=True)
    parent_fd = -1
    destination_name = None
    temporary_name = None
    temporary_fd = -1
    source_cas_fd = -1
    try:
        parent_fd, destination_name = ensure_parent_at(destination, destination_identity)
        temporary_name, temporary_fd = mkdir_temp_at(parent_fd, f".{destination.name}.")
        source_cas_fd = open_directory_chain(store.cas_root)
        cas_root_fd = mkdir_chain_at(temporary_fd, "cas/sha256")
        os.close(cas_root_fd)
        with store._mutex:
            # The live connection is already pinned to the selected realm.  Do
            # not reopen ``store.db_path`` by name after parent validation.
            cas = cas_manifest(store, cas_root=store.cas_root, cas_root_fd=source_cas_fd)
            cwd_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fchdir(parent_fd)
                target_db = Path(temporary_name) / "realm.sqlite3"
                target = sqlite3.connect(str(target_db))
            finally:
                os.fchdir(cwd_fd)
                os.close(cwd_fd)
            try:
                store.conn.backup(target)
                target.commit()
            finally:
                target.close()
            # A backup target may inherit WAL mode from the live connection.
            # The authenticated backup format contains one consolidated
            # database, so remove SQLite's target-only sidecars before the
            # directory is manifested and published.
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    os.unlink(f"realm.sqlite3{suffix}", dir_fd=temporary_fd)
                except FileNotFoundError:
                    pass
            for obj in cas["objects"]:
                obj_dir = mkdir_chain_at(temporary_fd, f"cas/sha256/{obj['digest'][:2]}")
                try:
                    copy_file_at(source_cas_fd, f"{obj['digest'][:2]}/{obj['digest'][2:]}", obj_dir, obj["digest"][2:])
                    os.fsync(obj_dir)
                finally:
                    os.close(obj_dir)
            write_bytes_at(temporary_fd, "cas-manifest.json", (canonical_json(cas) + "\n").encode())
            realm = store.realm
            schema_version = store.conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            auth_path = absolute_path(key_path or (store.root / ".operator-backup-key"))
            auth_key = bytes(key) if key is not None else _provision_key(auth_path)
            if len(auth_key) < 32:
                raise ConflictError("backup authentication key is too short")
            manifest = {
                "format_version": 2,
                "created_at": now(),
                "realm": {"id": realm["id"], "display_name": realm["display_name"]},
                "schema": {"version": schema_version},
                "files": {"realm.sqlite3": _file_record_at(temporary_fd, "realm.sqlite3"), "cas-manifest.json": _file_record_at(temporary_fd, "cas-manifest.json")},
                # Stable aliases make the transition readable to existing
                # operators while the authenticated envelope is authoritative.
                "schema_version": schema_version,
                "realm_id": realm["id"],
                "display_name": realm["display_name"],
                "database_sha256": _file_record_at(temporary_fd, "realm.sqlite3")["sha256"],
                "cas_manifest_sha256": cas["manifest_sha256"],
                "authentication": {"algorithm": "hmac-sha256", "key_id": _key_id(auth_key), "key_path": str(auth_path)},
            }
            if binding is not None:
                manifest["destination_binding"] = dict(binding)
            manifest["manifest_sha256"] = _authenticated_digest(manifest)
            manifest["manifest_hmac"] = _manifest_mac(manifest, auth_key)
            write_bytes_at(temporary_fd, "manifest.json", (canonical_json(manifest) + "\n").encode())
            os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        validate_created_parent(destination, destination_identity, parent_fd)
        # A fresh destination must still be absent relative to the retained
        # parent.  The final rename is the only publication syscall.
        try:
            os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ConflictError("backup destination appeared before publication")
        os.rename(temporary_name, destination_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        validate_created_parent(destination, destination_identity, parent_fd)
        return verify_backup(destination, key=auth_key, directory_identity=destination_identity)
    except Exception:
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if temporary_name is not None and parent_fd >= 0:
            try:
                remove_tree_at(parent_fd, temporary_name)
            except OSError:
                pass
        raise
    finally:
        if source_cas_fd >= 0:
            os.close(source_cas_fd)
        if parent_fd >= 0 and parent_fd != destination_identity.get("_parent_fd"):
            os.close(parent_fd)
        if own_destination_identity:
            close_pinned(destination_identity)


def restore_backup(
    backup_dir: str | Path,
    destination: str | Path,
    *,
    key: bytes | None = None,
    key_path: str | Path | None = None,
    destination_identity: Mapping[str, Any] | None = None,
    source_identity: Mapping[str, Any] | None = None,
) -> dict:
    """Restore an authenticated backup into a new inactive realm.

    ``key``/``key_path`` are explicit escape hatches for callers that keep the
    operator key in a stable support root. When omitted, the authenticated
    manifest's recorded key path is used. Every path still goes through the
    manifest key-id and HMAC checks in :func:`verify_backup`.
    """
    source = absolute_path(backup_dir)
    destination = absolute_path(destination)
    if os.path.lexists(str(destination)):
        raise ConflictError("restore destination must be a new inactive realm", details={"destination": str(destination)})
    own_source_identity = source_identity is None
    own_destination_identity = destination_identity is None
    source_fd = -1
    parent_fd = -1
    destination_name = None
    temporary_name = None
    temporary_fd = -1
    try:
        if source_identity is None:
            source_identity, source_fd, _ = pin_directory(source)
        else:
            source_fd = int(source_identity.get("_target_fd", -1))
            if source_fd < 0:
                # A caller may provide the retained source parent but not the root
                # fd; open the root once, with O_NOFOLLOW, before material reads.
                source_fd = os.open(source.name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=int(source_identity["_parent_fd"]))
        verified = verify_backup(source, key=key, key_path=key_path, directory_identity=source_identity)
        destination_identity = destination_identity or capture_parent(destination, require_fresh_target=True)
        parent_fd, destination_name = ensure_parent_at(destination, destination_identity)
    except Exception:
        if source_fd >= 0:
            os.close(source_fd)
        if own_source_identity:
            close_pinned(source_identity)
        if own_destination_identity and destination_identity is not None:
            close_pinned(destination_identity)
        raise
    try:
        temporary_name, temporary_fd = mkdir_temp_at(parent_fd, f".{destination.name}.")
        copy_file_at(source_fd, "realm.sqlite3", temporary_fd, "realm.sqlite3")
        copy_tree_at(source_fd, "cas", temporary_fd, "cas")
        report, realm = _inspect_consolidated_realm(temporary_fd)
        if not realm or realm["id"] != verified["manifest"].get("realm_id"):
            raise ConflictError("restored realm identity mismatch", details=report)
        source_manifest_sha256, _ = _sha256_at(source_fd, "manifest.json")
        handoff = {"format_version": 2, "state": "prepared", "realm_id": realm["id"], "display_name": realm["display_name"], "source_backup": str(source), "source_manifest_sha256": source_manifest_sha256, "source_database_sha256": verified["manifest"].get("database_sha256"), "source_cas_manifest_sha256": verified["manifest"].get("cas_manifest_sha256"), "candidate_database_sha256": _file_record_at(temporary_fd, "realm.sqlite3")["sha256"], "candidate_cas_manifest_sha256": verified["cas_manifest"].get("manifest_sha256"), "prepared_at": now()}
        handoff["handoff_sha256"] = _authenticated_digest(handoff)
        auth_key = _resolve_key(verified["manifest"], key=key, key_path=key_path)
        handoff["handoff_hmac"] = hmac.new(auth_key, canonical_json(_auth_payload(handoff)).encode("utf-8"), hashlib.sha256).hexdigest()
        write_bytes_at(temporary_fd, "activation-handoff.json", (canonical_json(handoff) + "\n").encode())
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        validate_created_parent(destination, destination_identity, parent_fd)
        try:
            os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ConflictError("restore destination appeared before publication")
        os.rename(temporary_name, destination_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        validate_created_parent(destination, destination_identity, parent_fd)
        return {"destination": str(destination), "realm_id": realm["id"], "activation_handoff": str(destination / "activation-handoff.json"), "source_manifest_sha256": handoff["source_manifest_sha256"], "verification": verified["manifest"]}
    except Exception:
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if temporary_name is not None:
            try:
                remove_tree_at(parent_fd, temporary_name)
            except OSError:
                pass
        raise
    finally:
        os.close(source_fd)
        if own_source_identity:
            close_pinned(source_identity)
        if parent_fd >= 0 and parent_fd != destination_identity.get("_parent_fd"):
            os.close(parent_fd)
        if own_destination_identity:
            close_pinned(destination_identity)


def structured_export(store) -> dict:
    def rows(query, transform=None):
        values = [dict(row) for row in store.conn.execute(query)]
        return [transform(value) if transform else value for value in values]

    projects = rows("SELECT * FROM projects ORDER BY created_at", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    runs = rows("SELECT * FROM runs ORDER BY created_at", lambda value: value | {"spec": json.loads(value.pop("spec_json"))})
    tasks = rows("SELECT * FROM tasks ORDER BY created_at", lambda value: value | {"spec": json.loads(value.pop("spec_json")), **({"result": json.loads(value["result_json"])} if value.get("result_json") else {})})
    for task in tasks:
        task.pop("result_json", None)
        if task.get("expected_effect_json"):
            task["expected_effect"] = json.loads(task.pop("expected_effect_json"))
        else:
            task.pop("expected_effect_json", None)
    events = rows("SELECT * FROM events ORDER BY id", lambda value: value | {"payload": json.loads(value.pop("payload_json"))})
    capabilities = rows("SELECT * FROM capabilities ORDER BY id", lambda value: value | {"required_resource_keys": json.loads(value.pop("required_resource_keys_json"))})
    executors = rows("SELECT * FROM executors ORDER BY id", lambda value: value | {"capabilities": json.loads(value.pop("capabilities_json")), "resource_keys": json.loads(value.pop("resource_keys_json"))})
    reservations = rows("SELECT * FROM reservations ORDER BY task_id, resource_key")
    documents = rows("SELECT * FROM project_documents ORDER BY project_id, created_at, id", lambda value: value | {"content": json.loads(value.pop("content_json"))})
    generations = rows("SELECT * FROM generations ORDER BY project_id, created_at, id", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    variants = rows("SELECT * FROM generation_variants ORDER BY generation_id, created_at, id", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    shots = rows("SELECT * FROM project_shots ORDER BY project_id, created_at, id", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    shot_items = rows("SELECT * FROM shot_items ORDER BY shot_id, sort_key, id", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    text_bindings = rows("SELECT * FROM shot_text_bindings ORDER BY project_id, id")
    text_binding_events = rows("SELECT * FROM shot_text_binding_events ORDER BY project_id, binding_id, seq", lambda value: value | {"payload": json.loads(value.pop("payload_json"))})
    owner_records = rows("SELECT source_table, source_key, source_ordinal, row_json, row_sha256, created_at FROM migration_owner_records ORDER BY source_table, source_ordinal, source_key")
    for record in owner_records:
        record["row"] = json.loads(record.pop("row_json"))
    return {"format_version": 1, "exported_at": now(), "realm": store.realm, "projects": projects, "objects": rows("SELECT * FROM objects ORDER BY digest"), "project_objects": rows("SELECT * FROM project_objects ORDER BY project_id, digest, relation"), "documents": documents, "runs": runs, "tasks": tasks, "events": events, "capabilities": capabilities, "executors": executors, "reservations": reservations, "generations": generations, "variants": variants, "shots": shots, "shot_items": shot_items, "shot_text_bindings": text_bindings, "shot_text_binding_events": text_binding_events, "migration_owner_records": owner_records}
