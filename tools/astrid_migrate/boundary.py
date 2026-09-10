"""Small neutral migration boundary.

This module is intentionally self contained: it only uses the Python standard
library and describes the filesystem/backup wire format used by the operator
protocol.  Runtime implementations are supplied by callers as duck-typed
generated-client-shaped objects.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from datetime import datetime, timezone
from typing import Any, Mapping
from migration_boundary import AuthorizationError, ConflictError, ValidationError


class MigrationBoundaryError(Exception):
    def __init__(self, message: str, *, details: Any = None):
        super().__init__(message)
        self.details = details




class RealmCatalog:
    """Minimal public catalog writer used by operator activation."""
    def __init__(self, path: str | Path):
        self.path = absolute_path(path)
    def _read(self, *, identity: Mapping[str, Any]):
        try:
            validate_parent(self.path, identity, allow_parent_appeared=True)
            parent = Path(str(identity["parent"]))
            fd = _open_relative(int(identity["_parent_fd"]), self.path.relative_to(parent))
            try:
                value = os.fstat(fd)
                if not stat.S_ISREG(value.st_mode):
                    raise ConflictError(f"catalog is not an ordinary file: {self.path}")
                chunks = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                os.close(fd)
            validate_parent(self.path, identity, allow_parent_appeared=True)
            return json.loads(b"".join(chunks).decode("utf-8"))
        except FileNotFoundError:
            return {"format_version": 1, "realms": [], "selected_realm_id": None}
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise ConflictError(f"catalog is unreadable: {self.path}") from exc

    def _write(self, value, *, identity: Mapping[str, Any]):
        atomic_json_write(self.path, value, identity=identity)

    def _update(self, update, *, identity: Mapping[str, Any] | None = None):
        own = identity is None
        identity = identity or capture_parent(self.path)
        try:
            value = self._read(identity=identity)
            update(value)
            self._write(value, identity=identity)
            return value
        finally:
            if own:
                close_pinned(identity)

    def register(self, *, realm_id, display_name, data_root, path_identity=None):
        def update(value):
            rows = [r for r in value.get("realms", []) if r.get("realm_id") != realm_id]
            rows.append({"realm_id": realm_id, "display_name": display_name, "data_root": str(data_root)})
            value["realms"] = rows
        return self._update(update, identity=path_identity)

    def select(self, realm_id, *, path_identity=None):
        return self._update(lambda value: value.__setitem__("selected_realm_id", realm_id), identity=path_identity)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def durable_json_bytes(value: Any) -> bytes:
    """Encode the exact owner-only JSON representation used by this boundary."""
    return json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id() -> str:
    return hashlib.sha256(f"{os.getpid()}:{time.time_ns()}".encode()).hexdigest()[:32]


def absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _parent(path: Path) -> Path:
    parent = path
    while not os.path.lexists(str(parent)):
        if parent == parent.parent:
            raise ConflictError(f"filesystem path has no existing parent: {path}")
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ConflictError(f"filesystem parent is not an ordinary directory: {parent}")
    return parent


def _identity(path: Path) -> tuple[int, int, int]:
    value = path.stat(follow_symlinks=False)
    return int(value.st_dev), int(value.st_ino), int(value.st_mode)


def _has_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def capture_parent(path: str | Path, *, require_fresh_target: bool = False) -> dict[str, Any]:
    target = absolute_path(path)
    if _has_symlink(target):
        raise ConflictError(f"filesystem path contains a symlink component: {target}")
    if require_fresh_target and os.path.lexists(str(target)):
        raise ConflictError(f"filesystem target must be fresh: {target}")
    parent = _parent(target.parent)
    fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    dev, ino, mode = _identity(parent)
    return {"path": str(target), "parent": str(parent), "target_parent": str(target.parent), "parent_was_missing": parent != target.parent,
            "parent_st_dev": dev, "parent_st_ino": ino, "parent_st_mode": mode, "_parent_fd": fd}


def close_pinned(identity: Mapping[str, Any] | None) -> None:
    if identity and int(identity.get("_parent_fd", -1)) >= 0:
        try: os.close(int(identity["_parent_fd"]))
        except OSError: pass


def validate_parent(path: str | Path, identity: Mapping[str, Any], *, allow_parent_appeared: bool = False) -> int:
    target = absolute_path(path)
    if identity.get("path") != str(target) or _has_symlink(target):
        raise ConflictError(f"filesystem path identity changed: {target}")
    fd = int(identity.get("_parent_fd", -1))
    expected = tuple(
        int(identity[f"parent_{key}"] if f"parent_{key}" in identity else identity[key])
        for key in ("st_dev", "st_ino", "st_mode")
    )
    if fd < 0 or _identity(Path(str(identity["parent"]))) != expected:
        raise ConflictError(f"filesystem parent identity changed: {target.parent}")
    if identity.get("parent_was_missing") and os.path.lexists(str(target.parent)) and not allow_parent_appeared:
        raise ConflictError(f"filesystem target parent appeared: {target.parent}")
    return fd


def validate_created_parent(path: str | Path, identity: Mapping[str, Any], final_parent_fd: int) -> int:
    validate_parent(path, identity, allow_parent_appeared=True)
    return int(final_parent_fd)


def pin_directory(path: str | Path):
    target = absolute_path(path)
    identity = capture_parent(target)
    try:
        root_fd = os.open(target.name if target.parent == Path(identity["parent"]) else str(target.relative_to(Path(identity["parent"]))), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=int(identity["_parent_fd"]))
        return identity, root_fd, os.fstat(root_fd)
    except Exception:
        close_pinned(identity)
        raise


def ensure_parent_at(path: str | Path, identity: Mapping[str, Any]):
    target = absolute_path(path)
    parent = Path(str(identity["parent"]))
    fd = validate_parent(target, identity, allow_parent_appeared=True)
    if target.parent == parent:
        return fd, target.name
    relative = target.parent.relative_to(parent)
    current = os.dup(fd)
    for part in relative.parts:
        try: os.mkdir(part, 0o700, dir_fd=current)
        except FileExistsError: pass
        nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
        os.close(current); current = nxt
    return current, target.name


def ensure_directory(path: str | Path, *, mode: int = 0o700):
    target = absolute_path(path)
    identity = capture_parent(target)
    parent_fd, name = ensure_parent_at(target, identity)
    try: os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError: pass
    child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    if parent_fd != identity["_parent_fd"]: os.close(parent_fd)
    close_pinned(identity)
    dev, ino, smode = _identity(target)
    return {"path": str(target), "parent": str(target.parent), "target_parent": str(target.parent), "parent_st_dev": dev, "parent_st_ino": ino, "parent_st_mode": smode, "_parent_fd": child}


def mkdir_temp_at(parent_fd: int, prefix: str, *, mode: int = 0o700):
    for attempt in range(100):
        name = f"{prefix}{os.getpid()}-{time.time_ns()}-{attempt}"
        try: os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError: continue
        return name, os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    raise ConflictError("temporary filesystem directory could not be allocated")


def write_bytes_at(directory_fd: int, name: str, data: bytes, *, mode: int = 0o600):
    name = Path(name).name
    temp = f".{name}.{os.getpid()}-{time.time_ns()}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=directory_fd)
    try:
        os.write(fd, bytes(data)); os.fsync(fd); os.close(fd); fd = -1
        os.rename(temp, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd); os.fsync(directory_fd)
    finally:
        if fd >= 0: os.close(fd)
        try: os.unlink(temp, dir_fd=directory_fd)
        except OSError: pass


def atomic_json_write(path: str | Path, value: bytes | Mapping[str, Any], *, identity: Mapping[str, Any] | None = None):
    encoded = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    own = identity is None; identity = identity or capture_parent(path)
    try:
        parent_fd, name = ensure_parent_at(path, identity)
        write_bytes_at(parent_fd, name, encoded)
        # Recheck after publication as well: hostile tests and operators may
        # replace the lexical parent inside the rename syscall.  The retained
        # descriptor prevents redirection; this check still reports the
        # identity change instead of silently accepting it.
        validate_parent(path, identity, allow_parent_appeared=True)
        if parent_fd != identity.get("_parent_fd"): os.close(parent_fd)
    finally:
        if own: close_pinned(identity)


def copy_file_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, replace: bool = False):
    src = os.open(source_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
    try:
        dstflags = os.O_WRONLY | os.O_CREAT | (0 if replace else os.O_EXCL) | getattr(os, "O_NOFOLLOW", 0)
        dst = os.open(destination_name, dstflags, 0o600, dir_fd=destination_fd)
        try:
            while True:
                data = os.read(src, 1024 * 1024)
                if not data: break
                os.write(dst, data)
            os.fsync(dst)
        finally: os.close(dst)
    finally: os.close(src)


def copy_tree_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, preserve_symlinks: bool = False):
    src = os.open(source_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
    try:
        os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
        dst = os.open(destination_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=destination_fd)
        try:
            for entry in os.scandir(src):
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode): copy_tree_at(src, entry.name, dst, entry.name, preserve_symlinks=preserve_symlinks)
                elif stat.S_ISREG(mode): copy_file_at(src, entry.name, dst, entry.name)
                elif stat.S_ISLNK(mode) and preserve_symlinks: os.symlink(os.readlink(entry.name, dir_fd=src), entry.name, dir_fd=dst)
                else: raise ConflictError(f"source contains unsupported entry: {entry.name}")
        finally: os.close(dst)
    finally: os.close(src)


def remove_tree_at(parent_fd: int, name: str):
    target = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    try:
        for entry in os.scandir(target):
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode): remove_tree_at(target, entry.name)
            else: os.unlink(entry.name, dir_fd=target)
    finally: os.close(target)
    os.rmdir(name, dir_fd=parent_fd)


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def _json_at(root_fd: int, name: str) -> dict[str, Any]:
    fd = _open_relative(root_fd, name)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConflictError(f"backup entry is not an ordinary file: {name}")
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        value = json.loads(bytes(data).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConflictError(f"backup artifact is invalid: {name}") from exc
    finally:
        os.close(fd)
    if not isinstance(value, dict):
        raise ConflictError(f"backup artifact must be an object: {name}")
    return value


def _sha256_at(root_fd: int, relative: str | Path) -> tuple[str, int]:
    fd = _open_relative(root_fd, relative)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConflictError(f"backup entry is not an ordinary file: {relative}")
        return _sha256_fd(fd), int(metadata.st_size)
    finally:
        os.close(fd)


def _connection_from_fd(root_fd: int, name: str) -> sqlite3.Connection:
    fd = _open_relative(root_fd, name)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConflictError(f"backup SQLite entry is not an ordinary file: {name}")
        duplicate = os.dup(fd)
        try:
            connection = sqlite3.connect(f"file:/dev/fd/{duplicate}?immutable=1", uri=True)
            os.close(duplicate)
            return connection
        except Exception:
            os.close(duplicate)
            raise
    finally:
        os.close(fd)


def _reject_sqlite_sidecars(root_fd: int, *, label: str) -> None:
    """Backups/candidates contain one consolidated SQLite database."""
    for suffix in ("-wal", "-shm", "-journal"):
        name = "realm.sqlite3" + suffix
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ConflictError(f"{label} contains an unmanifested SQLite sidecar", details={"file": name})


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:32]


def _auth_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"manifest_sha256", "manifest_hmac", "handoff_sha256", "handoff_hmac"}}


def _manifest_digest_payload(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "manifest_hmac"}}


def _handoff_digest_payload(handoff: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in handoff.items() if key not in {"handoff_sha256", "handoff_hmac"}}


def _resolve_key(manifest: Mapping[str, Any], *, key: bytes | None = None, key_path: str | Path | None = None) -> bytes:
    if key is not None:
        value = bytes(key)
    else:
        auth = manifest.get("authentication")
        if not isinstance(auth, Mapping):
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
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConflictError("backup authentication key is unavailable")
            value = bytearray()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                value.extend(chunk)
            validate_parent(path, identity, allow_parent_appeared=True)
            value = bytes(value)
        except FileNotFoundError as exc:
            raise ConflictError("backup authentication key is unavailable") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            close_pinned(identity)
    if len(value) < 32:
        raise ConflictError("backup authentication key is too short")
    auth = manifest.get("authentication")
    if not isinstance(auth, Mapping) or auth.get("algorithm") != "hmac-sha256" or auth.get("key_id") != _key_id(value):
        raise ConflictError("backup authentication key does not match manifest realm")
    return value


def _verify_cas_manifest(root_fd: int, manifest: Mapping[str, Any]) -> None:
    objects = manifest.get("objects")
    payload = {"format_version": manifest.get("format_version"), "objects": objects}
    if not isinstance(objects, list) or manifest.get("manifest_sha256") != hashlib.sha256(canonical_json(payload).encode()).hexdigest():
        raise ConflictError("CAS manifest hash mismatch")
    cas_root_fd = _open_relative(root_fd, "cas/sha256", directory=True)
    try:
        for item in objects:
            if not isinstance(item, Mapping):
                raise ConflictError("backup CAS manifest contains an invalid object")
            digest = str(item.get("digest", ""))
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ConflictError("backup CAS manifest contains an invalid digest")
            actual_hash, actual_size = _sha256_at(cas_root_fd, f"{digest[:2]}/{digest[2:]}")
            if actual_size != int(item.get("size", -1)) or actual_hash != item.get("sha256") or item.get("sha256") != digest:
                raise ConflictError("backup CAS object failed verification", details={"digest": digest})
    finally:
        os.close(cas_root_fd)


def verify_backup(backup_dir: str | Path, *, key: bytes | None = None, key_path: str | Path | None = None, directory_identity: Mapping[str, Any] | None = None):
    """Verify an authenticated backup through one retained parent identity."""
    root = absolute_path(backup_dir)
    own_identity = directory_identity is None
    identity = directory_identity or capture_parent(root)
    backup_fd = -1
    try:
        validate_parent(root, identity, allow_parent_appeared=bool(identity.get("parent_was_missing")))
        parent = Path(str(identity["parent"]))
        backup_fd = _open_relative(int(identity["_parent_fd"]), root.relative_to(parent), directory=True)
        _reject_sqlite_sidecars(backup_fd, label="backup")
        manifest = _json_at(backup_fd, "manifest.json")
        if manifest.get("format_version") != 2:
            raise ConflictError("legacy or unsupported backup format")
        digest = manifest.get("manifest_sha256")
        if not isinstance(digest, str) or not hmac.compare_digest(digest, hashlib.sha256(canonical_json(_manifest_digest_payload(manifest)).encode()).hexdigest()):
            raise ConflictError("backup manifest authentication failed (public digest mismatch)")
        auth_key = _resolve_key(manifest, key=key, key_path=key_path)
        mac = manifest.get("manifest_hmac")
        if not isinstance(mac, str) or not hmac.compare_digest(mac, hmac.new(auth_key, canonical_json(_auth_payload(manifest)).encode(), hashlib.sha256).hexdigest()):
            raise ConflictError("backup manifest authentication failed")
        realm_meta = manifest.get("realm")
        schema_meta = manifest.get("schema")
        files = manifest.get("files")
        if not isinstance(realm_meta, Mapping) or not realm_meta.get("id") or not isinstance(schema_meta, Mapping) or not isinstance(schema_meta.get("version"), int) or not isinstance(files, Mapping):
            raise ConflictError("backup manifest metadata is incomplete")
        if manifest.get("realm_id") != realm_meta["id"] or manifest.get("schema_version") != schema_meta["version"]:
            raise ConflictError("backup manifest metadata aliases mismatch")
        for name in ("realm.sqlite3", "cas-manifest.json"):
            record = files.get(name)
            actual_hash, actual_size = _sha256_at(backup_fd, name)
            if not isinstance(record, Mapping) or record.get("sha256") != actual_hash or int(record.get("size", -1)) != actual_size:
                raise ConflictError("backup file digest mismatch", details={"file": name})
        database_hash, _ = _sha256_at(backup_fd, "realm.sqlite3")
        if manifest.get("database_sha256") != database_hash:
            raise ConflictError("backup SQLite hash mismatch")
        cas = _json_at(backup_fd, "cas-manifest.json")
        if manifest.get("cas_manifest_sha256") != cas.get("manifest_sha256"):
            raise ConflictError("backup CAS manifest hash mismatch")
        _verify_cas_manifest(backup_fd, cas)
        connection = _connection_from_fd(backup_fd, "realm.sqlite3")
        try:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ConflictError("backup SQLite quick check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise ConflictError("backup SQLite foreign-key check failed")
            realm = connection.execute("SELECT id FROM realm LIMIT 1").fetchone()
            if not realm or realm[0] != manifest.get("realm_id"):
                raise ConflictError("backup realm identity mismatch")
        finally:
            connection.close()
        validate_parent(root, identity, allow_parent_appeared=bool(identity.get("parent_was_missing")))
        return {"manifest": manifest, "cas_manifest": cas}
    except FileNotFoundError as exc:
        raise ConflictError("backup is incomplete") from exc
    finally:
        if backup_fd >= 0:
            os.close(backup_fd)
        if own_identity:
            close_pinned(identity)


def verify_restore_candidate(candidate_dir: str | Path, *, directory_identity: Mapping[str, Any] | None = None):
    """Verify a restored realm using descriptor-pinned candidate and backup reads."""
    root = absolute_path(candidate_dir)
    own_identity = directory_identity is None
    identity = directory_identity or capture_parent(root)
    candidate_fd = source_fd = -1
    source_identity = None
    try:
        validate_parent(root, identity, allow_parent_appeared=bool(identity.get("parent_was_missing")))
        parent = Path(str(identity["parent"]))
        candidate_fd = _open_relative(int(identity["_parent_fd"]), root.relative_to(parent), directory=True)
        if not stat.S_ISDIR(os.fstat(candidate_fd).st_mode):
            raise ConflictError("restore candidate is not an ordinary directory")
        _reject_sqlite_sidecars(candidate_fd, label="restore candidate")
        handoff = _json_at(candidate_fd, "activation-handoff.json")
        candidate_hash, _ = _sha256_at(candidate_fd, "realm.sqlite3")
        source = absolute_path(str(handoff.get("source_backup", "")))
        source_identity, source_fd, _ = pin_directory(source)
        verified = verify_backup(source, directory_identity=source_identity)
        manifest = verified["manifest"]
        if handoff.get("format_version") != 2:
            raise ConflictError("legacy restore handoff requires explicit migration")
        if not isinstance(handoff.get("handoff_sha256"), str) or not hmac.compare_digest(handoff["handoff_sha256"], hashlib.sha256(canonical_json(_handoff_digest_payload(handoff)).encode()).hexdigest()):
            raise ConflictError("restore handoff authentication failed")
        auth_key = _resolve_key(manifest)
        if not isinstance(handoff.get("handoff_hmac"), str) or not hmac.compare_digest(handoff["handoff_hmac"], hmac.new(auth_key, canonical_json(_auth_payload(handoff)).encode(), hashlib.sha256).hexdigest()):
            raise ConflictError("restore handoff authentication failed")
        source_manifest_hash, _ = _sha256_at(source_fd, "manifest.json")
        if handoff.get("source_manifest_sha256") != source_manifest_hash:
            raise ConflictError("restore handoff source manifest mismatch")
        if handoff.get("realm_id") != manifest.get("realm_id"):
            raise ConflictError("restore candidate realm does not match its backup")
        if handoff.get("candidate_database_sha256") != candidate_hash or candidate_hash != manifest.get("database_sha256"):
            raise ConflictError("restore candidate SQLite bytes differ from its verified backup")
        expected = {str(item["digest"]): item for item in verified["cas_manifest"].get("objects", []) if isinstance(item, Mapping)}
        actual: dict[str, tuple[str, str]] = {}
        cas_fd = _open_relative(candidate_fd, "cas/sha256", directory=True)
        try:
            for prefix_entry in os.scandir(cas_fd):
                if not prefix_entry.is_dir(follow_symlinks=False):
                    continue
                prefix_fd = os.open(prefix_entry.name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=cas_fd)
                try:
                    for object_entry in os.scandir(prefix_fd):
                        if object_entry.is_file(follow_symlinks=False):
                            actual[prefix_entry.name + object_entry.name] = (prefix_entry.name, object_entry.name)
                finally:
                    os.close(prefix_fd)
        finally:
            os.close(cas_fd)
        if set(actual) != set(expected):
            raise ConflictError("restore candidate CAS object set differs from its verified backup")
        cas_fd = _open_relative(candidate_fd, "cas/sha256", directory=True)
        try:
            for digest, item in expected.items():
                prefix, name = actual[digest]
                prefix_fd = os.open(prefix, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=cas_fd)
                try:
                    actual_hash, actual_size = _sha256_at(prefix_fd, name)
                finally:
                    os.close(prefix_fd)
                if actual_size != int(item.get("size", -1)) or actual_hash != item.get("sha256"):
                    raise ConflictError("restore candidate CAS bytes differ from its verified backup", details={"digest": digest})
        finally:
            os.close(cas_fd)
        connection = _connection_from_fd(candidate_fd, "realm.sqlite3")
        try:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ConflictError("restore candidate SQLite quick check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise ConflictError("restore candidate SQLite foreign-key check failed")
            realm = connection.execute("SELECT id FROM realm LIMIT 1").fetchone()
            if not realm or realm[0] != manifest.get("realm_id"):
                raise ConflictError("restore candidate realm identity mismatch")
        finally:
            connection.close()
        validate_parent(root, identity, allow_parent_appeared=bool(identity.get("parent_was_missing")))
        return {"handoff": handoff, "manifest": manifest, "doctor": {"ok": True}, "database_sha256": candidate_hash, "cas_manifest_sha256": verified["cas_manifest"].get("manifest_sha256")}
    except FileNotFoundError as exc:
        raise ConflictError("restore candidate is incomplete") from exc
    finally:
        if candidate_fd >= 0:
            os.close(candidate_fd)
        if source_fd >= 0:
            os.close(source_fd)
        if source_identity is not None:
            close_pinned(source_identity)
        if own_identity:
            close_pinned(identity)


def _open_relative(root_fd: int, relative: str | Path, *, directory: bool = False) -> int:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {"", ".", ".."} for p in parts): raise ValidationError("invalid descriptor-relative path")
    current = root_fd; opened = []
    try:
        for i, part in enumerate(parts):
            fd = os.open(part, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if directory or i < len(parts)-1 else 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
            if current != root_fd: opened.append(current)
            current = fd
        for fd in opened: os.close(fd)
        return current
    except Exception:
        for fd in opened:
            try: os.close(fd)
            except OSError: pass
        raise


def _sha256_at(root_fd: int, relative: str | Path):
    fd = _open_relative(root_fd, relative)
    try:
        value = os.fstat(fd); digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            digest.update(chunk)
        return digest.hexdigest(), int(value.st_size)
    finally: os.close(fd)


def _connection_from_fd(root_fd: int, name: str):
    import sqlite3
    fd = _open_relative(root_fd, name); duplicate = os.dup(fd); os.close(fd)
    return sqlite3.connect(f"file:/dev/fd/{duplicate}?immutable=1", uri=True)
