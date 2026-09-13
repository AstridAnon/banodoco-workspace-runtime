from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import shutil
import stat
import tempfile
import threading
import time
from collections import defaultdict
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .errors import CapabilityUnavailableError, ConflictError, InvalidRequestError, LeaseError, NotFoundError, OwnerBusyError, RealmAdmissionError, ValidationError
from .canonical_schema import CANONICAL_FORMAT_ID, CANONICAL_SCHEMA_SQL
from .dirfd import remove_tree_at
from .util import canonical_json, new_id, now

try:
    import fcntl
except ImportError:  # pragma: no cover - supported beta host is POSIX
    fcntl = None


SCHEMA_VERSION = 24
LEASE_SECONDS = 30
EXECUTOR_LIVENESS_SECONDS = 90
REALM_ADMISSION_TIMEOUT_SECONDS = 5.0
OBJECT_ID_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
# JSON clients (including TypeScript) must be able to preserve the exact byte
# count used in the admission hash.  Stay within IEEE-754's safe integer range.
MAX_STORAGE_ESTIMATE_BYTES = (1 << 53) - 1
GENERATION_INTENT_STORAGE_KEY = "__runtime_generation_intent"
LEGACY_GENERATION_INTENT_STORAGE_KEY = "generation_intent"
FACT_EXACT_KEYS = frozenset({
    "interpreter", "runtime_lock", "engine_lock", "model_digest",
    "custom_node_digest", "driver", "root", "port",
})
FACT_MINIMUM_KEYS = frozenset({"vram_bytes", "scratch_bytes"})
# Admission checks the complete canonical shape against an isolated snapshot.
# This list is the canonical contract and is intentionally independent of
# any historical schema artifacts:
# an existing database must already have this shape and is never upgraded on
# open or verify.
REQUIRED_SCHEMA_COLUMNS = {
    "attempts": frozenset("id task_id lease_id fence executor_id lease_expires_at settled runtime_epoch recovery_nonce recovery_nonce_expires_at recovery_nonce_used".split()),
    "capabilities": frozenset("id definition_digest status required_resource_keys_json estimated_scratch_bytes estimated_output_bytes unavailable_reason created_at updated_at".split()),
    "command_idempotency": frozenset("command_kind aggregate_id idempotency_key request_hash result_json created_at txn_id primary_stream_id resulting_stream_seq first_project_seq last_project_seq event_ids_json".split()),
    "continuation_admissions": frozenset("continuation_task_id dependency_snapshot_json admitted_at".split()),
    "events": frozenset("id run_id task_id kind payload_json previous_hash event_hash created_at".split()),
    "executors": frozenset("id max_concurrency resource_keys_json capabilities_json protocol created_at runtime_epoch readiness readiness_reason last_seen_at source_digest dependency_digest source_epoch".split()),
    "generation_variants": frozenset("id generation_id object_id variant_type metadata_json created_at".split()),
    "generations": frozenset("id project_id source_task_id type status metadata_json version created_at updated_at".split()),
    "media_references": frozenset("id reference_id media_id role ordinal is_primary metadata_json created_at".split()),
    "media_relations": frozenset("project_id from_digest to_digest kind ordinal metadata_json created_at".split()),
    "managed_output_associations": frozenset("association_id task_id attempt_id project_id output_port group_key generation_id variant_key object_digest manifest_digest size filename media_type ordinal role producer_json provenance_json durability regeneration_json coverage_json created_at".split()),
    "managed_output_lifecycle": frozenset("association_id state version expires_at pinned_at lease_id lease_owner lease_expires_at updated_at created_at".split()),
    "objects": frozenset("digest size media_type original_name created_at".split()),
    "project_documents": frozenset("id project_id kind content_json version created_at updated_at".split()),
    "project_objects": frozenset("project_id digest relation created_at".split()),
    "project_references": frozenset("id project_id kind name description metadata_json version created_at updated_at archived_at".split()),
    "project_selections": frozenset("actor_id scope project_id updated_at".split()),
    "project_sequences": frozenset("project_id next_seq".split()),
    "project_shots": frozenset("id project_id name metadata_json version created_at updated_at archived_at".split()),
    "projects": frozenset("id realm_id slug name metadata_json version created_at updated_at idempotency_key".split()),
    "realm": frozenset("id display_name created_at updated_at".split()),
    "realm_lifecycle": frozenset("realm_id state tombstoned_at reason version".split()),
    "recovery_checkpoints": frozenset("id attempt_id task_id executor_id runtime_epoch lease_id fence nonce checkpoint_path checkpoint_digest checkpoint_size state recovery_receipt_json created_at updated_at".split()),
    "reference_links": frozenset("from_reference_id to_reference_id kind metadata_json created_at".split()),
    "reservations": frozenset("task_id resource_key lease_token created_at released_at executor_id fence lease_expires_at runtime_epoch".split()),
    "runs": frozenset("id project_id capability spec_json status idempotency_key created_at updated_at".split()),
    "runtime_lifecycle": frozenset("id runtime_epoch boot_id previous_boot_id started_at recovered_task_count".split()),
    "shot_items": frozenset("id shot_id media_id sort_key source_frame metadata_json created_at".split()),
    "shot_text_binding_events": frozenset("event_id binding_id project_id seq kind payload_json previous_hash event_hash created_at".split()),
    "shot_text_bindings": frozenset("id project_id shot_id kind slot media_digest event_stream_id head_seq created_at updated_at".split()),
    "task_dependencies": frozenset("continuation_task_id predecessor_task_id ordinal".split()),
    "tasks": frozenset("id run_id capability spec_json status lease_token executor_id attempt expected_effect_json result_json created_at updated_at capability_digest waiting_reason lease_expires_at lease_fence attempt_id runtime_epoch".split()),
    "timeline_events": frozenset("id timeline_id kind payload_json previous_hash event_hash created_at".split()),
    "timeline_reference_state": frozenset("id version archived_at".split()),
    "timeline_references": frozenset("id timeline_id object_id role".split()),
    "timeline_render_publications": frozenset("authoring_task_id attempt_id fence runtime_epoch request_hash prepared_json state timeline_id timeline_version render_task_id render_run_id result_json created_at updated_at".split()),
    "timeline_revisions": frozenset("id timeline_id version shots_json references_json created_at".split()),
    "timeline_shot_state": frozenset("id version archived_at".split()),
    "timeline_shots": frozenset("id timeline_id start_ms duration_ms reference_ids_json".split()),
    "timelines": frozenset("id project_id version created_at archived_at".split()),
    "runtime_schema": frozenset("id format_id version created_at".split()),
}
REQUIRED_SCHEMA_TABLES = frozenset(REQUIRED_SCHEMA_COLUMNS)
_REALM_METADATA_TABLES = frozenset({"runtime_schema", "realm_lifecycle", "runtime_lifecycle"})


def normalize_execution_facts(value, *, field="execution facts"):
    """Validate the small engine-neutral required/verified-facts contract."""
    if not isinstance(value, dict):
        raise ValidationError(f"{field} must be an object")
    unknown = set(value) - {"exact", "minimum"}
    if unknown:
        raise ValidationError(f"{field} contains unsupported fields", details={"fields": sorted(unknown)})
    exact = value.get("exact", {})
    minimum = value.get("minimum", {})
    if not isinstance(exact, dict) or not isinstance(minimum, dict):
        raise ValidationError(f"{field}.exact and {field}.minimum must be objects")
    unknown_exact = set(exact) - FACT_EXACT_KEYS
    if unknown_exact:
        raise ValidationError(f"{field}.exact contains unsupported facts", details={"facts": sorted(unknown_exact)})
    unknown_minimum = set(minimum) - FACT_MINIMUM_KEYS
    if unknown_minimum:
        raise ValidationError(f"{field}.minimum contains unsupported facts", details={"facts": sorted(unknown_minimum)})
    normalized_exact = {}
    for key, fact in exact.items():
        if key == "port":
            if isinstance(fact, bool) or not isinstance(fact, (str, int)) or not fact:
                raise ValidationError(f"{field}.exact.port must be a non-empty string or integer")
            if isinstance(fact, int) and not 0 <= fact <= 65535:
                raise ValidationError(f"{field}.exact.port is out of range")
        elif not isinstance(fact, str) or not fact:
            raise ValidationError(f"{field}.exact.{key} must be a non-empty string")
        normalized_exact[key] = fact
    normalized_minimum = {}
    for key, fact in minimum.items():
        if isinstance(fact, bool) or not isinstance(fact, int):
            raise ValidationError(f"{field}.minimum.{key} must be an integer")
        if fact < 0 or fact > MAX_STORAGE_ESTIMATE_BYTES:
            raise ValidationError(f"{field}.minimum.{key} is out of range")
        normalized_minimum[key] = fact
    return {"exact": normalized_exact, "minimum": normalized_minimum}


def public_task_spec(spec):
    """Split internal generation intent from the public task spec."""
    public = dict(spec or {})
    intent = public.pop(GENERATION_INTENT_STORAGE_KEY, None)
    if intent is None and LEGACY_GENERATION_INTENT_STORAGE_KEY in public:
        intent = public.pop(LEGACY_GENERATION_INTENT_STORAGE_KEY)
    else:
        public.pop(LEGACY_GENERATION_INTENT_STORAGE_KEY, None)
    return public, intent


def canonical_task_spec_for_compare(spec):
    """Canonicalize legacy/current intent storage for idempotency comparison."""
    public, intent = public_task_spec(spec)
    if intent is not None:
        public[GENERATION_INTENT_STORAGE_KEY] = intent
    return public


def task_spec_for_request_hash(spec):
    """Keep the pre-fix request hash stable across the storage-key change."""
    public, intent = public_task_spec(spec)
    if intent is not None:
        public[LEGACY_GENERATION_INTENT_STORAGE_KEY] = intent
    return public


def execution_facts_match(required, verified):
    """Return whether verified facts satisfy every task-selected fact."""
    required = normalize_execution_facts(required, field="required_facts")
    verified = normalize_execution_facts(verified, field="verified_facts")
    verified_exact = verified["exact"]
    for key, expected in required["exact"].items():
        if key not in verified_exact or verified_exact[key] != expected:
            return False
    verified_minimum = verified["minimum"]
    for key, expected in required["minimum"].items():
        if key not in verified_minimum or verified_minimum[key] < expected:
            return False
    return True


class RealmStore:
    """The sole durable writer for one realm.

    A daemon holds ``owner.lock`` for its lifetime.  The connection is
    private to this object and every mutating operation runs under the
    process lock and a SQLite transaction.
    """

    @classmethod
    def initialize(cls, root: str | Path, *, display_name: str = "Workspace", realm_id: str | None = None):
        """Explicitly create and verify one fresh canonical realm.

        Normal open never creates a root, schema, identity, lock directory, or
        CAS directory.  Creation is a separate operation so a missing path is
        an admission failure rather than an implicit bootstrap.
        """
        root = Path(root).expanduser().resolve()
        # Validate the complete identity before touching the requested root.
        # Creation is a sibling build followed by one directory publication;
        # the final name must never expose the schema without its identity.
        if not isinstance(display_name, str) or not display_name.strip():
            raise ValidationError("fresh realm identity is invalid")
        rid = str(realm_id or new_id())
        if not rid.strip():
            raise ValidationError("fresh realm identity is invalid")
        if root.exists():
            if root.is_symlink() or not root.is_dir():
                raise RealmAdmissionError("fresh realm root is not a directory")
            if any(root.iterdir()):
                raise RealmAdmissionError("fresh realm root must be absent or empty")
        else:
            root.parent.mkdir(parents=True, exist_ok=True)
        staged_root = Path(tempfile.mkdtemp(prefix=f".{root.name}.create-", dir=str(root.parent)))
        staged_root.chmod(0o700)
        store = cls.__new__(cls)
        store.root = staged_root
        store.lock_path = staged_root / "owner.lock"
        store.db_path = staged_root / "realm.sqlite3"
        store.cas_root = staged_root / "cas" / "sha256"
        store.staging_root = staged_root / "staging"
        store._lock_file = None
        store._mutex = threading.RLock()
        store.conn = None
        parent_fd = -1
        published = False
        root_was_present = root.exists()
        try:
            store._acquire_owner()
            store._open(fresh=True)
            timestamp = now()
            with store._transaction():
                store.conn.execute(
                    "INSERT INTO realm(id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (rid, display_name, timestamp, timestamp),
                )
                store.conn.execute(
                    "INSERT INTO realm_lifecycle(realm_id, state, version) VALUES (?, 'active', 1)",
                    (rid,),
                )
            store.admission_report = store.integrity_report()
            if not store.admission_report.get("ok"):
                raise RealmAdmissionError("fresh realm failed canonical admission", details=store.admission_report)
            staged_fd = os.open(staged_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(staged_fd)
            finally:
                os.close(staged_fd)
            parent_fd = os.open(root.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            os.rename(staged_root.name, root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            published = True
            os.fsync(parent_fd)
            # Keep the staged owner lock held through publication and final
            # admission. Reopening here would create an ownership race in
            # which another opener can acquire the just-published root before
            # the creator's second admission completes.
            store.root = root
            store.lock_path = root / "owner.lock"
            store.db_path = root / "realm.sqlite3"
            store.cas_root = root / "cas" / "sha256"
            store.staging_root = root / "staging"
            return store
        except Exception:
            rollback_error = None
            if published and parent_fd >= 0:
                # The final name may already be visible when durability or
                # post-publication admission fails.  Remove it below the
                # retained parent descriptor so a retry cannot admit a
                # partially published tree or follow a swapped path.
                try:
                    remove_tree_at(parent_fd, root.name)
                    if root_was_present:
                        os.mkdir(root.name, 0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except Exception as exc:
                    rollback_error = exc
            elif staged_root.exists():
                try:
                    shutil.rmtree(staged_root)
                except Exception as exc:
                    rollback_error = exc
            try:
                store.close()
            except Exception as exc:
                rollback_error = rollback_error or exc
            if rollback_error is not None:
                raise RealmAdmissionError(
                    "fresh realm publication rollback failed; manual recovery is required",
                    details={"root": str(root), "rollback_error": str(rollback_error)},
                ) from rollback_error
            raise
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    def __init__(self, root: str | Path, *, create: bool = False, acquire_owner: bool = True, admission_timeout: float = REALM_ADMISSION_TIMEOUT_SECONDS):
        self.root = Path(root).expanduser().resolve()
        if create:
            raise ValidationError("implicit realm creation is disabled; use RealmStore.initialize")
        if self.root.is_symlink() or not self.root.exists() or not self.root.is_dir():
            raise RealmAdmissionError(
                "realm root is missing or is not a directory",
                details=self._integrity_failure("missing_root", "realm root does not exist or is not a directory"),
            )
        self.lock_path = self.root / "owner.lock"
        self.db_path = self.root / "realm.sqlite3"
        self.cas_root = self.root / "cas" / "sha256"
        self.staging_root = self.root / "staging"
        self._lock_file = None
        self._mutex = threading.RLock()
        self.conn = None
        try:
            sqlite_components = [
                self.db_path,
                *(Path(str(self.db_path) + suffix) for suffix in ("-wal", "-shm", "-journal")),
            ]
            if not any(path.exists() or path.is_symlink() for path in sqlite_components):
                self.admission_report = self._integrity_failure("missing_database", "realm.sqlite3 is missing")
                raise RealmAdmissionError("realm failed startup admission", details=self.admission_report)
            # Inspect before creating owner.lock so malformed or unsupported
            # roots fail without changing their source tree.  Reinspect under
            # the lock to close the race with a concurrent writer.
            self.admission_report = self.inspect_realm(self.root, timeout_seconds=admission_timeout)
            if not self.admission_report.get("ok"):
                raise RealmAdmissionError("realm failed startup admission", details=self.admission_report)
            if acquire_owner:
                self._acquire_owner()
                self.admission_report = self.inspect_realm(self.root, timeout_seconds=admission_timeout)
                if not self.admission_report.get("ok"):
                    raise RealmAdmissionError("realm failed startup admission", details=self.admission_report)
            self._open(fresh=False)
        except Exception:
            self.close()
            raise

    @contextmanager
    def _transaction(self):
        # Service decorators and a few domain operations compose transactions
        # (for example a timeline mutation records its revision inside the
        # command transaction).  SQLite has no nested ``BEGIN``; use a
        # savepoint so an inner failure still rolls back with the outer
        # mutation while preserving the single commit boundary.
        if self.conn.in_transaction:
            savepoint = f"runtime_nested_{id(self)}_{threading.get_ident()}"
            self.conn.execute(f"SAVEPOINT {savepoint}")
            try:
                yield
            except Exception:
                self.conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            return
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def _acquire_owner(self):
        if not self.root.exists() or not self.root.is_dir() or self.root.is_symlink():
            raise RealmAdmissionError("realm root is unavailable before owner admission")
        if self.lock_path.is_symlink():
            raise RealmAdmissionError("owner lock must not be a symlink")
        self._lock_file = open(self.lock_path, "a+")
        self.lock_path.chmod(0o600)
        if fcntl is not None:
            try:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                self._lock_file.close()
                self._lock_file = None
                raise OwnerBusyError("another runtime daemon owns this realm") from exc

    @staticmethod
    def _copy_admission_file(source: Path, destination: Path, deadline: float) -> None:
        """Copy one stable SQLite component without following a sidecar link."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        source_fd = os.open(source, flags)
        try:
            metadata = os.fstat(source_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"realm SQLite component is not a regular file: {source.name}")
            with destination.open("wb") as target:
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("realm inspection timed out")
                    block = os.read(source_fd, 1024 * 1024)
                    if not block:
                        break
                    target.write(block)
        finally:
            os.close(source_fd)

    @classmethod
    def inspect_realm(cls, root: str | Path, *, catalog_path=None, timeout_seconds: float = REALM_ADMISSION_TIMEOUT_SECONDS):
        """Inspect a WAL-aware isolated snapshot without opening the source DB.

        Startup calls this only after acquiring the realm owner lock, so the
        main database and durable WAL/rollback journal are stable while copied.
        Offline doctor uses the same path and fails closed if a concurrent
        writer changes or removes a component.  SQLite may recover or create
        sidecars in the temporary directory; the realm itself remains byte-safe.

        The incident's physical corruption trigger is not proven.  Admission
        therefore diagnoses and stops; it never attempts automatic salvage.
        """
        root = Path(root).expanduser().resolve()
        db_path = root / "realm.sqlite3"
        if timeout_seconds <= 0:
            return cls._integrity_failure("timeout", "realm inspection timed out")
        deadline = time.monotonic() + timeout_seconds
        candidates = [db_path, *(Path(str(db_path) + suffix) for suffix in ("-wal", "-shm", "-journal"))]
        if not db_path.exists() and not db_path.is_symlink():
            if any(path.exists() or path.is_symlink() for path in candidates[1:]):
                return cls._integrity_failure(
                    "unreadable", "realm.sqlite3 is missing while SQLite sidecars exist"
                )
            return {"state": "uninitialized", "ok": True, "issues": [], "checks": {}}
        try:
            identities = {}
            components = []
            for path in candidates:
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    identities[path] = None
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError(f"realm SQLite component is not a regular file: {path.name}")
                identities[path] = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
                components.append(path)
            with tempfile.TemporaryDirectory(prefix="banodoco-realm-preflight-") as temporary:
                snapshot_root = Path(temporary)
                for source in components:
                    cls._copy_admission_file(source, snapshot_root / source.name, deadline)
                for path, expected in identities.items():
                    try:
                        metadata = path.lstat()
                        actual = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
                    except FileNotFoundError:
                        actual = None
                    if actual != expected:
                        raise OSError(f"realm SQLite component changed during inspection: {path.name}")
                connection = sqlite3.connect(snapshot_root / "realm.sqlite3", timeout=max(0.001, deadline - time.monotonic()))
                connection.row_factory = sqlite3.Row
                inspector = object.__new__(cls)
                inspector.root = root
                inspector.db_path = db_path
                inspector.cas_root = root / "cas" / "sha256"
                inspector.conn = connection
                inspector._mutex = threading.RLock()
                try:
                    connection.execute("PRAGMA query_only=ON")
                    return inspector.integrity_report(
                        catalog_path=catalog_path,
                        timeout_seconds=max(0.001, deadline - time.monotonic()),
                    )
                finally:
                    connection.close()
        except TimeoutError as exc:
            return cls._integrity_failure("timeout", str(exc))
        except (json.JSONDecodeError, ValidationError) as exc:
            return cls._integrity_failure("malformed", str(exc))
        except (OSError, sqlite3.DatabaseError, ValueError) as exc:
            return cls._integrity_failure("unreadable", str(exc))

    @staticmethod
    def _integrity_failure(reason: str, message: str) -> dict:
        issue = "sqlite_integrity"
        return {
            "state": "unhealthy",
            "ok": False,
            "schema_version": SCHEMA_VERSION,
            "issues": [issue],
            "recovery_action": "Restore the realm from a verified backup, then re-run doctor.",
            "next_action": "Restore the realm from a verified backup, then re-run doctor.",
            "checks": {
                "sqlite_integrity": {"ok": False, "result": f"error: {message}", "reason": reason},
                "sqlite": {"ok": False, "result": f"error: {message}", "reason": reason},
                "foreign_keys": {"ok": False, "violations": [], "reason": "not_checked"},
                "schema": {"ok": False, "expected_version": SCHEMA_VERSION, "actual_version": None, "missing_tables": [], "missing_columns": {}, "reason": "not_checked"},
                "realm_identity": {"ok": False, "realm_id": None, "row_count": None, "reason": "not_checked"},
                "reachable_cas": {"ok": False, "missing": [], "corrupt": [], "orphaned": [], "reason": "not_checked"},
                "event_chain": {"ok": False, "errors": [], "reason": "not_checked"},
                "catalog": {"status": "not_checked", "ok": False, "issues": []},
                "activation": {"status": "not_checked", "ok": False, "issues": []},
            },
        }

    def _open(self, *, fresh=False):
        if not self.root.exists() or not self.root.is_dir():
            raise RealmAdmissionError("realm root is unavailable")
        if any(path.is_symlink() for path in (self.cas_root.parent, self.cas_root, self.staging_root)):
            raise ValidationError("runtime storage roots must not be symlinks")
        if fresh:
            self.cas_root.parent.mkdir(parents=True, exist_ok=False)
            self.cas_root.mkdir(parents=True, exist_ok=False)
            self.cas_root.parent.chmod(0o700)
            self.cas_root.chmod(0o700)
            self.staging_root.mkdir(parents=True, exist_ok=False)
            self.staging_root.chmod(0o700)
            self.conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None, check_same_thread=False)
        else:
            for path in (self.cas_root.parent, self.cas_root, self.staging_root):
                if not path.exists() or not path.is_dir():
                    raise RealmAdmissionError("realm storage roots are incomplete")
            self.conn = sqlite3.connect(
                f"file:{self.db_path}?mode=rw", uri=True, timeout=10,
                isolation_level=None, check_same_thread=False,
            )
        self.db_path.chmod(0o600)
        self.conn.row_factory = sqlite3.Row
        if fresh:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(CANONICAL_SCHEMA_SQL)
            self.conn.execute(
                "INSERT INTO runtime_schema(id, format_id, version, created_at) VALUES (1, ?, ?, ?)",
                (CANONICAL_FORMAT_ID, SCHEMA_VERSION, now()),
            )
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=10000")

    def attempt_staging_dir(self, attempt_id):
        """Return the private staging directory for one persisted attempt."""
        if not isinstance(attempt_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", attempt_id):
            raise ValidationError("attempt_id is invalid")
        settlements_root = self.staging_root / "settlements"
        if settlements_root.is_symlink() or (settlements_root.exists() and not settlements_root.is_dir()):
            raise ValidationError("attempt staging root is invalid")
        settlements_root.mkdir(parents=True, exist_ok=True)
        settlements_root.chmod(0o700)
        return settlements_root / attempt_id

    def begin_runtime_session(self, boot_id, *, epoch_floor: int | None = None):
        """Open a durable boot session and recover work owned by old boots.

        The monotonically increasing epoch lives in SQLite and is advanced
        atomically with recovery of every running task. Recovery returns
        interrupted tasks to the durable queue with their original task/run
        ids; old lease tokens and fences cannot settle after this commits.
        """
        if not boot_id:
            raise ValidationError("boot_id is required")
        with self._mutex:
            with self._transaction():
                row = self.conn.execute("SELECT * FROM runtime_lifecycle WHERE id=1").fetchone()
                previous_epoch = int(row["runtime_epoch"]) if row else 0
                previous_boot = row["boot_id"] if row else None
                if epoch_floor is not None:
                    try:
                        epoch_floor = int(epoch_floor)
                    except (TypeError, ValueError) as exc:
                        raise ValidationError("runtime epoch floor is invalid") from exc
                    if epoch_floor < 0:
                        raise ValidationError("runtime epoch floor must be non-negative")
                epoch = max(previous_epoch, int(epoch_floor or 0)) + 1
                started_at = now()
                self.conn.execute(
                    "INSERT INTO runtime_lifecycle(id, runtime_epoch, boot_id, previous_boot_id, started_at, recovered_task_count) VALUES (1, ?, ?, ?, ?, 0) ON CONFLICT(id) DO UPDATE SET runtime_epoch=excluded.runtime_epoch, boot_id=excluded.boot_id, previous_boot_id=excluded.previous_boot_id, started_at=excluded.started_at, recovered_task_count=0",
                    (epoch, boot_id, previous_boot, started_at),
                )
                interrupted = self.conn.execute(
                    "SELECT id, run_id, lease_token, lease_fence, attempt FROM tasks WHERE status='running' ORDER BY created_at, id"
                ).fetchall()
                for task in interrupted:
                    self.conn.execute(
                        "UPDATE tasks SET status='queued', executor_id=NULL, lease_token=NULL, lease_expires_at=NULL, attempt_id=NULL, waiting_reason='runtime_recovery', updated_at=? WHERE id=? AND status='running'",
                        (started_at, task["id"]),
                    )
                    self.conn.execute(
                        "UPDATE runs SET status='queued', updated_at=? WHERE id=? AND status='running'",
                        (started_at, task["run_id"]),
                    )
                    self._release_reservations(task["id"], task["lease_token"])
                    self._append_event(
                        task["run_id"], task["id"], "task.runtime_recovered",
                        {"previous_runtime_epoch": previous_epoch or None, "runtime_epoch": epoch, "previous_boot_id": previous_boot, "boot_id": boot_id, "stale_fence": int(task["lease_fence"] or 0), "attempt": int(task["attempt"] or 0), "recovery": "requeued"},
                    )
                # A checkpoint from an interrupted boot is now eligible for
                # the explicit resume command, but its old attempt identity
                # remains fenced and can never settle work itself.
                if previous_epoch:
                    self.conn.execute(
                        "UPDATE recovery_checkpoints SET state='recovered', updated_at=? WHERE runtime_epoch=? AND state IN ('durable', 'reboot_requested')",
                        (started_at, previous_epoch),
                    )
                self.conn.execute("UPDATE runtime_lifecycle SET recovered_task_count=? WHERE id=1", (len(interrupted),))
            value = dict(self.conn.execute("SELECT * FROM runtime_lifecycle WHERE id=1").fetchone())
            value["recovered_task_count"] = int(value["recovered_task_count"])
            value["runtime_epoch"] = int(value["runtime_epoch"])
            return value

    def runtime_lifecycle(self):
        with self._mutex:
            row = self.conn.execute("SELECT * FROM runtime_lifecycle WHERE id=1").fetchone()
            return dict(row) if row else None

    def _table_columns(self, table):
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def close(self):
        with self._mutex:
            if self.conn is not None:
                self.conn.close()
                self.conn = None
            if self._lock_file is not None:
                if fcntl is not None:
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                self._lock_file.close()
                self._lock_file = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def realm(self):
        row = self.conn.execute("SELECT * FROM realm LIMIT 1").fetchone()
        return dict(row) if row else None

    def ensure_realm(self, display_name: str = "Workspace", realm_id: str | None = None):
        with self._mutex:
            row = self.realm
            if row:
                if realm_id is not None and str(realm_id) != row["id"]:
                    raise ConflictError(
                        "requested realm identity does not match the admitted realm",
                        details={"expected": row["id"], "actual": str(realm_id)},
                    )
                return row
            raise RealmAdmissionError(
                "realm identity is missing; implicit identity creation is disabled",
                details={"reason": "realm_identity_missing"},
            )

    def realm_lifecycle(self):
        row = self.conn.execute("SELECT * FROM realm_lifecycle WHERE realm_id=?", (self.realm["id"],)).fetchone()
        return dict(row) if row else {"realm_id": self.realm["id"], "state": "active", "tombstoned_at": None, "reason": None, "version": 1}

    def tombstone_realm(self, *, reason=None, expected_version=None):
        with self._mutex:
            lifecycle = self.realm_lifecycle()
            if expected_version is not None and int(expected_version) != int(lifecycle["version"]):
                raise ConflictError("realm lifecycle version conflict", details={"expected": expected_version, "actual": lifecycle["version"]})
            if lifecycle["state"] == "tombstoned":
                return lifecycle
            timestamp = now()
            self.conn.execute("UPDATE realm_lifecycle SET state='tombstoned', tombstoned_at=?, reason=?, version=version+1 WHERE realm_id=?", (timestamp, reason, self.realm["id"]))
            return self.realm_lifecycle()

    def restore_tombstone(self, *, expected_version=None):
        with self._mutex:
            lifecycle = self.realm_lifecycle()
            if expected_version is not None and int(expected_version) != int(lifecycle["version"]):
                raise ConflictError("realm lifecycle version conflict", details={"expected": expected_version, "actual": lifecycle["version"]})
            self.conn.execute("UPDATE realm_lifecycle SET state='active', tombstoned_at=NULL, reason=NULL, version=version+1 WHERE realm_id=?", (self.realm["id"],))
            return self.realm_lifecycle()

    def _project(self, selector: str):
        row = self.conn.execute("SELECT * FROM projects WHERE id=? OR slug=?", (selector, selector)).fetchone()
        if not row:
            raise NotFoundError("project not found", details={"project": selector})
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        return result

    def create_project(self, slug: str, name: str, metadata=None, *, idempotency_key=None):
        if not slug or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in slug):
            raise ValidationError("slug must contain only letters, numbers, '-' or '_'")
        if not name:
            raise ValidationError("name is required")
        with self._mutex:
            realm = self.ensure_realm()
            request_hash = hashlib.sha256(canonical_json({"slug": slug, "name": name, "metadata": metadata or {}}).encode()).hexdigest()
            with self._transaction():
                if idempotency_key:
                    receipt = self.conn.execute(
                        "SELECT result_json, request_hash FROM command_idempotency "
                        "WHERE command_kind='project.create' AND idempotency_key=?",
                        (idempotency_key,),
                    ).fetchone()
                    if receipt:
                        if receipt["request_hash"] != request_hash:
                            raise ConflictError("idempotency key was already used with different input")
                        return self._public_task_result(json.loads(receipt["result_json"]))
                    prior = self.conn.execute("SELECT * FROM projects WHERE realm_id=? AND idempotency_key=?", (realm["id"], idempotency_key)).fetchone()
                    if prior:
                        if prior["slug"] != slug or prior["name"] != name or json.loads(prior["metadata_json"]) != (metadata or {}):
                            raise ConflictError("idempotency key was already used with different input")
                        result = self._project(prior["id"])
                        self._record_command_receipt(
                            "project.create", prior["id"], idempotency_key, request_hash,
                            result, project_id=prior["id"], created_at=prior["created_at"],
                        )
                        return result
                try:
                    pid, timestamp = new_id(), now()
                    self.conn.execute("INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at, idempotency_key) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
                                      (pid, realm["id"], slug, name, canonical_json(metadata or {}), timestamp, timestamp, idempotency_key))
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("project slug already exists") from exc
                result = self._project(pid)
                if idempotency_key:
                    self._record_command_receipt(
                        "project.create", pid, idempotency_key, request_hash,
                        result, project_id=pid, created_at=result["created_at"],
                    )
                return result

    def get_project(self, selector: str):
        with self._mutex:
            return self._project(selector)

    def list_projects(self):
        return {"items": [self._project(row["id"]) for row in self.conn.execute("SELECT id FROM projects ORDER BY created_at")], "next_cursor": None}

    def select_project(self, actor_id: str, selector: str, scope: str = "workspace", *, idempotency_key=None):
        """Persist a project routing selection for one authenticated actor.

        Selection is runtime state, not a product-local preference file.  The
        actor and scope are part of the primary key, so two clients cannot
        overwrite one another's selection and reconnects read the same value.
        """
        if not actor_id:
            raise ValidationError("actor_id is required")
        if scope not in {"workspace", "user"}:
            raise ValidationError("selection scope must be 'workspace' or 'user'")
        with self._mutex:
            project = self._project(selector)
            timestamp = now()
            with self._transaction():
                request_hash = hashlib.sha256(canonical_json({"actor_id": actor_id, "scope": scope, "project_id": project["id"]}).encode()).hexdigest()
                aggregate_id = f"{actor_id}:{scope}"
                if idempotency_key:
                    prior = self.conn.execute(
                        "SELECT result_json, request_hash FROM command_idempotency WHERE command_kind='project.select' AND aggregate_id=? AND idempotency_key=?",
                        (aggregate_id, idempotency_key),
                    ).fetchone()
                    if prior:
                        if prior["request_hash"] != request_hash:
                            raise ConflictError("idempotency key was already used with different input")
                        return json.loads(prior["result_json"])
                self.conn.execute(
                    "INSERT INTO project_selections(actor_id, scope, project_id, updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(actor_id, scope) DO UPDATE SET project_id=excluded.project_id, updated_at=excluded.updated_at",
                    (actor_id, scope, project["id"], timestamp),
                )
                result = {"actor_id": actor_id, "scope": scope, "project": self._project(project["id"]), "updated_at": timestamp}
                if idempotency_key:
                    self._record_command_receipt(
                        "project.select", aggregate_id, idempotency_key, request_hash,
                        result, project_id=project["id"], created_at=timestamp,
                    )
                return result

    def current_project(self, actor_id: str):
        """Return the actor's effective selection (workspace precedes user)."""
        if not actor_id:
            raise ValidationError("actor_id is required")
        with self._mutex:
            row = self.conn.execute(
                "SELECT actor_id, scope, project_id, updated_at FROM project_selections "
                "WHERE actor_id=? ORDER BY CASE scope WHEN 'workspace' THEN 0 ELSE 1 END LIMIT 1",
                (actor_id,),
            ).fetchone()
            if not row:
                raise NotFoundError("no project is selected", details={"next_action": "astrid projects select <project>"})
            return {"actor_id": row["actor_id"], "scope": row["scope"], "project": self._project(row["project_id"]), "updated_at": row["updated_at"]}

    def update_project(self, selector: str, *, name=None, metadata=None, expected_version=None, idempotency_key=None):
        with self._mutex:
            current = self._project(selector)
            request_hash = hashlib.sha256(canonical_json({"name": name, "metadata": metadata, "expected_version": expected_version}).encode()).hexdigest()
            if idempotency_key:
                prior = self.conn.execute("SELECT * FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?", ("project.update", current["id"], idempotency_key)).fetchone()
                if prior:
                    if prior["request_hash"] != request_hash:
                        raise ConflictError("idempotency key was already used with different input")
                    return json.loads(prior["result_json"])
            if expected_version is not None and expected_version != current["version"]:
                raise ConflictError("stale project version", details={"expected": expected_version, "actual": current["version"]})
            changed_name = current["name"] if name is None else name
            changed_meta = current["metadata"] if metadata is None else metadata
            timestamp = now()
            with self._transaction():
                self.conn.execute("UPDATE projects SET name=?, metadata_json=?, version=version+1, updated_at=? WHERE id=?",
                                  (changed_name, canonical_json(changed_meta), timestamp, current["id"]))
                result = self._project(current["id"])
                if idempotency_key:
                    self.conn.execute("INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", ("project.update", current["id"], idempotency_key, request_hash, canonical_json(result), timestamp))
            return result

    def add_object_ref(self, project: str, digest: str, relation="managed"):
        with self._mutex:
            p = self._project(project)
            if not self.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone():
                raise NotFoundError("object not found")
            self.conn.execute("INSERT OR IGNORE INTO project_objects VALUES (?, ?, ?, ?)", (p["id"], digest, relation, now()))

    def list_project_objects(self, project: str):
        p = self._project(project)
        # The service cursor is keyed by ``(created_at, digest)``. Keep the
        # storage order identical so objects sharing a timestamp cannot move
        # between pages or be skipped when a cursor is resumed.
        rows = self.conn.execute("SELECT o.*, po.relation FROM objects o JOIN project_objects po ON po.digest=o.digest WHERE po.project_id=? ORDER BY o.created_at, o.digest", (p["id"],)).fetchall()
        return [dict(row) for row in rows]

    def promote_shot_items(self, shot_id, expected_version, updates, *, timestamp):
        """Apply candidate metadata and advance the shot head atomically."""
        for item_id, metadata in updates:
            self.conn.execute(
                "UPDATE shot_items SET metadata_json=? WHERE id=? AND shot_id=?",
                (canonical_json(metadata), str(item_id), str(shot_id)),
            )
        changed = self.conn.execute(
            "UPDATE project_shots SET version=?, updated_at=? WHERE id=? AND version=?",
            (int(expected_version) + 1, timestamp, str(shot_id), int(expected_version)),
        ).rowcount
        if changed != 1:
            raise ConflictError("shot head conflict", details={"expected": int(expected_version)})
        return int(expected_version) + 1

    def record_object(self, digest, size, media_type, original_name=None):
        with self._mutex:
            self.conn.execute("INSERT OR IGNORE INTO objects VALUES (?, ?, ?, ?, ?)", (digest, size, media_type, original_name, now()))
            return dict(self.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone())

    def _validate_task_inputs(self, project_id, spec):
        """Validate and authorize immutable task input object references.

        Task inputs are content-addressed runtime objects, not arbitrary
        product-local identifiers.  A project task may consume only objects
        that are both present in the CAS index and associated with that
        project.  Keeping this check beside task creation makes admission
        atomic with the project lookup and prevents a client-side precheck
        from becoming an authorization gap.
        """
        if not isinstance(spec, dict):
            raise ValidationError("task spec must be an object")
        if "storage_estimate" in spec:
            if spec["storage_estimate"] is None:
                raise ValidationError("storage_estimate must be an object")
            self._validate_storage_estimate(spec["storage_estimate"])
        input_object_ids = spec.get("input_object_ids", [])
        if not isinstance(input_object_ids, list):
            raise ValidationError("input_object_ids must be a list")
        normalized = []
        for index, object_id in enumerate(input_object_ids):
            if not isinstance(object_id, str):
                raise ValidationError("input_object_ids must contain strings", details={"index": index})
            match = OBJECT_ID_RE.fullmatch(object_id)
            if not match:
                raise ValidationError("input_object_ids must contain sha256 object IDs", details={"index": index})
            digest = match.group(1)
            if digest in normalized:
                raise ValidationError("input_object_ids must be unique", details={"index": index, "object_id": object_id})
            normalized.append(digest)
        if normalized and project_id is None:
            raise ValidationError("project is required when input_object_ids are supplied")
        for object_id, digest in zip(input_object_ids, normalized):
            associated = self.conn.execute(
                "SELECT 1 FROM objects o JOIN project_objects po ON po.digest=o.digest "
                "WHERE po.project_id=? AND o.digest=?",
                (project_id, digest),
            ).fetchone()
            if not associated:
                raise ConflictError(
                    "task input object is not associated with the task project",
                    details={"project_id": project_id, "object_id": object_id},
                )

    def _freeze_managed_render_inputs(self, project_id, spec, supplied_input_object_ids):
        """Freeze a managed ``rendering.render`` timeline at admission.

        Some consumers submit the HC-04 shape directly instead of going
        through Astrid's managed-render helper.  Runtime is the authenticated
        project/timeline authority, so it may resolve that reference once and
        carry the resulting immutable snapshot into the claimed task.  The
        generic host still receives only the snapshot and never gets project
        or timeline read scope.
        """
        if not isinstance(spec, dict):
            raise ValidationError("task spec must be an object")
        params = spec.get("params")
        if not isinstance(params, dict) or "timeline_ref" not in params:
            return spec, supplied_input_object_ids
        frozen = json.loads(canonical_json(spec))
        params = frozen["params"]
        timeline_ref = params.get("timeline_ref")
        if not isinstance(timeline_ref, str) or not timeline_ref.strip():
            raise ValidationError("rendering.render timeline_ref must be a non-empty project-scoped selector")
        timeline_ref = timeline_ref.strip()
        params["timeline_ref"] = timeline_ref
        if project_id is None:
            raise ValidationError("rendering.render timeline_ref requires a project")
        inputs = frozen.get("inputs")
        if inputs is None:
            inputs = {}
            frozen["inputs"] = inputs
        if not isinstance(inputs, dict):
            raise ValidationError("rendering.render inputs must be an object")
        for field, message in (
            ("timeline", "managed rendering does not accept a caller-supplied timeline path"),
            ("assets_registry", "managed rendering does not accept a caller-supplied assets registry path"),
            ("materialized_root", "managed rendering materialization is host-owned"),
            ("materialized_objects", "managed rendering materialization is host-owned"),
            ("timeline_snapshot", "managed rendering timeline_snapshot is Runtime-owned"),
            ("timeline_authority", "managed rendering timeline_authority is Runtime-owned"),
        ):
            if inputs.get(field) not in (None, ""):
                raise ValidationError(message)
        supplied_input_ref = inputs.get("timeline_ref")
        if supplied_input_ref not in (None, "", timeline_ref):
            raise ConflictError("render timeline_ref bindings conflict")
        supplied_version = params.get("expected_version")
        if supplied_version is not None and (
            isinstance(supplied_version, bool)
            or not isinstance(supplied_version, int)
            or supplied_version < 1
        ):
            raise ValidationError("render expected_version must be a positive integer")

        rows = self.conn.execute(
            "SELECT id, archived_at FROM timelines WHERE project_id=? ORDER BY created_at, id",
            (project_id,),
        ).fetchall()
        matches = []
        for row in rows:
            document = self.conn.execute(
                "SELECT content_json, version FROM project_documents WHERE id=? AND project_id=?",
                (f"timeline:{row['id']}", project_id),
            ).fetchone()
            content = json.loads(document["content_json"]) if document else {}
            slug = content.get("slug") if isinstance(content, dict) else None
            if timeline_ref in {str(row["id"]), str(slug or "")}:
                matches.append((row, document, content))
        if not matches:
            raise NotFoundError(
                "timeline_ref is not in the selected project",
                details={"project_id": project_id, "timeline_ref": timeline_ref},
            )
        if len(matches) != 1:
            raise ConflictError("timeline_ref is ambiguous within the selected project")
        row, document, content = matches[0]
        if row["archived_at"]:
            raise ConflictError(
                "timeline_ref identifies an archived timeline",
                details={"timeline_id": row["id"], "timeline_ref": timeline_ref},
            )
        if not isinstance(content, dict) or not isinstance(content.get("config"), dict) or not isinstance(content.get("registry"), dict):
            raise ValidationError("canonical timeline config and registry must be objects")
        config = content["config"]
        registry = content["registry"]
        assets = registry.get("assets", {})
        if not isinstance(assets, dict):
            raise ValidationError("canonical timeline registry assets must be an object")
        ordered_input_ids = []
        managed_media = {}
        for asset_name, asset in assets.items():
            if not isinstance(asset, dict):
                raise ValidationError("canonical timeline registry assets must contain objects")
            media_id = asset.get("media_id") or asset.get("object_id")
            if not isinstance(media_id, str) or not media_id.strip():
                raise ValidationError(
                    f"canonical timeline asset {asset_name!r} has no runtime media identity"
                )
            digest = next(
                (
                    value
                    for key in ("content_sha256", "object_id", "digest", "sha256", "hash")
                    for value in (asset.get(key),)
                    if isinstance(value, str) and OBJECT_ID_RE.fullmatch(value)
                ),
                None,
            )
            if digest is None:
                raise ValidationError(
                    f"canonical timeline asset {asset_name!r} has no runtime content digest"
                )
            normalized = "sha256:" + OBJECT_ID_RE.fullmatch(digest).group(1)
            if normalized not in ordered_input_ids:
                ordered_input_ids.append(normalized)
            managed_media[media_id] = normalized
        supplied = list(supplied_input_object_ids or [])
        if supplied:
            normalized_supplied = []
            for value in supplied:
                match = OBJECT_ID_RE.fullmatch(value) if isinstance(value, str) else None
                if match is None:
                    raise ValidationError("input_object_ids must contain sha256 object IDs")
                normalized_supplied.append("sha256:" + match.group(1))
            if normalized_supplied != ordered_input_ids:
                raise ConflictError(
                    "render input_object_ids do not match the canonical timeline registry",
                    details={"expected": ordered_input_ids, "actual": normalized_supplied},
                )

        config_version = int(document["version"] if document else row["version"])
        if supplied_version is not None and supplied_version != config_version:
            raise ConflictError(
                "render expected_version does not match the canonical timeline",
                details={"expected": supplied_version, "actual": config_version},
            )
        config_hash = hashlib.sha256(canonical_json(config).encode()).hexdigest()
        registry_hash = hashlib.sha256(canonical_json(registry).encode()).hexdigest()
        event = self.conn.execute(
            "SELECT id, event_hash FROM timeline_events WHERE timeline_id=? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        authority = {
            "authority": "kernel",
            "project_id": project_id,
            "project_slug": self._project(project_id)["slug"],
            "timeline_id": row["id"],
            "timeline_ulid": row["id"],
            "timeline_slug": content.get("slug", row["id"]),
            "config_version": config_version,
            "head_event_id": str(event["id"] if event else f"timeline:{row['id']}:{config_version}"),
            "head_hash": event["event_hash"] if event else config_hash,
            "config_hash": config_hash,
            "registry_hash": registry_hash,
            "materialized_registry_hash": registry_hash,
            "managed_media_admissions": managed_media,
        }
        frozen["timeline_snapshot"] = {"config": config, "registry": registry}
        inputs["timeline_ref"] = timeline_ref
        inputs["timeline_authority"] = authority
        return frozen, ordered_input_ids

    @staticmethod
    def _validate_storage_estimate(storage_estimate):
        """Validate an optional immutable, request-specific disk estimate.

        The estimate is stored in ``tasks.spec_json`` so admission, claim, and
        replay all use the exact value supplied with the admitted task.  A
        missing estimate deliberately retains the capability-wide fallback.
        """
        if storage_estimate is None:
            return None
        if not isinstance(storage_estimate, dict):
            raise ValidationError("storage_estimate must be an object")
        if any(not isinstance(key, str) for key in storage_estimate):
            raise ValidationError("storage_estimate keys must be strings")
        expected = {"scratch_bytes", "output_bytes"}
        actual = set(storage_estimate)
        if actual != expected:
            raise ValidationError(
                "storage_estimate must contain exactly scratch_bytes and output_bytes",
                details={"missing": sorted(expected - actual), "unexpected": sorted(actual - expected)},
            )
        normalized = {}
        for key in ("scratch_bytes", "output_bytes"):
            value = storage_estimate[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValidationError(f"storage_estimate.{key} must be an integer")
            if value < 0 or value > MAX_STORAGE_ESTIMATE_BYTES:
                raise ValidationError(
                    f"storage_estimate.{key} is out of range",
                    details={"minimum": 0, "maximum": MAX_STORAGE_ESTIMATE_BYTES},
                )
            normalized[key] = value
        if normalized["scratch_bytes"] + normalized["output_bytes"] > MAX_STORAGE_ESTIMATE_BYTES:
            raise ValidationError(
                "storage_estimate total is out of range",
                details={"maximum": MAX_STORAGE_ESTIMATE_BYTES},
            )
        return normalized

    def create_task(self, capability, spec, project=None, idempotency_key=None, expected_effect=None, capability_digest=None, *, enforce_readiness=False):
        if not capability:
            raise ValidationError("capability is required")
        if isinstance(spec, dict) and "required_facts" in spec:
            spec = dict(spec)
            spec["required_facts"] = normalize_execution_facts(spec["required_facts"], field="required_facts")
        with self._mutex:
            project_id = self._project(project)["id"] if project else None
            if capability == "rendering.render":
                admitted_spec = spec.get("spec") if isinstance(spec, dict) else None
                admitted_spec, frozen_inputs = self._freeze_managed_render_inputs(
                    project_id, admitted_spec, spec.get("input_object_ids", []) if isinstance(spec, dict) else [],
                )
                spec = dict(spec)
                spec["spec"] = admitted_spec
                spec["input_object_ids"] = frozen_inputs
            predecessors = self._continuation_predecessors(spec)
            if isinstance(expected_effect, dict) and expected_effect.get("effect_type") == "generation.publish_v1":
                # The typed GEN publication plan is admitted against the task
                # project before any durable task/run rows are created. Its
                # output/member semantics are rechecked against staged bytes
                # inside the fenced settlement transaction.
                self._validate_settlement_effect(expected_effect, project_id=project_id)
                if project_id is None:
                    raise ConflictError("generation.publish_v1 requires a project-scoped task")
            self._validate_task_inputs(project_id, spec)
            with self._transaction():
                request_hash = hashlib.sha256(canonical_json({"capability": capability, "spec": task_spec_for_request_hash(spec), "project_id": project_id, "expected_effect": expected_effect, "capability_digest": capability_digest}).encode()).hexdigest()
                aggregate_id = project_id or "unscoped"
                if idempotency_key:
                    receipt = self.conn.execute(
                        "SELECT result_json, request_hash FROM command_idempotency WHERE command_kind='task.create' AND aggregate_id=? AND idempotency_key=?",
                        (aggregate_id, idempotency_key),
                    ).fetchone()
                    if receipt:
                        if receipt["request_hash"] != request_hash:
                            raise ConflictError("idempotency key was already used with different input")
                        return json.loads(receipt["result_json"])
                if idempotency_key:
                    old = self.conn.execute("SELECT * FROM runs WHERE project_id IS ? AND idempotency_key=?", (project_id, idempotency_key)).fetchone()
                    if old:
                        old_spec = json.loads(old["spec_json"])
                        if canonical_task_spec_for_compare(old_spec) != canonical_task_spec_for_compare(spec) or old["capability"] != capability:
                            raise ConflictError("idempotency key was already used with different input")
                        task = self.conn.execute("SELECT * FROM tasks WHERE run_id=?", (old["id"],)).fetchone()
                        result = self._task_result(old, task)
                        self.conn.execute(
                            "INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                            ("task.create", aggregate_id, idempotency_key, request_hash, canonical_json(result), old["created_at"]),
                        )
                        return result
                registered = self.conn.execute("SELECT * FROM capabilities WHERE id=?", (capability,)).fetchone()
                if registered:
                    registered_digest = registered["definition_digest"]
                    if capability_digest is not None and capability_digest != registered_digest:
                        raise ConflictError("capability definition digest does not match registered capability", details={"expected": registered_digest, "actual": capability_digest})
                    capability_digest = registered_digest
                    if registered["status"] != "ready":
                        if enforce_readiness:
                            reason = registered["unavailable_reason"] or f"capability_status_{registered['status']}"
                            raise CapabilityUnavailableError(
                                "capability is not ready for admission",
                                details={
                                    "capability_id": capability,
                                    "status": registered["status"],
                                    "reason": reason,
                                    "next_action": "wait for capability readiness and retry",
                                },
                            )
                        waiting_reason = "capability_unavailable"
                    else:
                        waiting_reason = None
                else:
                    # Keep task admission durable for clients that submit work
                    # before a worker host comes online, but mark it blocked.
                    # The task cannot be claimed until a matching capability
                    # and live executor registration is present.
                    waiting_reason = "capability_unavailable" if capability_digest is not None else None
                storage_estimate = spec.get("storage_estimate")
                if enforce_readiness and waiting_reason is None and not self.matching_live_executor(capability, capability_digest, include_storage=False, required_facts=spec.get("required_facts")):
                    # Queue the durable task while making the unavailable
                    # readiness explicit. Claiming remains impossible until a
                    # matching live executor appears.
                    if spec.get("required_facts") and self.matching_live_executor(capability, capability_digest, include_storage=False):
                        waiting_reason = "waiting_for_executor_facts"
                    else:
                        waiting_reason = "capability_unavailable"
                if waiting_reason is None and not self.storage_preflight(capability, storage_estimate=storage_estimate)["ok"]:
                    waiting_reason = "insufficient_storage"
                if predecessors:
                    self._validate_continuation_predecessors(predecessors, project_id)
                    waiting_reason = "waiting_for_dependencies"
                timestamp, run_id, task_id = now(), new_id(), new_id()
                self.conn.execute("INSERT INTO runs VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)", (run_id, project_id, capability, canonical_json(spec), idempotency_key, timestamp, timestamp))
                self.conn.execute("INSERT INTO tasks(id, run_id, capability, spec_json, status, capability_digest, waiting_reason, expected_effect_json, created_at, updated_at) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)", (task_id, run_id, capability, canonical_json(spec), capability_digest, waiting_reason, canonical_json(expected_effect) if expected_effect else None, timestamp, timestamp))
                admitted_event_id = self._append_event(run_id, task_id, "task.admitted", {"capability": capability})
                event_ids = [admitted_event_id]
                if predecessors:
                    for ordinal, predecessor_task_id in enumerate(predecessors):
                        self.conn.execute(
                            "INSERT INTO task_dependencies(continuation_task_id, predecessor_task_id, ordinal) VALUES (?, ?, ?)",
                            (task_id, predecessor_task_id, ordinal),
                        )
                    continuation_event = self._admit_continuation(task_id)
                    if continuation_event is not None:
                        event_ids.append(continuation_event)
                run = dict(self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())
                task = dict(self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())
                result = self._task_result(run, task)
                if idempotency_key:
                    self._record_command_receipt(
                        "task.create", aggregate_id, idempotency_key, request_hash,
                        result, project_id=project_id or "unscoped", event_ids=event_ids,
                        primary_stream_id=run_id, resulting_stream_seq=len(event_ids), created_at=timestamp,
                    )
                return result

    @staticmethod
    def _continuation_predecessors(spec):
        """Return the ordered predecessor ids for the bounded continuation form."""
        public_spec = spec.get("spec") if isinstance(spec, dict) else None
        dependencies = public_spec.get("runtime_dependencies") if isinstance(public_spec, dict) else None
        if dependencies is None:
            return ()
        if not isinstance(dependencies, dict):
            raise ValidationError("runtime_dependencies must be an object")
        edges = dependencies.get("edges")
        if not isinstance(edges, list) or len(edges) != 2:
            raise ValidationError("runtime continuation requires exactly two ordered dependency edges")
        aggregation = dependencies.get("aggregation")
        if not isinstance(aggregation, dict) or aggregation.get("kind") != "ordered_cas_inputs":
            raise ValidationError("runtime continuation requires ordered_cas_inputs aggregation")
        if spec.get("input_object_ids"):
            raise ValidationError("runtime continuation inputs are derived from predecessor outputs")
        predecessors = []
        for edge in edges:
            if not isinstance(edge, dict):
                raise ValidationError("runtime dependency edges must be objects")
            predecessor = edge.get("from_task_id")
            if not isinstance(predecessor, str) or not predecessor:
                raise ValidationError("runtime dependency edge requires from_task_id")
            if edge.get("to") != "self" or edge.get("requires_event") != "task.succeeded" or edge.get("fence") != "runtime_task":
                raise ValidationError("runtime dependency edge must require fenced task.succeeded for self")
            predecessors.append(predecessor)
        if len(set(predecessors)) != 2:
            raise ValidationError("runtime continuation predecessor task ids must be unique")
        return tuple(predecessors)

    def _validate_continuation_predecessors(self, predecessors, project_id):
        for predecessor_task_id in predecessors:
            row = self.conn.execute(
                "SELECT runs.project_id FROM tasks JOIN runs ON runs.id=tasks.run_id WHERE tasks.id=?",
                (predecessor_task_id,),
            ).fetchone()
            if not row:
                raise NotFoundError("runtime continuation predecessor task not found", details={"task_id": predecessor_task_id})
            if row["project_id"] != project_id:
                raise ConflictError("runtime continuation predecessor is outside the task project", details={"task_id": predecessor_task_id})

    def _continuation_rows(self, task_id):
        return self.conn.execute(
            "SELECT dependency.ordinal, predecessor.id AS task_id, predecessor.status, predecessor.result_json "
            "FROM task_dependencies AS dependency "
            "JOIN tasks AS predecessor ON predecessor.id=dependency.predecessor_task_id "
            "WHERE dependency.continuation_task_id=? ORDER BY dependency.ordinal",
            (task_id,),
        ).fetchall()

    def _continuation_waiting_reason(self, rows):
        statuses = [row["status"] for row in rows]
        if "cancelled" in statuses:
            return "dependency_cancelled"
        if "failed" in statuses:
            return "dependency_failed"
        if any(status != "completed" for status in statuses):
            return "waiting_for_dependencies"
        return None

    def _admit_continuation(self, task_id):
        """Materialize ordered inputs once, inside the caller's transaction."""
        rows = self._continuation_rows(task_id)
        if not rows:
            return None
        task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task or task["status"] != "queued":
            return None
        if self.conn.execute("SELECT 1 FROM continuation_admissions WHERE continuation_task_id=?", (task_id,)).fetchone():
            return None
        reason = self._continuation_waiting_reason(rows)
        if reason is not None:
            self._set_waiting_reason(task_id, reason)
            return None

        resolved_children = []
        ordered_inputs = []
        for row in rows:
            result = json.loads(row["result_json"] or "{}")
            outputs = result.get("outputs")
            if not isinstance(outputs, list):
                raise ValidationError("runtime continuation predecessor result has no outputs", details={"task_id": row["task_id"]})
            child_outputs = []
            for output in outputs:
                digest = output.get("digest") if isinstance(output, dict) else None
                if not isinstance(digest, str) or not OBJECT_ID_RE.fullmatch(digest):
                    raise ValidationError("runtime continuation predecessor output is invalid", details={"task_id": row["task_id"]})
                # Keep the complete already-validated settlement identity
                # (including role/ordinal/primary fields when present) while
                # deriving the claim's unique CAS input list from its digest.
                child_outputs.append(dict(output))
                if digest not in ordered_inputs:
                    ordered_inputs.append(digest)
            resolved_children.append({"task_id": row["task_id"], "ordinal": int(row["ordinal"]), "outputs": child_outputs})

        spec = json.loads(task["spec_json"])
        spec["input_object_ids"] = ordered_inputs
        spec["spec"]["runtime_dependencies"]["resolved_children"] = resolved_children
        run = self.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()
        self._validate_task_inputs(run["project_id"], spec)
        snapshot = {"children": resolved_children, "input_object_ids": ordered_inputs}
        timestamp = now()
        self.conn.execute(
            "INSERT INTO continuation_admissions(continuation_task_id, dependency_snapshot_json, admitted_at) VALUES (?, ?, ?)",
            (task_id, canonical_json(snapshot), timestamp),
        )
        self.conn.execute(
            "UPDATE tasks SET spec_json=?, waiting_reason=NULL, updated_at=? WHERE id=? AND status='queued'",
            (canonical_json(spec), timestamp, task_id),
        )
        return self._append_event(task["run_id"], task_id, "task.continuation_admitted", snapshot)

    def _refresh_continuations_for_predecessor(self, predecessor_task_id):
        rows = self.conn.execute(
            "SELECT continuation_task_id FROM task_dependencies WHERE predecessor_task_id=? ORDER BY continuation_task_id",
            (predecessor_task_id,),
        ).fetchall()
        event_ids = []
        for row in rows:
            event_id = self._admit_continuation(row["continuation_task_id"])
            if event_id is not None:
                event_ids.append(event_id)
            if not self.conn.execute("SELECT 1 FROM continuation_admissions WHERE continuation_task_id=?", (row["continuation_task_id"],)).fetchone():
                dependencies = self._continuation_rows(row["continuation_task_id"])
                self._set_waiting_reason(row["continuation_task_id"], self._continuation_waiting_reason(dependencies))
        return event_ids

    def timeline_render_publication(self, authoring_task_id):
        row = self.conn.execute(
            "SELECT * FROM timeline_render_publications WHERE authoring_task_id=?",
            (authoring_task_id,),
        ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["prepared"] = json.loads(value.pop("prepared_json"))
        value["result"] = json.loads(value.pop("result_json")) if value.get("result_json") else None
        return value

    def prepare_timeline_render_publication(
        self, authoring_task_id, attempt_id, fence, runtime_epoch, request_hash, prepared
    ):
        """Freeze one publication request before either downstream mutation."""
        with self._transaction():
            current = self.timeline_render_publication(authoring_task_id)
            if current is not None:
                if current["request_hash"] != request_hash:
                    raise ConflictError("authoring task publication payload changed")
                return current
            timestamp = now()
            self.conn.execute(
                "INSERT INTO timeline_render_publications("
                "authoring_task_id, attempt_id, fence, runtime_epoch, request_hash, prepared_json, state, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, 'prepared', ?, ?)",
                (
                    authoring_task_id, attempt_id, int(fence), int(runtime_epoch), request_hash,
                    canonical_json(prepared), timestamp, timestamp,
                ),
            )
            return self.timeline_render_publication(authoring_task_id)

    def complete_timeline_render_publication(
        self, authoring_task_id, *, attempt_id, fence, runtime_epoch,
        timeline_id, timeline_version, render_task_id, render_run_id, result,
    ):
        """Record the link in the caller's timeline-save/task-admission transaction."""
        updated = self.conn.execute(
            "UPDATE timeline_render_publications SET attempt_id=?, fence=?, runtime_epoch=?, state='published', "
            "timeline_id=?, timeline_version=?, render_task_id=?, render_run_id=?, result_json=?, updated_at=? "
            "WHERE authoring_task_id=? AND state='prepared'",
            (
                attempt_id, int(fence), int(runtime_epoch), timeline_id, int(timeline_version),
                render_task_id, render_run_id, canonical_json(result), now(), authoring_task_id,
            ),
        )
        if updated.rowcount != 1:
            raise ConflictError("timeline render publication checkpoint is no longer prepared")
        return self.timeline_render_publication(authoring_task_id)

    def _task_result(self, run, task):
        result = dict(task)
        result["spec"], generation_intent = public_task_spec(json.loads(result.pop("spec_json")))
        if generation_intent is not None:
            # The producer intent is part of the immutable admission payload;
            # expose the same opaque value on canonical task readback.
            result["generation_intent"] = generation_intent
        if "required_facts" in result["spec"]:
            result["required_facts"] = dict(result["spec"]["required_facts"])
        if result.get("expected_effect_json"):
            result["expected_effect"] = json.loads(result.pop("expected_effect_json"))
        else:
            result.pop("expected_effect_json", None)
        if result.get("result_json") is not None:
            result["result"] = json.loads(result["result_json"])
        if result.get("waiting_reason"):
            result["blocked_reason"] = result["waiting_reason"]
        return self._public_task_result({"run": dict(run), "task": result})

    def _public_task_result(self, value):
        """Remove internal/legacy intent keys from a stored task result."""
        result = dict(value)
        task = result.get("task")
        if isinstance(task, dict):
            task = dict(task)
            task["spec"], generation_intent = public_task_spec(task.get("spec") or {})
            if generation_intent is None and task.get("generation_intent") is not None:
                generation_intent = task["generation_intent"]
            if generation_intent is None:
                task.pop("generation_intent", None)
            else:
                task["generation_intent"] = generation_intent
            result["task"] = task
        return result

    def get_task(self, task_id):
        row = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise NotFoundError("task not found")
        run = self.conn.execute("SELECT * FROM runs WHERE id=?", (row["run_id"],)).fetchone()
        return self._task_result(run, row)

    def list_events(self, run_id):
        rows = self.conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
        return [dict(row) | {"payload": json.loads(row["payload_json"])} for row in rows]

    def _append_event(self, run_id, task_id, kind, payload):
        previous = self.conn.execute("SELECT event_hash FROM events WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,)).fetchone()
        previous_hash = previous[0] if previous else ""
        timestamp = now()
        event_hash = hashlib.sha256(canonical_json({"run_id":run_id,"task_id":task_id,"kind":kind,"payload":payload,"previous_hash":previous_hash,"created_at":timestamp}).encode()).hexdigest()
        self.conn.execute("INSERT INTO events(run_id, task_id, kind, payload_json, previous_hash, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (run_id, task_id, kind, canonical_json(payload), previous_hash, event_hash, timestamp))
        # Event IDs are the committed event-table identities, never a ledger
        # identity or a process-local surrogate.
        event = self.conn.execute(
            "SELECT id FROM events WHERE run_id=? AND event_hash=? AND created_at=? LIMIT 1",
            (run_id, event_hash, timestamp),
        ).fetchone()
        return str(event[0])

    def _append_timeline_event(self, timeline_id, kind, payload):
        """Append a timeline event in the caller's transaction."""
        previous = self.conn.execute(
            "SELECT event_hash FROM timeline_events WHERE timeline_id=? ORDER BY id DESC LIMIT 1",
            (timeline_id,),
        ).fetchone()
        timestamp = now()
        previous_hash = previous[0] if previous else ""
        event_hash = hashlib.sha256(canonical_json({
            "timeline_id": timeline_id, "kind": kind, "payload": payload,
            "previous_hash": previous_hash, "created_at": timestamp,
        }).encode()).hexdigest()
        self.conn.execute(
            "INSERT INTO timeline_events(timeline_id, kind, payload_json, previous_hash, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (timeline_id, kind, canonical_json(payload), previous_hash, event_hash, timestamp),
        )
        return str(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    def _allocate_project_seq(self, project_id):
        """Allocate the next canonical project transaction sequence."""
        self.conn.execute(
            "INSERT INTO project_sequences(project_id, next_seq) VALUES (?, 2) "
            "ON CONFLICT(project_id) DO UPDATE SET next_seq=next_seq+1",
            (str(project_id),),
        )
        return int(self.conn.execute(
            "SELECT next_seq - 1 FROM project_sequences WHERE project_id=?",
            (str(project_id),),
        ).fetchone()[0])

    def _record_command_receipt(
        self, command_kind, aggregate_id, idempotency_key, request_hash, result,
        *, project_id, event_ids=(), primary_stream_id=None,
        resulting_stream_seq=None, created_at=None,
    ):
        """Persist complete receipt facts in the active mutation transaction."""
        project_seq = self._allocate_project_seq(project_id)
        txn_id = "txn-" + new_id()
        timestamp = created_at or now()
        self.conn.execute(
            "INSERT INTO command_idempotency("
            "command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at, "
            "txn_id, primary_stream_id, resulting_stream_seq, first_project_seq, last_project_seq, event_ids_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                command_kind, aggregate_id, idempotency_key, request_hash,
                canonical_json(result), timestamp, txn_id, primary_stream_id,
                resulting_stream_seq, project_seq, project_seq,
                canonical_json([str(event_id) for event_id in event_ids]),
            ),
        )
        return txn_id

    @staticmethod
    def _waiting_for_resource(resource_key):
        safe = "".join(ch if ch.isalnum() else "_" for ch in str(resource_key)).strip("_").lower()
        return f"waiting_for_{safe or 'resource'}"

    def _set_waiting_reason(self, task_id, reason):
        self.conn.execute("UPDATE tasks SET waiting_reason=?, updated_at=? WHERE id=? AND status='queued'", (reason, now(), task_id))

    def _release_reservations(self, task_id, lease_token=None):
        timestamp = now()
        if lease_token is None:
            self.conn.execute("UPDATE reservations SET released_at=? WHERE task_id=? AND released_at IS NULL", (timestamp, task_id))
        else:
            self.conn.execute("UPDATE reservations SET released_at=? WHERE task_id=? AND lease_token=? AND released_at IS NULL", (timestamp, task_id, lease_token))

    def _reap_expired_leases(self):
        """Return expired attempts to the queue and release their resources.

        Called inside the caller's transaction; expiry only affects attempts
        that carry the v2 lease deadline.
        """
        current = datetime.now(timezone.utc)
        rows = self.conn.execute("SELECT id, run_id, lease_token, lease_expires_at FROM tasks WHERE status='running' AND lease_expires_at IS NOT NULL").fetchall()
        for row in rows:
            try:
                expired = datetime.fromisoformat(row["lease_expires_at"]) <= current
            except (TypeError, ValueError):
                expired = True
            if not expired:
                continue
            timestamp = now()
            self.conn.execute("UPDATE tasks SET status='queued', executor_id=NULL, lease_token=NULL, lease_expires_at=NULL, waiting_reason='waiting_for_worker', updated_at=? WHERE id=?", (timestamp, row["id"]))
            self.conn.execute("UPDATE runs SET status='queued', updated_at=? WHERE id=? AND status='running'", (timestamp, row["run_id"]))
            self._release_reservations(row["id"], row["lease_token"])
            self._append_event(row["run_id"], row["id"], "task.lease_expired", {"waiting_reason": "waiting_for_worker"})

    def register_capability(self, capability_id, definition_digest, *, required_resource_keys=None, status="ready", unavailable_reason=None, estimated_scratch_bytes=0, estimated_output_bytes=0):
        if not capability_id or not definition_digest:
            raise ValidationError("capability_id and definition_digest are required")
        if status not in {"ready", "unavailable", "unsupported", "retired"}:
            raise ValidationError("invalid capability readiness status")
        keys = list(dict.fromkeys(required_resource_keys or []))
        if any(not isinstance(key, str) or not key for key in keys):
            raise ValidationError("resource keys must be non-empty strings")
        if int(estimated_scratch_bytes) < 0 or int(estimated_output_bytes) < 0:
            raise ValidationError("estimated resource bytes must be non-negative")
        with self._mutex:
            timestamp = now()
            self.conn.execute("INSERT INTO capabilities(id, definition_digest, status, required_resource_keys_json, estimated_scratch_bytes, estimated_output_bytes, unavailable_reason, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET definition_digest=excluded.definition_digest, status=excluded.status, required_resource_keys_json=excluded.required_resource_keys_json, estimated_scratch_bytes=excluded.estimated_scratch_bytes, estimated_output_bytes=excluded.estimated_output_bytes, unavailable_reason=excluded.unavailable_reason, updated_at=excluded.updated_at", (capability_id, definition_digest, status, canonical_json(keys), int(estimated_scratch_bytes), int(estimated_output_bytes), unavailable_reason, timestamp, timestamp))
            row = self.conn.execute("SELECT * FROM capabilities WHERE id=?", (capability_id,)).fetchone()
            return self._capability_result(row)

    def _capability_result(self, row):
        result = dict(row)
        result["required_resource_keys"] = json.loads(result.pop("required_resource_keys_json"))
        return result

    def list_capabilities(self):
        with self._mutex:
            return [self._capability_result(row) for row in self.conn.execute("SELECT * FROM capabilities ORDER BY id")]

    def _current_runtime_epoch(self):
        row = self.conn.execute("SELECT runtime_epoch FROM runtime_lifecycle WHERE id=1").fetchone()
        return int(row[0]) if row else 1

    def _validate_runtime_epoch(self, supplied, *, identity, identity_id=None, required=False):
        current = self._current_runtime_epoch()
        if required and supplied is None:
            raise LeaseError(f"{identity} runtime epoch is required", details={"expected": current})
        # Bootstrap callers may omit the epoch when establishing a brand-new
        # identity.  An identity which survived a reboot is different: an
        # omitted epoch is ambiguous and is rejected rather than allowing a
        # stale client to mutate the new session.
        if supplied is None and identity_id:
            row = self.conn.execute("SELECT runtime_epoch FROM executors WHERE id=?", (identity_id,)).fetchone()
            if row and int(row[0]) != current:
                raise LeaseError(f"{identity} runtime epoch is required after restart", details={"expected": current})
        # For a supplied epoch, always apply the identity fence.
        if supplied is not None:
            try:
                supplied = int(supplied)
            except (TypeError, ValueError) as exc:
                raise LeaseError(f"{identity} runtime epoch is invalid") from exc
            if supplied != current:
                raise LeaseError(f"{identity} belongs to a stale runtime epoch", details={"expected": current, "actual": supplied})
        return current

    def set_executor_readiness(self, executor_id, *, ready, reason=None, runtime_epoch=None):
        if not executor_id:
            raise ValidationError("executor_id is required")
        if not isinstance(ready, bool):
            raise ValidationError("ready must be a boolean")
        with self._mutex:
            epoch = self._validate_runtime_epoch(runtime_epoch, identity="executor", identity_id=executor_id, required=True)
            if not self.conn.execute("SELECT 1 FROM executors WHERE id=?", (executor_id,)).fetchone():
                raise NotFoundError("executor not found")
            self.conn.execute("UPDATE executors SET readiness=?, readiness_reason=?, last_seen_at=?, runtime_epoch=? WHERE id=?", ("ready" if ready else "not_ready", None if ready else (reason or "executor_not_ready"), now(), epoch, executor_id))
            row = self.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone()
            return self._executor_result(row)

    def heartbeat_executor(self, executor_id, *, ready=None, reason=None, runtime_epoch=None):
        if not executor_id:
            raise ValidationError("executor_id is required")
        with self._mutex:
            epoch = self._validate_runtime_epoch(runtime_epoch, identity="executor", identity_id=executor_id, required=True)
            row = self.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone()
            if not row:
                raise NotFoundError("executor not found")
            if ready is not None:
                if not isinstance(ready, bool):
                    raise ValidationError("ready must be a boolean")
                self.conn.execute("UPDATE executors SET readiness=?, readiness_reason=? WHERE id=?", ("ready" if ready else "not_ready", None if ready else (reason or "executor_not_ready"), executor_id))
            self.conn.execute("UPDATE executors SET last_seen_at=?, runtime_epoch=? WHERE id=?", (now(), epoch, executor_id))
            return self._executor_result(self.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone())

    def _executor_result(self, row):
        result = dict(row)
        stored_capabilities = json.loads(result.pop("capabilities_json"))
        verified_facts = None
        capabilities = []
        for value in stored_capabilities:
            if isinstance(value, dict) and "verified_facts" in value:
                candidate = value["verified_facts"]
                if verified_facts is None:
                    verified_facts = candidate
                elif verified_facts != candidate:
                    raise ValidationError("executor capability facts are inconsistent")
                value = {key: fact for key, fact in value.items() if key != "verified_facts"}
            capability_id = value if isinstance(value, str) else value.get("capability_id", value.get("id"))
            if not isinstance(capability_id, str) or not capability_id:
                raise ValidationError("executor capability must identify a capability")
            capability = self.conn.execute(
                "SELECT id, definition_digest, status, required_resource_keys_json, "
                "estimated_scratch_bytes, estimated_output_bytes, unavailable_reason "
                "FROM capabilities WHERE id=?",
                (capability_id,),
            ).fetchone()
            if not capability:
                raise ValidationError("executor capability is not registered")
            capabilities.append({
                "capability_id": capability["id"],
                "definition_digest": capability["definition_digest"],
                "status": capability["status"],
                "required_resource_keys": json.loads(capability["required_resource_keys_json"]),
                "estimated_scratch_bytes": capability["estimated_scratch_bytes"],
                "estimated_output_bytes": capability["estimated_output_bytes"],
                "unavailable_reason": capability["unavailable_reason"],
            })
        result["capabilities"] = capabilities
        result["resource_keys"] = json.loads(result.pop("resource_keys_json"))
        result.setdefault("readiness", "ready")
        if verified_facts is not None:
            result["verified_facts"] = verified_facts
        return result

    def _executor_capability_ids(self, row):
        values = json.loads(row["capabilities_json"])
        return {item if isinstance(item, str) else item.get("capability_id", item.get("id")) for item in values}

    def _executor_capability(self, row, capability_id):
        """Return the exact descriptor advertised by an executor."""
        for value in json.loads(row["capabilities_json"]):
            if isinstance(value, str) and value == capability_id:
                return {"capability_id": value}
            if isinstance(value, dict) and (value.get("capability_id") or value.get("id")) == capability_id:
                return value
        return None

    @staticmethod
    def _executor_live(row):
        if not row or not row["last_seen_at"]:
            return False
        try:
            seen = datetime.fromisoformat(row["last_seen_at"])
        except (TypeError, ValueError):
            return False
        return seen > datetime.now(timezone.utc) - timedelta(seconds=EXECUTOR_LIVENESS_SECONDS)

    def _executor_can_run(self, executor, capability_id, capability_digest=None, *, include_storage=True, required_facts=None):
        if not executor or executor["readiness"] != "ready" or not self._executor_live(executor):
            return False
        descriptor = self._executor_capability(executor, capability_id)
        if not descriptor or descriptor.get("status", "ready") != "ready":
            return False
        capability = self.conn.execute("SELECT * FROM capabilities WHERE id=?", (capability_id,)).fetchone()
        if not capability or capability["status"] != "ready":
            return False
        if capability_digest is not None and capability["definition_digest"] != capability_digest:
            return False
        advertised_digest = descriptor.get("definition_digest")
        if advertised_digest and advertised_digest != capability["definition_digest"]:
            return False
        if required_facts is not None:
            verified_facts = descriptor.get("verified_facts", {"exact": {}, "minimum": {}})
            if not execution_facts_match(required_facts, verified_facts):
                return False
        available = set(json.loads(executor["resource_keys_json"]))
        for key in self._required_resource_keys(capability_id):
            if key not in available:
                return False
        return not include_storage or self.storage_preflight(capability_id)["ok"]

    def matching_live_executor(self, capability_id, capability_digest=None, *, include_storage=True, required_facts=None):
        with self._mutex:
            return any(self._executor_can_run(row, capability_id, capability_digest, include_storage=include_storage, required_facts=required_facts) for row in self.conn.execute("SELECT * FROM executors"))

    def _required_resource_keys(self, capability):
        row = self.conn.execute("SELECT required_resource_keys_json FROM capabilities WHERE id=?", (capability,)).fetchone()
        return json.loads(row[0]) if row else []

    def storage_preflight(self, capability, *, storage_estimate=None):
        estimate = self._validate_storage_estimate(storage_estimate)
        if estimate is None:
            row = self.conn.execute("SELECT estimated_scratch_bytes, estimated_output_bytes FROM capabilities WHERE id=?", (capability,)).fetchone()
            scratch_bytes, output_bytes = (int(row[0]), int(row[1])) if row else (0, 0)
            source = "capability"
        else:
            scratch_bytes = estimate["scratch_bytes"]
            output_bytes = estimate["output_bytes"]
            source = "task"
        required = scratch_bytes + output_bytes
        available = int(shutil.disk_usage(self.root).free)
        return {"ok": available >= required, "required_bytes": required, "available_bytes": available, "scratch_bytes": scratch_bytes, "output_bytes": output_bytes, "estimate_source": source, "reason": None if available >= required else "insufficient_storage"}

    def _claim_task(self, task_id, executor_id, lease_token, *, runtime_epoch=None, _transactional=True):
        """Claim one exact task, optionally as part of a larger mutation.

        ``claim_next`` must persist task claim, attempt fence, and its
        idempotency record in one transaction.  The private switch keeps the
        original exact-task API atomic while allowing that enclosing command
        to reuse the same claim checks without a nested ``BEGIN``.
        """
        with self._mutex:
            if not executor_id or not lease_token:
                raise ValidationError("executor_id and lease_token are required")
            epoch = self._validate_runtime_epoch(runtime_epoch, identity="executor", identity_id=executor_id, required=True)
            transaction = self._transaction() if _transactional else nullcontext()
            with transaction:
                self._reap_expired_leases()
                task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
                if not task:
                    raise NotFoundError("task not found")
                if task["status"] != "queued":
                    raise ConflictError("task is not claimable", details={"status": task["status"]})
                dependency_rows = self._continuation_rows(task_id)
                if dependency_rows and not self.conn.execute(
                    "SELECT 1 FROM continuation_admissions WHERE continuation_task_id=?", (task_id,)
                ).fetchone():
                    self._admit_continuation(task_id)
                    if not self.conn.execute(
                        "SELECT 1 FROM continuation_admissions WHERE continuation_task_id=?", (task_id,)
                    ).fetchone():
                        return self.get_task(task_id)
                    task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
                executor = self.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone()
                capability = self.conn.execute("SELECT * FROM capabilities WHERE id=?", (task["capability"],)).fetchone()
                task_spec = json.loads(task["spec_json"])
                waiting_reason = None
                if not executor:
                    waiting_reason = "waiting_for_worker"
                elif executor["readiness"] != "ready":
                    waiting_reason = "waiting_for_worker"
                elif not capability and task["capability_digest"] is not None:
                    # A task admitted before its executor advertises the
                    # capability remains queued, never claimable, until a
                    # matching registration arrives.
                    waiting_reason = "capability_unavailable"
                elif capability and capability["status"] != "ready":
                    waiting_reason = "capability_unavailable"
                elif not self.storage_preflight(task["capability"], storage_estimate=task_spec.get("storage_estimate"))["ok"]:
                    waiting_reason = "insufficient_storage"
                elif task["capability"] not in self._executor_capability_ids(executor):
                    waiting_reason = "waiting_for_worker"
                elif not self._executor_live(executor):
                    waiting_reason = "waiting_for_worker"
                elif task["capability_digest"] is not None and (not capability or capability["definition_digest"] != task["capability_digest"]):
                    waiting_reason = "capability_unavailable"
                elif (self._executor_capability(executor, task["capability"]) or {}).get("status", "ready") != "ready":
                    waiting_reason = "waiting_for_worker"
                elif not execution_facts_match(
                    task_spec.get("required_facts", {"exact": {}, "minimum": {}}),
                    (self._executor_capability(executor, task["capability"]) or {}).get(
                        "verified_facts", {"exact": {}, "minimum": {}
                    }),
                ):
                    waiting_reason = "waiting_for_executor_facts"
                else:
                    active = self.conn.execute("SELECT COUNT(*) FROM tasks WHERE executor_id=? AND status='running'", (executor_id,)).fetchone()[0]
                    if active >= executor["max_concurrency"]:
                        waiting_reason = "waiting_for_worker"
                    else:
                        available = set(json.loads(executor["resource_keys_json"]))
                        for key in self._required_resource_keys(task["capability"]):
                            if key not in available:
                                waiting_reason = self._waiting_for_resource(key)
                                break
                            occupied = self.conn.execute("SELECT 1 FROM reservations WHERE executor_id=? AND resource_key=? AND released_at IS NULL LIMIT 1", (executor_id, key)).fetchone()
                            if occupied:
                                waiting_reason = self._waiting_for_resource(key)
                                break
                if waiting_reason:
                    self._set_waiting_reason(task_id, waiting_reason)
                    return self.get_task(task_id)
                timestamp = now()
                fence = int(task["lease_fence"] or 0) + 1
                deadline = (datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)).isoformat(timespec="milliseconds")
                self.conn.execute("UPDATE tasks SET status='running', executor_id=?, lease_token=?, lease_fence=?, lease_expires_at=?, waiting_reason=NULL, attempt=attempt+1, runtime_epoch=?, updated_at=? WHERE id=? AND status='queued'", (executor_id, lease_token, fence, deadline, epoch, timestamp, task_id))
                self.conn.execute("UPDATE runs SET status='running', updated_at=? WHERE id=?", (timestamp, task["run_id"]))
                self.conn.execute("UPDATE executors SET runtime_epoch=?, last_seen_at=? WHERE id=?", (epoch, timestamp, executor_id))
                for key in self._required_resource_keys(task["capability"]):
                    self.conn.execute("INSERT INTO reservations(task_id, resource_key, lease_token, created_at, released_at, executor_id, fence, lease_expires_at, runtime_epoch) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?) ON CONFLICT(task_id, resource_key) DO UPDATE SET lease_token=excluded.lease_token, created_at=excluded.created_at, released_at=NULL, executor_id=excluded.executor_id, fence=excluded.fence, lease_expires_at=excluded.lease_expires_at, runtime_epoch=excluded.runtime_epoch", (task_id, key, lease_token, timestamp, executor_id, fence, deadline, epoch))
                self._append_event(task["run_id"], task_id, "task.claimed", {"executor_id": executor_id, "attempt": task["attempt"] + 1, "fence": fence, "resource_keys": self._required_resource_keys(task["capability"])})
                return self.get_task(task_id)

    def upsert_executor(self, executor_id, capabilities, max_concurrency=1, resource_keys=None, *, protocol="workspace.v1", readiness="ready", readiness_reason=None, runtime_epoch=None, source_digest=None, dependency_digest=None, source_epoch=None, verified_facts=None):
        if not executor_id or max_concurrency < 1:
            raise ValidationError("executor_id and positive max_concurrency are required")
        if readiness not in {"ready", "not_ready"}:
            raise ValidationError("readiness must be ready or not_ready")
        with self._mutex:
            # Epoch fencing is deliberately the first operation under the
            # owner lock. A stale executor must have zero capability or
            # registration side effects.
            epoch = self._validate_runtime_epoch(runtime_epoch, identity="executor", identity_id=executor_id)
            capability_values = list(capabilities or [])
            normalized_facts = normalize_execution_facts(verified_facts, field="verified_facts") if verified_facts is not None else None
            capability_ids = []
            descriptors = []
            for value in capability_values:
                if isinstance(value, str):
                    capability_ids.append(value)
                elif isinstance(value, dict) and (value.get("capability_id") or value.get("id")):
                    capability_id = value.get("capability_id") or value.get("id")
                    capability_ids.append(capability_id)
                    if value.get("definition_digest"):
                        descriptors.append((capability_id, value))
                else:
                    raise ValidationError("capabilities must contain ids or capability descriptors")
            keys = list(dict.fromkeys(resource_keys or []))
            if any(not isinstance(key, str) or not key for key in keys):
                raise ValidationError("resource keys must be non-empty strings")
            # All input validation follows the epoch check, and descriptor
            # registration only happens after the complete request shape is
            # known to be valid.
            for capability_id, value in descriptors:
                # Upsert every descriptor inside executor.register's outer
                # transaction. A later executor failure rolls back capability
                # visibility as one command. A changed digest deliberately
                # supersedes the old descriptor; tasks pinned to the old
                # digest remain unclaimable rather than blocking bootstrap.
                self.register_capability(capability_id, value["definition_digest"], required_resource_keys=value.get("required_resource_keys"), status=value.get("status", "ready"), unavailable_reason=value.get("unavailable_reason"), estimated_scratch_bytes=value.get("estimated_scratch_bytes", 0), estimated_output_bytes=value.get("estimated_output_bytes", 0))
            # Preserve the historical convenience of string capability ids,
            # but make the registration explicit and digest-pinned.  This is
            # no longer a boot-time default: a fresh runtime has no ready
            # capability until an executor actually advertises one.
            for capability_id in capability_ids:
                if not self.conn.execute("SELECT 1 FROM capabilities WHERE id=?", (capability_id,)).fetchone():
                    self.register_capability(capability_id, "sha256:" + hashlib.sha256(str(capability_id).encode()).hexdigest(), required_resource_keys=[])
            stored_capabilities = capability_values
            if normalized_facts is not None:
                stored_capabilities = []
                for value in capability_values:
                    if isinstance(value, str):
                        stored_capabilities.append({"capability_id": value, "verified_facts": normalized_facts})
                    else:
                        stored_capabilities.append({**value, "verified_facts": normalized_facts})
            timestamp = now()
            self.conn.execute("INSERT INTO executors(id, max_concurrency, resource_keys_json, capabilities_json, protocol, created_at, runtime_epoch, readiness, readiness_reason, last_seen_at, source_digest, dependency_digest, source_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET capabilities_json=excluded.capabilities_json, max_concurrency=excluded.max_concurrency, resource_keys_json=excluded.resource_keys_json, protocol=excluded.protocol, readiness=excluded.readiness, readiness_reason=excluded.readiness_reason, last_seen_at=excluded.last_seen_at, runtime_epoch=excluded.runtime_epoch, source_digest=excluded.source_digest, dependency_digest=excluded.dependency_digest, source_epoch=excluded.source_epoch", (executor_id, max_concurrency, canonical_json(keys), canonical_json(stored_capabilities), protocol, timestamp, epoch, readiness, None if readiness == "ready" else (readiness_reason or "executor_not_ready"), timestamp, source_digest, dependency_digest, source_epoch))
            row = self.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone()
            return self._executor_result(row)

    def _validate_settlement_effect(self, effect, *, project_id=None, result=None, input_object_ids=None):
        if not isinstance(effect, dict):
            raise ValidationError("settlement effect must be an object")
        kind = effect.get("effect_type")
        if kind == "generation.publish_v1":
            return self._validate_generation_publish_v1_effect(
                effect,
                project_id=project_id,
                result=result,
            )
        if kind == "generation.create_with_variant":
            self._validate_generation_create_with_variant_effect(
                effect,
                project_id=project_id,
                result=result,
                input_object_ids=input_object_ids,
            )
            return
        target = effect.get("target_id")
        expected = effect.get("expected_version")
        try:
            expected_version = int(expected)
        except (TypeError, ValueError) as exc:
            raise ValidationError("settlement effect expected_version must be a positive integer") from exc
        if not target or expected is None or expected_version < 1:
            raise ValidationError("settlement effect requires target_id and positive expected_version")
        if kind == "generation.variant.append":
            self._validate_generation_variant_append_effect(
                effect,
                project_id=project_id,
                result=result,
                input_object_ids=input_object_ids,
            )
            return
        if kind != "project.update":
            raise ValidationError("unsupported settlement effect_type")
        try:
            current = self._project(str(target))
        except NotFoundError as exc:
            raise NotFoundError("settlement effect target project not found", details={"target_id": target}) from exc
        if current is not None and int(current["version"]) != expected_version:
            raise ConflictError("stale settlement effect target version", details={"target": target, "expected": expected_version, "actual": int(current["version"])})

    @staticmethod
    def _generation_publish_output_key(output):
        ordinal = output.get("ordinal", 0)
        return (
            output.get("output_port", output.get("name", "output")),
            output.get("group_key", "default"),
            output.get("variant_key", str(ordinal)),
            int(ordinal),
        )

    def _validate_generation_publish_v1_effect(self, effect, *, project_id=None, result=None):
        """Validate the exact GEN D1 multi-output publication effect."""
        if set(effect) != {"effect_type", "target_id", "payload"}:
            raise ValidationError(
                "generation.publish_v1 effect has the wrong fields",
                details={
                    "required": ["effect_type", "target_id", "payload"],
                    "unexpected": sorted(set(effect) - {"effect_type", "target_id", "payload"}),
                },
            )
        if effect["effect_type"] != "generation.publish_v1":
            raise ValidationError("generation.publish_v1 effect_type is invalid")
        target_id = effect["target_id"]
        if not isinstance(target_id, str) or not target_id:
            raise ValidationError("generation.publish_v1 target_id must be a non-empty string")
        payload = effect["payload"]
        if not isinstance(payload, dict):
            raise ValidationError("generation.publish_v1 payload must be an object")
        required_payload = {
            "version", "modality", "generation_type", "metadata",
            "partial_success_policy", "groups",
        }
        if set(payload) != required_payload:
            raise ValidationError(
                "generation.publish_v1 payload has the wrong fields",
                details={
                    "required": sorted(required_payload),
                    "unexpected": sorted(set(payload) - required_payload),
                },
            )
        if isinstance(payload["version"], bool) or payload["version"] != 1:
            raise ValidationError("generation.publish_v1 payload.version must be 1")
        if not isinstance(payload["modality"], str) or payload["modality"] not in {"image", "video", "audio"}:
            raise ValidationError("generation.publish_v1 payload.modality is invalid")
        if not isinstance(payload["generation_type"], str) or not payload["generation_type"] or len(payload["generation_type"]) > 128:
            raise ValidationError("generation.publish_v1 generation_type must be a non-empty string of at most 128 characters")
        if not isinstance(payload["metadata"], dict):
            raise ValidationError("generation.publish_v1 metadata must be an object")
        if not isinstance(payload["partial_success_policy"], str) or payload["partial_success_policy"] not in {"reject", "allow"}:
            raise ValidationError("generation.publish_v1 partial_success_policy is invalid")
        groups = payload["groups"]
        if not isinstance(groups, list) or not groups:
            raise ValidationError("generation.publish_v1 groups must be a non-empty list")

        declared = []
        seen_groups = set()
        seen_selectors = set()
        for group in groups:
            if not isinstance(group, dict) or set(group) != {"group_key", "selectors"}:
                raise ValidationError("generation.publish_v1 group requires exactly group_key and selectors")
            group_key = group["group_key"]
            if not isinstance(group_key, str) or not group_key or len(group_key) > 255:
                raise ValidationError("generation.publish_v1 group_key must be a non-empty string")
            if group_key in seen_groups:
                raise ValidationError("generation.publish_v1 groups must not contain duplicate group_key")
            seen_groups.add(group_key)
            selectors = group["selectors"]
            if not isinstance(selectors, list) or not selectors:
                raise ValidationError("generation.publish_v1 selectors must be a non-empty list")
            group_declarations = []
            seen_group_variants = set()
            for selector in selectors:
                if not isinstance(selector, dict) or set(selector) != {"selector", "ordinal", "variant_key", "output_port"}:
                    raise ValidationError(
                        "generation.publish_v1 selector requires exactly selector, ordinal, variant_key, and output_port"
                    )
                label = selector["selector"]
                output_port = selector["output_port"]
                variant_key = selector["variant_key"]
                ordinal = selector["ordinal"]
                if not isinstance(label, str) or not label or len(label) > 255:
                    raise ValidationError("generation.publish_v1 selector must be a non-empty string")
                if not isinstance(output_port, str) or not output_port or len(output_port) > 255:
                    raise ValidationError("generation.publish_v1 output_port must be a non-empty string")
                if not isinstance(variant_key, str) or not variant_key or len(variant_key) > 255:
                    raise ValidationError("generation.publish_v1 variant_key must be a non-empty string")
                if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
                    raise ValidationError("generation.publish_v1 ordinal must be a non-negative integer")
                key = (output_port, group_key, variant_key, ordinal)
                if key in seen_selectors:
                    raise ValidationError("generation.publish_v1 selectors must not contain duplicates")
                seen_selectors.add(key)
                group_variant = (ordinal, variant_key)
                if group_variant in seen_group_variants:
                    raise ValidationError("generation.publish_v1 group selectors must not duplicate ordinal and variant_key")
                seen_group_variants.add(group_variant)
                declaration = {
                    "selector": label,
                    "ordinal": ordinal,
                    "variant_key": variant_key,
                    "output_port": output_port,
                }
                group_declarations.append((key, declaration))
            declared.append((group_key, group_declarations))

        if project_id is not None:
            if not project_id:
                raise ConflictError("generation.publish_v1 requires a project-scoped task")
            if target_id != str(project_id):
                raise ConflictError(
                    "generation.publish_v1 target project does not match the task project",
                    details={"target_id": target_id, "project_id": project_id},
                )
            target_project = self._project(target_id)
            if target_project["id"] != str(project_id):
                raise ConflictError(
                    "generation.publish_v1 target project does not match the task project",
                    details={"target_id": target_id, "project_id": project_id},
                )
        if result is None:
            return None

        outputs = result.get("outputs") if isinstance(result, dict) else None
        if not isinstance(outputs, list):
            raise ValidationError("generation.publish_v1 settlement requires an outputs list")
        output_matches = defaultdict(list)
        for output in outputs:
            if not isinstance(output, dict):
                continue
            key = self._generation_publish_output_key(output)
            if any(key == declared_key for _group_key, selectors in declared for declared_key, _selector in selectors):
                output_matches[key].append(output)

        plan = []
        selected_count = 0
        for group_key, selectors in declared:
            selected = []
            missing = []
            for key, declaration in selectors:
                matches = output_matches.get(key, [])
                if len(matches) > 1:
                    raise ValidationError(
                        "generation.publish_v1 selector matched duplicate outputs",
                        details={"selector": declaration["selector"], "output_port": declaration["output_port"], "ordinal": declaration["ordinal"]},
                    )
                if not matches:
                    missing.append(declaration)
                    continue
                output = matches[0]
                if output.get("kind") != "object":
                    raise ValidationError("generation.publish_v1 selectors must resolve verified object outputs")
                selected.append((key, declaration, output))
            if payload["partial_success_policy"] == "reject" and missing:
                raise ValidationError(
                    "generation.publish_v1 reject policy requires every declared selector",
                    details={"group_key": group_key, "missing": missing},
                )
            selected_count += len(selected)
            plan.append({"group_key": group_key, "selected": selected, "missing": missing})
        if selected_count == 0:
            raise ValidationError("generation.publish_v1 requires at least one successful declared output")
        return plan

    def _validate_generation_create_with_variant_effect(
        self,
        effect,
        *,
        project_id=None,
        result=None,
        input_object_ids=None,
    ):
        """Validate Runtime-owned creation of a generation and first variant.

        This is the new-generation counterpart to ``generation.variant.append``.
        The task project is the sole target authority; Runtime derives stable
        generation/variant identities from the admitted task at settlement.
        That lets upload-driven producers publish into the gallery atomically
        without a browser-side generation-create mutation.
        """
        if not isinstance(effect.get("target_id"), str) or not effect["target_id"]:
            raise ValidationError("generation.create_with_variant target_id must be a non-empty string")
        payload = effect.get("payload")
        if not isinstance(payload, dict):
            raise ValidationError("generation.create_with_variant payload must be an object")
        required = {
            "generation_type", "metadata", "variant_type",
            "output_name", "output_ordinal", "primary_policy",
        }
        unknown = sorted(set(payload) - required)
        missing = sorted(required - set(payload))
        if missing or unknown:
            raise ValidationError(
                "generation.create_with_variant payload has the wrong fields",
                details={"missing": missing, "unexpected": unknown},
            )
        generation_type = payload["generation_type"]
        if not isinstance(generation_type, str) or not generation_type or len(generation_type) > 128:
            raise ValidationError("generation_type must be a non-empty string of at most 128 characters")
        metadata = payload["metadata"]
        if not isinstance(metadata, dict):
            raise ValidationError("generation metadata must be an object")
        if "params" in metadata and not isinstance(metadata["params"], dict):
            raise ValidationError("generation.create_with_variant metadata.params must be an object")
        variant_type = payload["variant_type"]
        if not isinstance(variant_type, str) or not variant_type or len(variant_type) > 128:
            raise ValidationError("variant_type must be a non-empty string of at most 128 characters")
        output_name = payload["output_name"]
        if not isinstance(output_name, str) or not output_name or len(output_name) > 512:
            raise ValidationError("output_name must be a non-empty string of at most 512 characters")
        if isinstance(payload["output_ordinal"], bool) or payload["output_ordinal"] != 0:
            raise ValidationError("output_ordinal must be zero for generation.create_with_variant")
        if payload["primary_policy"] != "preserve":
            raise ValidationError("primary_policy must be preserve")

        # Shape-only validation is used before output staging. Project and
        # input custody checks run again inside the fenced settlement.
        if project_id is None and result is None:
            return
        if not project_id:
            raise ConflictError("generation.create_with_variant requires a project-scoped task")
        target_project = self._project(str(effect["target_id"]))
        if target_project["id"] != str(project_id):
            raise ConflictError(
                "generation.create_with_variant target project does not match the task project",
                details={"target_id": effect["target_id"], "project_id": project_id},
            )
        # The producer-facing contract admits either the Runtime project ID or
        # its canonical slug.  Settlement remains Runtime-owned: the resolved
        # project ID is used for the generation row below.
        if not isinstance(input_object_ids, list) or not input_object_ids:
            raise ConflictError("generation.create_with_variant requires admitted task inputs")
        if result is None:
            return
        outputs = result.get("outputs") if isinstance(result, dict) else None
        if not isinstance(outputs, list) or len(outputs) != 1:
            raise ValidationError("generation.create_with_variant requires exactly one settlement output")
        selected = outputs[0]
        if (
            not isinstance(selected, dict)
            or selected.get("name") != output_name
            or selected.get("kind") != "object"
            or not isinstance(selected.get("digest"), str)
            or not OBJECT_ID_RE.fullmatch(selected["digest"])
        ):
            raise ValidationError(
                "generation.create_with_variant output selector did not resolve exactly one object",
                details={"output_name": output_name, "output_ordinal": 0},
            )

    def _validate_generation_variant_append_effect(
        self,
        effect,
        *,
        project_id=None,
        result=None,
        input_object_ids=None,
    ):
        """Validate the narrow, Runtime-owned generation append contract.

        This is intentionally stricter than the legacy project update effect.
        The generation, source variant, source object, and selected output are
        all bound before any variant row or generation version is changed.
        """
        if not isinstance(effect.get("target_id"), str) or not effect["target_id"]:
            raise ValidationError("generation.variant.append target_id must be a non-empty string")
        expected_version = effect.get("expected_version")
        if isinstance(expected_version, bool) or not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("generation.variant.append expected_version must be a positive integer")
        payload = effect.get("payload")
        if not isinstance(payload, dict):
            raise ValidationError("generation.variant.append payload must be an object")
        required = {
            "source_variant_id", "source_object_id", "variant_type",
            "output_name", "output_ordinal", "primary_policy",
        }
        unknown = sorted(set(payload) - required)
        missing = sorted(required - set(payload))
        if missing or unknown:
            raise ValidationError(
                "generation.variant.append payload has the wrong fields",
                details={"missing": missing, "unexpected": unknown},
            )
        source_variant_id = payload["source_variant_id"]
        if not isinstance(source_variant_id, str) or not source_variant_id:
            raise ValidationError("source_variant_id must be a non-empty string")
        source_object_id = payload["source_object_id"]
        if not isinstance(source_object_id, str) or not OBJECT_ID_RE.fullmatch(source_object_id):
            raise ValidationError("source_object_id must be a canonical sha256 object id")
        if not source_object_id.startswith("sha256:"):
            raise ValidationError("source_object_id must include the sha256 prefix")
        source_digest = source_object_id.removeprefix("sha256:")
        variant_type = payload["variant_type"]
        if not isinstance(variant_type, str) or not variant_type or len(variant_type) > 128:
            raise ValidationError("variant_type must be a non-empty string of at most 128 characters")
        output_name = payload["output_name"]
        if not isinstance(output_name, str) or not output_name or len(output_name) > 512:
            raise ValidationError("output_name must be a non-empty string of at most 512 characters")
        output_ordinal = payload["output_ordinal"]
        if isinstance(output_ordinal, bool) or not isinstance(output_ordinal, int) or output_ordinal != 0:
            raise ValidationError("output_ordinal must be zero for generation.variant.append")
        if payload["primary_policy"] != "preserve":
            raise ValidationError("primary_policy must be preserve")

        # Shape-only validation is used at admission/settlement request
        # parsing. The ownership and custody checks require the task project
        # and the normalized staged result, and therefore run again below.
        if project_id is None and result is None:
            return
        if not project_id:
            raise ConflictError("generation.variant.append requires a project-scoped task")
        generation = self.conn.execute(
            "SELECT * FROM generations WHERE id=?", (str(effect["target_id"]),)
        ).fetchone()
        if not generation:
            raise NotFoundError("settlement effect target generation not found", details={"target_id": effect["target_id"]})
        if generation["project_id"] != str(project_id):
            raise ConflictError(
                "settlement effect generation is outside the task project",
                details={"target_id": effect["target_id"], "project_id": project_id},
            )
        if int(generation["version"]) != int(effect["expected_version"]):
            raise ConflictError(
                "stale settlement effect target generation version",
                details={"target": effect["target_id"], "expected": int(effect["expected_version"]), "actual": int(generation["version"])},
            )
        source_variant = self.conn.execute(
            "SELECT * FROM generation_variants WHERE id=?", (source_variant_id,)
        ).fetchone()
        if not source_variant or source_variant["generation_id"] != generation["id"]:
            raise ConflictError(
                "source variant does not belong to the target generation",
                details={"source_variant_id": source_variant_id, "target_id": generation["id"]},
            )
        if source_variant["object_id"] != source_digest:
            raise ConflictError(
                "source variant object does not match source_object_id",
                details={"source_variant_id": source_variant_id, "expected": source_variant["object_id"], "actual": source_digest},
            )
        if not self.conn.execute("SELECT 1 FROM objects WHERE digest=?", (source_digest,)).fetchone():
            raise ConflictError("source object is not present in Runtime CAS", details={"source_object_id": source_object_id})
        if not self.conn.execute(
            "SELECT 1 FROM project_objects WHERE project_id=? AND digest=?",
            (str(project_id), source_digest),
        ).fetchone():
            raise ConflictError(
                "source object is outside the task project",
                details={"project_id": project_id, "source_object_id": source_object_id},
            )
        if not isinstance(input_object_ids, list) or source_object_id not in input_object_ids:
            raise ConflictError(
                "source object is not an admitted task input",
                details={"source_object_id": source_object_id},
            )
        if result is None:
            return
        outputs = result.get("outputs") if isinstance(result, dict) else None
        if not isinstance(outputs, list) or len(outputs) != 1:
            raise ValidationError("generation.variant.append requires exactly one settlement output")
        selected = outputs[0]
        if (
            not isinstance(selected, dict)
            or selected.get("name") != output_name
            or output_ordinal != 0
            or selected.get("kind") != "object"
            or not isinstance(selected.get("digest"), str)
            or not OBJECT_ID_RE.fullmatch(selected["digest"])
        ):
            raise ValidationError(
                "generation.variant.append output selector did not resolve exactly one object",
                details={"output_name": output_name, "output_ordinal": output_ordinal},
            )

    def _apply_settlement_effect(
        self,
        effect,
        *,
        project_id=None,
        result=None,
        task_id=None,
        input_object_ids=None,
    ):
        kind = effect.get("effect_type")
        if kind == "generation.publish_v1":
            plan = self._validate_settlement_effect(
                effect,
                project_id=project_id,
                result=result,
            )
            payload = effect["payload"]
            publications = []
            association_overrides = {}
            for group in plan:
                group_key = group["group_key"]
                missing = list(group["missing"])
                if not group["selected"]:
                    publications.append({
                        "group_key": group_key,
                        "published": [],
                        "missing_selectors": missing,
                    })
                    continue
                generation_id = "generation-" + hashlib.sha256(
                    canonical_json({"task_id": str(task_id), "group_key": group_key}).encode()
                ).hexdigest()
                timestamp = now()
                self.conn.execute(
                    "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, 'completed', ?, 1, ?, ?)",
                    (
                        generation_id,
                        str(project_id),
                        str(task_id),
                        payload["generation_type"],
                        canonical_json(payload["metadata"]),
                        timestamp,
                        timestamp,
                    ),
                )
                variants = []
                for key, declaration, output in group["selected"]:
                    variant_id = "variant-" + hashlib.sha256(
                        canonical_json({
                            "generation_id": generation_id,
                            "ordinal": declaration["ordinal"],
                            "variant_key": declaration["variant_key"],
                        }).encode()
                    ).hexdigest()
                    output_digest = output["digest"].removeprefix("sha256:")
                    variant_metadata = {
                        "selector": declaration["selector"],
                        "output_port": declaration["output_port"],
                        "group_key": group_key,
                        "variant_key": declaration["variant_key"],
                        "ordinal": declaration["ordinal"],
                        "filename": output.get("filename", output.get("name", "output")),
                        "media_type": output.get("media_type", "application/octet-stream"),
                        "size": int(output["size"]),
                        "role": output.get("role") or "output",
                        "producer": dict(output.get("producer") or {}),
                        "provenance": dict(output.get("provenance") or {}),
                        "durability": output.get("durability", "durable"),
                        "regeneration": output.get("regeneration"),
                        "coverage": output.get("coverage"),
                    }
                    self.conn.execute(
                        "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            variant_id,
                            generation_id,
                            output_digest,
                            declaration["variant_key"],
                            canonical_json(variant_metadata),
                            timestamp,
                        ),
                    )
                    association_overrides[key] = {
                        "generation_id": generation_id,
                        "variant_id": variant_id,
                        "selector": declaration["selector"],
                    }
                    variants.append({
                        "variant_id": variant_id,
                        "generation_id": generation_id,
                        "object_id": output["digest"],
                        "variant_key": declaration["variant_key"],
                        "ordinal": declaration["ordinal"],
                        "output_port": declaration["output_port"],
                    })
                publications.append({
                    "group_key": group_key,
                    "generation_id": generation_id,
                    "variants": variants,
                    "missing_selectors": missing,
                })
            return {
                "effect_type": "generation.publish_v1",
                "publications": publications,
                "_association_overrides": association_overrides,
            }
        if kind == "generation.create_with_variant":
            self._validate_settlement_effect(
                effect,
                project_id=project_id,
                result=result,
                input_object_ids=input_object_ids,
            )
            payload = effect["payload"]
            output = result["outputs"][payload["output_ordinal"]]
            output_digest = output["digest"].removeprefix("sha256:")
            generation_id = "generation-task-" + str(task_id)
            identity = {
                "generation_id": generation_id,
                "variant_type": payload["variant_type"],
                "output_name": payload["output_name"],
                "output_ordinal": payload["output_ordinal"],
                "output_digest": output["digest"],
                "task_id": str(task_id),
            }
            variant_id = "initial-" + hashlib.sha256(canonical_json(identity).encode()).hexdigest()
            timestamp = now()
            generation_metadata = dict(payload["metadata"])
            params = generation_metadata.get("params", {})
            if not isinstance(params, dict):
                raise ValidationError("generation.create_with_variant metadata.params must be an object")
            params = dict(params)
            params["source_task_id"] = str(task_id)
            params["input_object_ids"] = list(input_object_ids or [])
            params["output_name"] = payload["output_name"]
            params.setdefault("content_type", "video" if "video" in payload["generation_type"].lower() else "image")
            generation_metadata["params"] = params
            generation_metadata["source_task_id"] = str(task_id)
            generation_metadata["input_object_ids"] = list(input_object_ids or [])
            generation_metadata["output_name"] = payload["output_name"]
            generation_metadata["output_ordinal"] = payload["output_ordinal"]
            generation_metadata["primary_policy"] = payload["primary_policy"]
            self.conn.execute(
                "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, 'completed', ?, 1, ?, ?)",
                (
                    generation_id,
                    str(project_id),
                    str(task_id),
                    payload["generation_type"],
                    canonical_json(generation_metadata),
                    timestamp,
                    timestamp,
                ),
            )
            variant_metadata = {
                "is_primary": True,
                "source_task_id": str(task_id),
                "input_object_ids": list(input_object_ids or []),
                "output_name": payload["output_name"],
                "output_ordinal": payload["output_ordinal"],
                "primary_policy": payload["primary_policy"],
                "media_type": output.get("media_type"),
                "size": output.get("size"),
            }
            self.conn.execute(
                "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    variant_id,
                    generation_id,
                    output_digest,
                    payload["variant_type"],
                    canonical_json(variant_metadata),
                    timestamp,
                ),
            )
            return {
                "variant_id": variant_id,
                "generation_id": generation_id,
                "object_id": output["digest"],
                "variant_type": payload["variant_type"],
                "metadata": variant_metadata,
                "created_at": timestamp,
            }
        if kind != "project.update":
            if kind != "generation.variant.append":
                raise ValidationError("unsupported settlement effect_type")
            self._validate_settlement_effect(
                effect,
                project_id=project_id,
                result=result,
                input_object_ids=input_object_ids,
            )
            payload = effect["payload"]
            output = result["outputs"][payload["output_ordinal"]]
            output_digest = output["digest"].removeprefix("sha256:")
            identity = {
                "generation_id": str(effect["target_id"]),
                "source_variant_id": payload["source_variant_id"],
                "source_object_id": payload["source_object_id"],
                "variant_type": payload["variant_type"],
                "output_name": payload["output_name"],
                "output_ordinal": payload["output_ordinal"],
                "output_digest": output["digest"],
                "task_id": str(task_id),
            }
            variant_id = "append-" + hashlib.sha256(canonical_json(identity).encode()).hexdigest()
            timestamp = now()
            changed = self.conn.execute(
                "UPDATE generations SET version=version+1, updated_at=? WHERE id=? AND project_id=? AND version=?",
                (timestamp, str(effect["target_id"]), str(project_id), int(effect["expected_version"])),
            )
            if changed.rowcount != 1:
                raise ConflictError("stale settlement effect target generation version")
            metadata = {
                "source_task_id": str(task_id),
                "source_variant_id": payload["source_variant_id"],
                "source_object_id": payload["source_object_id"],
                "output_name": payload["output_name"],
                "output_ordinal": payload["output_ordinal"],
                "primary_policy": payload["primary_policy"],
            }
            try:
                self.conn.execute(
                    "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (variant_id, str(effect["target_id"]), output_digest, payload["variant_type"], canonical_json(metadata), timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    "generation variant append conflicts with an existing variant",
                    details={"variant_id": variant_id},
                ) from exc
            return {
                "variant_id": variant_id,
                "generation_id": str(effect["target_id"]),
                "object_id": output["digest"],
                "variant_type": payload["variant_type"],
                "metadata": metadata,
                "created_at": timestamp,
            }
        target = effect.get("target_id")
        current = self._project(str(target))
        payload = effect.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValidationError("project.update payload must be an object")
        name = payload.get("name", current["name"])
        metadata = payload.get("metadata", current["metadata"])
        if not name:
            raise ValidationError("project name is required")
        changed = self.conn.execute("UPDATE projects SET name=?, metadata_json=?, version=version+1, updated_at=? WHERE id=? AND version=?", (name, canonical_json(metadata), now(), current["id"], int(effect["expected_version"])))
        if changed.rowcount != 1:
            raise ConflictError("stale settlement effect target version")

    def _validated_manifest_digest(self, result, *, project_id=None):
        """Validate an optional managed-manifest reference before publication."""
        reference = result.get("manifest_ref") if isinstance(result, dict) else None
        if reference is None:
            return None
        if not isinstance(reference, dict):
            raise ValidationError("manifest_ref must be an object")
        unknown = set(reference) - {"object_id", "digest", "size"}
        if unknown:
            raise ValidationError("manifest_ref contains unsupported fields", details={"fields": sorted(unknown)})
        object_id = reference.get("object_id", reference.get("digest"))
        if not isinstance(object_id, str) or not OBJECT_ID_RE.fullmatch(object_id) or not object_id.startswith("sha256:"):
            raise ValidationError("manifest_ref requires a canonical sha256 object_id")
        digest = object_id.removeprefix("sha256:")
        size = reference.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValidationError("manifest_ref size must be a non-negative integer")
        matching_output = next(
            (output for output in result.get("outputs", [])
             if isinstance(output, dict) and output.get("digest") == object_id),
            None,
        )
        if matching_output is not None:
            if int(matching_output["size"]) != size:
                raise ConflictError("manifest_ref size does not match settled output")
        else:
            row = self.conn.execute("SELECT size FROM objects WHERE digest=?", (digest,)).fetchone()
            if not row or int(row["size"]) != size:
                raise ConflictError("manifest_ref is not a verified managed object")
            if project_id and not self.conn.execute(
                "SELECT 1 FROM project_objects WHERE project_id=? AND digest=?",
                (project_id, digest),
            ).fetchone():
                raise ConflictError("manifest_ref is outside the task project")
        return digest

    def _managed_output_value(self, row):
        value = dict(row)
        for field in ("producer_json", "provenance_json", "regeneration_json", "coverage_json"):
            value[field.removesuffix("_json")] = json.loads(value[field]) if value[field] is not None else None
            value.pop(field)
        value["object_id"] = "sha256:" + value.pop("object_digest")
        value["digest"] = value["object_id"]
        if value.get("manifest_digest"):
            value["manifest_ref"] = "sha256:" + value.pop("manifest_digest")
        else:
            value.pop("manifest_digest", None)
            value["manifest_ref"] = None
        value["selector"] = {"group_key": value["group_key"], "variant_key": value["variant_key"]}
        value["lifecycle"] = {
            "state": value["state"], "version": int(value["version"]),
            "expires_at": value["expires_at"], "pinned_at": value["pinned_at"],
            "lease_id": value.get("lease_id"), "lease_owner": value.get("lease_owner"),
            "lease_expires_at": value.get("lease_expires_at"),
            "updated_at": value["lifecycle_updated_at"],
        }
        return value

    @staticmethod
    def _managed_output_select():
        return (
            "SELECT a.*, t.run_id AS run_id, l.state, l.version, l.expires_at, l.pinned_at, "
            "l.lease_id, l.lease_owner, l.lease_expires_at, l.updated_at AS lifecycle_updated_at "
            "FROM managed_output_associations a "
            "JOIN managed_output_lifecycle l ON l.association_id=a.association_id "
            "JOIN tasks t ON t.id=a.task_id "
        )

    def _associate_managed_outputs(self, result, *, task_id, attempt_id, project_id, applied_effect=None):
        """Persist immutable output identity and initial Runtime lifecycle atomically."""
        manifest_digest = self._validated_manifest_digest(result, project_id=project_id)
        if manifest_digest is None:
            manifest_output = next(
                (output for output in result.get("outputs", [])
                 if isinstance(output, dict) and output.get("role") == "manifest"),
                None,
            )
            if manifest_output is not None:
                manifest_digest = str(manifest_output["digest"]).removeprefix("sha256:")
        associations = []
        publish_overrides = {}
        if isinstance(applied_effect, dict) and applied_effect.get("effect_type") == "generation.publish_v1":
            publish_overrides = applied_effect.get("_association_overrides") or {}
        for output in result.get("outputs", []):
            if not isinstance(output, dict) or output.get("kind") != "object":
                continue
            digest = str(output["digest"]).removeprefix("sha256:")
            output_port = output.get("output_port", output.get("name", "output"))
            group_key = output.get("group_key", "default")
            variant_key = output.get("variant_key", str(output.get("ordinal", 0)))
            ordinal = int(output.get("ordinal", 0))
            publish_key = (output_port, group_key, variant_key, ordinal)
            if isinstance(applied_effect, dict) and applied_effect.get("effect_type") == "generation.publish_v1":
                publish_override = publish_overrides.get(publish_key) or {}
                generation_id = publish_override.get("generation_id")
            elif isinstance(applied_effect, dict):
                publish_override = {}
                generation_id = applied_effect.get("generation_id")
            else:
                # Producer-supplied generation IDs are never authoritative;
                # generic managed outputs stay outside the generation domain.
                publish_override = {}
                generation_id = None
            role = output.get("role") or "output"
            durability = output.get("durability", "durable")
            producer = dict(output.get("producer") or {})
            provenance = dict(output.get("provenance") or {})
            if publish_override.get("selector") is not None:
                # The managed association schema already has an extensible
                # provenance object; retain GEN's selector label there rather
                # than adding a second association column.
                provenance["selector"] = publish_override["selector"]
            task_row = self.conn.execute("SELECT capability FROM tasks WHERE id=?", (str(task_id),)).fetchone()
            attempt_row = self.conn.execute(
                "SELECT executor_id, fence, runtime_epoch FROM attempts WHERE id=?",
                (str(attempt_id),),
            ).fetchone()
            if task_row:
                producer.setdefault("capability_id", task_row["capability"])
            provenance.setdefault("task_id", str(task_id))
            provenance.setdefault("attempt_id", str(attempt_id))
            if task_row:
                provenance.setdefault("capability_id", task_row["capability"])
            if attempt_row:
                provenance.setdefault("executor_id", attempt_row["executor_id"])
                provenance.setdefault("fence", int(attempt_row["fence"]))
                provenance.setdefault("runtime_epoch", int(attempt_row["runtime_epoch"]))
            else:
                provenance.setdefault("runtime_epoch", self._current_runtime_epoch())
            identity = {
                "task_id": str(task_id), "output_port": output_port,
                "group_key": group_key, "generation_id": generation_id,
                "variant_key": variant_key, "ordinal": ordinal,
            }
            association_id = "managed-output-" + hashlib.sha256(
                canonical_json(identity).encode()
            ).hexdigest()
            self.conn.execute(
                "INSERT OR IGNORE INTO managed_output_associations("
                "association_id, task_id, attempt_id, project_id, output_port, group_key, "
                "generation_id, variant_key, object_digest, manifest_digest, size, filename, "
                "media_type, ordinal, role, producer_json, provenance_json, durability, "
                "regeneration_json, coverage_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    association_id, str(task_id), str(attempt_id), project_id, output_port,
                    group_key, generation_id, variant_key, digest, manifest_digest,
                    int(output["size"]), output.get("filename", output.get("name", "output")),
                    output.get("media_type", "application/octet-stream"), ordinal, role,
                    canonical_json(producer), canonical_json(provenance), durability,
                    canonical_json(output["regeneration"]) if output.get("regeneration") is not None else None,
                    canonical_json(output["coverage"]) if output.get("coverage") is not None else None,
                    now(),
                ),
            )
            lifecycle_state = "temporary" if durability == "temporary" else "available"
            self.conn.execute(
                "INSERT OR IGNORE INTO managed_output_lifecycle(association_id, state, version, expires_at, pinned_at, lease_id, lease_owner, lease_expires_at, updated_at, created_at) VALUES (?, ?, 1, NULL, NULL, NULL, NULL, NULL, ?, ?)",
                (association_id, lifecycle_state, now(), now()),
            )
            row = self.conn.execute(
                self._managed_output_select() +
                "WHERE a.association_id=?",
                (association_id,),
            ).fetchone()
            associations.append(self._managed_output_value(row))
        return associations

    def list_managed_outputs(self, task_id):
        with self._mutex:
            rows = self.conn.execute(
                self._managed_output_select() +
                "WHERE a.task_id=? ORDER BY a.created_at, a.association_id",
                (str(task_id),),
            ).fetchall()
            return [self._managed_output_value(row) for row in rows]

    def get_managed_output(self, association_id):
        with self._mutex:
            row = self.conn.execute(
                self._managed_output_select() + "WHERE a.association_id=?",
                (str(association_id),),
            ).fetchone()
        if not row:
            raise NotFoundError("managed output not found")
        return self._managed_output_value(row)

    def update_managed_output_lifecycle(
        self, association_id, operation, *, expected_version, lease_id=None,
        lease_owner=None, lease_seconds=None,
    ):
        """Apply one Runtime-owned lifecycle transition in the caller's transaction."""
        row = self.conn.execute(
            self._managed_output_select() + "WHERE a.association_id=?",
            (str(association_id),),
        ).fetchone()
        if not row:
            raise NotFoundError("managed output not found")
        try:
            expected = int(expected_version)
        except (TypeError, ValueError) as exc:
            raise ValidationError("managed output expected_version must be a positive integer") from exc
        if expected < 1:
            raise ValidationError("managed output expected_version must be a positive integer")
        actual = int(row["version"])
        if expected != actual:
            raise ConflictError(
                "managed output lifecycle version conflict",
                details={"expected": expected, "actual": actual},
            )
        if operation not in {"lease", "release", "pin", "unpin", "expire", "reclaim", "promote"}:
            raise ValidationError("unsupported managed output lifecycle operation")

        state = row["state"]
        pinned_at = row["pinned_at"]
        current_lease_id = row["lease_id"]
        current_lease_owner = row["lease_owner"]
        current_lease_expires = row["lease_expires_at"]
        timestamp = now()
        active_lease = bool(current_lease_id and current_lease_expires and current_lease_expires > timestamp)
        next_state = state
        next_expires = row["expires_at"]
        next_lease_id = current_lease_id
        next_lease_owner = current_lease_owner
        next_lease_expires = current_lease_expires
        if operation == "lease":
            if state in {"expired", "reclaimed"}:
                raise ConflictError("managed output is not leaseable", details={"state": state})
            if active_lease and lease_id and str(lease_id) != str(current_lease_id):
                raise ConflictError("managed output lease is held by another owner")
            if lease_seconds is None:
                raise ValidationError("managed output lease_seconds is required")
            if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds <= 0:
                raise ValidationError("managed output lease_seconds must be a positive integer")
            next_lease_id = str(lease_id or current_lease_id or "managed-lease-" + new_id())
            next_lease_owner = str(lease_owner or current_lease_owner or "managed-output-client")
            next_lease_expires = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat(timespec="milliseconds")
        elif operation == "release":
            if active_lease and lease_id and str(lease_id) != str(current_lease_id):
                raise ConflictError("managed output lease does not belong to caller")
            next_lease_id = next_lease_owner = next_lease_expires = None
        elif operation == "pin":
            if state in {"expired", "reclaimed"}:
                raise ConflictError("managed output cannot be pinned", details={"state": state})
            pinned_at = pinned_at or timestamp
        elif operation == "unpin":
            pinned_at = None
        elif operation == "expire":
            if state != "temporary":
                raise ConflictError("only temporary managed outputs can expire", details={"state": state})
            if pinned_at or active_lease:
                raise ConflictError("managed output is protected from expiry")
            next_state = "expired"
            next_expires = next_expires or timestamp
        elif operation == "reclaim":
            if state != "expired":
                raise ConflictError("only expired managed outputs can be reclaimed", details={"state": state})
            if pinned_at or active_lease:
                raise ConflictError("managed output is protected from reclaim")
            next_state = "reclaimed"
            next_lease_id = next_lease_owner = next_lease_expires = None
        elif operation == "promote":
            if state not in {"available", "temporary"}:
                raise ConflictError("managed output cannot be promoted", details={"state": state})
            if row["project_id"] is None:
                raise ConflictError("managed output promotion requires a project association")
            self.conn.execute(
                "INSERT OR IGNORE INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, 'promoted', ?)",
                (row["project_id"], row["object_digest"], timestamp),
            )
            next_state = "promoted"
            next_expires = None
            next_lease_id = next_lease_owner = next_lease_expires = None
        changed = self.conn.execute(
            "UPDATE managed_output_lifecycle SET state=?, version=?, expires_at=?, pinned_at=?, lease_id=?, lease_owner=?, lease_expires_at=?, updated_at=? WHERE association_id=? AND version=?",
            (
                next_state, actual + 1, next_expires, pinned_at, next_lease_id,
                next_lease_owner, next_lease_expires, timestamp, str(association_id), actual,
            ),
        )
        if changed.rowcount != 1:
            raise ConflictError("managed output lifecycle changed during update")
        return self.get_managed_output(association_id)

    def _settle_attempt(self, task_id, lease_token, result, *, effect=None, fence=None, attempt_id, publish=None, record=None):
        with self._mutex:
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] != "running" or task["lease_token"] != lease_token:
                raise LeaseError("attempt lease is stale or already settled")
            if fence is not None and int(fence) != int(task["lease_fence"] or 0):
                raise LeaseError("attempt fence is stale", details={"expected": task["lease_fence"], "actual": fence})
            if task["lease_expires_at"]:
                try:
                    if datetime.fromisoformat(task["lease_expires_at"]) <= datetime.now(timezone.utc):
                        raise LeaseError("attempt lease has expired")
                except ValueError as exc:
                    raise LeaseError("attempt lease deadline is invalid") from exc
            declared = json.loads(task["expected_effect_json"]) if task["expected_effect_json"] else None
            task_spec = json.loads(task["spec_json"] or "{}")
            input_object_ids = task_spec.get("input_object_ids", [])
            if effect is not None and declared != effect:
                raise ValidationError("settlement effect was not predeclared", details={"declared": declared})
            if declared is not None and effect is None:
                raise ValidationError("declared settlement effect is required")
            run = self.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()
            task_project_id = run["project_id"] if run else None
            if effect is not None and effect.get("effect_type") == "generation.publish_v1" and not task_project_id:
                raise ConflictError("generation.publish_v1 requires a project-scoped task")
            with self._transaction():
                timestamp = now()
                # The service stages output bytes before entering this fenced
                # transaction.  Publication and object/project metadata are
                # performed only after all lease/effect checks succeeded.
                if effect is not None:
                    self._validate_settlement_effect(
                        effect,
                        project_id=task_project_id,
                        result=result,
                        input_object_ids=input_object_ids,
                    )
                self._validated_manifest_digest(result, project_id=task_project_id)
                applied_effect = None
                append_effect = effect is not None and effect.get("effect_type") in {
                    "generation.variant.append",
                    "generation.create_with_variant",
                    "generation.publish_v1",
                }
                if publish is not None:
                    if append_effect:
                        # Variant rows reference CAS objects.  Publish first
                        # inside this transaction, then append the variant;
                        # rollback plus staged cleanup removes all new bytes
                        # if the append or receipt fails. project.update keeps
                        # its historical effect-before-publication ordering.
                        publish()
                if effect is not None:
                    applied_effect = self._apply_settlement_effect(
                        effect,
                        project_id=task_project_id,
                        result=result,
                        task_id=task_id,
                        input_object_ids=input_object_ids,
                    )
                if publish is not None and not append_effect:
                    publish()
                if applied_effect is not None:
                    if effect.get("effect_type") == "generation.publish_v1":
                        result["generation_publish_v1"] = {
                            key: value
                            for key, value in applied_effect.items()
                            if not key.startswith("_")
                        }
                    else:
                        result["generation_variant"] = applied_effect
                managed_outputs = self._associate_managed_outputs(
                    result,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    project_id=task_project_id,
                    applied_effect=applied_effect,
                )
                self.conn.execute("UPDATE tasks SET status='completed', result_json=?, lease_expires_at=NULL, waiting_reason=NULL, updated_at=? WHERE id=?", (canonical_json(result), timestamp, task_id))
                self.conn.execute("UPDATE runs SET status='completed', updated_at=? WHERE id=?", (timestamp, task["run_id"]))
                self.conn.execute("UPDATE attempts SET settled=1 WHERE id=? AND settled=0", (attempt_id,))
                self._release_reservations(task_id, lease_token)
                event_id = self._append_event(task["run_id"], task_id, "task.completed", {"result": result, "effect": effect, "objects": result.get("outputs", [])})
                continuation_event_ids = self._refresh_continuations_for_predecessor(task_id)
                value = self.get_task(task_id)
                if record is not None:
                    record(value, event_ids=[event_id, *continuation_event_ids], primary_stream_id=task["run_id"], resulting_stream_seq=None)
                return value

    def heartbeat_task(self, task_id, lease_token, *, fence=None, lease_seconds=LEASE_SECONDS, record=None):
        if int(lease_seconds) <= 0:
            raise ValidationError("lease_seconds must be positive")
        with self._mutex:
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] != "running" or task["lease_token"] != lease_token:
                raise LeaseError("attempt lease is stale or already settled")
            if fence is not None and int(fence) != int(task["lease_fence"] or 0):
                raise LeaseError("attempt fence is stale", details={"expected": task["lease_fence"], "actual": fence})
            try:
                if task["lease_expires_at"] and datetime.fromisoformat(task["lease_expires_at"]) <= datetime.now(timezone.utc):
                    raise LeaseError("attempt lease has expired")
            except ValueError as exc:
                raise LeaseError("attempt lease deadline is invalid") from exc
            deadline = (datetime.now(timezone.utc) + timedelta(seconds=int(lease_seconds))).isoformat(timespec="milliseconds")
            with self._transaction():
                self.conn.execute("UPDATE tasks SET lease_expires_at=?, updated_at=? WHERE id=?", (deadline, now(), task_id))
                self.conn.execute("UPDATE reservations SET lease_expires_at=? WHERE task_id=? AND lease_token=? AND released_at IS NULL", (deadline, task_id, lease_token))
                self.conn.execute("UPDATE executors SET last_seen_at=? WHERE id=?", (now(), task["executor_id"]))
                value = self.get_task(task_id)
                if record is not None:
                    record(value)
                return value

    def cancel_task(self, task_id, *, record=None):
        with self._mutex:
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] in ("completed", "cancelled"):
                value = self.get_task(task_id)
                if record is not None:
                    record(value)
                return value
            with self._transaction():
                self.conn.execute("UPDATE tasks SET status='cancelled', lease_token=NULL, executor_id=NULL, attempt_id=NULL, lease_expires_at=NULL, waiting_reason=NULL, updated_at=? WHERE id=?", (now(), task_id))
                self.conn.execute("UPDATE runs SET status='cancelled', updated_at=? WHERE id=?", (now(), task["run_id"]))
                self._release_reservations(task_id, task["lease_token"])
                event_id = self._append_event(task["run_id"], task_id, "task.cancelled", {})
                self._refresh_continuations_for_predecessor(task_id)
                value = self.get_task(task_id)
                if record is not None:
                    record(value, event_ids=[event_id], primary_stream_id=task["run_id"], resulting_stream_seq=None)
                return value

    def cancel_run(self, run_id, *, idempotency_key=None):
        """Cancel every non-terminal child of a queued/running run atomically."""
        with self._mutex:
            run = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run:
                raise NotFoundError("run not found")
            request_hash = hashlib.sha256(b"{}").hexdigest()
            if idempotency_key:
                prior = self.conn.execute("SELECT * FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?", ("run.cancel", run_id, idempotency_key)).fetchone()
                if prior:
                    if prior["request_hash"] != request_hash:
                        raise ConflictError("idempotency key was already used with different input")
                    return json.loads(prior["result_json"])
            if run["status"] not in {"queued", "running"}:
                raise ConflictError("run is not cancellable", details={"status": run["status"]})
            with self._transaction():
                timestamp = now()
                children = self.conn.execute("SELECT * FROM tasks WHERE run_id=? ORDER BY created_at, id", (run_id,)).fetchall()
                cancelled = []
                for task in children:
                    if task["status"] in {"completed", "failed", "cancelled"}:
                        continue
                    self.conn.execute("UPDATE tasks SET status='cancelled', lease_token=NULL, executor_id=NULL, attempt_id=NULL, lease_expires_at=NULL, waiting_reason=NULL, updated_at=? WHERE id=?", (timestamp, task["id"]))
                    self._release_reservations(task["id"], task["lease_token"])
                    self._append_event(run_id, task["id"], "task.cancelled", {"reason": "run.cancelled"})
                    self._refresh_continuations_for_predecessor(task["id"])
                    cancelled.append(task["id"])
                self.conn.execute("UPDATE runs SET status='cancelled', updated_at=? WHERE id=?", (timestamp, run_id))
                self._append_event(run_id, None, "run.cancelled", {"task_ids": cancelled})
                result = dict(self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())
                if idempotency_key:
                    self.conn.execute("INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", ("run.cancel", run_id, idempotency_key, request_hash, canonical_json(result), now()))
            return result

    def retry_run(self, run_id, *, selected_task_ids=None, idempotency_key=None):
        """Requeue failed children of a failed run, preserving task identity."""
        with self._mutex:
            run = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run:
                raise NotFoundError("run not found")
            if selected_task_ids is not None:
                if not isinstance(selected_task_ids, list) or any(not isinstance(value, str) or not value for value in selected_task_ids):
                    raise InvalidRequestError("selected_task_ids must be an array of non-empty strings", details={"field": "selected_task_ids"})
                if len(selected_task_ids) != len(set(selected_task_ids)):
                    raise InvalidRequestError("selected_task_ids must not contain duplicates", details={"field": "selected_task_ids"})
                selected = sorted(selected_task_ids)
            else:
                selected = None
            request_hash = hashlib.sha256(canonical_json({"selected_task_ids": selected}).encode()).hexdigest()
            if idempotency_key:
                prior = self.conn.execute("SELECT * FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?", ("run.retry", run_id, idempotency_key)).fetchone()
                if prior:
                    if prior["request_hash"] != request_hash:
                        raise ConflictError("idempotency key was already used with different input")
                    return json.loads(prior["result_json"])
            if run["status"] != "failed":
                raise ConflictError("run is not retryable", details={"status": run["status"]})
            with self._transaction():
                timestamp = now()
                query = "SELECT * FROM tasks WHERE run_id=? ORDER BY created_at, id"
                children = self.conn.execute(query, (run_id,)).fetchall()
                eligible = [task for task in children if task["status"] == "failed" and (selected is None or task["id"] in selected)]
                if selected is not None:
                    unknown = sorted(set(selected) - {task["id"] for task in children})
                    if unknown:
                        raise NotFoundError("run child task not found", details={"task_ids": unknown})
                if not eligible:
                    raise ConflictError("run has no eligible failed children", details={"selected_task_ids": selected or []})
                retried = []
                for task in eligible:
                    self._release_reservations(task["id"], task["lease_token"])
                    self.conn.execute("UPDATE tasks SET status='queued', lease_token=NULL, executor_id=NULL, lease_expires_at=NULL, waiting_reason=NULL, result_json=NULL, attempt_id=NULL, updated_at=? WHERE id=?", (timestamp, task["id"]))
                    self._append_event(run_id, task["id"], "task.retried", {"from_status": "failed", "attempt": int(task["attempt"] or 0) + 1, "reason": "run.retry"})
                    self._refresh_continuations_for_predecessor(task["id"])
                    retried.append(task["id"])
                self.conn.execute("UPDATE runs SET status='queued', updated_at=? WHERE id=?", (timestamp, run_id))
                self._append_event(run_id, None, "run.retried", {"task_ids": retried})
                result = dict(self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())
                if idempotency_key:
                    self.conn.execute("INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)", ("run.retry", run_id, idempotency_key, request_hash, canonical_json(result), now()))
            return result

    def fail_task(self, task_id, lease_token, failure, *, fence=None, attempt_id=None, record=None):
        with self._mutex:
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] != "running" or task["lease_token"] != lease_token:
                raise LeaseError("attempt lease is stale or already settled")
            if fence is not None and int(fence) != int(task["lease_fence"] or 0):
                raise LeaseError("attempt fence is stale", details={"expected": task["lease_fence"], "actual": fence})
            if task["lease_expires_at"]:
                try:
                    if datetime.fromisoformat(task["lease_expires_at"]) <= datetime.now(timezone.utc):
                        raise LeaseError("attempt lease has expired")
                except ValueError as exc:
                    raise LeaseError("attempt lease deadline is invalid") from exc
            with self._transaction():
                timestamp = now()
                result = {"error": failure}
                self.conn.execute("UPDATE tasks SET status='failed', result_json=?, lease_expires_at=NULL, waiting_reason=NULL, updated_at=? WHERE id=?", (canonical_json(result), timestamp, task_id))
                self.conn.execute("UPDATE runs SET status='failed', updated_at=? WHERE id=?", (timestamp, task["run_id"]))
                if attempt_id is not None:
                    self.conn.execute("UPDATE attempts SET settled=1 WHERE id=? AND settled=0", (attempt_id,))
                self._release_reservations(task_id, lease_token)
                event_id = self._append_event(task["run_id"], task_id, "task.failed", {"error": failure})
                self._refresh_continuations_for_predecessor(task_id)
                value = self.get_task(task_id)
                if record is not None:
                    record(value, event_ids=[event_id], primary_stream_id=task["run_id"], resulting_stream_seq=None)
                return value

    def doctor(self, *, catalog_path=None):
        """Return a read-only, actionable integrity report.

        ``catalog_path`` is optional because the store is also useful outside
        the daemon (for example during an offline backup check).  When it is
        supplied, support-state checks are included alongside the authoritative
        SQLite/CAS checks.
        """
        return self.integrity_report(catalog_path=catalog_path)

    def integrity_report(self, *, catalog_path=None, timeout_seconds: float = REALM_ADMISSION_TIMEOUT_SECONDS):
        """Return a bounded report even when SQLite metadata is malformed."""
        if timeout_seconds <= 0:
            return self._integrity_failure("timeout", "realm inspection timed out")
        deadline = time.monotonic() + timeout_seconds
        timed_out = False

        def progress():
            nonlocal timed_out
            timed_out = time.monotonic() >= deadline
            return 1 if timed_out else 0

        with self._mutex:
            self.conn.set_progress_handler(progress, 1000)
            try:
                return self._integrity_report(catalog_path=catalog_path, deadline=deadline)
            except TimeoutError as exc:
                return self._integrity_failure("timeout", str(exc))
            except (sqlite3.DatabaseError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
                return self._integrity_failure("timeout" if timed_out else "malformed", str(exc))
            finally:
                self.conn.set_progress_handler(None, 0)

    def _integrity_report(self, *, catalog_path=None, deadline=None):
        try:
            quick_rows = [str(row[0]) for row in self.conn.execute("PRAGMA quick_check").fetchall()]
            quick = "ok" if quick_rows == ["ok"] else quick_rows
        except sqlite3.DatabaseError as exc:
            quick = f"error: {exc}"
        try:
            fk_rows = self.conn.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.DatabaseError as exc:
            fk_rows = [("error", str(exc))]
        fk = [tuple(row) for row in fk_rows]
        actual_tables = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing_tables = sorted(REQUIRED_SCHEMA_TABLES - actual_tables)
        missing_columns = {}
        extra_columns = {}
        for table, required in REQUIRED_SCHEMA_COLUMNS.items():
            if table in actual_tables:
                actual_columns = self._table_columns(table)
                missing = sorted(required - actual_columns)
                extra = sorted(actual_columns - required)
                if missing:
                    missing_columns[table] = missing
                if extra:
                    extra_columns[table] = extra
        actual_schema = None
        actual_format = None
        if "runtime_schema" in actual_tables:
            schema_row = self.conn.execute(
                "SELECT format_id, version FROM runtime_schema WHERE id=1"
            ).fetchone()
            if schema_row:
                actual_format = schema_row["format_id"]
                actual_schema = int(schema_row["version"])
        unexpected_tables = sorted(
            table for table in actual_tables
            if not str(table).startswith("sqlite_") and table not in REQUIRED_SCHEMA_TABLES
        )
        schema_ok = (
            actual_schema == SCHEMA_VERSION
            and actual_format == CANONICAL_FORMAT_ID
            and not missing_tables
            and not missing_columns
            and not extra_columns
            and not unexpected_tables
        )
        realm_identity = {"ok": False, "realm_id": None, "row_count": None, "reason": "realm_table_missing"}
        if "realm" in actual_tables:
            realm_rows = self.conn.execute("SELECT id FROM realm LIMIT 2").fetchall()
            realm_identity["row_count"] = len(realm_rows)
            if len(realm_rows) == 0:
                realm_identity["reason"] = "realm_identity_missing"
            elif len(realm_rows) > 1:
                realm_identity["reason"] = "realm_identity_ambiguous"
            else:
                realm_id = realm_rows[0][0]
                if isinstance(realm_id, str) and realm_id.strip():
                    realm_identity = {"ok": True, "realm_id": realm_id, "row_count": 1, "reason": None}
                else:
                    realm_identity["reason"] = "realm_identity_invalid"
        uninitialized = False
        objects = self.conn.execute("SELECT digest, size FROM objects").fetchall() if "objects" in actual_tables else []
        reachable = {str(row[0]) for row in objects}
        missing = []
        corrupt = []
        for object_row in objects:
            digest = str(object_row["digest"])
            try:
                actual = self._cas_digest(digest, deadline=deadline)
                actual_size = self._cas_size(digest)
            except TimeoutError:
                raise
            except OSError:
                missing.append(digest)
                continue
            if actual != digest or actual_size != int(object_row["size"]):
                corrupt.append({
                    "digest": digest,
                    "reason": "digest_mismatch" if actual != digest else "size_mismatch",
                    "actual_sha256": actual,
                    "expected_size": int(object_row["size"]),
                    "actual_size": actual_size,
                })
        orphaned = self._cas_orphans(reachable, deadline=deadline)
        cas_ok = not missing and not corrupt
        event_errors = []
        if {"runs", "events"}.issubset(actual_tables):
            for run in self.conn.execute("SELECT id FROM runs"):
                previous = ""
                for event in self.conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY id", (run[0],)):
                    if event["previous_hash"] != previous:
                        event_errors.append({"run_id": run[0], "event_id": event["id"], "reason": "broken_link"})
                    expected = hashlib.sha256(canonical_json({"run_id": event["run_id"], "task_id": event["task_id"], "kind": event["kind"], "payload": json.loads(event["payload_json"]), "previous_hash": event["previous_hash"], "created_at": event["created_at"]}).encode()).hexdigest()
                    if expected != event["event_hash"]:
                        event_errors.append({"run_id": run[0], "event_id": event["id"], "reason": "hash_mismatch"})
                    previous = event["event_hash"]
        relational_errors = []
        if realm_identity["ok"] and {"realm", "realm_lifecycle"}.issubset(actual_tables):
            lifecycle_rows = self.conn.execute(
                "SELECT realm_id, state FROM realm_lifecycle"
            ).fetchall()
            if len(lifecycle_rows) != 1 or lifecycle_rows[0]["realm_id"] != realm_identity["realm_id"]:
                relational_errors.append({"table": "realm_lifecycle", "reason": "realm_lifecycle_identity"})
        if {"managed_output_associations", "managed_output_lifecycle", "objects", "attempts", "tasks"}.issubset(actual_tables):
            association_rows = self.conn.execute("SELECT * FROM managed_output_associations").fetchall()
            for association in association_rows:
                object_row = self.conn.execute(
                    "SELECT size, media_type FROM objects WHERE digest=?",
                    (association["object_digest"],),
                ).fetchone()
                if not object_row or int(object_row["size"]) != int(association["size"]) or object_row["media_type"] != association["media_type"]:
                    relational_errors.append({"association_id": association["association_id"], "reason": "object_metadata"})
                attempt = self.conn.execute(
                    "SELECT task_id FROM attempts WHERE id=?", (association["attempt_id"],)
                ).fetchone()
                if not attempt or attempt["task_id"] != association["task_id"]:
                    relational_errors.append({"association_id": association["association_id"], "reason": "attempt_task_identity"})
                if association["manifest_digest"] is not None and not self.conn.execute(
                    "SELECT 1 FROM objects WHERE digest=?", (association["manifest_digest"],)
                ).fetchone():
                    relational_errors.append({"association_id": association["association_id"], "reason": "manifest_object_missing"})
                lifecycle_count = self.conn.execute(
                    "SELECT COUNT(*) FROM managed_output_lifecycle WHERE association_id=?",
                    (association["association_id"],),
                ).fetchone()[0]
                if lifecycle_count != 1:
                    relational_errors.append({"association_id": association["association_id"], "reason": "lifecycle_missing"})
        if {"managed_output_associations", "managed_output_lifecycle"}.issubset(actual_tables):
            orphan_lifecycle = self.conn.execute(
                "SELECT association_id FROM managed_output_lifecycle WHERE association_id NOT IN (SELECT association_id FROM managed_output_associations)"
            ).fetchall()
            relational_errors.extend(
                {"association_id": row["association_id"], "reason": "lifecycle_orphan"}
                for row in orphan_lifecycle
            )
        sqlite_ok = quick == "ok"
        catalog_check = {"status": "not_configured", "ok": True, "issues": []}
        activation_check = {"status": "not_configured", "ok": True, "issues": []}
        if catalog_path is not None and realm_identity["ok"]:
            catalog_check = self._catalog_check(Path(catalog_path))
            activation_check = self._activation_check(catalog_check)
        elif catalog_path is not None:
            catalog_check = {"status": "blocked", "ok": False, "issues": ["catalog_realm_unavailable"], "path": str(catalog_path)}
            activation_check = {"status": "blocked", "ok": False, "issues": ["activation_catalog_unavailable"]}
        identity_ok = realm_identity["ok"]
        healthy = sqlite_ok and not fk and schema_ok and identity_ok and cas_ok and not event_errors and not relational_errors and catalog_check["ok"] and activation_check["ok"]
        issues = []
        if not sqlite_ok: issues.append("sqlite_integrity")
        if fk: issues.append("foreign_keys")
        if not schema_ok: issues.append("schema")
        if not identity_ok: issues.append("realm_identity")
        if missing: issues.append("reachable_cas")
        if corrupt: issues.append("corrupt_cas")
        if event_errors: issues.append("event_chain")
        if relational_errors: issues.append("relational")
        issues.extend(catalog_check.get("issues", [])); issues.extend(activation_check.get("issues", []))
        recovery = "No recovery action required." if healthy else "Restore the realm from a verified backup, then re-run doctor."
        if (catalog_check["ok"] is False or activation_check["ok"] is False) and sqlite_ok and not fk and schema_ok and identity_ok and cas_ok:
            recovery = "Repair the catalog and activation manifest, then restart the runtime."
        return {
            "state": "uninitialized" if healthy and uninitialized else "ready" if healthy else "unhealthy", "ok": healthy,
            "schema_version": SCHEMA_VERSION, "issues": issues,
            "recovery_action": recovery, "next_action": recovery,
            "checks": {
                "sqlite_integrity": {"ok": sqlite_ok, "result": quick},
                "sqlite": {"ok": sqlite_ok, "result": quick},
                "sqlite_quick_check": quick,
                "foreign_keys": {"ok": not bool(fk), "violations": [list(row) for row in fk]},
                "foreign_key": {"ok": not bool(fk), "violations": [list(row) for row in fk]},
                "schema": {
                    "ok": schema_ok,
                    "expected_format_id": CANONICAL_FORMAT_ID,
                    "actual_format_id": actual_format,
                    "expected_version": SCHEMA_VERSION,
                    "actual_version": actual_schema,
                    "missing_tables": missing_tables,
                    "missing_columns": missing_columns,
                    "extra_columns": extra_columns,
                    "unexpected_tables": unexpected_tables,
                },
                "realm_identity": realm_identity,
                "reachable_cas": {"ok": cas_ok, "missing": missing, "corrupt": corrupt, "orphaned": sorted(orphaned)},
                "cas_missing": missing,
                "event_chain": {"ok": not bool(event_errors), "errors": event_errors},
                "event_chain_errors": event_errors,
                "relational": {"ok": not bool(relational_errors), "errors": relational_errors},
                "catalog": catalog_check,
                "activation": activation_check,
                "catalog_activation": {"ok": catalog_check["ok"] and activation_check["ok"], "catalog": catalog_check, "activation": activation_check},
            },
        }

    def _cas_digest(self, digest, *, deadline=None):
        """Hash one CAS entry, optionally beneath a pinned directory fd."""
        cas_root_fd = getattr(self, "_cas_root_fd", None)
        if cas_root_fd is not None:
            if cas_root_fd < 0:
                raise FileNotFoundError(digest)
            prefix_fd = os.open(
                digest[:2],
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=cas_root_fd,
            )
            try:
                fd = os.open(digest[2:], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=prefix_fd)
            finally:
                os.close(prefix_fd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("CAS entry is not a regular file")
                digest_value = hashlib.sha256()
                while True:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError("realm inspection timed out")
                    block = os.read(fd, 1024 * 1024)
                    if not block:
                        return digest_value.hexdigest()
                    digest_value.update(block)
            finally:
                os.close(fd)

        path = self.cas_root / digest[:2] / digest[2:]
        # A reachable CAS entry is content-addressed, not merely a path.
        # ``is_file`` follows links and therefore cannot be the integrity
        # check on its own.
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(digest)
        digest_value = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("realm inspection timed out")
                block = handle.read(1024 * 1024)
                if not block:
                    return digest_value.hexdigest()
                digest_value.update(block)

    def _cas_size(self, digest):
        """Read the verified CAS entry size without following a link."""
        cas_root_fd = getattr(self, "_cas_root_fd", None)
        if cas_root_fd is not None:
            if cas_root_fd < 0:
                raise FileNotFoundError(digest)
            prefix_fd = os.open(
                digest[:2],
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=cas_root_fd,
            )
            try:
                fd = os.open(digest[2:], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=prefix_fd)
            finally:
                os.close(prefix_fd)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError("CAS entry is not a regular file")
                return int(metadata.st_size)
            finally:
                os.close(fd)
        path = self.cas_root / digest[:2] / digest[2:]
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(digest)
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("CAS entry is not a regular file")
        return int(metadata.st_size)

    def _cas_orphans(self, reachable, *, deadline=None):
        cas_root_fd = getattr(self, "_cas_root_fd", None)
        if cas_root_fd is not None:
            if cas_root_fd < 0:
                return []
            orphaned = []
            for prefix in os.listdir(cas_root_fd):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("realm inspection timed out")
                try:
                    prefix_fd = os.open(
                        prefix,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=cas_root_fd,
                    )
                except OSError:
                    continue
                try:
                    for name in os.listdir(prefix_fd):
                        if deadline is not None and time.monotonic() >= deadline:
                            raise TimeoutError("realm inspection timed out")
                        try:
                            item = os.stat(name, dir_fd=prefix_fd, follow_symlinks=False)
                        except OSError:
                            continue
                        digest = prefix + name
                        if stat.S_ISREG(item.st_mode) and digest not in reachable:
                            orphaned.append(digest)
                finally:
                    os.close(prefix_fd)
            return sorted(orphaned)

        orphaned = []
        if self.cas_root.exists():
            for path in self.cas_root.glob("*/*"):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("realm inspection timed out")
                if path.is_file():
                    digest = path.parent.name + path.name
                    if digest not in reachable:
                        orphaned.append(digest)
        return sorted(orphaned)

    def _catalog_check(self, path):
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"status": "invalid", "ok": False, "issues": ["catalog_missing" if isinstance(exc, FileNotFoundError) else "catalog_invalid"], "path": str(path)}
        realm = self.realm
        selected = value.get("selected_realm_id")
        registered = [row for row in value.get("realms", []) if row.get("realm_id") == (realm or {}).get("id")]
        issues = []
        if selected != (realm or {}).get("id"): issues.append("catalog_selection")
        if not registered: issues.append("catalog_realm_missing")
        return {"status": "ready" if not issues else "invalid", "ok": not issues, "issues": issues, "path": str(path), "selected_realm_id": selected}

    def _activation_check(self, catalog_check):
        if catalog_check.get("status") == "not_configured":
            return catalog_check.copy()
        if not catalog_check.get("ok"):
            return {"status": "blocked", "ok": False, "issues": ["activation_catalog_unavailable"]}
        try:
            catalog = json.loads(Path(catalog_check["path"]).read_text(encoding="utf-8"))
            row = next(item for item in catalog.get("realms", []) if item.get("realm_id") == self.realm["id"])
            # A bare RuntimeDaemon may be launched without the optional
            # banodoco-local activation layer.  In that mode catalog
            # registration is still authoritative, but activation is not
            # configured and therefore cannot be called broken.
            if not row.get("activation_manifest"):
                return {"status": "not_configured", "ok": True, "issues": []}
            activation_path = Path(str(row.get("activation_manifest", "")))
            if not activation_path.is_file():
                raise FileNotFoundError
            activation = json.loads(activation_path.read_text(encoding="utf-8"))
            issues = []
            if activation.get("realm_id") != self.realm["id"]: issues.append("activation_realm_mismatch")
            if Path(str(activation.get("destination_realm_root", ""))).resolve() != self.root.resolve(): issues.append("activation_root_mismatch")
            expected_digest = row.get("activation_digest")
            if expected_digest and hashlib.sha256(activation_path.read_bytes()).hexdigest() != expected_digest: issues.append("activation_digest_mismatch")
            return {"status": "ready" if not issues else "invalid", "ok": not issues, "issues": issues, "path": str(activation_path)}
        except (OSError, StopIteration, json.JSONDecodeError):
            return {"status": "invalid", "ok": False, "issues": ["activation_missing"]}
