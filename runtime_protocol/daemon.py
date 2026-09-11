from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

from .auth import CredentialStore
from .catalog import LiveDiscovery, RealmCatalog, process_birth_identity
from .backup import verify_restore_candidate
from .dirfd import capture_parent, close_pinned, validate_parent
from .errors import ConflictError
from .server import RuntimeHTTPServer, RuntimeHandler
from .service import RuntimeService
from .util import atomic_json_write, now


WORKER_ACTOR = "astrid-pack-host"
WORKER_SCOPES = (
    "handshake",
    "worker:register",
    "worker:execute",
    "tasks:read",
    "objects:read",
    "objects:write",
)


def _authority_path(value, label):
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
            raise ValueError(f"{label} must not traverse a symlink")
    return path


class RuntimeDaemon:
    """Loopback-only daemon owning one realm and its storage."""

    def __init__(self, root, *, support_root=None, display_name="Workspace", host="127.0.0.1", port=0, realm_id=None, owner_lock=None, bootstrap_token_file=None, reboot_executor=None, reboot_allowlist=None, production_worker_credentials=False):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("runtime daemon only binds to loopback")
        self.root = _authority_path(root, "realm root").resolve()
        self.support_root = (_authority_path(support_root, "support root").resolve() if support_root else self.root / "support")
        self.host, self.port, self.display_name = host, port, display_name
        self.realm_id = realm_id
        self.owner_lock = _authority_path(owner_lock, "owner lock").resolve() if owner_lock else None
        self.bootstrap_token_file = _authority_path(bootstrap_token_file, "bootstrap token file").resolve() if bootstrap_token_file else None
        # Reboot is deliberately disabled unless a host supplies an executor.
        # The service additionally validates that any configured command is in
        # its small, explicit allowlist.
        self.reboot_executor = reboot_executor
        self.reboot_allowlist = reboot_allowlist
        # In-process RuntimeDaemon fixtures historically use ``worker_token``
        # as an administrator convenience for arbitrary fake executor IDs.
        # The installed CLI passes production_worker_credentials=True, which
        # switches the real process to the bound least-privilege pack-host
        # credential below.  Keeping the fixture mode explicit avoids granting
        # that administrator credential to the production host.
        self.production_worker_credentials = bool(production_worker_credentials)
        self.instance_id = uuid.uuid4().hex
        self.service = None
        self.httpd = None
        self.thread = None
        self.catalog = RealmCatalog(self.support_root / "catalog.json")
        self.discovery = LiveDiscovery(self.support_root / "discovery.json")
        # CredentialStore creates its directory. Defer that side effect until
        # the realm has passed RuntimeService's fenced startup admission.
        self.credentials = None
        self.token = None
        self.worker_token = None
        self.credential_path = None
        self.worker_credential_path = None

    @property
    def endpoint(self):
        if not self.httpd:
            return None
        host = "127.0.0.1" if self.host == "localhost" else self.host
        return f"http://{host}:{self.httpd.server_port}"

    def start(self):
        if self.httpd:
            return self
        return self._start(rotate_credentials=False)

    def _catalog_owner_valid(self, proof):
        return self.service is not None and self.service.validate_catalog_admission(proof)

    def _provision_credentials(self, *, rotate=False):
        self.credentials = CredentialStore(_authority_path(self.support_root / "credentials", "credential root"))
        owner_scopes = ["admin", "handshake", "projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write", "worker:execute", "worker:register", "credentials:provision"]
        self.token, self.credential_path = self.credentials.provision("owner", owner_scopes, rotate=rotate)
        self.worker_token, self.worker_credential_path = self.credentials.provision(WORKER_ACTOR, list(WORKER_SCOPES), rotate=rotate)
        if not self.production_worker_credentials:
            # Test-only in-process convenience.  The production CLI never
            # selects this branch; its pack host receives WORKER_ACTOR's
            # scoped token and cannot call admin/project routes.
            self.worker_token = self.token
        if self.bootstrap_token_file and self.bootstrap_token_file.exists():
            bootstrap_token = self.bootstrap_token_file.read_text(encoding="utf-8").strip()
            self.credentials.provision_static("bootstrap", bootstrap_token, ["admin", "credentials:provision"])
            self.bootstrap_token_file.unlink(missing_ok=True)

    def _shutdown_http(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        self.thread = None

    def _revoke_readiness(self, report):
        if self.service is None:
            return
        try:
            realm_id = self.service.realm["id"]
        except Exception:
            return
        self.catalog.revoke_readiness(realm_id, instance_id=self.instance_id, reason="runtime_admission_failed")
        self.discovery.clear(self.instance_id)

    def _start(self, *, rotate_credentials=False):
        self.service = RuntimeService(self.root, display_name=self.display_name, realm_id=self.realm_id, support_root=self.support_root, reboot_executor=self.reboot_executor, reboot_allowlist=self.reboot_allowlist)
        self.service.set_readiness_callback(self._revoke_readiness)
        self.catalog.bind_owner(self._catalog_owner_valid)
        self._provision_credentials(rotate=rotate_credentials)
        self.httpd = RuntimeHTTPServer((self.host, self.port), RuntimeHandler)
        self.httpd.runtime = self.service
        self.httpd.credentials = self.credentials
        owner = self.service.catalog_admission(self.instance_id)
        self.catalog.register(realm_id=self.service.realm["id"], display_name=self.service.realm["display_name"], data_root=str(self.root), owner=owner, runtime_epoch=owner["runtime_epoch"], runtime_instance_id=self.instance_id, readiness="ready")
        birth_id = process_birth_identity()
        if self.owner_lock:
            atomic_json_write(self.owner_lock, {"pid": os.getpid(), "process_birth_id": birth_id, "runtime_instance_id": self.instance_id, "realm_id": self.service.realm["id"]})
        self.discovery.publish(version=1, endpoint=self.endpoint, pid=os.getpid(), process_birth_id=birth_id, runtime_instance_id=self.instance_id, active_realm=self.service.realm["id"], protocol_version="workspace.v1", schema_version="workspace-schema-v1", coordinator_epoch=self.instance_id, credential_file=str(self.credential_path), worker_credential_file=str(self.worker_credential_path), worker_actor=WORKER_ACTOR, worker_scopes=list(WORKER_SCOPES))
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="banodoco-runtime", daemon=True)
        self.thread.start()
        return self

    def _replacement_state_path(self):
        return self.support_root / "replacement-state.json"

    def _write_replacement_state(self, *, state, candidate, superseded=None, error=None):
        value = {
            "format_version": 1,
            "state": state,
            "active_root": str(self.root),
            "candidate_root": str(candidate),
            "superseded_root": str(superseded) if superseded else None,
            "updated_at": now(),
        }
        if error:
            value["error"] = str(error)
        atomic_json_write(self._replacement_state_path(), value)

    def activate_candidate(self, candidate_root, *, retain_superseded=True):
        """Atomically activate a verified inactive candidate under one owner."""
        if self.service is None or self.httpd is None:
            raise ConflictError("replacement requires a running runtime owner")
        candidate = _authority_path(candidate_root, "restore candidate").resolve()
        if candidate == self.root or candidate.parent != self.root.parent:
            raise ConflictError("replacement candidate must be an inactive sibling of the active realm")
        if candidate.is_symlink() or not candidate.is_dir():
            raise ConflictError("replacement candidate must be an ordinary directory")
        active_identity = capture_parent(self.root)
        candidate_identity = capture_parent(candidate)
        superseded = self.root.parent / f".{self.root.name}.superseded-{uuid.uuid4().hex}"
        moved_old = False
        moved_candidate = False
        try:
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            first = verify_restore_candidate(candidate, directory_identity=candidate_identity)
            if self.service.realm["id"] != first["manifest"].get("realm_id"):
                raise ConflictError("replacement realm identity does not match the live realm")
            self._write_replacement_state(state="verified", candidate=candidate, superseded=superseded)
            self.stop()
            self._write_replacement_state(state="owner_stopped", candidate=candidate, superseded=superseded)
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            second = verify_restore_candidate(candidate, directory_identity=candidate_identity)
            if second["database_sha256"] != first["database_sha256"]:
                raise ConflictError("replacement candidate changed during preparation")
            parent_fd = int(active_identity["_parent_fd"])
            os.rename(self.root.name, superseded.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_old = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="old_quarantined", candidate=candidate, superseded=superseded)
            os.rename(candidate.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_candidate = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="candidate_published", candidate=candidate, superseded=superseded)
            self.instance_id = uuid.uuid4().hex
            self._start(rotate_credentials=True)
            self._write_replacement_state(state="complete", candidate=candidate, superseded=superseded)
            return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded), "retained": bool(retain_superseded)}
        except Exception as exc:
            try:
                self.stop()
            except Exception:
                pass
            try:
                parent_fd = int(active_identity["_parent_fd"])
                def present(name):
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        return False
                    return True
                if moved_candidate and not present(candidate.name) and present(self.root.name):
                    os.rename(self.root.name, candidate.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                if moved_old and not present(self.root.name) and present(superseded.name):
                    os.rename(superseded.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
                self._write_replacement_state(state="rolled_back", candidate=candidate, superseded=superseded, error=exc)
            except Exception:
                pass
            self.instance_id = uuid.uuid4().hex
            try:
                self._start(rotate_credentials=True)
            except Exception:
                pass
            raise
        finally:
            close_pinned(candidate_identity)
            close_pinned(active_identity)

    def stop(self):
        if self.service is not None:
            try:
                self.catalog.revoke_readiness(self.service.realm["id"], instance_id=self.instance_id, reason="runtime_stopped")
            except Exception:
                pass
        self.discovery.clear(self.instance_id)
        self._shutdown_http()
        if self.service:
            self.service.close()
            self.service = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()
