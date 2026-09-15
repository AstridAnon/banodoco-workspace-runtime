from __future__ import annotations

from .cas import ContentAddressedStore
from .backup import create_backup, restore_backup, structured_export
from .store import (
    GENERATION_INTENT_STORAGE_KEY,
    OBJECT_ID_RE,
    RealmStore,
    normalize_execution_facts,
    public_task_spec,
)
from .util import atomic_json_write
from .util import canonical_json, durable_json_bytes, new_id, now, sha256_bytes
import hashlib
import json
import sqlite3
import base64
import copy
import os
import re
import subprocess
import uuid
import stat
import math
from collections.abc import Mapping
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .errors import AuthorizationError, ConflictError, NotFoundError, ValidationError, LeaseError, InvalidRequestError, RealmAdmissionError
from .contract_metadata import PROTOCOL, SCHEMA_DIGEST
from .herzchen_bridge import HerzchenUnavailable, RuntimeHerzchenBridge
from .dirfd import close_pinned as _close_pinned, mkdir_chain_at as _mkdir_chain_at, open_directory_chain as _open_directory_chain, pin_directory as _pin_directory, write_bytes_at as _write_bytes_at
from .shot_dependencies import analyze_invalidation


CHECKPOINT_MAX_BYTES = 1024 * 1024
OBJECT_MAX_BYTES = 64 * 1024 * 1024
REBOOT_COMMAND_ALLOWLIST = frozenset({"reboot", "resume"})
PAGE_DEFAULT_LIMIT = 50
PAGE_MAX_LIMIT = 200
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$")
MANAGED_COVERAGE_MODES = frozenset({"interval", "clips", "cuts", "shots"})
MANAGED_COVERAGE_REASONS = frozenset({"interval", "before_cut", "after_cut", "clip_first", "shot_midpoint"})
MANAGED_DURABILITIES = frozenset({"durable", "temporary"})
TEXT_BINDING_KINDS = ("prompt", "voiceover_script", "transcript")
TEXT_BINDING_MAX_BYTES = 1_048_576
TEXT_BINDING_SLOT_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
TEXT_BINDING_IDENTITY_SCHEMA = "workspace.shot.text_binding.identity/v1"
MEDIA_PROBE_TIMEOUT_SECONDS = 10


LEGACY_MANAGED_OUTPUT_PREFIXES = frozenset({"images", "videos", "audio"})


def _canonical_managed_output_filename(value):
    """Return a flat export name for the known producer-relative namespaces."""
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValidationError("output filename is invalid")
    if any(ord(char) < 32 for char in value):
        raise ValidationError("output filename is invalid")
    if value not in {".", ".."} and "/" not in value and "\\" not in value:
        return value
    prefix, separator, leaf = value.partition("/")
    if separator and prefix in LEGACY_MANAGED_OUTPUT_PREFIXES:
        if leaf and leaf not in {".", ".."} and "/" not in leaf and "\\" not in leaf:
            return leaf
    raise ValidationError("output filename must be a direct safe file name or a known producer namespace/<direct safe file name>")


def _validate_rational(value, field):
    """Validate the V1 exact rational wire form without floating-point loss."""
    if isinstance(value, str):
        match = re.fullmatch(r"([0-9]+)/([1-9][0-9]*)", value)
        if match:
            return value
    elif isinstance(value, dict) and set(value) == {"numerator", "denominator"}:
        numerator, denominator = value["numerator"], value["denominator"]
        if (
            isinstance(numerator, int) and not isinstance(numerator, bool) and numerator >= 0
            and isinstance(denominator, int) and not isinstance(denominator, bool) and denominator > 0
        ):
            return {"numerator": numerator, "denominator": denominator}
    raise ValidationError(f"{field} must be a non-negative rational")


def _validate_coverage(value):
    """Validate the V1 sampling evidence carried by a managed output."""
    if not isinstance(value, dict) or set(value) != {"sampling"}:
        raise ValidationError(
            "output coverage must contain only V1 sampling evidence",
            details={"required": "sampling", "modes": sorted(MANAGED_COVERAGE_MODES)},
        )
    sampling = value["sampling"]
    if not isinstance(sampling, dict):
        raise ValidationError("output coverage.sampling must be an object")
    allowed = {"mode", "range", "step_frames_rational", "every", "every_frames", "cards"}
    unknown = set(sampling) - allowed
    if unknown:
        raise ValidationError("output coverage.sampling contains unsupported fields", details={"fields": sorted(unknown)})
    mode = sampling.get("mode")
    if mode not in MANAGED_COVERAGE_MODES:
        raise ValidationError("output coverage.sampling.mode is invalid", details={"modes": sorted(MANAGED_COVERAGE_MODES)})
    rendered_range = sampling.get("range")
    if not isinstance(rendered_range, dict) or set(rendered_range) != {"start", "end"}:
        raise ValidationError("output coverage.sampling.range must be a half-open object")
    start, end = rendered_range["start"], rendered_range["end"]
    if (
        isinstance(start, bool) or not isinstance(start, int) or start < 0
        or isinstance(end, bool) or not isinstance(end, int) or end <= start
    ):
        raise ValidationError("output coverage.sampling.range must satisfy 0 <= start < end")
    if "step_frames_rational" in sampling:
        _validate_rational(sampling["step_frames_rational"], "output coverage.sampling.step_frames_rational")
    if "every" in sampling and "every_frames" in sampling:
        raise ValidationError("output coverage.sampling.every and every_frames are mutually exclusive")
    if ("every" in sampling or "every_frames" in sampling) and mode != "interval":
        raise ValidationError("output coverage.sampling.every/every_frames are valid only for interval mode")
    if "every" in sampling and (
        isinstance(sampling["every"], bool) or not isinstance(sampling["every"], (int, float))
        or not math.isfinite(float(sampling["every"])) or float(sampling["every"]) <= 0
    ):
        raise ValidationError("output coverage.sampling.every must be a positive finite number")
    if "every_frames" in sampling and (
        isinstance(sampling["every_frames"], bool) or not isinstance(sampling["every_frames"], int)
        or sampling["every_frames"] <= 0
    ):
        raise ValidationError("output coverage.sampling.every_frames must be a positive integer")
    cards = sampling.get("cards", [])
    if not isinstance(cards, list):
        raise ValidationError("output coverage.sampling.cards must be a list")
    for card in cards:
        if not isinstance(card, dict) or set(card) != {"frame", "time_seconds", "time_rational", "sample_reasons"}:
            raise ValidationError("each coverage card requires frame, time_seconds, time_rational, and sample_reasons")
        if isinstance(card["frame"], bool) or not isinstance(card["frame"], int) or card["frame"] < 0:
            raise ValidationError("coverage card frame must be a non-negative integer")
        if (
            isinstance(card["time_seconds"], bool) or not isinstance(card["time_seconds"], (int, float))
            or not math.isfinite(float(card["time_seconds"])) or float(card["time_seconds"]) < 0
        ):
            raise ValidationError("coverage card time_seconds must be a non-negative finite number")
        _validate_rational(card["time_rational"], "coverage card time_rational")
        reasons = card["sample_reasons"]
        if not isinstance(reasons, list) or not reasons or any(reason not in MANAGED_COVERAGE_REASONS for reason in reasons):
            raise ValidationError("coverage card sample_reasons contains an invalid reason")
    return value


def _contains_latest(value):
    if isinstance(value, str):
        return value.lower() == "latest"
    if isinstance(value, dict):
        return any(_contains_latest(key) or _contains_latest(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_latest(item) for item in value)
    return False


def _validate_regeneration(value):
    """Validate the immutable regeneration declaration, including unavailable."""
    if not isinstance(value, dict) or set(value) != {"available", "capability_id", "source_refs", "recipe_digest", "exact_inputs"}:
        raise ValidationError(
            "output regeneration requires exactly available, capability_id, source_refs, recipe_digest, and exact_inputs"
        )
    available = value["available"]
    if not isinstance(available, bool):
        raise ValidationError("output regeneration.available must be a boolean")
    capability_id = value["capability_id"]
    if capability_id is not None and (not isinstance(capability_id, str) or not capability_id):
        raise ValidationError("output regeneration.capability_id must be a non-empty string or null")
    if available and capability_id is None:
        raise ValidationError("available regeneration requires capability_id")
    source_refs = value["source_refs"]
    if not isinstance(source_refs, list) or any(
        not isinstance(reference, str) or not OBJECT_ID_RE.fullmatch(reference) or not reference.startswith("sha256:")
        for reference in source_refs
    ):
        raise ValidationError("output regeneration.source_refs must contain canonical sha256 object IDs")
    recipe_digest = value["recipe_digest"]
    if not isinstance(recipe_digest, str) or not OBJECT_ID_RE.fullmatch(recipe_digest) or not recipe_digest.startswith("sha256:"):
        raise ValidationError("output regeneration.recipe_digest must be a canonical sha256 digest")
    exact_inputs = value["exact_inputs"]
    if not isinstance(exact_inputs, (dict, list)):
        raise ValidationError("output regeneration.exact_inputs must be an object or list")
    if _contains_latest(exact_inputs):
        raise ValidationError("output regeneration.exact_inputs must never use latest")
    return value


def validate_idempotency_key(value):
    """Validate the wire-level idempotency-key grammar in one place."""
    if not isinstance(value, str) or not IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise InvalidRequestError(
            "Idempotency-Key must start with an alphanumeric character and contain at most 256 ASCII characters"
        )
    return value


def require_idempotency_key(value):
    """Require and validate the key for every durable state mutation."""
    if value is None:
        raise InvalidRequestError("Idempotency-Key is required for state mutations")
    return validate_idempotency_key(value)
def _wire_string(body, field):
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} is required")
    return value


def _wire_integer(body, field, *, positive=False):
    value = body.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or (positive and value < 1):
        kind = "positive integer" if positive else "an integer"
        raise ValidationError(f"{field} must be {kind}")
    return value
def _wire_object(body, *, required=(), allowed=()):
    """Validate a worker JSON object before any durable lookup or side effect."""
    if not isinstance(body, dict):
        raise InvalidRequestError("request body must be a JSON object")
    missing = sorted(field for field in required if field not in body)
    if missing:
        raise ValidationError("request body is missing required fields", details={"fields": missing})
    unknown = sorted(set(body) - set(allowed))
    if unknown:
        raise ValidationError("request body contains unsupported fields", details={"fields": unknown})
    return body


def _require_runtime_epoch_for_lease(body):
    """Reject an omitted epoch as malformed request data before any lookup."""
    if isinstance(body, dict) and "runtime_epoch" not in body:
        raise ValidationError(
            "request body is missing required fields",
            details={"fields": ["runtime_epoch"]},
        )


def _probe_media_bytes(data):
    """Return verified stream facts for media bytes without a metadata service."""
    try:
        completed = subprocess.run(
            [
                "ffprobe", "-v", "error", "-print_format", "json",
                "-show_entries", "stream=codec_type,duration:format=duration",
                "-i", "pipe:0",
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=MEDIA_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError("source media could not be verified") from exc
    if completed.returncode != 0:
        raise ValidationError("source media is malformed")
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("source media probe returned malformed metadata") from exc
    if not isinstance(value, dict) or not isinstance(value.get("streams"), list) or not value["streams"]:
        raise ValidationError("source media has no streams")
    stream_types = []
    durations = {}
    for stream in value["streams"]:
        if not isinstance(stream, dict) or not isinstance(stream.get("codec_type"), str):
            raise ValidationError("source media stream metadata is malformed")
        stream_type = stream["codec_type"]
        stream_types.append(stream_type)
        raw_duration = stream.get("duration")
        if raw_duration is not None and raw_duration not in ("N/A", ""):
            try:
                duration = float(raw_duration)
            except (TypeError, ValueError) as exc:
                raise ValidationError("source media duration is malformed") from exc
            if not math.isfinite(duration) or duration < 0:
                raise ValidationError("source media duration is malformed")
            durations.setdefault(stream_type, duration)
    raw_format_duration = (value.get("format") or {}).get("duration") if isinstance(value.get("format"), dict) else None
    format_duration = None
    if raw_format_duration is not None and raw_format_duration not in ("N/A", ""):
        try:
            format_duration = float(raw_format_duration)
        except (TypeError, ValueError) as exc:
            raise ValidationError("source media duration is malformed") from exc
        if not math.isfinite(format_duration) or format_duration < 0:
            raise ValidationError("source media duration is malformed")
    return {"stream_types": tuple(stream_types), "durations": durations, "format_duration": format_duration}


def _page_args(cursor, limit):
    """Validate the public page arguments and decode an opaque keyset cursor."""
    if isinstance(limit, bool):
        raise InvalidRequestError("limit must be an integer between 1 and 200")
    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise InvalidRequestError("limit must be an integer between 1 and 200") from exc
    if limit < 1 or limit > PAGE_MAX_LIMIT:
        raise InvalidRequestError("limit must be an integer between 1 and 200")
    if cursor in (None, ""):
        return limit, None
    if not isinstance(cursor, str):
        raise InvalidRequestError("cursor must be a non-empty string")
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRequestError("cursor is invalid") from exc
    if not isinstance(value, dict) or value.get("v") != 1 or not isinstance(value.get("k"), list) or not value["k"]:
        raise InvalidRequestError("cursor is invalid")
    return limit, value


def _page_cursor(scope, key):
    raw = json.dumps({"v": 1, "s": scope, "k": list(key)}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _page_rows(rows, *, scope, cursor, limit, key_fn, resource_fn, skip_after=None):
    limit, decoded = _page_args(cursor, limit)
    if decoded is not None and decoded.get("s") != scope:
        raise InvalidRequestError("cursor does not belong to this collection")
    after = tuple(decoded["k"]) if decoded is not None else None
    selected = []
    for row in rows:
        key = tuple(key_fn(row))
        if after is not None:
            if len(key) != len(after):
                raise InvalidRequestError("cursor is invalid")
            try:
                before = skip_after(key, after) if skip_after is not None else key <= after
            except (TypeError, IndexError) as exc:
                raise InvalidRequestError("cursor is invalid") from exc
            if before:
                continue
        selected.append((key, resource_fn(row)))
        if len(selected) > limit:
            break
    has_more = len(selected) > limit
    selected = selected[:limit]
    return {"items": [resource for _, resource in selected], "next_cursor": _page_cursor(scope, selected[-1][0]) if has_more else None}


def _verified_mutation(function):
    """Fence the complete mutation against a concurrent admission loss."""
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with self.store._mutex:
            self._assert_mutation_admitted()
            return function(self, *args, **kwargs)
    return wrapped


def _durable_mutation(function):
    """Keep a B7 project mutation and its idempotency receipt atomic."""
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with self.store._mutex:
            self._assert_mutation_admitted()
            try:
                with self.store._transaction():
                    result = function(self, *args, **kwargs)
            except Exception:
                # A CAS publication is journaled before its destination is
                # renamed.  Reconcile after SQLite has rolled back so a
                # failed commit cannot leave an unreferenced object behind.
                self._recover_cas_publication_journals()
                raise
            self._recover_cas_publication_journals()
            return result
    return wrapped


class RuntimeService:
    """Neutral application service composed by the daemon or an isolated test."""

    def __init__(self, root, *, display_name="Workspace", realm_id=None, support_root=None, export_root=None, reboot_executor=None, reboot_allowlist=None, runtime_epoch_floor=None):
        root_path = Path(root).expanduser().resolve()
        # Service startup is an open/admission operation.  Realm creation is
        # explicit through RealmStore.initialize; a missing path must fail
        # before schema, identity, lock, or storage roots can be created.
        self.store = RealmStore(root_path)
        self._verified = False
        self._admission_failure = None
        self._readiness_callback = None
        try:
            if not self.store.admission_report.get("ok"):
                raise RealmAdmissionError(
                    "realm failed startup admission",
                    details=self.store.admission_report,
                )
            self.cas = ContentAddressedStore(self.store.cas_root)
            self.realm = self.store.ensure_realm(display_name, realm_id=realm_id)
            report = self.store.doctor()
            if not report.get("ok"):
                raise RealmAdmissionError("realm is not usable after initialization", details=report)
            self.runtime_session_id = new_id()
            self._runtime_state = self.store.begin_runtime_session(
                self.runtime_session_id, epoch_floor=runtime_epoch_floor
            )
            self._verified = True
        except Exception:
            self.store.close()
            raise
        self.support_root = Path(support_root).expanduser().resolve() if support_root else None
        self.export_root = Path(export_root).expanduser().resolve() if export_root else None
        if self.export_root is not None:
            if self.export_root == self.store.root or self.export_root.is_relative_to(self.store.root) or self.store.root.is_relative_to(self.export_root):
                raise ValidationError("managed-output export root must be outside the active realm root")
            if self.export_root.is_symlink() or not self.export_root.is_dir():
                raise ValidationError("managed-output export root must be an existing ordinary directory")
        self.reboot_executor = reboot_executor
        configured_allowlist = frozenset(reboot_allowlist or REBOOT_COMMAND_ALLOWLIST)
        if not configured_allowlist or not configured_allowlist.issubset(REBOOT_COMMAND_ALLOWLIST):
            raise ValidationError("reboot allowlist contains an unsupported command", details={"allowlist": sorted(configured_allowlist), "supported": sorted(REBOOT_COMMAND_ALLOWLIST)})
        self.reboot_allowlist = configured_allowlist
        self._recover_cas_publication_journals()
        # When the pinned shared package is present, expose the actual
        # Runtime-owner binding used by Astrid/Herzchen consumers.  The
        # standalone Runtime distribution remains valid without that optional
        # package; no second store or writer is created in either case.
        try:
            self.herzchen = RuntimeHerzchenBridge(self)
        except HerzchenUnavailable:
            self.herzchen = None

    def close(self):
        self.store.close()

    def set_readiness_callback(self, callback) -> None:
        """Install the daemon-owned readiness revocation hook."""
        self._readiness_callback = callback

    def catalog_admission(self, instance_id):
        """Return an unforgeable-in-practice proof for this live owner."""
        return {
            "realm_id": self.realm["id"],
            "runtime_epoch": int(self.store._current_runtime_epoch()),
            "runtime_session_id": self.runtime_session_id,
            "runtime_instance_id": str(instance_id),
        }

    def validate_catalog_admission(self, proof) -> bool:
        if not self._verified or not isinstance(proof, dict) or self.store._lock_file is None:
            return False
        try:
            return (
                proof.get("realm_id") == self.realm["id"]
                and proof.get("runtime_session_id") == self.runtime_session_id
                and proof.get("runtime_instance_id")
                and int(proof.get("runtime_epoch")) == int(self.store._current_runtime_epoch())
            )
        except (KeyError, TypeError, ValueError):
            return False

    def backup(self, destination, *, binding=None, destination_identity=None):
        key_path = (self.support_root / "backup-auth.key") if self.support_root else (self.store.root / ".operator-backup-key")
        return create_backup(self.store, destination, binding=binding, key_path=key_path, destination_identity=destination_identity)

    def restore(self, backup_dir, destination, *, destination_identity=None, source_identity=None):
        # The backup's authenticated manifest owns the key identity.  Do not
        # force this service's current support key: a B12 destination backup
        # may have been signed by the destination realm's key while the
        # active service is restoring it. ``restore_backup`` resolves the
        # manifest key through descriptor-pinned I/O and checks its key id.
        return restore_backup(backup_dir, destination, destination_identity=destination_identity, source_identity=source_identity)

    def export_structured(self, destination=None):
        value = structured_export(self.store)
        if destination is not None:
            atomic_json_write(Path(destination).expanduser().resolve(), value)
        return value

    def doctor(self):
        with self.store._mutex:
            report = self.store.doctor(catalog_path=(self.support_root / "catalog.json") if self.support_root else None)
            if not report.get("ok"):
                # Admission is monotonic for one service instance. Repair is
                # verified by a fresh startup; an unhealthy process never
                # silently resumes writes after observing damaged authority.
                self._verified = False
                self._admission_failure = report
                if self._readiness_callback is not None:
                    try:
                        self._readiness_callback(report)
                    except Exception:
                        pass
            return report

    @_verified_mutation
    def tombstone(self, body=None):
        body = body or {}
        return self.store.tombstone_realm(reason=body.get("reason"), expected_version=body.get("expected_version"))

    @_verified_mutation
    def recover_realm(self, body=None):
        body = body or {}
        # Recovery is a destructive lifecycle transition.  Require an
        # operator-scoped expectation before touching durable state, even when
        # the realm is already active (the no-op path must be fenced too).
        expected_realm_id = body.get("expected_realm_id")
        expected_version = body.get("expected_version")
        if not expected_realm_id or expected_version is None:
            raise ValidationError("recovery requires expected_realm_id and expected_version")
        if str(expected_realm_id) != str(self.realm["id"]):
            raise ConflictError("recovery realm identity mismatch", details={"expected": expected_realm_id, "actual": self.realm["id"]})
        noninteractive = body.get("noninteractive") is True
        confirmation = body.get("confirmation")
        required_confirmation = f"RECOVER {self.realm['id']}"
        if bool(noninteractive) == bool(confirmation):
            raise ValidationError(f"recovery requires exactly one of confirmation {required_confirmation!r} or noninteractive=true")
        if not noninteractive and confirmation != required_confirmation:
            raise ValidationError(f"recovery requires confirmation exactly {required_confirmation!r} or noninteractive=true")
        return self.store.restore_tombstone(expected_version=expected_version)

    def purge(self, body=None):
        """Return the explicit offline purge boundary; never purge online."""
        body = body or {}
        confirmation = body.get("confirmation")
        required = f"PURGE {self.realm['id']}"
        if confirmation != required:
            raise ValidationError(f"whole-realm purge requires confirmation exactly {required!r}")
        if self.store.realm_lifecycle()["state"] != "tombstoned":
            raise ConflictError("whole-realm purge requires a tombstoned realm")
        raise ConflictError("whole-realm purge is offline-only; stop the runtime and use the purge command", details={"next_action": "banodoco-runtime purge --root <realm> --confirm 'PURGE <realm_id>'"})

    def health(self):
        report = self.doctor()
        return {"status": "ok" if self._verified and report.get("ok") else "degraded", "protocol": PROTOCOL, "schema_digest": SCHEMA_DIGEST, "runtime_epoch": self._runtime_state["runtime_epoch"]}

    def _assert_mutation_admitted(self):
        if not self._verified:
            raise RealmAdmissionError(
                "realm is not admitted for mutations",
                details=self._admission_failure or self.store.admission_report,
            )

    def runtime_lifecycle(self):
        """Return current boot/session and recovery facts for diagnostics."""
        value = dict(self._runtime_state)
        value["runtime_session_id"] = self.runtime_session_id
        return value

    def realm_resource(self):
        row = self.store.realm
        lifecycle = self.store.realm_lifecycle()
        return {"realm_id": row["id"], "display_name": row["display_name"], "version": 1, "created_at": row["created_at"], "state": lifecycle["state"], "tombstoned_at": lifecycle["tombstoned_at"], "lifecycle_version": lifecycle["version"]}

    def handshake(self, body):
        requested = list(body.get("requested_scopes") or [])
        actor = body.get("authenticated_actor")
        if not actor:
            raise ValidationError("authenticated actor is required")
        if any(not isinstance(scope, str) or not scope for scope in requested) or len(set(requested)) != len(requested):
            raise ValidationError("requested_scopes must contain unique non-empty strings")
        authenticated = set(body.get("authenticated_scopes") or [])
        # ``admin`` authorizes endpoint access but is not a wildcard grant for
        # handshake negotiation.  The session is the exact authenticated
        # scope intersection, and asking for anything outside it fails closed.
        negotiated = authenticated - {"admin"}
        excess = sorted(set(requested) - negotiated)
        if excess:
            raise AuthorizationError("credential cannot negotiate requested scopes", details={"scopes": excess})
        return {"protocol": PROTOCOL, "schema_digest": SCHEMA_DIGEST, "session_id": new_id(), "actor_id": actor, "realm_id": self.realm["id"], "scopes": requested}

    @staticmethod
    def _assert_executor_identity(identity, executor_id):
        """Bind bearer worker credentials to the executor they operate.

        ``identity`` is supplied only by the HTTP boundary.  Direct service
        calls remain useful for in-process control-plane tests and have no
        bearer principal to bind.  HTTP worker credentials are accepted only
        when their actor is the executor itself or they carry the explicit
        administrator scope.
        """
        if identity is None:
            return
        if not executor_id:
            raise AuthorizationError("executor identity is required")
        actor = identity.get("actor")
        if actor == executor_id or "admin" in set(identity.get("scopes", [])):
            return
        raise AuthorizationError("worker credential is not bound to executor", details={"executor_id": executor_id, "actor_id": actor})

    def _assert_attempt_identity(self, row, identity):
        if not row:
            return
        self._assert_executor_identity(identity, row["executor_id"])

    @_verified_mutation
    def create_project(self, body, *, idempotency_key=None):
        name = str(body.get("name") or "")
        slug = str(body.get("slug") or "-".join(name.lower().split()))
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in slug).strip("-") or "project"
        return self.store.create_project(slug, name, body.get("metadata"), idempotency_key=idempotency_key)

    def get_project(self, selector):
        return self.store.get_project(selector)

    def list_projects(self, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        rows = self.store.conn.execute("SELECT id, created_at FROM projects ORDER BY created_at, id").fetchall()
        return _page_rows(rows, scope="projects", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self._project_resource(self.store.get_project(row["id"])))

    @_verified_mutation
    def select_project(self, actor_id, selector, *, scope="workspace", idempotency_key=None):
        value = self.store.select_project(actor_id, selector, scope, idempotency_key=idempotency_key)
        return {
            "actor_id": value["actor_id"],
            "scope": value["scope"],
            "project": self._project_resource(value["project"]),
            "updated_at": value["updated_at"],
        }

    def current_project(self, actor_id):
        value = self.store.current_project(actor_id)
        return {
            "actor_id": value["actor_id"],
            "scope": value["scope"],
            "project": self._project_resource(value["project"]),
            "updated_at": value["updated_at"],
        }

    @_verified_mutation
    def update_project(self, selector, body, *, idempotency_key=None):
        return self.store.update_project(selector, name=body.get("name"), metadata=body.get("metadata"), expected_version=body.get("expected_version"), idempotency_key=idempotency_key)

    def _project_resource(self, value):
        return {"project_id": value["id"], "realm_id": value["realm_id"], "slug": value["slug"], "name": value["name"], "metadata": value.get("metadata", {}), "version": value["version"], "created_at": value["created_at"], "updated_at": value["updated_at"], "archived": False}

    def _timeline_resource(self, timeline_id):
        row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not row: raise NotFoundError("timeline not found")
        shots = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
        refs = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
        result = {"timeline_id": row["id"], "project_id": row["project_id"], "version": row["version"], "archived": bool(row["archived_at"]), "shots": [{"shot_id": x["id"], "start_ms": x["start_ms"], "duration_ms": x["duration_ms"], "reference_ids": json.loads(x["reference_ids_json"])} for x in shots], "references": [{"reference_id": x["id"], "object_id": x["object_id"], **({"role": x["role"]} if x["role"] else {})} for x in refs]}
        document = self.store.conn.execute("SELECT content_json, version FROM project_documents WHERE id=? AND project_id=?", (f"timeline:{timeline_id}", row["project_id"])).fetchone()
        if document:
            content = json.loads(document["content_json"])
            if isinstance(content, dict):
                result.update({"slug": content.get("slug", timeline_id), "name": content.get("name", timeline_id), "config_version": int(document["version"]), "config": content.get("config", {}), "registry": content.get("registry", {})})
        return result

    def _record_timeline_revision(self, timeline_id, resource=None):
        resource = resource or self._timeline_resource(timeline_id)
        self.store.conn.execute(
            "INSERT OR IGNORE INTO timeline_revisions(timeline_id, version, shots_json, references_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (timeline_id, resource["version"], canonical_json(resource["shots"]), canonical_json(resource["references"]), now()),
        )

    def _timeline_revision(self, timeline_id, version):
        row = self.store.conn.execute("SELECT * FROM timeline_revisions WHERE timeline_id=? AND version=?", (timeline_id, version)).fetchone()
        if row:
            return {"timeline_id": timeline_id, "version": int(row["version"]), "shots": json.loads(row["shots_json"]), "references": json.loads(row["references_json"]), "created_at": row["created_at"]}
        current = self._timeline_resource(timeline_id)
        if int(current["version"]) == int(version):
            return {"timeline_id": timeline_id, "version": current["version"], "shots": current["shots"], "references": current["references"], "created_at": now()}
        raise NotFoundError("timeline revision not found", details={"timeline_id": timeline_id, "version": version})

    @staticmethod
    def _expected_version(body):
        value = (body or {}).get("expected_version")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValidationError("expected_version must be a positive integer")
        return value

    def _verified_source_media(self, source, digest, *, clip_type, track_kind=None):
        """Verify immutable bytes and the stream needed by the selected clip."""
        path = self.cas.path_for(digest)
        if path.is_symlink() or not path.is_file():
            raise ConflictError("managed source media is unavailable")
        try:
            data = self.cas.read(digest)
        except (NotFoundError, ConflictError) as exc:
            raise ConflictError("managed source media failed immutable verification") from exc
        try:
            expected_size = int(source["size"])
        except (TypeError, ValueError) as exc:
            raise ConflictError("managed source media metadata is malformed") from exc
        if path.is_symlink() or len(data) != expected_size:
            raise ConflictError("managed source media failed immutable verification")
        media_type = source["media_type"]
        if not isinstance(media_type, str) or not media_type:
            raise ValidationError("managed source media type is malformed")
        media_type = media_type.split(";", 1)[0].strip().lower()
        if "/" not in media_type:
            raise ValidationError("managed source media type is malformed")
        expected_stream = {"image": "video", "video": "video", "audio": "audio"}.get(clip_type)
        if expected_stream is None and clip_type == "media":
            # A generic media clip inherits its stream from the canonical
            # track. Visual tracks are video by definition; never let the
            # replacement MIME type silently turn one into an audio clip.
            expected_stream = "audio" if track_kind in {"audio", "sound"} else "video"
        if expected_stream not in {"video", "audio"}:
            raise ValidationError("selected clip has an unsupported media stream")
        if media_type.split("/", 1)[0] not in {"application", "binary"}:
            declared_stream = "video" if media_type.startswith("image/") else media_type.split("/", 1)[0]
            if declared_stream != expected_stream:
                raise ValidationError("source media stream does not match selected clip")
        probe = _probe_media_bytes(data)
        if expected_stream not in probe["stream_types"]:
            raise ValidationError("source media stream does not match selected clip")
        duration = probe["durations"].get(expected_stream, probe["format_duration"])
        return data, expected_stream, duration

    @staticmethod
    def _authored_clip_interval(clip):
        start, end = clip.get("from"), clip.get("to")
        if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            raise ValidationError("selected clip must have a numeric authored interval")
        if not math.isfinite(float(start)) or not math.isfinite(float(end)) or end <= start:
            raise ValidationError("selected clip must have a positive authored interval")
        if start < 0:
            raise ValidationError("selected clip must have a non-negative authored source offset")
        return float(start), float(end)

    @_durable_mutation
    def update_timeline(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not row:
            raise NotFoundError("timeline not found")
        project_id = str(row["project_id"])
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body}).encode()).hexdigest()
        replay = self._command_replay("timeline.update", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        if int(row["version"]) != expected:
            raise ConflictError("timeline version conflict", details={"expected": expected, "actual": int(row["version"])})
        shots = body.get("shots")
        refs = body.get("references")
        if shots is not None:
            if not isinstance(shots, list) or len({item.get("shot_id") for item in shots if isinstance(item, dict)}) != len(shots):
                raise ValidationError("shots must be a list with unique shot_id values")
            for shot in shots:
                if not isinstance(shot, dict) or not shot.get("shot_id") or int(shot.get("start_ms", -1)) < 0 or int(shot.get("duration_ms", 0)) < 1:
                    raise ValidationError("invalid shot timing")
        if refs is not None:
            if not isinstance(refs, list) or len({item.get("reference_id") for item in refs if isinstance(item, dict)}) != len(refs):
                raise ValidationError("references must be a list with unique reference_id values")
            for reference in refs:
                if not isinstance(reference, dict) or not reference.get("reference_id") or not reference.get("object_id"):
                    raise ValidationError("references require reference_id and object_id")
        if shots is None:
            shots = [dict(value) for value in self.store.conn.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
            shots = [{"shot_id": value["id"], "start_ms": value["start_ms"], "duration_ms": value["duration_ms"], "reference_ids": json.loads(value["reference_ids_json"])} for value in shots]
        if refs is None:
            refs = [dict(value) for value in self.store.conn.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
            refs = [{"reference_id": value["id"], "object_id": value["object_id"], **({"role": value["role"]} if value["role"] else {})} for value in refs]
        with self.store._transaction():
            self.store.conn.execute("DELETE FROM timeline_shot_state WHERE id IN (SELECT id FROM timeline_shots WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_reference_state WHERE id IN (SELECT id FROM timeline_references WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_shots WHERE timeline_id=?", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_references WHERE timeline_id=?", (timeline_id,))
            for shot in shots:
                self.store.conn.execute("INSERT INTO timeline_shots VALUES (?, ?, ?, ?, ?)", (shot["shot_id"], timeline_id, int(shot["start_ms"]), int(shot["duration_ms"]), canonical_json(shot.get("reference_ids", []))))
                self.store.conn.execute("INSERT INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (shot["shot_id"],))
            for reference in refs:
                self.store.conn.execute("INSERT INTO timeline_references VALUES (?, ?, ?, ?)", (reference["reference_id"], timeline_id, reference["object_id"], reference.get("role")))
                self.store.conn.execute("INSERT INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (reference["reference_id"],))
            self.store.conn.execute("UPDATE timelines SET version=?, created_at=created_at WHERE id=?", (expected + 1, timeline_id))
            resource = self._timeline_resource(timeline_id)
            self._record_timeline_revision(timeline_id, resource)
            event_id = self.store._append_timeline_event(timeline_id, "timeline.updated", {"project_id": project_id, "version": resource["version"]})
            event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            return self._command_record("timeline.update", timeline_id, idempotency_key, request_hash, resource, project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    @_durable_mutation
    def replace_timeline_clip(self, timeline_id, body, *, idempotency_key=None):
        """Replace one canonical composition clip with a project-owned object."""
        self._require_object_body(body)
        unexpected = set(body) - {"clip_id", "source_object_id", "expected_version", "timing"}
        if unexpected:
            raise ValidationError("replacement request contains unsupported fields", details={"fields": sorted(unexpected)})
        expected = self._expected_version(body)
        clip_id = body.get("clip_id")
        source_object_id = body.get("source_object_id")
        timing = body.get("timing", "preserve-duration")
        if not isinstance(clip_id, str) or not clip_id:
            raise ValidationError("clip_id is required")
        if not isinstance(source_object_id, str) or not source_object_id:
            raise ValidationError("source_object_id is required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", source_object_id):
            raise ValidationError("source_object_id must be a canonical SHA-256 object id")
        if timing != "preserve-duration":
            raise ValidationError("timing must be preserve-duration")

        timeline = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not timeline:
            raise NotFoundError("timeline not found")
        project_id = str(timeline["project_id"])
        request = {
            "timeline_id": timeline_id,
            "clip_id": clip_id,
            "source_object_id": source_object_id,
            "expected_version": expected,
            "timing": timing,
        }
        request_hash = hashlib.sha256(canonical_json(request).encode()).hexdigest()
        replay = self._command_replay("timeline.clip.replace", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay

        document_id = f"timeline:{timeline_id}"
        document = self.store.conn.execute(
            "SELECT * FROM project_documents WHERE id=? AND project_id=?",
            (document_id, project_id),
        ).fetchone()
        if not document:
            raise NotFoundError("timeline composition document not found")
        if int(document["version"]) != expected:
            raise ConflictError("timeline composition version conflict", details={"expected": expected, "actual": int(document["version"])})

        digest = source_object_id.removeprefix("sha256:")
        source = self.store.conn.execute(
            "SELECT objects.* FROM objects JOIN project_objects ON project_objects.digest=objects.digest "
            "WHERE objects.digest=? AND project_objects.project_id=? AND project_objects.relation='managed'",
            (digest, project_id),
        ).fetchone()
        if not source:
            raise NotFoundError("managed source object not found in timeline project", details={"source_object_id": source_object_id, "project_id": project_id})

        content = json.loads(document["content_json"])
        config = content.get("config") if isinstance(content, dict) else None
        registry = content.get("registry") if isinstance(content, dict) else None
        clips = config.get("clips") if isinstance(config, dict) else None
        assets = registry.get("assets") if isinstance(registry, dict) else None
        if not isinstance(clips, list):
            raise ValidationError("timeline config.clips must be a list")
        if not isinstance(assets, dict):
            raise ValidationError("timeline registry.assets must be an object")
        matches = [clip for clip in clips if isinstance(clip, dict) and clip.get("id") == clip_id]
        if len(matches) != 1:
            raise ValidationError("clip_id must identify exactly one clip", details={"clip_id": clip_id, "match_count": len(matches)})
        target = matches[0]
        if target.get("clipType", "media") not in {"media", "image", "video", "audio"}:
            raise ValidationError("selected clip is not a media clip", details={"clip_id": clip_id})
        old_asset_id = target.get("asset")
        if not isinstance(old_asset_id, str) or not isinstance(assets.get(old_asset_id), Mapping):
            raise ValidationError("selected clip must reference an existing registry asset", details={"clip_id": clip_id})

        clip_type = str(target.get("clipType", "media")).lower()
        _, authored_source_end = self._authored_clip_interval(target)
        track_kind = None
        track_id = target.get("track")
        tracks = config.get("tracks", []) if isinstance(config, dict) else []
        if isinstance(tracks, list):
            for track in tracks:
                if isinstance(track, dict) and track.get("id") == track_id:
                    track_kind = str(track.get("kind") or "").lower()
                    break
        _, _, source_duration = self._verified_source_media(source, digest, clip_type=clip_type, track_kind=track_kind)
        if (clip_type != "image" and source_duration is None) or (source_duration is not None and source_duration + 1e-6 < authored_source_end):
            raise ValidationError("source media is too short for preserve-duration", details={"required_source_end": authored_source_end, "source_duration": source_duration})

        changed_content = copy.deepcopy(content)
        changed_config = changed_content["config"]
        changed_registry = changed_content["registry"]
        changed_target = next(clip for clip in changed_config["clips"] if isinstance(clip, dict) and clip.get("id") == clip_id)
        canonical_object_id = "sha256:" + digest
        existing = changed_registry["assets"].get(canonical_object_id)
        asset_entry = {
            "media_id": canonical_object_id,
            "content_sha256": digest,
            "type": str(source["media_type"]),
        }
        if existing is not None and existing != asset_entry:
            raise ConflictError("source object id collides with a different registry asset", details={"source_object_id": canonical_object_id})
        changed_registry["assets"][canonical_object_id] = asset_entry
        changed_target["asset"] = canonical_object_id

        timestamp = now()
        self.store.conn.execute(
            "UPDATE project_documents SET content_json=?, version=?, updated_at=? WHERE id=? AND project_id=?",
            (canonical_json(changed_content), expected + 1, timestamp, document_id, project_id),
        )
        resource = self._timeline_resource(timeline_id)
        event_id = self.store._append_timeline_event(
            timeline_id,
            "timeline.clip.replaced",
            {"project_id": project_id, "clip_id": clip_id, "source_object_id": canonical_object_id, "config_version": expected + 1},
        )
        event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
        return self._command_record(
            "timeline.clip.replace", timeline_id, idempotency_key, request_hash, resource,
            project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id,
            resulting_stream_seq=event_seq,
        )

    @_durable_mutation
    def create_timeline(self, project_id, timeline_id, *, idempotency_key=None):
        if not isinstance(timeline_id, str) or not timeline_id:
            raise ValidationError("timeline_id is required")
        project = self.store.get_project(project_id)
        request_hash = hashlib.sha256(canonical_json({
            "project_id": project["id"], "timeline_id": timeline_id,
        }).encode()).hexdigest()
        # A create request has no pre-existing aggregate, so keep its key in
        # one operation namespace and bind project/timeline identity in the
        # request hash. Reusing a key for any changed request is a conflict;
        # a retry gets the exact committed resource and receipt.
        replay = self._command_replay("timeline.create", "timelines", idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        if self.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (timeline_id,)).fetchone():
            raise ConflictError("timeline already exists", details={"timeline_id": timeline_id})
        timestamp = now()
        self.store.conn.execute("INSERT INTO timelines(id, project_id, version, created_at, archived_at) VALUES (?, ?, 1, ?, NULL)", (timeline_id, project["id"], timestamp))
        resource = self._timeline_resource(timeline_id)
        self._record_timeline_revision(timeline_id, resource)
        event_id = self.store._append_timeline_event(timeline_id, "timeline.created", {"project_id": project["id"]})
        event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
        return self._command_record(
            "timeline.create", "timelines", idempotency_key, request_hash,
            resource, project_id=project["id"], event_ids=(event_id,),
            primary_stream_id=timeline_id, resulting_stream_seq=event_seq,
        )

    @_durable_mutation
    def create_timeline_document(self, project_id, body, *, idempotency_key=None):
        """Create the timeline and composition document in one transaction."""
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")
        project = self.store.get_project(project_id)
        timeline_id = str(body.get("timeline_id") or "")
        if not timeline_id:
            raise ValidationError("timeline_id is required")
        config, registry = body.get("config", {}), body.get("registry", {})
        if not isinstance(config, dict) or not isinstance(registry, dict):
            raise ValidationError("config and registry must be objects")
        slug, name = str(body.get("slug") or timeline_id), str(body.get("name") or body.get("slug") or timeline_id)
        content = {"slug": slug, "name": name, "config": config, "registry": registry}
        request_hash = hashlib.sha256(canonical_json({
            "project_id": project["id"], "timeline_id": timeline_id,
            "slug": slug, "name": name, "config": config, "registry": registry,
        }).encode()).hexdigest()
        replay = self._command_replay("timeline_document.create", timeline_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        if self.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (timeline_id,)).fetchone():
            raise ConflictError("timeline already exists", details={"timeline_id": timeline_id})
        document_id = f"timeline:{timeline_id}"
        if self.store.conn.execute("SELECT 1 FROM project_documents WHERE id=?", (document_id,)).fetchone():
            raise ConflictError("timeline document already exists", details={"document_id": document_id})
        timestamp = now()
        self.store.conn.execute("INSERT INTO timelines(id, project_id, version, created_at, archived_at) VALUES (?, ?, 1, ?, NULL)", (timeline_id, project["id"], timestamp))
        self.store.conn.execute("INSERT INTO project_documents(id, project_id, kind, content_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)", (document_id, project["id"], "timeline.composition", canonical_json(content), timestamp, timestamp))
        resource = self._timeline_resource(timeline_id)
        self._record_timeline_revision(timeline_id, resource)
        event_id = self.store._append_timeline_event(timeline_id, "timeline.document.created", {"project_id": project["id"], "document_id": document_id, "config_version": resource["config_version"]})
        event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
        return self._command_record("timeline_document.create", timeline_id, idempotency_key, request_hash, resource, project_id=project["id"], event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    def list_timelines(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id, created_at FROM timelines WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"timelines:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self._timeline_resource(row["id"]))

    def _shot_resource(self, row):
        state = self.store.conn.execute("SELECT version, archived_at FROM timeline_shot_state WHERE id=?", (row["id"],)).fetchone()
        timeline = self.store.conn.execute("SELECT project_id FROM timelines WHERE id=?", (row["timeline_id"],)).fetchone()
        return {"shot_id": row["id"], "timeline_id": row["timeline_id"], "project_id": timeline["project_id"], "start_ms": int(row["start_ms"]), "duration_ms": int(row["duration_ms"]), "reference_ids": json.loads(row["reference_ids_json"]), "version": int(state["version"] if state else 1), "archived": bool(state and state["archived_at"])}

    def _reference_resource(self, row):
        state = self.store.conn.execute("SELECT version, archived_at FROM timeline_reference_state WHERE id=?", (row["id"],)).fetchone()
        timeline = self.store.conn.execute("SELECT project_id FROM timelines WHERE id=?", (row["timeline_id"],)).fetchone()
        return {"reference_id": row["id"], "timeline_id": row["timeline_id"], "project_id": timeline["project_id"], "object_id": row["object_id"], **({"role": row["role"]} if row["role"] else {}), "version": int(state["version"] if state else 1), "archived": bool(state and state["archived_at"])}

    def list_project_tasks(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id, created_at FROM tasks WHERE run_id IN (SELECT id FROM runs WHERE project_id=?) ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"tasks:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self._task_resource(self.store.get_task(row["id"])))

    def list_project_runs(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id, created_at FROM runs WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"runs:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self.run(row["id"]))

    def list_project_shots(self, project_id, *, cursor=None, include_archived=False, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        query = "SELECT * FROM project_shots WHERE project_id=?"
        if not include_archived: query += " AND archived_at IS NULL"
        rows = self.store.conn.execute(query + " ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"project-shots:{project['id']}:{int(include_archived)}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._project_shot_resource)

    def list_project_references(self, project_id, *, cursor=None, include_archived=False, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        query = "SELECT * FROM project_references WHERE project_id=?"
        if not include_archived: query += " AND archived_at IS NULL"
        rows = self.store.conn.execute(query + " ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"project-references:{project['id']}:{int(include_archived)}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._project_reference_resource)

    @staticmethod
    def _require_object_body(body):
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")

    def _receipt_payload(self, row, *, project_id):
        """Expose the canonical receipt facts committed with the mutation."""
        if row is None or row["txn_id"] is None:
            return None
        result = json.loads(row["result_json"])
        return {
            "receipt_id": row["txn_id"],
            "command_kind": row["command_kind"],
            "idempotency_key": row["idempotency_key"],
            "request_hash": row["request_hash"],
            "project_id": project_id,
            "project_seq": [int(row["first_project_seq"]), int(row["last_project_seq"])],
            "event_ids": json.loads(row["event_ids_json"]),
            "result": result,
            "created_at": row["created_at"],
        }

    def committed_receipt(self, command_kind, aggregate_id, idempotency_key, *, project_id):
        """Return the receipt persisted with a successful mutation.

        This reads the command ledger; it never derives a receipt from client
        state or caches one in the service process.
        """
        if not idempotency_key:
            return None
        # HTTP handlers share the owner's SQLite connection. Serialize this
        # post-mutation read with the writer lock so another handler cannot
        # interleave a transaction on the same connection between the
        # mutation and receipt lookup, yielding a spurious null receipt.
        with self.store._mutex:
            row = self.store.conn.execute(
                "SELECT txn_id, command_kind, idempotency_key, request_hash, result_json, "
                "first_project_seq, last_project_seq, event_ids_json, created_at "
                "FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
                (command_kind, aggregate_id, idempotency_key),
            ).fetchone()
        return self._receipt_payload(row, project_id=project_id) if row else None

    def _command_replay_state(self, kind, aggregate_id, idempotency_key, request_hash, *, project_id=None, with_receipt=True):
        """Return ``(found, value)`` so a committed null result is replayable."""
        if idempotency_key is None:
            return False, None
        validate_idempotency_key(idempotency_key)
        prior = self.store.conn.execute(
            "SELECT txn_id, command_kind, idempotency_key, request_hash, result_json, "
            "first_project_seq, last_project_seq, event_ids_json, created_at "
            "FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
            (kind, aggregate_id, idempotency_key),
        ).fetchone()
        if not prior:
            return False, None
        if prior["request_hash"] != request_hash:
            raise ConflictError("idempotency key was already used with different input")
        result = json.loads(prior["result_json"])
        if project_id is not None and with_receipt:
            result = {"data": result, "receipt": self._receipt_payload(prior, project_id=project_id)}
        return True, result

    def _command_replay(self, kind, aggregate_id, idempotency_key, request_hash, *, project_id=None, with_receipt=True):
        found, result = self._command_replay_state(
            kind, aggregate_id, idempotency_key, request_hash,
            project_id=project_id, with_receipt=with_receipt,
        )
        return result if found else None

    def _command_record(self, kind, aggregate_id, idempotency_key, request_hash, result, *, project_id=None, event_ids=(), primary_stream_id=None, resulting_stream_seq=None, with_receipt=True):
        if idempotency_key is not None:
            validate_idempotency_key(idempotency_key)
            if project_id is not None:
                self.store._record_command_receipt(
                    kind, aggregate_id, idempotency_key, request_hash, result,
                    project_id=project_id, event_ids=event_ids,
                    primary_stream_id=primary_stream_id,
                    resulting_stream_seq=resulting_stream_seq,
                )
                row = self.store.conn.execute(
                    "SELECT txn_id, command_kind, idempotency_key, request_hash, result_json, "
                    "first_project_seq, last_project_seq, event_ids_json, created_at "
                    "FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
                    (kind, aggregate_id, idempotency_key),
                ).fetchone()
                if with_receipt:
                    return {"data": result, "receipt": self._receipt_payload(row, project_id=project_id)}
                return result
            self.store.conn.execute(
                "INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (kind, aggregate_id, idempotency_key, request_hash, canonical_json(result), now()),
            )
        return result

    def _open_publication_directory(self, *, create):
        """Open the publication journal directory below pinned staging fds."""
        staging_fd = _open_directory_chain(self.store.staging_root)
        try:
            if create:
                publication_fd = _mkdir_chain_at(staging_fd, "publications")
            else:
                publication_fd = os.open(
                    "publications",
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=staging_fd,
                )
            try:
                if not stat.S_ISDIR(os.fstat(publication_fd).st_mode):
                    raise ConflictError("publication journal directory is invalid")
            except Exception:
                os.close(publication_fd)
                raise
            return staging_fd, publication_fd
        except Exception:
            os.close(staging_fd)
            raise


    def _begin_cas_publication_journal(self, kind, entries, *, project_id=None, task_id=None):
        """Durably describe CAS destinations before making them reachable.

        The journal is intentionally outside SQLite: a process crash can occur
        after ``rename`` and before the SQLite commit.  Startup then keeps a
        destination only when the durable metadata proves that this operation
        committed; otherwise it removes the exact content-addressed path.
        """
        if not entries:
            return None
        payload = {
            "version": 1,
            "kind": kind,
            "project_id": project_id,
            "task_id": task_id,
            "entries": [{"digest": str(entry["digest"])} for entry in entries],
        }
        journal_name = f"{new_id()}.json"
        staging_fd = publication_fd = -1
        try:
            staging_fd, publication_fd = self._open_publication_directory(create=True)
            _write_bytes_at(publication_fd, journal_name, durable_json_bytes(payload))
            os.fsync(staging_fd)
        finally:
            if publication_fd >= 0:
                os.close(publication_fd)
            if staging_fd >= 0:
                os.close(staging_fd)
        return self.store.staging_root / "publications" / journal_name

    @staticmethod
    def _remove_publication_journal_at(directory_fd, name):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        try:
            os.fsync(directory_fd)
        except OSError:
            return False
        return True


    def _publication_committed(self, journal):
        entries = journal.get("entries")
        if not isinstance(entries, list) or not entries:
            return False
        digests = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("digest"), str):
                return False
            digest = entry["digest"]
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                return False
            digests.append(digest)
            if not self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone():
                return False
        project_id = journal.get("project_id")
        if project_id and project_id != "unscoped":
            for digest in digests:
                if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone():
                    return False
        if journal.get("kind") == "settlement":
            task_id = journal.get("task_id")
            task = self.store.conn.execute("SELECT status, result_json FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task or task["status"] != "completed":
                return False
            try:
                result_digests = {
                    str(item.get("digest", "")).removeprefix("sha256:")
                    for item in (json.loads(task["result_json"] or "{}").get("outputs") or [])
                    if isinstance(item, dict)
                }
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
            if not set(digests).issubset(result_digests):
                return False
        return True

    def _recover_cas_publication_journals(self):
        """Finish or roll back CAS publications left by a crashed mutation."""
        staging_fd = publication_fd = -1
        try:
            try:
                staging_fd, publication_fd = self._open_publication_directory(create=False)
            except FileNotFoundError:
                return
            try:
                names = sorted(
                    entry.name
                    for entry in os.scandir(publication_fd)
                    if entry.name.endswith(".json")
                    and not entry.is_symlink()
                    and stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode)
                )
            except OSError:
                return
            for name in names:
                journal_fd = -1
                try:
                    journal_fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=publication_fd,
                    )
                    chunks = []
                    while True:
                        chunk = os.read(journal_fd, 1024 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    journal = json.loads(b"".join(chunks).decode("utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    # Leave malformed evidence for doctor/operator inspection;
                    # do not guess at a path and risk deleting unrelated data.
                    continue
                finally:
                    if journal_fd >= 0:
                        os.close(journal_fd)
                if not isinstance(journal, dict) or journal.get("version") != 1:
                    continue
                try:
                    committed = self._publication_committed(journal)
                except (OSError, sqlite3.DatabaseError, TypeError, ValueError):
                    continue
                if not committed:
                    cleanup_failed = False
                    for entry in journal.get("entries", []):
                        digest = entry.get("digest") if isinstance(entry, dict) else None
                        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                            continue
                        # If another operation has since durable-metadata-claimed
                        # this object, it owns the file and it must be retained.
                        if self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone():
                            continue
                        try:
                            self._unlink_cas_destination(digest)
                        except (OSError, ConflictError):
                            # Keep durable evidence when the CAS prefix cannot
                            # be opened or its pinned entry cannot be removed.
                            cleanup_failed = True
                            continue
                    if cleanup_failed:
                        continue
                if not self._remove_publication_journal_at(publication_fd, name):
                    continue
        finally:
            if publication_fd >= 0:
                os.close(publication_fd)
            if staging_fd >= 0:
                os.close(staging_fd)

    def _project_shot_resource(self, row):
        value = dict(row)
        value["shot_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        value["archived"] = bool(value.pop("archived_at"))
        value["items"] = [self._shot_item_resource(item) for item in self.store.conn.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (value["shot_id"],))]
        return value

    @staticmethod
    def _shot_item_resource(row):
        value = dict(row)
        value["item_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        return value

    @_durable_mutation
    def create_project_shot(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        name = str(body.get("name") or "")
        if not name.strip():
            raise ValidationError("name is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("metadata must be an object")
        shot_id = str(body.get("shot_id") or new_id())
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.create", project["id"], idempotency_key, request_hash, project_id=project["id"])
            if replay is not None:
                return replay
            if self.store.conn.execute("SELECT 1 FROM project_shots WHERE id=?", (shot_id,)).fetchone():
                raise ConflictError("shot already exists", details={"shot_id": shot_id})
            timestamp = now()
            self.store.conn.execute("INSERT INTO project_shots(id, project_id, name, metadata_json, version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, 1, ?, ?, NULL)", (shot_id, project["id"], name, canonical_json(metadata), timestamp, timestamp))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone())
            return self._command_record("shot.create", project["id"], idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def create_project_reference(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        kind, name = str(body.get("kind") or ""), str(body.get("name") or "")
        if kind not in {"character", "place", "object", "clothing", "other"}:
            raise ValidationError("invalid reference kind")
        if not name.strip():
            raise ValidationError("name is required")
        if "object_id" in body:
            raise ValidationError("object_id is not supported; use media_id")
        media_id = str(body.get("media_id") or "").removeprefix("sha256:")
        reference_id = str(body.get("reference_id") or "")
        if not media_id:
            raise ValidationError("media_id is required")
        if not reference_id:
            reference_id = new_id()
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("metadata must be an object")
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.create", project["id"], idempotency_key, request_hash, project_id=project["id"])
            if replay is not None:
                return replay
            if self.store.conn.execute("SELECT 1 FROM project_references WHERE id=?", (reference_id,)).fetchone():
                raise ConflictError("reference already exists", details={"reference_id": reference_id})
            if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project["id"], media_id)).fetchone():
                raise NotFoundError("media is not owned by project")
            timestamp = now()
            self.store.conn.execute("INSERT INTO project_references(id, project_id, kind, name, description, metadata_json, version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)", (reference_id, project["id"], kind, name, str(body.get("description") or ""), canonical_json(metadata), timestamp, timestamp))
            self.store.conn.execute("INSERT INTO media_references(id, reference_id, media_id, role, ordinal, is_primary, metadata_json, created_at) VALUES (?, ?, ?, 'canonical', 0, 1, '{}', ?)", (new_id(), reference_id, media_id, timestamp))
            result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone())
            return self._command_record("reference.create", project["id"], idempotency_key, request_hash, result, project_id=project["id"])

    def get_project_shot(self, project_id, shot_id):
        project = self.store.get_project(project_id)
        row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=? AND project_id=?", (shot_id, project["id"])).fetchone()
        if not row: raise NotFoundError("shot not found")
        return self._project_shot_resource(row)

    @_durable_mutation
    def update_project_shot(self, project_id, shot_id, body, *, idempotency_key=None, archived=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        expected = self._expected_version(body)
        action = "update" if archived is None else "archive" if archived else "recover"
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay(f"shot.{action}", shot_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=? AND project_id=?", (shot_id, project["id"])).fetchone()
            if not row: raise NotFoundError("shot not found")
            if int(row["version"]) != expected: raise ConflictError("shot version conflict", details={"expected": expected, "actual": int(row["version"])})
            timestamp = now()
            name = str(body.get("name", row["name"]))
            metadata = body.get("metadata", json.loads(row["metadata_json"]))
            if not name.strip() or not isinstance(metadata, dict): raise ValidationError("invalid shot name or metadata")
            archived_at = (timestamp if archived is True else None if archived is False else row["archived_at"])
            self.store.conn.execute("UPDATE project_shots SET name=?, metadata_json=?, version=?, updated_at=?, archived_at=? WHERE id=?", (name, canonical_json(metadata), expected + 1, timestamp, archived_at, shot_id))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone())
            return self._command_record(f"shot.{action}", shot_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def add_shot_item(self, project_id, shot_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        media_id = str(body.get("media_id") or "").removeprefix("sha256:")
        if not media_id: raise ValidationError("media_id is required")
        if not isinstance(body.get("metadata", {}), dict): raise ValidationError("metadata must be an object")
        shot = self.get_project_shot(project["id"], shot_id)
        key = idempotency_key
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.item.add", shot_id, key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project["id"], media_id)).fetchone(): raise NotFoundError("media is not owned by project")
            position = body.get("position")
            rows = self.store.conn.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (shot_id,)).fetchall()
            if position is None: position = len(rows)
            if isinstance(position, bool) or not isinstance(position, int) or position < 0 or position > len(rows): raise ValidationError("position is out of range")
            item_id = str(body.get("item_id") or new_id())
            stamp = now()
            self.store.conn.execute("INSERT INTO shot_items(id, shot_id, media_id, sort_key, source_frame, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (item_id, shot_id, media_id, f"~{item_id}", body.get("source_frame"), canonical_json(body.get("metadata", {})), stamp))
            ordered_ids = [row["id"] for row in rows]; ordered_ids.insert(position, item_id)
            for index, ordered_id in enumerate(ordered_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"tmp-{index:08d}-{item_id}", ordered_id))
            for index, ordered_id in enumerate(ordered_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"{index:08d}", ordered_id))
            self.store.conn.execute("UPDATE project_shots SET version=version+1, updated_at=? WHERE id=?", (stamp, shot_id))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone())
            return self._command_record("shot.item.add", shot_id, key, request_hash, result, project_id=project["id"])

    def _renumber_shot_items(self, shot_id):
        rows = self.store.conn.execute("SELECT id FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (shot_id,)).fetchall()
        for index, row in enumerate(rows): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"{index:08d}", row["id"]))

    @_durable_mutation
    def remove_shot_item(self, project_id, shot_id, item_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        self.get_project_shot(project_id, shot_id)
        expected = self._expected_version(body)
        request_hash = hashlib.sha256(canonical_json({"item_id": item_id, **body}).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.item.remove", shot_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone()
            if int(row["version"]) != expected: raise ConflictError("shot version conflict", details={"expected": expected, "actual": int(row["version"])})
            if not self.store.conn.execute("SELECT 1 FROM shot_items WHERE id=? AND shot_id=?", (item_id, shot_id)).fetchone(): raise NotFoundError("shot item not found")
            self.store.conn.execute("DELETE FROM shot_items WHERE id=?", (item_id,)); self._renumber_shot_items(shot_id)
            self.store.conn.execute("UPDATE project_shots SET version=version+1, updated_at=? WHERE id=?", (now(), shot_id))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone()); return self._command_record("shot.item.remove", shot_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def reorder_shot_items(self, project_id, shot_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        self.get_project_shot(project_id, shot_id); expected = self._expected_version(body)
        if "items" in body:
            raise ValidationError("items is not supported; use item_ids")
        item_ids = body.get("item_ids")
        if not isinstance(item_ids, list) or any(not isinstance(item_id, str) for item_id in item_ids) or len(item_ids) != len(set(item_ids)): raise ValidationError("items must be a unique complete permutation")
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.item.reorder", shot_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone(); current = [x["id"] for x in self.store.conn.execute("SELECT id FROM shot_items WHERE shot_id=?", (shot_id,))]
            if int(row["version"]) != expected: raise ConflictError("shot version conflict", details={"expected": expected, "actual": int(row["version"])})
            if set(map(str, item_ids)) != set(current): raise ValidationError("items must name the complete shot permutation")
            for index, item_id in enumerate(item_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"tmp-{index:08d}-{shot_id}", item_id))
            for index, item_id in enumerate(item_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"{index:08d}", item_id))
            self.store.conn.execute("UPDATE project_shots SET version=version+1, updated_at=? WHERE id=?", (now(), shot_id)); result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone()); return self._command_record("shot.item.reorder", shot_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def promote_project_shot_candidate(self, project_id, shot_id, body, *, idempotency_key=None):
        """Atomically promote a shot candidate and persist its invalidation report.

        The receipt lookup is deliberately the first database read.  A retry
        therefore returns the exact stored result without inspecting the
        mutable shot, candidate, or media projections.
        """
        self._require_object_body(body)
        key = require_idempotency_key(idempotency_key)
        candidate_id = body.get("candidate_item_id")
        expected = body.get("expected_head_seq")
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValidationError("candidate_item_id is required")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 1:
            raise ValidationError("expected_head_seq must be a positive integer")
        timeline_assets = body.get("timeline_assets", [])
        if isinstance(timeline_assets, Mapping):
            timeline_assets = list(timeline_assets.values())
        if not isinstance(timeline_assets, list) or any(not isinstance(item, Mapping) for item in timeline_assets):
            raise ValidationError("timeline_assets must be a list of objects")
        request = {"project_id": str(project_id), "shot_id": str(shot_id), "candidate_item_id": candidate_id, "expected_head_seq": expected, "timeline_assets": timeline_assets}
        request_hash = hashlib.sha256(canonical_json(request).encode()).hexdigest()
        # Receipt-first is important: do not resolve the project or read the
        # shot before proving this is not an idempotent replay.
        replay = self._command_replay("shot.promote_candidate", str(shot_id), key, request_hash, project_id=str(project_id))
        if replay is not None:
            return replay
        project = self.store.get_project(project_id)
        shot_row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=? AND project_id=?", (str(shot_id), project["id"])).fetchone()
        if shot_row is None:
            raise NotFoundError("shot not found")
        actual = int(shot_row["version"])
        if actual != expected:
            raise ConflictError("shot head conflict", details={"expected": expected, "actual": actual})
        item_rows = self.store.conn.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (str(shot_id),)).fetchall()
        candidate_row = next((row for row in item_rows if str(row["id"]) == candidate_id), None)
        if candidate_row is None:
            raise NotFoundError("shot candidate not found")
        try:
            candidate_metadata = json.loads(candidate_row["metadata_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError("candidate metadata is invalid") from exc
        if not isinstance(candidate_metadata, dict) or candidate_metadata.get("role") != "primary_visual" or candidate_metadata.get("status") != "candidate":
            raise ValidationError("candidate item must have role='primary_visual' and status='candidate'")
        # Product provenance is carried in metadata, but the authority check
        # is neutral: only verify fields that a producer supplied.
        provenance = candidate_metadata.get("provenance")
        recipe = candidate_metadata.get("recipe")
        for label, value in (("candidate metadata", candidate_metadata), ("candidate provenance", provenance), ("candidate recipe", recipe)):
            if not isinstance(value, Mapping):
                continue
            if value.get("project_id") is not None and str(value["project_id"]) != str(project["id"]):
                raise ValidationError(f"{label} project_id does not match target project")
            if value.get("shot_id") is not None and str(value["shot_id"]) != str(shot_id):
                raise ValidationError(f"{label} shot_id does not match target shot")
            if value.get("target_role") is not None and value["target_role"] != "primary_visual":
                raise ValidationError(f"{label} target_role must be primary_visual")
            supplied_media = value.get("media_id") or value.get("output_media_id")
            if supplied_media is not None and str(supplied_media).removeprefix("sha256:") != str(candidate_row["media_id"]).removeprefix("sha256:"):
                raise ValidationError(f"{label} media_id does not match candidate media")
        media_digest = str(candidate_row["media_id"]).removeprefix("sha256:")
        owned = self.store.conn.execute("SELECT o.* FROM objects o JOIN project_objects po ON po.digest=o.digest WHERE po.project_id=? AND o.digest=?", (project["id"], media_digest)).fetchone()
        if owned is None:
            raise NotFoundError("candidate media is not owned by project")
        # Verify both the durable object identity and the bytes behind it.  A
        # database row alone is not provenance evidence after a damaged CAS.
        try:
            actual_digest = sha256_bytes(self.cas.read(media_digest))
        except Exception as exc:  # pragma: no cover - CAS backend-specific
            raise ValidationError("candidate media is unavailable") from exc
        if actual_digest != media_digest:
            raise ValidationError("candidate media digest does not match stored bytes")
        primaries = []
        for row in item_rows:
            metadata = json.loads(row["metadata_json"])
            if isinstance(metadata, dict) and metadata.get("role") == "primary_visual" and metadata.get("status") == "primary":
                primaries.append((row, metadata))
        if len(primaries) > 1:
            raise ValidationError("shot must contain at most one primary_visual item")
        if primaries and str(primaries[0][0]["id"]) == candidate_id:
            raise ValidationError("candidate item is already the primary")
        updates = []
        superseded_id = None
        if primaries:
            old_row, old_metadata = primaries[0]
            superseded_id = str(old_row["id"])
            old_metadata = dict(old_metadata); old_metadata["status"] = "superseded"
            updates.append((superseded_id, old_metadata))
        candidate_metadata = dict(candidate_metadata); candidate_metadata["status"] = "primary"
        updates.append((candidate_id, candidate_metadata))
        stamp = now()
        resulting_head = self.store.promote_shot_items(shot_id, expected, updates, timestamp=stamp)
        promoted = {"shot_id": str(shot_id), "project_id": str(project["id"]), "candidate_item_id": candidate_id, "primary_item_id": candidate_id, "superseded_item_id": superseded_id, "item_ids": [str(row["id"]) for row in item_rows], "event_head_seq": resulting_head}
        item_resources = []
        for row in self.store.conn.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (shot_id,)).fetchall():
            value = self._shot_item_resource(row)
            value["media_id"] = "sha256:" + str(value["media_id"]).removeprefix("sha256:")
            item_resources.append(value)
        media_records = []
        for row in self.store.conn.execute("SELECT o.* FROM objects o JOIN project_objects po ON po.digest=o.digest WHERE po.project_id=? ORDER BY o.digest", (project["id"],)).fetchall():
            media_records.append({"id": "sha256:" + str(row["digest"]), "media_id": "sha256:" + str(row["digest"]), "content_hash": "sha256:" + str(row["digest"]), "digest": "sha256:" + str(row["digest"])})
        relation_rows = self.store.conn.execute("SELECT * FROM media_relations WHERE project_id=? ORDER BY from_digest, to_digest, kind, ordinal", (project["id"],)).fetchall()
        relations = [{"from_media_id": "sha256:" + str(row["from_digest"]), "to_media_id": "sha256:" + str(row["to_digest"]), "kind": row["kind"], "ordinal": int(row["ordinal"]), "metadata": json.loads(row["metadata_json"])} for row in relation_rows]
        invalidation = analyze_invalidation(item_resources, media_records, timeline_assets, media_relations=relations)
        result = {"promotion": promoted, "invalidation": invalidation}
        return self._command_record("shot.promote_candidate", str(shot_id), key, request_hash, result, project_id=project["id"])

    # Short neutral service alias used by adapters that do not expose the
    # project-qualified generated method name.
    promote_candidate = promote_project_shot_candidate

    # -- immutable shot text bindings -----------------------------------

    @staticmethod
    def _text_binding_id(project_id, shot_id, kind, slot):
        if not isinstance(kind, str) or kind not in TEXT_BINDING_KINDS:
            raise ValidationError("kind must be prompt, voiceover_script, or transcript", details={"reason": "kind"})
        if slot is not None and (kind != "prompt" or not isinstance(slot, str) or not TEXT_BINDING_SLOT_RE.fullmatch(slot)):
            raise ValidationError("slot is allowed only for prompt bindings and must be a lowercase slug", details={"reason": "slot"})
        identity = {"schema": TEXT_BINDING_IDENTITY_SCHEMA, "project_id": str(project_id), "shot_id": str(shot_id), "kind": kind, "slot": slot}
        return str(uuid.uuid5(uuid.NAMESPACE_URL, canonical_json(identity)))

    @staticmethod
    def _freeze_text(value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValidationError("text must be UTF-8 text or bytes", details={"reason": "text"})
        data = bytes(value)
        if len(data) > TEXT_BINDING_MAX_BYTES:
            raise ValidationError("text exceeds 1 MiB", details={"reason": "too_large"})
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError("text is not valid UTF-8", details={"reason": "invalid_utf8"}) from exc
        return data, sha256_bytes(data)

    def _verify_text_object(self, project_id, digest, *, candidate=False):
        digest = str(digest).removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            details = {"reason": "malformed_hash", "media_id": "sha256:" + digest}
            if candidate:
                raise ValidationError("text media candidate failed integrity", details=details)
            raise ConflictError("bound text media failed integrity", details=details)
        row = self.store.conn.execute(
            "SELECT o.* FROM objects o JOIN project_objects po ON po.digest=o.digest "
            "WHERE o.digest=? AND po.project_id=? AND po.relation='managed'", (digest, project_id)
        ).fetchone()
        reason = None
        if row is None:
            reason = "media_not_owned"
        elif not str(row["media_type"]).startswith("text/"):
            reason = "media_type_not_text"
        elif int(row["size"]) > TEXT_BINDING_MAX_BYTES:
            reason = "text_too_large"
        else:
            path = self.cas.path_for(digest)
            try:
                if path.is_symlink() or not path.is_file():
                    reason = "managed_file_not_regular"
                else:
                    data = path.read_bytes()
                    if len(data) != int(row["size"]): reason = "managed_size_mismatch"
                    elif sha256_bytes(data) != digest: reason = "managed_hash_mismatch"
                    else:
                        data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                reason = "managed_bytes_invalid_utf8"
            except (OSError, ValidationError):
                reason = "managed_file_missing"
        if reason:
            details = {"reason": reason, "media_id": "sha256:" + digest}
            if candidate:
                raise ValidationError("text media candidate failed integrity", details=details)
            raise ConflictError("bound text media failed integrity", details=details)
        return row

    def _text_binding_resource(self, row, *, verify=True):
        project_id = str(row["project_id"])
        shot = self.store.conn.execute("SELECT project_id FROM project_shots WHERE id=?", (row["shot_id"],)).fetchone()
        if shot is None or str(shot["project_id"]) != project_id:
            raise ConflictError("text binding shot is outside its project", details={"reason": "binding_shot_project_mismatch"})
        expected_id = self._text_binding_id(project_id, row["shot_id"], row["kind"], row["slot"])
        if str(row["id"]) != expected_id:
            raise ConflictError("text binding identity is corrupt", details={"reason": "binding_natural_tuple_mismatch"})
        expected_stream = expected_id + ":shot.text_binding"
        if str(row["event_stream_id"]) != expected_stream:
            raise ConflictError("text binding stream identity is corrupt", details={"reason": "binding_stream_id_mismatch"})
        events = self.store.conn.execute(
            "SELECT event_id, project_id, seq, kind, payload_json, previous_hash, event_hash "
            "FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq", (row["id"],)
        ).fetchall()
        if int(row["head_seq"]) != len(events) or any(int(event["seq"]) != index for index, event in enumerate(events, 1)):
            raise ConflictError("text binding replay ordering is corrupt", details={"reason": "binding_event_order"})
        previous_hash = ""
        for event in events:
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, json.JSONDecodeError):
                raise ConflictError("text binding event payload is corrupt", details={"reason": "binding_event_payload"})
            if str(event["project_id"]) != project_id or str(event["previous_hash"]) != previous_hash:
                raise ConflictError("text binding event chain is corrupt", details={"reason": "binding_event_chain"})
            expected_hash = hashlib.sha256(canonical_json({
                "event_id": event["event_id"], "binding_id": row["id"], "seq": int(event["seq"]),
                "kind": event["kind"], "payload": payload, "previous_hash": previous_hash,
            }).encode()).hexdigest()
            if str(event["event_hash"]) != expected_hash:
                raise ConflictError("text binding event hash is corrupt", details={"reason": "binding_event_hash"})
            previous_hash = expected_hash
        if verify:
            media = self._verify_text_object(project_id, row["media_digest"])
        else:
            media = self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (row["media_digest"],)).fetchone()
        if media is None:
            raise ConflictError("bound text media is missing", details={"reason": "bound_media_missing"})
        return {
            "binding_id": str(row["id"]), "project_id": project_id, "shot_id": str(row["shot_id"]),
            "kind": str(row["kind"]), "slot": row["slot"], "media_id": "sha256:" + str(media["digest"]),
            "event_stream_id": str(row["event_stream_id"]), "head": int(row["head_seq"]),
            "content_hash": "sha256:" + str(media["digest"]), "mime_type": str(media["media_type"]),
            "byte_size": int(media["size"]), "created_at": str(row["created_at"]), "updated_at": str(row["updated_at"]),
        }

    def _resolve_text_binding(self, project_id, body):
        binding_id = body.get("binding_id")
        if binding_id is not None:
            if any(body.get(key) is not None for key in ("shot_id", "shot_ref", "kind", "slot")):
                raise ValidationError("binding_id cannot be combined with friendly selectors")
            row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=? AND project_id=?", (str(binding_id), project_id)).fetchone()
            if row is None: raise NotFoundError("text binding not found")
            return row
        shot_id = body.get("shot_id") or body.get("shot_ref")
        kind = body.get("kind")
        if not shot_id or not kind: raise ValidationError("shot_id and kind are required")
        self.store.get_project(project_id)
        shot = self.store.conn.execute("SELECT id FROM project_shots WHERE id=? AND project_id=?", (shot_id, project_id)).fetchone()
        if shot is None: raise NotFoundError("shot not found")
        slot = body.get("slot")
        self._text_binding_id(project_id, shot["id"], kind, slot)
        params = [project_id, shot["id"], kind]
        query = "SELECT * FROM shot_text_bindings WHERE project_id=? AND shot_id=? AND kind=?"
        if "slot" in body:
            query += " AND slot IS ?"; params.append(slot)
        rows = self.store.conn.execute(query + " ORDER BY slot IS NOT NULL ASC, slot ASC, id ASC", tuple(params)).fetchall()
        if not rows: raise NotFoundError("text binding not found")
        if len(rows) > 1: raise ConflictError("text binding selector is ambiguous", details={"reason": "ambiguous_selector", "candidates": [str(value["id"]) for value in rows]})
        return rows[0]

    def _record_text_binding_event(self, row, event_kind, payload, *, timestamp):
        prior = self.store.conn.execute("SELECT event_hash FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq DESC LIMIT 1", (row["id"],)).fetchone()
        previous_hash = str(prior[0]) if prior else ""
        seq = int(row["head_seq"]) + 1
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{row['id']}:shot.text_binding:{seq}"))
        event_hash = hashlib.sha256(canonical_json({"event_id": event_id, "binding_id": row["id"], "seq": seq, "kind": event_kind, "payload": payload, "previous_hash": previous_hash}).encode()).hexdigest()
        self.store.conn.execute("INSERT INTO shot_text_binding_events(event_id,binding_id,project_id,seq,kind,payload_json,previous_hash,event_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)", (event_id, row["id"], row["project_id"], seq, event_kind, canonical_json(payload), previous_hash, event_hash, timestamp))
        return event_id, seq

    def _materialize_text_object(self, project_id, data, digest):
        existing = self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()
        if existing is not None:
            # CAS objects are workspace-global, while ownership is project
            # scoped.  A byte-identical object imported by another path may be
            # reused, but only after independently checking its immutable
            # bytes; then attach the project managed-local relation.
            if not str(existing["media_type"]).startswith("text/") or int(existing["size"]) > TEXT_BINDING_MAX_BYTES:
                raise ValidationError("text media candidate failed integrity", details={"reason": "media_type_not_text", "media_id": "sha256:" + digest})
            try:
                path = self.cas.path_for(digest)
                if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                    raise ValidationError("text media candidate failed integrity", details={"reason": "managed_hash_mismatch", "media_id": "sha256:" + digest})
            except OSError as exc:
                raise ValidationError("text media candidate failed integrity", details={"reason": "managed_file_missing", "media_id": "sha256:" + digest}) from exc
            relation = self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'", (project_id, digest)).fetchone()
            if relation is None:
                self.store.conn.execute("INSERT INTO project_objects(project_id,digest,relation,created_at) VALUES (?,?, 'managed', ?)", (project_id, digest, now()))
            return existing
        path = self.cas.path_for(digest)
        if not path.exists():
            self._begin_cas_publication_journal("shot-text-binding", [{"digest": digest}], project_id=project_id)
            self.cas.put(data, expected_digest=digest)
        stamp = now()
        self.store.conn.execute("INSERT INTO objects(digest,size,media_type,original_name,created_at) VALUES (?,?,?,?,?)", (digest, len(data), "text/plain", digest + ".txt", stamp))
        self.store.conn.execute("INSERT INTO project_objects(project_id,digest,relation,created_at) VALUES (?,?, 'managed', ?)", (project_id, digest, stamp))
        return self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()

    @_durable_mutation
    def set_project_shot_text_binding(self, project_id, body, *, idempotency_key=None):
        require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        project = self.store.get_project(project_id); project_id = str(project["id"])
        expected = body.get("expected_head")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0: raise ValidationError("expected_head must be a non-negative integer", details={"reason": "expected_head"})
        data, digest = self._freeze_text(body.get("text"))
        if expected == 0:
            if body.get("binding_id") is not None: raise ValidationError("head 0 requires a friendly shot selector", details={"reason": "expected_head"})
            shot_id = body.get("shot_id") or body.get("shot_ref"); kind = body.get("kind"); slot = body.get("slot")
            if not shot_id: raise ValidationError("shot_id is required")
            self._text_binding_id(project_id, shot_id, kind, slot)
            shot = self.store.conn.execute("SELECT id FROM project_shots WHERE id=? AND project_id=?", (shot_id, project_id)).fetchone()
            if shot is None: raise NotFoundError("shot not found")
            binding_id = self._text_binding_id(project_id, shot["id"], kind, slot)
            stream_id = binding_id + ":shot.text_binding"
            row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (binding_id,)).fetchone()
        else:
            row = self._resolve_text_binding(project_id, body); binding_id = str(row["id"]); stream_id = str(row["event_stream_id"])
            if int(row["head_seq"]) != expected: raise ConflictError("text binding head is stale", details={"expected_head": expected, "actual_head": int(row["head_seq"]), "binding_id": binding_id})
        facts = {"project_id": project_id, "binding_id": binding_id, "event_stream_id": stream_id, "expected_head": expected, "desired_content_hash": "sha256:" + digest}
        req_hash = hashlib.sha256(canonical_json({"command_kind": "shot.text_binding.set", **facts}).encode()).hexdigest()
        replay = self._command_replay("shot.text_binding.set", binding_id, idempotency_key, req_hash, project_id=project_id)
        if replay is not None: return replay
        if expected == 0 and row is not None:
            raise ConflictError("text binding head is stale", details={"expected_head": 0, "actual_head": int(row["head_seq"]), "binding_id": binding_id})
        if expected != 0:
            self._text_binding_resource(row)
        if expected == 0:
            desired = self._materialize_text_object(project_id, data, digest)
            stamp = now(); self.store.conn.execute("INSERT INTO shot_text_bindings(id,project_id,shot_id,kind,slot,media_digest,event_stream_id,head_seq,created_at,updated_at) VALUES (?,?,?,?,?,?,?,0,?,?)", (binding_id, project_id, shot_id, kind, slot, digest, stream_id, stamp, stamp))
            row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (binding_id,)).fetchone()
            event_id, seq = self._record_text_binding_event(row, "shot.text_binding.created", {"binding_id": binding_id, "media_id": "sha256:" + digest, "content_hash": "sha256:" + digest}, timestamp=stamp)
            self.store.conn.execute("UPDATE shot_text_bindings SET head_seq=1 WHERE id=?", (binding_id,))
        else:
            desired = self._materialize_text_object(project_id, data, digest) if self.store.conn.execute("SELECT 1 FROM objects WHERE digest=? AND EXISTS (SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed')", (digest, project_id, digest)).fetchone() is None else self._verify_text_object(project_id, digest, candidate=True)
            if str(row["media_digest"]) == digest:
                return {"data": self._text_binding_resource(row), "receipt": None}
            stamp = now(); event_id, seq = self._record_text_binding_event(row, "shot.text_binding.rebound", {"binding_id": binding_id, "previous_media_id": "sha256:" + str(row["media_digest"]), "media_id": "sha256:" + digest, "content_hash": "sha256:" + digest}, timestamp=stamp)
            self.store.conn.execute("UPDATE shot_text_bindings SET media_digest=?, head_seq=?, updated_at=? WHERE id=?", (digest, seq, stamp, binding_id))
        result = self._text_binding_resource(self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (binding_id,)).fetchone())
        recorded = self._command_record("shot.text_binding.set", binding_id, idempotency_key, req_hash, result, project_id=project_id, event_ids=(event_id,), primary_stream_id=stream_id, resulting_stream_seq=seq)
        return recorded

    @_durable_mutation
    def rebind_project_shot_text_binding(self, project_id, body, *, idempotency_key=None):
        require_idempotency_key(idempotency_key); self._require_object_body(body)
        project = self.store.get_project(project_id); project_id = str(project["id"])
        expected = body.get("expected_head")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 1: raise ValidationError("rebind requires a positive expected_head", details={"reason": "expected_head"})
        row = self._resolve_text_binding(project_id, body)
        if int(row["head_seq"]) != expected: raise ConflictError("text binding head is stale", details={"expected_head": expected, "actual_head": int(row["head_seq"]), "binding_id": str(row["id"])})
        desired_digest = str(body.get("media_id") or body.get("content_hash") or "").removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", desired_digest): raise ValidationError("media_id must be a SHA-256 object id", details={"reason": "media_id"})
        facts = {"project_id": project_id, "binding_id": str(row["id"]), "event_stream_id": str(row["event_stream_id"]), "expected_head": expected, "desired_media_id": "sha256:" + desired_digest, "desired_content_hash": "sha256:" + desired_digest}
        req_hash = hashlib.sha256(canonical_json({"command_kind": "shot.text_binding.rebind", **facts}).encode()).hexdigest()
        replay = self._command_replay("shot.text_binding.rebind", str(row["id"]), idempotency_key, req_hash, project_id=project_id)
        if replay is not None: return replay
        current = self._text_binding_resource(row)
        self._verify_text_object(project_id, desired_digest, candidate=True)
        if str(row["media_digest"]) == desired_digest: return {"data": current, "receipt": None}
        stamp = now(); event_id, seq = self._record_text_binding_event(row, "shot.text_binding.rebound", {"binding_id": str(row["id"]), "previous_media_id": current["media_id"], "media_id": "sha256:" + desired_digest, "content_hash": "sha256:" + desired_digest}, timestamp=stamp)
        self.store.conn.execute("UPDATE shot_text_bindings SET media_digest=?, head_seq=?, updated_at=? WHERE id=?", (desired_digest, seq, stamp, row["id"]))
        result = self._text_binding_resource(self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (row["id"],)).fetchone())
        return self._command_record("shot.text_binding.rebind", str(row["id"]), idempotency_key, req_hash, result, project_id=project_id, event_ids=(event_id,), primary_stream_id=str(row["event_stream_id"]), resulting_stream_seq=seq)

    def get_project_shot_text_binding(self, project_id, binding_id):
        project = self.store.get_project(project_id)
        row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=? AND project_id=?", (binding_id, project["id"])).fetchone()
        if row is None: raise NotFoundError("text binding not found")
        return self._text_binding_resource(row)

    def list_project_shot_text_bindings(self, project_id, *, shot_id=None, kind=None, slot=None):
        project = self.store.get_project(project_id); project_id = str(project["id"])
        params = [project_id]; query = "SELECT * FROM shot_text_bindings WHERE project_id=?"
        if shot_id is not None: query += " AND shot_id=?"; params.append(shot_id)
        if kind is not None:
            if kind not in TEXT_BINDING_KINDS: raise ValidationError("invalid text binding kind")
            query += " AND kind=?"; params.append(kind)
        if slot is not None: query += " AND slot=?"; params.append(slot)
        rows = self.store.conn.execute(query + " ORDER BY id", tuple(params)).fetchall()
        return {"items": [self._text_binding_resource(row) for row in rows], "next_cursor": None}

    def _project_reference_resource(self, row):
        value = dict(row); value["reference_id"] = value.pop("id"); value["metadata"] = json.loads(value.pop("metadata_json")); value["archived"] = bool(value.pop("archived_at")); value["media_references"] = []
        for assoc in self.store.conn.execute("SELECT * FROM media_references WHERE reference_id=? ORDER BY ordinal, id", (value["reference_id"],)):
            item = dict(assoc); item["association_id"] = item.pop("id"); item["metadata"] = json.loads(item.pop("metadata_json")); item["is_primary"] = bool(item["is_primary"]); item["media_id"] = "sha256:" + item["media_id"]; value["media_references"].append(item)
        value["links"] = [dict(x) for x in self.store.conn.execute("SELECT * FROM reference_links WHERE from_reference_id=? OR to_reference_id=?", (value["reference_id"], value["reference_id"]))]
        return value

    def get_project_reference(self, project_id, reference_id):
        project = self.store.get_project(project_id); row = self.store.conn.execute("SELECT * FROM project_references WHERE id=? AND project_id=?", (reference_id, project["id"])).fetchone()
        if not row: raise NotFoundError("reference not found")
        return self._project_reference_resource(row)

    @_durable_mutation
    def update_project_reference(self, project_id, reference_id, body, *, idempotency_key=None, archived=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        project = self.store.get_project(project_id); expected = self._expected_version(body); action = "update" if archived is None else "archive" if archived else "recover"; request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay(f"reference.{action}", reference_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_references WHERE id=? AND project_id=?", (reference_id, project["id"])).fetchone()
            if not row: raise NotFoundError("reference not found")
            if int(row["version"]) != expected: raise ConflictError("reference version conflict", details={"expected": expected, "actual": int(row["version"])})
            name = str(body.get("name", row["name"])); metadata = body.get("metadata", json.loads(row["metadata_json"]));
            if not name.strip() or not isinstance(metadata, dict): raise ValidationError("invalid reference name or metadata")
            self.store.conn.execute("UPDATE project_references SET name=?, description=?, metadata_json=?, version=version+1, updated_at=?, archived_at=? WHERE id=?", (name, str(body.get("description", row["description"])), canonical_json(metadata), now(), now() if archived is True else None if archived is False else row["archived_at"], reference_id))
            result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()); return self._command_record(f"reference.{action}", reference_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def associate_reference(self, project_id, reference_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id); media_id = str(body.get("media_id") or "").removeprefix("sha256:"); role = body.get("role") or "depicts"
        if role not in {"canonical", "used_as_input", "depicts", "inspired_by"}: raise ValidationError("invalid reference role")
        self.get_project_reference(project["id"], reference_id)
        if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project["id"], media_id)).fetchone(): raise NotFoundError("media is not owned by project")
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.associate", reference_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            if not isinstance(body.get("metadata", {}), dict): raise ValidationError("metadata must be an object")
            association_id = str(body.get("association_id") or new_id()); stamp = now()
            if role == "canonical": self.store.conn.execute("UPDATE media_references SET is_primary=0 WHERE reference_id=?", (reference_id,))
            self.store.conn.execute("INSERT INTO media_references(id, reference_id, media_id, role, ordinal, is_primary, metadata_json, created_at) VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(ordinal)+1,0) FROM media_references WHERE reference_id=?), ?, ?, ?)", (association_id, reference_id, media_id, role, reference_id, 1 if role == "canonical" else 0, canonical_json(body.get("metadata", {})), stamp))
            self.store.conn.execute("UPDATE project_references SET version=version+1, updated_at=? WHERE id=?", (stamp, reference_id)); result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()); return self._command_record("reference.associate", reference_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def link_references(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id); source, target, kind = body.get("from_reference_id"), body.get("to_reference_id"), body.get("kind")
        if kind not in {"belongs_to", "wears", "located_in", "associated_with", "related_to"}: raise ValidationError("invalid reference link kind")
        self.get_project_reference(project["id"], source); self.get_project_reference(project["id"], target)
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.link", source, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            stamp = now(); metadata = canonical_json(body.get("metadata", {}))
            self.store.conn.execute("INSERT OR IGNORE INTO reference_links VALUES (?, ?, ?, ?, ?)", (source, target, kind, metadata, stamp))
            if kind == "related_to": self.store.conn.execute("INSERT OR IGNORE INTO reference_links VALUES (?, ?, ?, ?, ?)", (target, source, kind, metadata, stamp))
            result = {"from_reference_id": source, "to_reference_id": target, "kind": kind}; return self._command_record("reference.link", source, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def set_primary_reference(self, project_id, reference_id, association_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id); self.get_project_reference(project["id"], reference_id); expected = self._expected_version(body); request_hash = hashlib.sha256(canonical_json({"association_id": association_id, **body}).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.primary", reference_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()
            if int(row["version"]) != expected: raise ConflictError("reference version conflict", details={"expected": expected, "actual": int(row["version"])})
            assoc = self.store.conn.execute("SELECT * FROM media_references WHERE id=? AND reference_id=?", (association_id, reference_id)).fetchone()
            if not assoc: raise NotFoundError("media association not found")
            self.store.conn.execute("UPDATE media_references SET is_primary=0 WHERE reference_id=?", (reference_id,)); self.store.conn.execute("UPDATE media_references SET is_primary=1, role='canonical' WHERE id=?", (association_id,)); self.store.conn.execute("UPDATE project_references SET version=version+1, updated_at=? WHERE id=?", (now(), reference_id)); result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()); return self._command_record("reference.primary", reference_id, idempotency_key, request_hash, result, project_id=project["id"])

    def list_timeline_history(self, timeline_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        self._timeline_resource(timeline_id)
        rows = self.store.conn.execute("SELECT * FROM timeline_revisions WHERE timeline_id=? ORDER BY version", (timeline_id,)).fetchall()
        if not rows:
            current = self._timeline_resource(timeline_id)
            rows = [{"version": current["version"], "shots_json": canonical_json(current["shots"]), "references_json": canonical_json(current["references"]), "created_at": now()}]
        page = _page_rows(rows, scope=f"timeline-history:{timeline_id}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (int(row["version"]),),
                          resource_fn=lambda row: {"timeline_id": timeline_id, "version": int(row["version"]), "shots": json.loads(row["shots_json"]), "references": json.loads(row["references_json"]), "created_at": row["created_at"]})
        return page

    @staticmethod
    def _diff_items(before, after, key):
        old = {str(item.get(key)): item for item in before}
        new = {str(item.get(key)): item for item in after}
        return {"added": [new[item_id] for item_id in sorted(new.keys() - old.keys())], "removed": [old[item_id] for item_id in sorted(old.keys() - new.keys())], "changed": [{"id": item_id, "before": old[item_id], "after": new[item_id]} for item_id in sorted(old.keys() & new.keys()) if old[item_id] != new[item_id]]}

    def diff_timeline(self, timeline_id, from_version, to_version):
        self._timeline_resource(timeline_id)
        before = self._timeline_revision(timeline_id, int(from_version))
        after = self._timeline_revision(timeline_id, int(to_version))
        return {"timeline_id": timeline_id, "from_version": int(from_version), "to_version": int(to_version), "changes": {"shots": self._diff_items(before["shots"], after["shots"], "shot_id"), "references": self._diff_items(before["references"], after["references"], "reference_id")}}

    @_durable_mutation
    def archive_timeline(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        current = self._timeline_resource(timeline_id)
        project_id = str(current["project_id"])
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body, "action": "archive"}).encode()).hexdigest()
        replay = self._command_replay("timeline.archive", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        if current["version"] != expected:
            raise ConflictError("timeline version conflict", details={"expected": expected, "actual": current["version"]})
        with self.store._transaction():
            self.store.conn.execute("UPDATE timelines SET archived_at=?, version=? WHERE id=?", (now(), expected + 1, timeline_id))
            resource = self._timeline_resource(timeline_id)
            self._record_timeline_revision(timeline_id, resource)
            event_id = self.store._append_timeline_event(timeline_id, "timeline.archived", {"project_id": project_id, "version": resource["version"]})
            event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            return self._command_record("timeline.archive", timeline_id, idempotency_key, request_hash, resource, project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    @_durable_mutation
    def recover_timeline(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        target = body.get("version")
        if isinstance(target, bool) or not isinstance(target, int) or target < 1:
            raise ValidationError("version must be a positive integer")
        current = self._timeline_resource(timeline_id)
        project_id = str(current["project_id"])
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body, "action": "recover"}).encode()).hexdigest()
        replay = self._command_replay("timeline.recover", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        if current["version"] != expected:
            raise ConflictError("timeline version conflict", details={"expected": expected, "actual": current["version"]})
        revision = self._timeline_revision(timeline_id, target)
        with self.store._transaction():
            self.store.conn.execute("DELETE FROM timeline_shot_state WHERE id IN (SELECT id FROM timeline_shots WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_reference_state WHERE id IN (SELECT id FROM timeline_references WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_shots WHERE timeline_id=?", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_references WHERE timeline_id=?", (timeline_id,))
            for shot in revision["shots"]:
                self.store.conn.execute("INSERT INTO timeline_shots VALUES (?, ?, ?, ?, ?)", (shot["shot_id"], timeline_id, int(shot["start_ms"]), int(shot["duration_ms"]), canonical_json(shot.get("reference_ids", []))))
                self.store.conn.execute("INSERT INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (shot["shot_id"],))
            for reference in revision["references"]:
                self.store.conn.execute("INSERT INTO timeline_references VALUES (?, ?, ?, ?)", (reference["reference_id"], timeline_id, reference["object_id"], reference.get("role")))
                self.store.conn.execute("INSERT INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (reference["reference_id"],))
            self.store.conn.execute("UPDATE timelines SET archived_at=NULL, version=? WHERE id=?", (expected + 1, timeline_id))
            resource = self._timeline_resource(timeline_id)
            self._record_timeline_revision(timeline_id, resource)
            event_id = self.store._append_timeline_event(timeline_id, "timeline.recovered", {"project_id": project_id, "version": resource["version"], "target_version": target})
            event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            return self._command_record("timeline.recover", timeline_id, idempotency_key, request_hash, resource, project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    @_durable_mutation
    def create_shot(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        if not isinstance(body.get("shot_id"), str) or not body["shot_id"]:
            raise ValidationError("shot_id is required")
        if int(body.get("duration_ms", 0)) < 1 or int(body.get("start_ms", 0)) < 0:
            raise ValidationError("invalid shot timing")
        references = body.get("reference_ids", [])
        if not isinstance(references, list) or any(not isinstance(value, str) or not value for value in references):
            raise ValidationError("reference_ids must be a list of non-empty strings")
        self._timeline_resource(timeline_id)
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "shot": body}).encode()).hexdigest()
        # The key is scoped to the create-shot operation, while the request
        # hash binds both the timeline path and complete body.  This makes a
        # key reused for a different timeline or shot a deterministic
        # conflict rather than an unrelated successful mutation.
        aggregate_id = "timeline.shots"
        replay = self._command_replay("timeline.shot.create", aggregate_id, idempotency_key, request_hash)
        if replay is not None:
            return replay
        try:
            self.store.conn.execute(
                "INSERT INTO timeline_shots(id, timeline_id, start_ms, duration_ms, reference_ids_json) VALUES (?, ?, ?, ?, ?)",
                (body["shot_id"], timeline_id, int(body["start_ms"]), int(body["duration_ms"]), canonical_json(references)),
            )
            self.store.conn.execute("INSERT INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (body["shot_id"],))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("shot already exists", details={"shot_id": body["shot_id"]}) from exc
        result = self._shot_resource(self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (body["shot_id"],)).fetchone())
        return self._command_record("timeline.shot.create", aggregate_id, idempotency_key, request_hash, result)

    def get_shot(self, shot_id):
        row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
        if not row: raise NotFoundError("shot not found")
        return self._shot_resource(row)

    @_durable_mutation
    def create_reference(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        if not isinstance(body.get("reference_id"), str) or not body["reference_id"]:
            raise ValidationError("reference_id is required")
        if not isinstance(body.get("object_id"), str) or not body["object_id"]:
            raise ValidationError("object_id is required")
        self._timeline_resource(timeline_id)
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "reference": body}).encode()).hexdigest()
        aggregate_id = "timeline.references"
        replay = self._command_replay("timeline.reference.create", aggregate_id, idempotency_key, request_hash)
        if replay is not None:
            return replay
        try:
            self.store.conn.execute(
                "INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?, ?, ?, ?)",
                (body["reference_id"], timeline_id, body["object_id"], body.get("role")),
            )
            self.store.conn.execute("INSERT INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (body["reference_id"],))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("reference already exists", details={"reference_id": body["reference_id"]}) from exc
        result = self._reference_resource(self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (body["reference_id"],)).fetchone())
        return self._command_record("timeline.reference.create", aggregate_id, idempotency_key, request_hash, result)

    def _document_resource(self, row):
        value = dict(row)
        value["document_id"] = value.pop("id")
        value["content"] = json.loads(value.pop("content_json"))
        return value

    @_durable_mutation
    def create_document(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        document_id = str(body.get("document_id") or "")
        kind = str(body.get("kind") or "")
        if not document_id or not kind or "content" not in body:
            raise ValidationError("document_id, kind, and content are required")
        content = body["content"]
        request_hash = hashlib.sha256(canonical_json({"project_id": project["id"], "document_id": document_id, "kind": kind, "content": content}).encode()).hexdigest()
        replay = self._command_replay("document.create", document_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        existing = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if existing:
            if existing["kind"] == kind and json.loads(existing["content_json"]) == content:
                return self._document_resource(existing)
            raise ConflictError("document already exists", details={"document_id": document_id})
        timestamp = now()
        self.store.conn.execute("INSERT INTO project_documents VALUES (?, ?, ?, ?, 1, ?, ?)", (document_id, project["id"], kind, canonical_json(content), timestamp, timestamp))
        result = self._document_resource(self.store.conn.execute("SELECT * FROM project_documents WHERE id=?", (document_id,)).fetchone())
        return self._command_record("document.create", document_id, idempotency_key, request_hash, result, project_id=project["id"])

    def list_documents(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"documents:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._document_resource)

    def get_document(self, project_id, document_id):
        project = self.store.get_project(project_id)
        row = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if not row:
            raise NotFoundError("document not found")
        return self._document_resource(row)

    @_durable_mutation
    def update_document(self, project_id, document_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        project = self.store.get_project(project_id)
        request_hash = hashlib.sha256(canonical_json({"project_id": project["id"], "document_id": document_id, "body": body}).encode()).hexdigest()
        replay = self._command_replay("document.update", document_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        row = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if not row:
            raise NotFoundError("document not found")
        if int(row["version"]) != expected:
            raise ConflictError("document version conflict", details={"expected": expected, "actual": int(row["version"])})
        kind = str(body.get("kind", row["kind"]))
        content = body.get("content", json.loads(row["content_json"]))
        if not kind:
            raise ValidationError("document kind is required")
        timestamp = now()
        self.store.conn.execute("UPDATE project_documents SET kind=?, content_json=?, version=?, updated_at=? WHERE id=?", (kind, canonical_json(content), expected + 1, timestamp, document_id))
        result = self._document_resource(self.store.conn.execute("SELECT * FROM project_documents WHERE id=?", (document_id,)).fetchone())
        return self._command_record("document.update", document_id, idempotency_key, request_hash, result, project_id=project["id"])

    def _generation_resource(self, row):
        value = dict(row)
        value["generation_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        return value

    @_durable_mutation
    def create_generation(self, project_id, body, *, idempotency_key=None):
        raise ConflictError(
            "direct generation publication is disabled; use an admitted GEN D1 settlement effect"
        )
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        generation_id = str(body.get("generation_id") or "")
        if not generation_id:
            raise ValidationError("generation_id is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("generation metadata must be an object")
        generation_type = str(body.get("type", "generation"))
        status = str(body.get("status", "created"))
        source_task_id = body.get("source_task_id")
        request_hash = hashlib.sha256(canonical_json({"project_id": project["id"], "generation_id": generation_id, "source_task_id": source_task_id, "type": generation_type, "status": status, "metadata": metadata}).encode()).hexdigest()
        replay = self._command_replay("generation.create", generation_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        try:
            self.store.conn.execute("INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)", (generation_id, project["id"], source_task_id, generation_type, status, canonical_json(metadata), now(), now()))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("generation already exists", details={"generation_id": generation_id}) from exc
        result = self._generation_resource(self.store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone())
        return self._command_record("generation.create", generation_id, idempotency_key, request_hash, result, project_id=project["id"])

    def list_generations(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT * FROM generations WHERE project_id=? ORDER BY created_at DESC, id ASC", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"generations:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._generation_resource,
                          skip_after=lambda key, after: (
                              key[0] > after[0]
                              or (key[0] == after[0] and key[1] <= after[1])
                          ))

    def get_generation(self, generation_id):
        row = self.store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
        if not row:
            raise NotFoundError("generation not found")
        return self._generation_resource(row)

    @_durable_mutation
    def create_variant(self, generation_id, body, *, idempotency_key=None):
        raise ConflictError(
            "direct variant publication is disabled; use an admitted GEN D1 settlement effect"
        )
        self._require_object_body(body)
        generation = self.get_generation(generation_id)
        variant_id = str(body.get("variant_id") or "")
        if not variant_id:
            raise ValidationError("variant_id is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("variant metadata must be an object")
        object_id = body.get("object_id")
        if object_id:
            object_id = str(object_id).removeprefix("sha256:")
            if not self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (object_id,)).fetchone():
                raise NotFoundError("object not found")
        variant_type = str(body.get("variant_type", "original"))
        request_hash = hashlib.sha256(canonical_json({"generation_id": generation_id, "variant_id": variant_id, "object_id": object_id, "variant_type": variant_type, "metadata": metadata}).encode()).hexdigest()
        replay = self._command_replay("variant.create", variant_id, idempotency_key, request_hash, project_id=generation["project_id"])
        if replay is not None:
            return replay
        try:
            self.store.conn.execute("INSERT INTO generation_variants VALUES (?, ?, ?, ?, ?, ?)", (variant_id, generation_id, object_id, variant_type, canonical_json(metadata), now()))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("generation variant already exists", details={"variant_id": variant_id}) from exc
        result = self._variant_resource(self.store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone())
        return self._command_record("variant.create", variant_id, idempotency_key, request_hash, result, project_id=generation["project_id"])

    @staticmethod
    def _variant_resource(row):
        value = dict(row)
        value["variant_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        if value.get("object_id"):
            value["object_id"] = "sha256:" + value["object_id"]
        return value

    def list_variants(self, generation_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        self.get_generation(generation_id)
        rows = self.store.conn.execute("SELECT * FROM generation_variants WHERE generation_id=? ORDER BY created_at, id", (generation_id,)).fetchall()
        return _page_rows(rows, scope=f"variants:{generation_id}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._variant_resource)

    def get_variant(self, variant_id):
        row = self.store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone()
        if not row:
            raise NotFoundError("generation variant not found")
        return self._variant_resource(row)

    def get_reference(self, reference_id):
        row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
        if not row: raise NotFoundError("reference not found")
        return self._reference_resource(row)

    @_verified_mutation
    def _update_shot_state(self, shot_id, body, *, archived=None, idempotency_key=None):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
            if not row: raise NotFoundError("shot not found")
            action = "update" if archived is None else "archive" if archived else "recover"
            request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
            replay = self._command_replay(f"shot.{action}", shot_id, idempotency_key, request_hash)
            if replay is not None:
                return replay
            state = self.store.conn.execute("SELECT version, archived_at FROM timeline_shot_state WHERE id=?", (shot_id,)).fetchone()
            actual = int(state["version"] if state else 1)
            if expected != actual: raise ConflictError("shot version conflict", details={"expected": expected, "actual": actual})
            if archived is None:
                if state and state["archived_at"]: raise ConflictError("archived shot must be recovered before update")
                start = body.get("start_ms", row["start_ms"]); duration = body.get("duration_ms", row["duration_ms"]); refs = body.get("reference_ids", json.loads(row["reference_ids_json"]))
                if int(start) < 0 or int(duration) < 1 or not isinstance(refs, list): raise ValidationError("invalid shot timing or reference_ids")
            else:
                start, duration, refs = row["start_ms"], row["duration_ms"], json.loads(row["reference_ids_json"])
            with self.store._transaction():
                self.store.conn.execute("UPDATE timeline_shots SET start_ms=?, duration_ms=?, reference_ids_json=? WHERE id=?", (int(start), int(duration), canonical_json(refs), shot_id))
                self.store.conn.execute("INSERT OR REPLACE INTO timeline_shot_state(id, version, archived_at) VALUES (?, ?, ?)", (shot_id, actual + 1, now() if archived is True else None if archived is False else (state["archived_at"] if state else None)))
                result = self.get_shot(shot_id)
                self._command_record(f"shot.{action}", shot_id, idempotency_key, request_hash, result)
            return result

    def update_shot(self, shot_id, body, *, idempotency_key=None): return self._update_shot_state(shot_id, body, idempotency_key=idempotency_key)
    def archive_shot(self, shot_id, body, *, idempotency_key=None): return self._update_shot_state(shot_id, body, archived=True, idempotency_key=idempotency_key)
    def recover_shot(self, shot_id, body, *, idempotency_key=None): return self._update_shot_state(shot_id, body, archived=False, idempotency_key=idempotency_key)

    @_verified_mutation
    def _update_reference_state(self, reference_id, body, *, archived=None, idempotency_key=None):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
            if not row: raise NotFoundError("reference not found")
            action = "update" if archived is None else "archive" if archived else "recover"
            request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
            replay = self._command_replay(f"reference.{action}", reference_id, idempotency_key, request_hash)
            if replay is not None:
                return replay
            state = self.store.conn.execute("SELECT version, archived_at FROM timeline_reference_state WHERE id=?", (reference_id,)).fetchone()
            actual = int(state["version"] if state else 1)
            if expected != actual: raise ConflictError("reference version conflict", details={"expected": expected, "actual": actual})
            if archived is None:
                if state and state["archived_at"]: raise ConflictError("archived reference must be recovered before update")
                object_id = body.get("object_id", row["object_id"]); role = body.get("role", row["role"])
                if not object_id: raise ValidationError("reference object_id is required")
            else: object_id, role = row["object_id"], row["role"]
            with self.store._transaction():
                self.store.conn.execute("UPDATE timeline_references SET object_id=?, role=? WHERE id=?", (object_id, role, reference_id))
                self.store.conn.execute("INSERT OR REPLACE INTO timeline_reference_state(id, version, archived_at) VALUES (?, ?, ?)", (reference_id, actual + 1, now() if archived is True else None if archived is False else (state["archived_at"] if state else None)))
                result = self.get_reference(reference_id)
                self._command_record(f"reference.{action}", reference_id, idempotency_key, request_hash, result)
            return result

    def update_reference(self, reference_id, body, *, idempotency_key=None): return self._update_reference_state(reference_id, body, idempotency_key=idempotency_key)
    def archive_reference(self, reference_id, body, *, idempotency_key=None): return self._update_reference_state(reference_id, body, archived=True, idempotency_key=idempotency_key)
    def recover_reference(self, reference_id, body, *, idempotency_key=None): return self._update_reference_state(reference_id, body, archived=False, idempotency_key=idempotency_key)

    @_durable_mutation
    def ingest(self, project, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise InvalidRequestError("object body must be bytes")
        if len(data) > OBJECT_MAX_BYTES:
            raise ValidationError("object exceeds 64 MiB limit")
        data = bytes(data)
        project_row = self.store.get_project(project)
        expected = (expected_digest or "").removeprefix("sha256:") or None
        request_hash = hashlib.sha256(canonical_json({
            "project_id": project_row["id"],
            "content_digest": sha256_bytes(data),
            "media_type": media_type,
            "original_name": original_name,
            "expected_digest": expected,
        }).encode()).hexdigest()
        aggregate_id = project_row["id"]
        replay = self._command_replay("object.ingest", aggregate_id, idempotency_key, request_hash, project_id=project_row["id"])
        if replay is not None:
            return replay
        destination = self.cas.path_for(sha256_bytes(data))
        if not destination.exists():
            self._begin_cas_publication_journal("ingest", [{"digest": sha256_bytes(data)}], project_id=project_row["id"])
        obj = self.cas.put(data, expected_digest=expected)
        try:
            timestamp = now()
            self.store.conn.execute(
                "INSERT OR IGNORE INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (obj["digest"], obj["size"], media_type, original_name, timestamp),
            )
            self.store.conn.execute(
                "INSERT OR IGNORE INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, 'managed', ?)",
                (project_row["id"], obj["digest"], timestamp),
            )
            row = dict(self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (obj["digest"],)).fetchone())
            # The durable result is the closed managed-object resource.  The
            # project association and CAS deduplication state remain durable
            # transaction facts, not extra fields in the public object wire.
            result = self._object_resource(row) | {"relation": "managed"}
            return self._command_record("object.ingest", aggregate_id, idempotency_key, request_hash, result, project_id=project_row["id"])
        except Exception:
            # The CAS write precedes the SQLite transaction.  If the durable
            # metadata/receipt transaction fails, remove only the file this
            # command introduced so a retry cannot observe a phantom object.
            if not obj["deduplicated"]:
                self._discard_published_digest(obj["digest"])
            raise

    @staticmethod
    def _generic_output_idempotency_key(binding):
        return "output-" + hashlib.sha256(canonical_json(binding).encode()).hexdigest()

    def _validate_generic_output_binding(self, binding, *, identity, digest, size, media_type, original_name, idempotency_key):
        """Validate the explicit attempt identity carried by an output upload."""
        if not isinstance(binding, dict):
            raise ValidationError("output upload binding must be an object")
        required = {
            "project_id", "run_id", "task_id", "attempt_id", "executor_id",
            "lease_id", "fence", "runtime_epoch", "output_key", "output_port",
            "filename", "digest", "size", "media_type",
        }
        if set(binding) != required:
            raise ValidationError("output upload binding has unsupported or missing fields")
        if binding["project_id"] is not None and (not isinstance(binding["project_id"], str) or not binding["project_id"]):
            raise ValidationError("output upload binding project_id is invalid")
        for field in ("run_id", "task_id", "attempt_id", "executor_id", "lease_id", "output_key", "output_port", "filename", "media_type"):
            if not isinstance(binding[field], str) or not binding[field]:
                raise ValidationError(f"output upload binding {field} is invalid")
        for field in ("fence", "runtime_epoch", "size"):
            if isinstance(binding[field], bool) or not isinstance(binding[field], int) or binding[field] < 0:
                raise ValidationError(f"output upload binding {field} is invalid")
        if binding["runtime_epoch"] < 1 or binding["size"] > OBJECT_MAX_BYTES:
            raise ValidationError("output upload binding numeric fields are invalid")
        if binding["digest"] != "sha256:" + digest or binding["size"] != int(size) or binding["media_type"] != media_type:
            raise ConflictError("output upload binding does not match object bytes")
        if binding["filename"] != original_name:
            raise ConflictError("output upload binding does not match object filename")
        if idempotency_key != self._generic_output_idempotency_key(binding):
            raise ConflictError("output upload idempotency key is not bound to its provenance")
        if identity is not None and identity.get("actor") != binding["executor_id"]:
            raise AuthorizationError("output upload worker is not bound to the upload executor")
        row = self.store.conn.execute(
            "SELECT a.id AS attempt_id, a.task_id, a.executor_id, a.lease_id, a.fence, a.runtime_epoch, a.settled, "
            "t.run_id, t.status, t.attempt_id AS current_attempt_id, t.executor_id AS task_executor_id, "
            "t.lease_token, t.lease_fence, t.runtime_epoch AS task_runtime_epoch, r.project_id "
            "FROM attempts AS a JOIN tasks AS t ON t.id=a.task_id JOIN runs AS r ON r.id=t.run_id "
            "WHERE a.id=?",
            (binding["attempt_id"],),
        ).fetchone()
        if not row or row["settled"] != 0 or row["status"] != "running" or row["current_attempt_id"] != row["attempt_id"]:
            raise LeaseError("output upload attempt is stale")
        if (
            row["task_id"] != binding["task_id"]
            or row["run_id"] != binding["run_id"]
            or row["project_id"] != binding["project_id"]
            or row["executor_id"] != binding["executor_id"]
            or row["task_executor_id"] != binding["executor_id"]
            or row["lease_id"] != binding["lease_id"]
            or int(row["fence"]) != int(binding["fence"])
            or int(row["lease_fence"]) != int(binding["fence"])
            or int(row["runtime_epoch"]) != int(binding["runtime_epoch"])
            or int(row["task_runtime_epoch"]) != int(binding["runtime_epoch"])
            or int(row["runtime_epoch"]) != int(self.store._current_runtime_epoch())
        ):
            raise LeaseError("output upload provenance does not match the live attempt")

    @staticmethod
    def _generic_output_request_hash(digest, media_type, original_name, expected_digest, binding):
        request = {
            "content_digest": digest,
            "media_type": media_type,
            "original_name": original_name,
            "expected_digest": expected_digest,
        }
        if binding is not None:
            request["publication_binding"] = binding
        return hashlib.sha256(canonical_json(request).encode()).hexdigest()

    @_durable_mutation
    def ingest_object(self, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None, idempotency_key=None, identity=None, upload_binding=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise InvalidRequestError("object body must be bytes")
        if len(data) > OBJECT_MAX_BYTES:
            raise ValidationError("object exceeds 64 MiB limit")
        data = bytes(data)
        expected = (expected_digest or "").removeprefix("sha256:") or None
        digest = sha256_bytes(data)
        binding = dict(upload_binding) if upload_binding is not None else None
        request_hash = self._generic_output_request_hash(
            digest, media_type, original_name, expected, binding,
        )
        aggregate_id = "objects"
        replay = self._command_replay("object.ingest", aggregate_id, idempotency_key, request_hash, project_id="unscoped")
        if replay is not None:
            return replay
        if binding is not None:
            self._validate_generic_output_binding(
                binding,
                identity=identity,
                digest=digest,
                size=len(data),
                media_type=media_type,
                original_name=original_name,
                idempotency_key=idempotency_key,
            )
        destination = self.cas.path_for(digest)
        if not destination.exists():
            self._begin_cas_publication_journal("ingest", [{"digest": digest}], project_id="unscoped")
        obj = self.cas.put(data, expected_digest=expected)
        try:
            timestamp = now()
            self.store.conn.execute(
                "INSERT OR IGNORE INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (obj["digest"], obj["size"], media_type, original_name, timestamp),
            )
            result = self._object_resource(dict(self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (obj["digest"],)).fetchone()))
            return self._command_record("object.ingest", aggregate_id, idempotency_key, request_hash, result, project_id="unscoped")
        except Exception:
            if not obj["deduplicated"]:
                self._discard_published_digest(obj["digest"])
            raise

    def _discard_published_digest(self, digest):
        """Remove a newly published CAS file after a failed metadata commit."""
        try:
            self._unlink_cas_destination(digest)
        except (FileNotFoundError, OSError, ConflictError):
            # A failed cleanup is reconciled from the publication journal.
            pass

    def _object_resource(self, row):
        return {"object_id": "sha256:" + row["digest"], "digest": "sha256:" + row["digest"], "media_type": row["media_type"], "size": int(row["size"]), "version": 1, "created_at": row["created_at"], **({"filename": row["original_name"]} if row.get("original_name") else {})}

    def object(self, digest):
        digest = digest.removeprefix("sha256:")
        row = self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()
        if not row:
            from .errors import NotFoundError
            raise NotFoundError("object not found")
        return dict(row), self.cas.read(digest)

    def objects(self, project):
        return self.store.list_project_objects(project)

    def list_project_objects(self, project, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        rows = self.store.list_project_objects(project)
        return _page_rows(rows, scope=f"objects:{self.store.get_project(project)['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["digest"])),
                          resource_fn=lambda row: self._object_resource(row) | {"relation": row["relation"]})

    @_durable_mutation
    def create_media_relation(self, project, body, *, idempotency_key=None):
        self._require_object_body(body)
        project_id = self.store.get_project(project)["id"]
        allowed = {"derived_from", "variant_of", "uses_as_input", "mask_for", "audio_for"}
        kind = str(body.get("kind") or "")
        if kind not in allowed: raise ValidationError("unsupported media relation kind")
        source = str(body.get("from_object_id") or "").removeprefix("sha256:")
        target = str(body.get("to_object_id") or "").removeprefix("sha256:")
        if not source or not target or source == target: raise ValidationError("media relation requires distinct from_object_id and to_object_id")
        for digest in (source, target):
            if not self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone(): raise NotFoundError("object not found")
            if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone(): raise NotFoundError("object is not in project")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict): raise ValidationError("media relation metadata must be an object")
        try:
            ordinal = int(body.get("ordinal", 0))
        except (TypeError, ValueError) as exc:
            raise ValidationError("media relation ordinal must be an integer") from exc
        if ordinal < 0: raise ValidationError("media relation ordinal must be non-negative")
        request_hash = hashlib.sha256(canonical_json({"project_id": project_id, "from_object_id": source, "to_object_id": target, "kind": kind, "ordinal": ordinal, "metadata": metadata}).encode()).hexdigest()
        aggregate_id = "media-relations"
        replay = self._command_replay("media_relation.create", aggregate_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        try:
            self.store.conn.execute("INSERT INTO media_relations VALUES (?, ?, ?, ?, ?, ?, ?)", (project_id, source, target, kind, ordinal, canonical_json(metadata), now()))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("media relation already exists") from exc
        created_at = self.store.conn.execute("SELECT created_at FROM media_relations WHERE project_id=? AND from_digest=? AND to_digest=? AND kind=? AND ordinal=?", (project_id, source, target, kind, ordinal)).fetchone()[0]
        result = {"project_id": project_id, "from_object_id": "sha256:" + source, "to_object_id": "sha256:" + target, "kind": kind, "ordinal": ordinal, "metadata": metadata, "created_at": created_at}
        return self._command_record("media_relation.create", aggregate_id, idempotency_key, request_hash, result, project_id=project_id)

    def list_media_relations(self, project, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project_id = self.store.get_project(project)["id"]
        rows = self.store.conn.execute("SELECT * FROM media_relations WHERE project_id=? ORDER BY created_at, from_digest, to_digest, kind, ordinal", (project_id,)).fetchall()
        return _page_rows(rows, scope=f"media-relations:{project_id}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["from_digest"]), str(row["to_digest"]), str(row["kind"]), int(row["ordinal"])),
                          resource_fn=lambda row: {"project_id": row["project_id"], "from_object_id": "sha256:" + row["from_digest"], "to_object_id": "sha256:" + row["to_digest"], "kind": row["kind"], "ordinal": int(row["ordinal"]), "metadata": json.loads(row["metadata_json"]), "created_at": row["created_at"]})

    @_verified_mutation
    def create_task(self, body, *, enforce_readiness=False):
        if "capability" in body or "expected_effect" in body:
            raise ValidationError("legacy task body aliases are not supported")
        capability = body.get("capability_id")
        digest = body.get("capability_digest", "sha256:" + hashlib.sha256(str(capability).encode()).hexdigest())
        task_spec = {"input_object_ids": body.get("input_object_ids", []), "schema_version": body.get("schema_version", "1"), "capability_digest": digest, "spec": body.get("spec", {})}
        if "generation_intent" in body:
            if not isinstance(body["generation_intent"], dict):
                raise ValidationError("generation_intent must be an object")
            # Runtime owns transport and durability only. GEN owns the
            # meaning of this opaque producer intent and its member fields.
            task_spec[GENERATION_INTENT_STORAGE_KEY] = body["generation_intent"]
        if "required_facts" in body:
            task_spec["required_facts"] = normalize_execution_facts(body["required_facts"], field="required_facts")
        if "storage_estimate" in body:
            task_spec["storage_estimate"] = self.store._validate_storage_estimate(body["storage_estimate"])
        value = self.store.create_task(capability, task_spec, body.get("project"), body.get("idempotency_key"), body.get("settlement_effect"), digest, enforce_readiness=enforce_readiness)
        return value

    def task(self, task_id):
        return self.store.get_task(task_id)

    def managed_outputs(self, task_id):
        """Read Runtime-owned immutable output associations and lifecycle state."""
        return self.store.list_managed_outputs(task_id)

    def managed_output_page(self, task_id):
        """Return the public task-scoped managed-output collection."""
        self.store.get_task(str(task_id))
        return {"items": self.store.list_managed_outputs(task_id), "next_cursor": None}

    def managed_output(self, association_id):
        """Read one named managed association without exposing CAS or SQLite."""
        return self.store.get_managed_output(association_id)

    def _export_source(self, association_id):
        """Resolve one retained output and validate its historical fence facts."""
        association = self.store.get_managed_output(association_id)
        if association.get("durability") != "durable":
            raise ConflictError("only durable managed outputs may be exported")
        attempt = self.store.conn.execute(
            "SELECT id, task_id, lease_id, fence, executor_id, runtime_epoch, settled FROM attempts WHERE id=?",
            (str(association["attempt_id"]),),
        ).fetchone()
        if not attempt or str(attempt["task_id"]) != str(association["task_id"]):
            raise ConflictError("managed output attempt provenance is unavailable")
        if not int(attempt["settled"]):
            raise ConflictError("managed output attempt is not completed")
        run = self.store.conn.execute(
            "SELECT id, project_id FROM runs WHERE id=?",
            (str(association["run_id"]),),
        ).fetchone()
        if not run or run["project_id"] != association.get("project_id"):
            raise ConflictError("managed output run/project provenance is inconsistent")
        provenance = association.get("provenance") or {}
        if not isinstance(provenance, dict):
            raise ConflictError("managed output provenance is malformed")
        for field, expected in (
            ("task_id", association["task_id"]),
            ("attempt_id", association["attempt_id"]),
            ("executor_id", attempt["executor_id"]),
            ("fence", int(attempt["fence"])),
            ("runtime_epoch", int(attempt["runtime_epoch"])),
        ):
            if field in provenance and provenance[field] != expected:
                raise ConflictError("managed output historical provenance is inconsistent", details={"field": field})
        if not attempt["lease_id"] or not attempt["executor_id"] or int(attempt["fence"]) < 1 or int(attempt["runtime_epoch"]) < 1:
            raise ConflictError("managed output attempt fence provenance is incomplete")
        digest = str(association["digest"])
        if not digest.startswith("sha256:"):
            raise ConflictError("managed output digest is not canonical")
        raw_digest = digest.removeprefix("sha256:")
        object_row = self.store.conn.execute(
            "SELECT size, media_type, original_name FROM objects WHERE digest=?",
            (raw_digest,),
        ).fetchone()
        if not object_row:
            raise ConflictError("managed output CAS object is unavailable")
        data = self.cas.read(raw_digest)
        if len(data) != int(association["size"]) or len(data) != int(object_row["size"]):
            raise ConflictError("managed output CAS size does not match its association")
        if str(object_row["media_type"]) != str(association["media_type"]):
            raise ConflictError("managed output media type does not match its CAS object")
        try:
            export_filename = _canonical_managed_output_filename(str(association["filename"]))
        except ValidationError as exc:
            raise ConflictError("managed output filename is not a direct safe file name") from exc
        return association, attempt, data, export_filename

    def _materialize_export(self, filename, data):
        if self.export_root is None:
            raise ConflictError("managed-output export root is not configured")
        identity, root_fd, _ = _pin_directory(self.export_root)
        temporary = f".{filename}.{os.getpid()}-{uuid.uuid4().hex}.tmp"
        fd = -1
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=root_fd)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            try:
                os.link(temporary, filename, src_dir_fd=root_fd, dst_dir_fd=root_fd, follow_symlinks=False)
            except FileExistsError as exc:
                raise ConflictError("managed-output export destination already exists") from exc
            os.unlink(temporary, dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            _close_pinned(identity)

    @_durable_mutation
    def export_managed_output(self, association_id, body, *, idempotency_key=None):
        """Materialize exact CAS bytes for one completed retained output."""
        idempotency_key = require_idempotency_key(idempotency_key)
        body = _wire_object(body, required=("destination_filename",), allowed=("destination_filename", "expected"))
        destination_filename = _wire_string(body, "destination_filename")
        expected = body.get("expected") or {}
        if not isinstance(expected, dict):
            raise ValidationError("expected export identity must be an object")
        allowed_expected = {
            "project_id", "run_id", "task_id", "attempt_id", "executor_id", "lease_id", "fence",
            "runtime_epoch", "association_id", "output_port", "role", "object_id", "digest", "size",
            "filename", "media_type",
        }
        unknown = sorted(set(expected) - allowed_expected)
        if unknown:
            raise ValidationError("expected export identity contains unsupported fields", details={"fields": unknown})
        association, attempt, data, export_filename = self._export_source(association_id)
        if destination_filename not in {association["filename"], export_filename}:
            raise ConflictError("export destination filename must equal managed output filename")
        source = {
            "project_id": association.get("project_id"),
            "run_id": association["run_id"], "task_id": association["task_id"],
            "attempt_id": association["attempt_id"], "executor_id": attempt["executor_id"],
            "lease_id": attempt["lease_id"], "fence": int(attempt["fence"]),
            "runtime_epoch": int(attempt["runtime_epoch"]), "association_id": association["association_id"],
            "output_port": association["output_port"], "role": association["role"],
            "object_id": association["object_id"], "digest": association["digest"],
            "size": int(association["size"]), "filename": association["filename"],
            "media_type": association["media_type"],
        }
        for field, value in expected.items():
            if field == "filename" and value == export_filename:
                continue
            if value != source[field]:
                raise ConflictError("export identity assertion does not match", details={"field": field})
        request_hash = hashlib.sha256(canonical_json({"association_id": str(association_id), "body": body}).encode()).hexdigest()
        project_id = association.get("project_id") or "unscoped"
        replay = self._command_replay("managed_output.export", str(association_id), idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        result = {
            "export_id": "export-" + new_id(),
            **source,
            "producer": association.get("producer") or {},
            "destination": {"root": str(self.export_root), "filename": export_filename},
            "source_provenance": association.get("provenance") or {},
            "exported_at": now(),
        }
        self._materialize_export(export_filename, data)
        event_id = self.store._append_event(
            association["run_id"], association["task_id"], "managed_output.exported", result,
        )
        event_seq = self.store.conn.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (association["run_id"],)).fetchone()[0]
        return self._command_record(
            "managed_output.export", str(association_id), idempotency_key, request_hash,
            result, project_id=project_id, event_ids=(event_id,), primary_stream_id=association["run_id"],
            resulting_stream_seq=event_seq,
        )

    @_durable_mutation
    def adopt_managed_output(self, association_id, body=None, *, idempotency_key=None):
        """Acknowledge/adopt an existing immutable association by managed name.

        Adoption never creates a second association or resolves a filesystem
        path. Optional identity fields are equality assertions against the
        Runtime-owned association, making a changed payload a conflict while
        preserving the durable receipt for an exact retry.
        """
        idempotency_key = require_idempotency_key(idempotency_key)
        body = {} if body is None else _wire_object(body, allowed=(
            "association_id", "manifest_ref", "object_id", "digest", "size",
            "filename", "media_type", "output_port", "selector", "ordinal",
            "role", "durability",
        ))
        association = self.store.get_managed_output(association_id)
        if body.get("association_id") is not None and str(body["association_id"]) != str(association_id):
            raise ConflictError("association_id does not match the managed-output path")
        for field in (
            "manifest_ref", "object_id", "digest", "size", "filename", "media_type",
            "output_port", "selector", "ordinal", "role", "durability",
        ):
            if field in body and body[field] != association.get(field):
                raise ConflictError("managed-output adoption identity does not match", details={"field": field})
        request_hash = hashlib.sha256(canonical_json({"association_id": str(association_id), "body": body}).encode()).hexdigest()
        project_id = association.get("project_id") or "unscoped"
        replay = self._command_replay("managed_output.adopt", str(association_id), idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        return self._command_record(
            "managed_output.adopt", str(association_id), idempotency_key, request_hash,
            association, project_id=project_id,
        )

    @_durable_mutation
    def update_managed_output_lifecycle(self, association_id, body, *, idempotency_key=None):
        """Mutate only Runtime lifecycle state for one immutable association."""
        idempotency_key = require_idempotency_key(idempotency_key)
        body = _wire_object(
            body,
            required=("operation", "expected_version"),
            allowed=("operation", "expected_version", "lease_id", "lease_owner", "lease_seconds", "provenance"),
        )
        operation = _wire_string(body, "operation")
        _wire_integer(body, "expected_version", positive=True)
        if "lease_id" in body and (not isinstance(body["lease_id"], str) or not body["lease_id"]):
            raise ValidationError("lease_id must be a non-empty string")
        if "lease_owner" in body and (not isinstance(body["lease_owner"], str) or not body["lease_owner"]):
            raise ValidationError("lease_owner must be a non-empty string")
        if "lease_seconds" in body and (
            isinstance(body["lease_seconds"], bool) or not isinstance(body["lease_seconds"], int)
            or body["lease_seconds"] <= 0
        ):
            raise ValidationError("lease_seconds must be a positive integer")
        if "provenance" in body and not isinstance(body["provenance"], dict):
            raise ValidationError("lifecycle provenance must be an object")
        association = self.store.get_managed_output(association_id)
        project_id = association.get("project_id") or "unscoped"
        request_hash = hashlib.sha256(canonical_json({"association_id": str(association_id), "body": body}).encode()).hexdigest()
        replay = self._command_replay("managed_output.lifecycle", str(association_id), idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        result = self.store.update_managed_output_lifecycle(
            association_id, operation, expected_version=body["expected_version"],
            lease_id=body.get("lease_id"), lease_owner=body.get("lease_owner"),
            lease_seconds=body.get("lease_seconds"),
        )
        if "provenance" in body:
            result["lifecycle_provenance"] = dict(body["provenance"])
        return self._command_record(
            "managed_output.lifecycle", str(association_id), idempotency_key, request_hash,
            result, project_id=project_id,
        )

    def run(self, run_id):
        row = self.store.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise NotFoundError("run not found")
        value = dict(row)
        value["spec"], generation_intent = public_task_spec(json.loads(value.pop("spec_json")))
        if generation_intent is not None:
            value["generation_intent"] = generation_intent
        value["task_ids"] = [task["id"] for task in self.store.conn.execute("SELECT id FROM tasks WHERE run_id=? ORDER BY created_at, id", (run_id,))]
        return value

    def _task_resource(self, value):
        task, run = value["task"], value["run"]
        spec, generation_intent = public_task_spec(task.get("spec", {}))
        if task.get("generation_intent") is not None:
            generation_intent = task["generation_intent"]
        resource = {"task_id": task["id"], "run_id": run["id"], "project_id": run.get("project_id"), "state": "succeeded" if task["status"] == "completed" else ("cancelled" if task["status"] == "cancelled" else task["status"]), "version": int(task.get("attempt", 0)) + 1, "capability_id": task["capability"], "capability_digest": task.get("capability_digest") or spec.get("capability_digest", "sha256:" + hashlib.sha256(task["capability"].encode()).hexdigest()), "schema_version": spec.get("schema_version", "1"), "input_object_ids": spec.get("input_object_ids", []), "spec": spec, "idempotency_key": run.get("idempotency_key") or task["id"], "created_at": task["created_at"], "updated_at": task["updated_at"], "attempt_id": task.get("attempt_id"), "runtime_epoch": int(task.get("runtime_epoch") or self.store._current_runtime_epoch())}
        if generation_intent is not None:
            resource["generation_intent"] = generation_intent
        if "required_facts" in spec:
            resource["required_facts"] = dict(spec["required_facts"])
        if "storage_estimate" in spec:
            resource["storage_estimate"] = dict(spec["storage_estimate"])
        if task.get("waiting_reason"):
            resource["waiting_reason"] = task["waiting_reason"]
        if task.get("lease_fence"):
            resource["lease_fence"] = task["lease_fence"]
        if task.get("lease_expires_at"):
            resource["lease_expires_at"] = task["lease_expires_at"]
        if task.get("result") is not None:
            resource["result"] = task["result"]
        return resource

    @_verified_mutation
    def cancel(self, task_id):
        return self.store.cancel_task(task_id)

    @_verified_mutation
    def cancel_task_canonical(self, task_id, body=None, *, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        body = {} if body is None else body
        self._require_object_body(body)
        with self.store._mutex:
            current = self.store.get_task(task_id)
            project_id = current["run"].get("project_id") or "unscoped"
            request_hash = hashlib.sha256(canonical_json({"task_id": task_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("task.cancel", task_id, idempotency_key, request_hash, project_id=project_id)
            if replay is not None:
                return replay
            expected = body.get("expected_version")
            if expected is not None and int(expected) != int(current["task"].get("attempt", 0)) + 1:
                raise ConflictError("stale task version", details={"expected": expected, "actual": int(current["task"].get("attempt", 0)) + 1})
            with self.store._transaction():
                recorded = None
                def record(value, *, event_ids=(), primary_stream_id=None, resulting_stream_seq=None):
                    nonlocal recorded
                    recorded = self._command_record("task.cancel", task_id, idempotency_key, request_hash, self._task_resource(value), project_id=project_id, event_ids=event_ids, primary_stream_id=primary_stream_id, resulting_stream_seq=resulting_stream_seq)
                self.store.cancel_task(task_id, record=record)
                return recorded

    @_verified_mutation
    def retry_task(self, task_id, body=None, *, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        body = {} if body is None else body
        self._require_object_body(body)
        with self.store._mutex:
            current = self.store.get_task(task_id)
            project_id = current["run"].get("project_id") or "unscoped"
            request_hash = hashlib.sha256(canonical_json({"task_id": task_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("task.retry", task_id, idempotency_key, request_hash, project_id=project_id)
            if replay is not None:
                return replay
            status = current["task"]["status"]
            if status not in {"completed", "cancelled", "failed"}:
                raise ConflictError("task is not retryable", details={"status": status})
            expected = (body or {}).get("expected_version")
            version = int(current["task"].get("attempt", 0)) + 1
            if expected is not None and int(expected) != version:
                raise ConflictError("stale task version", details={"expected": expected, "actual": version})
            with self.store._transaction():
                timestamp = now()
                self.store._release_reservations(task_id, current["task"].get("lease_token"))
                self.store.conn.execute("UPDATE tasks SET status='queued', lease_token=NULL, executor_id=NULL, lease_expires_at=NULL, waiting_reason=NULL, result_json=NULL, attempt_id=NULL, updated_at=? WHERE id=?", (timestamp, task_id))
                self.store.conn.execute("UPDATE runs SET status='queued', updated_at=? WHERE id=?", (timestamp, current["run"]["id"]))
                event_id = self.store._append_event(current["run"]["id"], task_id, "task.retried", {"from_status": status, "attempt": version})
                self.store._refresh_continuations_for_predecessor(task_id)
                result = self._task_resource(self.store.get_task(task_id))
                event_seq = self.store.conn.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (current["run"]["id"],)).fetchone()[0]
                return self._command_record("task.retry", task_id, idempotency_key, request_hash, result, project_id=project_id, event_ids=(event_id,), primary_stream_id=current["run"]["id"], resulting_stream_seq=event_seq)

    def events(self, run_id):
        return self.store.list_events(run_id)

    @_verified_mutation
    def cancel_run(self, run_id, body=None, *, idempotency_key=None):
        return self._run_resource(self.store.cancel_run(run_id, idempotency_key=idempotency_key))

    @_verified_mutation
    def retry_run(self, run_id, body=None, *, idempotency_key=None):
        body = body or {}
        return self._run_resource(self.store.retry_run(run_id, selected_task_ids=body.get("selected_task_ids"), idempotency_key=idempotency_key))

    def _run_resource(self, value):
        result = dict(value)
        result["spec"], generation_intent = public_task_spec(json.loads(result.pop("spec_json")))
        if generation_intent is not None:
            result["generation_intent"] = generation_intent
        result["task_ids"] = [task["id"] for task in self.store.conn.execute("SELECT id FROM tasks WHERE run_id=? ORDER BY created_at, id", (result["id"],))]
        return result

    def list_capabilities(self, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        # Registration updates capability descriptors and executor visibility
        # in one transaction. Readers share the same fence so the HTTP catalog
        # cannot observe the transaction halfway through.
        with self.store._mutex:
            rows = self.store.conn.execute("SELECT * FROM capabilities ORDER BY id").fetchall()
            return _page_rows(rows, scope="capabilities", cursor=cursor, limit=limit,
                              key_fn=lambda row: (str(row["id"]),),
                              resource_fn=lambda r: self._capability_resource(r))

    def _capability_resource(self, row):
        status = row["status"]
        reason = row["unavailable_reason"]
        if status == "ready" and not self.store.matching_live_executor(row["id"], row["definition_digest"]):
            status, reason = "unavailable", "no_live_matching_executor"
        return {"capability_id": row["id"], "definition_digest": row["definition_digest"], "status": status, "required_resource_keys": json.loads(row["required_resource_keys_json"]), "estimated_scratch_bytes": row["estimated_scratch_bytes"], "estimated_output_bytes": row["estimated_output_bytes"], "unavailable_reason": reason}

    @_verified_mutation
    def register_capability(self, body):
        value = self.store.register_capability(body.get("capability_id", ""), body.get("definition_digest", ""), required_resource_keys=body.get("required_resource_keys", []), status=body.get("status", "ready"), unavailable_reason=body.get("unavailable_reason"), estimated_scratch_bytes=body.get("estimated_scratch_bytes", 0), estimated_output_bytes=body.get("estimated_output_bytes", 0))
        # Registration acknowledges the executor's declared state. Discovery
        # computes liveness-aware availability via ``_capability_resource``.
        return {"capability_id": value["id"], "definition_digest": value["definition_digest"], "status": value["status"], "required_resource_keys": value["required_resource_keys"], "estimated_scratch_bytes": value["estimated_scratch_bytes"], "estimated_output_bytes": value["estimated_output_bytes"], "unavailable_reason": value.get("unavailable_reason")}

    @_durable_mutation
    def register_executor(self, body, *, idempotency_key=None, identity=None):
        body = _wire_object(
            body,
            allowed=(
                "executor_id", "max_concurrency", "resource_keys", "capabilities",
                "protocol", "readiness", "readiness_reason", "runtime_epoch",
                "source_digest", "dependency_digest", "source_epoch", "schema_digest",
                "verified_facts",
            ),
        )
        executor_id = _wire_string(body, "executor_id")
        self._assert_executor_identity(identity, executor_id)
        max_concurrency = body.get("max_concurrency", 1)
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or max_concurrency < 1:
            raise ValidationError("max_concurrency must be positive")
        capabilities = body.get("capabilities", [])
        if not isinstance(capabilities, list):
            raise ValidationError("capabilities must be a list")
        resource_keys = body.get("resource_keys", [])
        if not isinstance(resource_keys, list):
            raise ValidationError("resource_keys must be a list")
        protocol = body.get("protocol", "workspace.v1")
        if not isinstance(protocol, str) or protocol != "workspace.v1":
            raise ValidationError("protocol must be workspace.v1")
        readiness = body.get("readiness", "ready")
        if readiness not in {"ready", "not_ready"}:
            raise ValidationError("readiness must be ready or not_ready")
        if body.get("runtime_epoch") is not None:
            _wire_integer(body, "runtime_epoch", positive=True)
        for field in ("source_digest", "dependency_digest", "source_epoch"):
            if body.get(field) is not None:
                _wire_string(body, field)
        if body.get("schema_digest") is not None:
            if not isinstance(body["schema_digest"], str) or body["schema_digest"] != SCHEMA_DIGEST:
                raise ValidationError("schema_digest does not match the runtime contract")
        verified_facts = normalize_execution_facts(body["verified_facts"], field="verified_facts") if "verified_facts" in body else None
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        # Executor registration is an endpoint-scoped command.  The request
        # hash includes executor identity and all registration fields, so a
        # reused key can only replay the exact durable result.
        aggregate_id = "executors"
        existing = self.store.conn.execute("SELECT runtime_epoch FROM executors WHERE id=?", (body["executor_id"],)).fetchone()
        current_epoch = self.store._current_runtime_epoch()
        if body.get("runtime_epoch") is not None:
            self.store._validate_runtime_epoch(
                body.get("runtime_epoch"), identity="executor",
                identity_id=body.get("executor_id"), required=True,
            )
        prior = None
        if idempotency_key is not None:
            validate_idempotency_key(idempotency_key)
            prior = self.store.conn.execute(
                "SELECT request_hash, result_json FROM command_idempotency "
                "WHERE command_kind='executor.register' AND aggregate_id=? AND idempotency_key=?",
                (aggregate_id, idempotency_key),
            ).fetchone()
        if prior:
            if prior["request_hash"] != request_hash:
                raise ConflictError("idempotency key was already used with different input")
            replay = json.loads(prior["result_json"])
            # A replay is safe only in the same runtime session.  In
            # particular, do not let a pre-restart registration refresh a
            # dead executor lease merely because its key is known.
            if int(replay.get("runtime_epoch") or 0) != current_epoch:
                self.store._validate_runtime_epoch(
                    body.get("runtime_epoch"), identity="executor",
                    identity_id=body.get("executor_id"), required=True,
                )
            return replay
        # Re-registration is the canonical reconnect path after a runtime
        # restart or a deliberate capability/readiness refresh.  The bearer
        # fence above binds the caller to this executor (or an administrator),
        # while an existing identity must present the current runtime epoch.
        epoch = self.store._validate_runtime_epoch(
            body.get("runtime_epoch"), identity="executor",
            identity_id=body.get("executor_id"), required=existing is not None,
        )
        registered = self.store.upsert_executor(body["executor_id"], capabilities, max_concurrency, body.get("resource_keys", []), protocol=body.get("protocol", "workspace.v1"), readiness=body.get("readiness", "ready"), readiness_reason=body.get("readiness_reason"), runtime_epoch=epoch, source_digest=body.get("source_digest"), dependency_digest=body.get("dependency_digest"), source_epoch=body.get("source_epoch"), verified_facts=verified_facts)
        result = {"executor_id": body["executor_id"], "max_concurrency": max_concurrency, "resource_keys": body.get("resource_keys", []), "capabilities": registered["capabilities"], "protocol": body.get("protocol", "workspace.v1"), "readiness": body.get("readiness", "ready"), "runtime_epoch": epoch, "source_digest": body.get("source_digest"), "dependency_digest": body.get("dependency_digest"), "source_epoch": body.get("source_epoch")}
        if verified_facts is not None:
            result["verified_facts"] = verified_facts
        return self._command_record("executor.register", aggregate_id, idempotency_key, request_hash, result, project_id="unscoped", with_receipt=False)

    @_durable_mutation
    def claim_next(self, body, *, idempotency_key=None, identity=None):
        """Atomically select, claim, fence, and record a canonical claim.

        A claim has no task path, so its command aggregate is the endpoint's
        claim namespace.  The request hash binds executor, capabilities, and
        runtime epoch; a replay can never consume a second queued task.
        """
        _require_runtime_epoch_for_lease(body)
        body = _wire_object(
            body,
            required=("executor_id", "capability_ids", "runtime_epoch"),
            allowed=("executor_id", "capability_ids", "runtime_epoch"),
        )
        executor_id = _wire_string(body, "executor_id")
        capability_ids = body.get("capability_ids")
        runtime_epoch = body.get("runtime_epoch")
        self._assert_executor_identity(identity, executor_id)
        if not isinstance(capability_ids, list) or any(not isinstance(value, str) or not value for value in capability_ids) or len(set(capability_ids)) != len(capability_ids):
            raise ValidationError("capability_ids must be a list of unique non-empty strings")
        _wire_integer(body, "runtime_epoch", positive=True)
        request_hash = hashlib.sha256(canonical_json({
            "executor_id": executor_id, "capability_ids": capability_ids,
            "runtime_epoch": runtime_epoch,
        }).encode()).hexdigest()
        # Epoch validation intentionally precedes the idempotency lookup: a
        # stale worker must never turn an old claim receipt into a live lease.
        epoch = self.store._validate_runtime_epoch(runtime_epoch, identity="executor", identity_id=executor_id, required=True)
        replayed, replay = self._command_replay_state(
            "task.claim", "claim", idempotency_key, request_hash, with_receipt=False,
        )
        if replayed:
            return replay
        # Reap before selecting work. Otherwise an expired running task is
        # invisible to the queued-task query and reclaim waits for another
        # claim attempt.
        self.store._reap_expired_leases()
        caps = set(capability_ids)
        rows = self.store.conn.execute("SELECT id, capability FROM tasks WHERE status='queued' ORDER BY created_at, id").fetchall()
        row = next((item for item in rows if not caps or item["capability"] in caps), None)
        if row is None:
            # Persist the empty outcome too.  Otherwise a retry after another
            # task is admitted would silently claim new work.
            return self._command_record("task.claim", "claim", idempotency_key, request_hash, None, project_id="unscoped", with_receipt=False)
        attempt_id, lease_id = new_id(), new_id()
        value = self.store._claim_task(row["id"], executor_id, lease_id, runtime_epoch=epoch, _transactional=False)
        if value["task"]["status"] != "running":
            result = {"task": self._task_resource(value), "waiting_reason": value["task"].get("waiting_reason") or "waiting_for_worker"}
        else:
            task = value["task"]
            fence = int(task.get("lease_fence") or task.get("attempt") or 1)
            expires = task.get("lease_expires_at") or now()
            self.store.conn.execute("INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, ?, ?, ?, 0, ?)", (attempt_id, row["id"], lease_id, fence, executor_id, expires, epoch))
            self.store.conn.execute("UPDATE tasks SET attempt_id=? WHERE id=?", (attempt_id, row["id"]))
            # Return the immutable admitted spec alongside the lease. Workers
            # must execute exactly what was claimed, without a racy second read.
            admitted_spec, generation_intent = public_task_spec(task.get("spec") or {})
            if task.get("generation_intent") is not None:
                generation_intent = task["generation_intent"]
            result = {"attempt_id": attempt_id, "task_id": row["id"], "project_id": value["run"].get("project_id"), "lease_id": lease_id, "fence": fence, "lease_expires_at": expires, "runtime_epoch": epoch, "input_object_ids": list(admitted_spec.get("input_object_ids") or []), "spec": admitted_spec}
            if generation_intent is not None:
                result["generation_intent"] = generation_intent
            if task.get("expected_effect") is not None:
                result["expected_effect"] = dict(task["expected_effect"])
            if "required_facts" in admitted_spec:
                result["required_facts"] = dict(admitted_spec["required_facts"])
            if "storage_estimate" in admitted_spec:
                result["storage_estimate"] = dict(admitted_spec["storage_estimate"])
        return self._command_record("task.claim", "claim", idempotency_key, request_hash, result, project_id="unscoped", with_receipt=False)

    @_durable_mutation
    def settle_attempt(self, attempt_id, body, *, idempotency_key=None, identity=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        body = dict(_wire_object(
            body,
            allowed=("attempt_id", "lease_id", "fence", "runtime_epoch", "outputs", "effect", "result"),
        ))
        supplied_attempt_id = body.get("attempt_id")
        if supplied_attempt_id is not None and str(supplied_attempt_id) != str(attempt_id):
            raise ConflictError("attempt_id does not match the attempt path")
        body["attempt_id"] = str(attempt_id)
        _wire_string(body, "lease_id")
        _require_runtime_epoch_for_lease(body)
        # Keep a numerically typed stale fence on the lease path. A worker
        # presenting fence 0 (or another old fence) is a fenced lease error,
        # not a request-shape error; this preserves one guard taxonomy.
        _wire_integer(body, "fence")
        _wire_integer(body, "runtime_epoch", positive=True)
        if "outputs" in body and not isinstance(body["outputs"], list):
            raise ValidationError("outputs must be a list")
        if "result" in body and not isinstance(body["result"], dict):
            raise ValidationError("result must be an object")
        if isinstance(body.get("result"), dict) and "outputs" in body["result"]:
            raise ValidationError("result.outputs is reserved; send outputs at the settlement top level")
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            if not row:
                raise LeaseError("attempt lease is stale or already settled")
            current_epoch = self.store._current_runtime_epoch()
            self.store._validate_runtime_epoch(body["runtime_epoch"], identity="executor", identity_id=row["executor_id"], required=True)
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone()
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0] if task else "unscoped"
            request_hash = hashlib.sha256(canonical_json({"attempt_id": attempt_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("attempt.settle", attempt_id, idempotency_key, request_hash, project_id=project_id or "unscoped")
            if replay is not None:
                return replay
            self._validate_attempt_lease(row, body, current_epoch)
            if not task or (task["runtime_epoch"] is not None and int(task["runtime_epoch"]) != current_epoch):
                raise LeaseError("attempt belongs to a stale runtime epoch")
            if task["status"] != "running" or task["attempt_id"] != attempt_id or task["lease_token"] != row["lease_id"] or int(task["lease_fence"] or 0) != int(row["fence"]):
                raise LeaseError("attempt lease is stale or already settled")
            declared = json.loads(task["expected_effect_json"]) if task["expected_effect_json"] else None
            effect = body.get("effect")
            if effect is not None and declared != effect:
                raise ValidationError("settlement effect was not predeclared", details={"declared": declared})
            if declared is not None and effect is None:
                raise ValidationError("declared settlement effect is required")
            if effect is not None:
                self.store._validate_settlement_effect(effect)
            staged = self._stage_outputs(
                attempt_id,
                body.get("outputs", []),
                project_id=project_id,
                attempt_row=row,
                task_row=task,
                lease_body=body,
            )
            try:
                # Persist one flat result object. Outputs are the only
                # reserved field and are added atomically with user fields.
                result = dict(body.get("result") or {})
                result["outputs"] = staged["outputs"]
                recorded = None
                def record(value, *, event_ids=(), primary_stream_id=None, resulting_stream_seq=None):
                    nonlocal recorded
                    recorded = self._command_record(
                        "attempt.settle", attempt_id, idempotency_key, request_hash,
                        self._task_resource(value), project_id=project_id or "unscoped",
                        event_ids=event_ids, primary_stream_id=primary_stream_id,
                        resulting_stream_seq=resulting_stream_seq,
                    )
                self.store._settle_attempt(
                    row["task_id"], row["lease_id"], result,
                    effect=effect, fence=body["fence"], attempt_id=attempt_id,
                    publish=lambda: self._publish_staged_outputs(staged, project_id=project_id),
                    record=record,
                )
                staged["committed"] = True
                return recorded
            finally:
                self._discard_staged_outputs(staged)

    @_verified_mutation
    def publish_timeline_render(self, attempt_id, body, *, idempotency_key=None, identity=None):
        """Publish one canonical timeline revision and its render task once.

        The checkpoint is keyed by the authoring task rather than an attempt,
        so an exact retry may resume after a worker crash.  Every unfinished
        publication must still present the task's current live attempt fence.
        """
        require_idempotency_key(idempotency_key)
        body = dict(_wire_object(
            body,
            required=("lease_id", "fence", "runtime_epoch", "timeline_id", "expected_version", "config", "registry", "render"),
            allowed=("lease_id", "fence", "runtime_epoch", "timeline_id", "expected_version", "config", "registry", "render", "slug", "name"),
        ))
        _wire_string(body, "lease_id")
        _wire_integer(body, "fence")
        _wire_integer(body, "runtime_epoch", positive=True)
        timeline_id = _wire_string(body, "timeline_id")
        expected_version = self._expected_version(body)
        config, registry, render = body["config"], body["registry"], body["render"]
        if not isinstance(config, dict) or not isinstance(registry, dict) or not isinstance(render, dict):
            raise ValidationError("config, registry, and render must be objects")
        allowed_render = {"capability_id", "capability_digest", "schema_version", "spec", "storage_estimate", "settlement_effect"}
        unknown_render = sorted(set(render) - allowed_render)
        if unknown_render:
            raise ValidationError("render contains unsupported fields", details={"fields": unknown_render})
        if render.get("capability_id") != "rendering.render":
            raise ValidationError("publication render capability must be rendering.render")
        render_digest = _wire_string(render, "capability_digest")
        render_spec = render.get("spec")
        if not isinstance(render_spec, dict):
            raise ValidationError("render.spec must be an object")
        frozen = {
            "timeline_id": timeline_id,
            "expected_version": expected_version,
            "config": config,
            "registry": registry,
            "render": render,
            "slug": body.get("slug"),
            "name": body.get("name"),
        }
        request_hash = hashlib.sha256(canonical_json(frozen).encode()).hexdigest()

        with self.store._mutex:
            attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(attempt, identity)
            current_epoch = self.store._current_runtime_epoch()
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (attempt["task_id"],)).fetchone() if attempt else None
            authoring_task_id = str(task["id"]) if task else ""
            existing = self.store.timeline_render_publication(authoring_task_id) if authoring_task_id else None
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise ConflictError("authoring task publication payload changed")
                if existing["state"] == "published":
                    return existing["result"]
            self._validate_attempt_lease(attempt, body, current_epoch)
            if not task or task["status"] != "running" or task["attempt_id"] != attempt_id:
                raise LeaseError("attempt lease is stale or already settled")
            dependency_count = self.store.conn.execute(
                "SELECT COUNT(*) FROM task_dependencies WHERE continuation_task_id=?", (authoring_task_id,)
            ).fetchone()[0]
            admitted = self.store.conn.execute(
                "SELECT 1 FROM continuation_admissions WHERE continuation_task_id=?", (authoring_task_id,)
            ).fetchone()
            if dependency_count != 2 or admitted is None:
                raise ValidationError("timeline publication requires an admitted two-child continuation")
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0]
            timeline = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
            if not timeline:
                raise NotFoundError("timeline not found")
            if timeline["project_id"] != project_id:
                raise ConflictError("timeline is outside the authoring task project")
            self.store.prepare_timeline_render_publication(
                authoring_task_id, attempt_id, body["fence"], body["runtime_epoch"], request_hash, frozen
            )

            # Revalidate after the separately committed prepare checkpoint.
            attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._validate_attempt_lease(attempt, body, self.store._current_runtime_epoch())
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (authoring_task_id,)).fetchone()
            if not task or task["status"] != "running" or task["attempt_id"] != attempt_id:
                raise LeaseError("attempt lease is stale or already settled")

            with self.store._transaction():
                checkpoint = self.store.timeline_render_publication(authoring_task_id)
                if checkpoint["state"] == "published":
                    return checkpoint["result"]
                document_id = f"timeline:{timeline_id}"
                document = self.store.conn.execute(
                    "SELECT * FROM project_documents WHERE id=? AND project_id=?", (document_id, project_id)
                ).fetchone()
                if not document:
                    raise NotFoundError("timeline document not found")
                if int(document["version"]) != expected_version:
                    raise ConflictError("timeline document version conflict", details={"expected": expected_version, "actual": int(document["version"])})
                content = json.loads(document["content_json"])
                content.update({"config": config, "registry": registry})
                if body.get("slug") is not None:
                    content["slug"] = body["slug"]
                if body.get("name") is not None:
                    content["name"] = body["name"]
                timeline_version = expected_version + 1
                timestamp = now()
                self.store.conn.execute(
                    "UPDATE project_documents SET content_json=?, version=?, updated_at=? WHERE id=? AND project_id=?",
                    (canonical_json(content), timeline_version, timestamp, document_id, project_id),
                )
                timeline_event_id = self.store._append_timeline_event(
                    timeline_id, "timeline.document.saved",
                    {"project_id": project_id, "document_id": document_id, "config_version": timeline_version, "authoring_task_id": authoring_task_id},
                )

                admitted_spec = copy.deepcopy(render_spec)
                inputs = admitted_spec.setdefault("inputs", {})
                if not isinstance(inputs, dict):
                    raise ValidationError("render.spec.inputs must be an object")
                supplied_ref = inputs.get("timeline_ref")
                if supplied_ref not in (None, timeline_id, content.get("slug")):
                    raise ConflictError("render timeline_ref does not identify the published timeline")
                supplied_version = inputs.get("expected_version")
                if supplied_version not in (None, timeline_version):
                    raise ConflictError("render expected_version does not match the published timeline")
                inputs.update({
                    "timeline_ref": timeline_id,
                    "expected_version": timeline_version,
                    "timeline_snapshot": {
                        "timeline_id": timeline_id, "project_id": project_id,
                        "config_version": timeline_version, "config": config, "registry": registry,
                    },
                })
                input_object_ids = []
                assets = registry.get("assets") if isinstance(registry.get("assets"), dict) else {}
                for asset in assets.values():
                    if not isinstance(asset, dict):
                        continue
                    candidate = next((asset.get(key) for key in ("object_id", "media_id", "content_sha256", "digest", "sha256", "hash") if isinstance(asset.get(key), str) and OBJECT_ID_RE.fullmatch(asset.get(key))), None)
                    if candidate is not None and candidate not in input_object_ids:
                        input_object_ids.append(candidate)
                task_spec = {
                    "input_object_ids": input_object_ids,
                    "schema_version": render.get("schema_version", "1"),
                    "capability_digest": render_digest,
                    "spec": admitted_spec,
                }
                if "storage_estimate" in render:
                    task_spec["storage_estimate"] = self.store._validate_storage_estimate(render["storage_estimate"])
                render_key = f"timeline-publication-{authoring_task_id}"
                render_value = self.store.create_task(
                    "rendering.render", task_spec, project_id, render_key,
                    render.get("settlement_effect"), render_digest, enforce_readiness=True,
                )
                render_task_id = render_value["task"]["id"]
                render_run_id = render_value["run"]["id"]
                author_event_id = self.store._append_event(
                    task["run_id"], authoring_task_id, "task.timeline_render_published",
                    {"timeline_id": timeline_id, "timeline_version": timeline_version, "render_task_id": render_task_id, "render_run_id": render_run_id},
                )
                result = {
                    "checkpoint_state": "published", "authoring_task_id": authoring_task_id,
                    "timeline_id": timeline_id, "timeline_version": timeline_version,
                    "render_task_id": render_task_id, "render_run_id": render_run_id,
                    "timeline_event_id": timeline_event_id, "authoring_event_id": author_event_id,
                }
                self.store.complete_timeline_render_publication(
                    authoring_task_id, attempt_id=attempt_id, fence=body["fence"], runtime_epoch=body["runtime_epoch"],
                    timeline_id=timeline_id, timeline_version=timeline_version,
                    render_task_id=render_task_id, render_run_id=render_run_id, result=result,
                )
                return result

    def _is_authorized_generic_output(
        self, digest, size, media_type, *, name, output_port, filename,
        recorded_filename, attempt_row, task_row, project_id, lease_body,
    ):
        """Recognize the worker's unscoped output upload receipt.

        Generic producers cannot create a project association during their
        upload. Settlement may adopt that exact object only when the
        unscoped upload's request hash carries the current task/run/project,
        attempt, executor, lease/fence, filename, and deterministic output
        key, and its durable result matches the descriptor.
        """
        if attempt_row is None or task_row is None or lease_body is None:
            return False
        try:
            canonical_recorded_filename = _canonical_managed_output_filename(recorded_filename)
        except ValidationError:
            return False
        if canonical_recorded_filename != filename:
            return False
        binding = {
            "project_id": project_id,
            "run_id": task_row["run_id"],
            "task_id": task_row["id"],
            "attempt_id": attempt_row["id"],
            "executor_id": attempt_row["executor_id"],
            "lease_id": lease_body["lease_id"],
            "fence": int(lease_body["fence"]),
            "runtime_epoch": int(lease_body["runtime_epoch"]),
            "output_key": name,
            "output_port": output_port,
            # Upload receipts are keyed by the producer's original name;
            # settlement stores its canonical flat managed name.
            "filename": recorded_filename,
            "digest": "sha256:" + digest,
            "size": int(size),
            "media_type": media_type,
        }
        idempotency_key = self._generic_output_idempotency_key(binding)
        row = self.store.conn.execute(
            "SELECT request_hash, result_json FROM command_idempotency "
            "WHERE command_kind='object.ingest' AND aggregate_id='objects' "
            "AND idempotency_key=?",
            (idempotency_key,),
        ).fetchone()
        if not row:
            return False
        try:
            result = json.loads(row["result_json"])
        except (TypeError, ValueError):
            return False
        if not isinstance(result, dict):
            return False
        expected_hash = self._generic_output_request_hash(
            digest, media_type, recorded_filename, None, binding,
        )
        if row["request_hash"] != expected_hash:
            return False
        try:
            recorded_size = int(result.get("size", -1))
        except (TypeError, ValueError):
            return False
        return (
            result.get("object_id") == "sha256:" + digest
            and result.get("digest") == "sha256:" + digest
            and recorded_size == int(size)
            and result.get("media_type") == media_type
        )

    def _stage_outputs(self, attempt_id, outputs, *, project_id=None, attempt_row=None, task_row=None, lease_body=None):
        """Validate and stage every output without making it globally reachable."""
        if not isinstance(outputs, list):
            raise ValidationError("outputs must be a list")
        stage_dir = self.store.attempt_staging_dir(attempt_id)
        stage_dir.mkdir(parents=True, exist_ok=True)
        if stage_dir.is_symlink() or not stage_dir.is_dir():
            raise ValidationError("attempt staging directory is invalid")
        stage_dir.chmod(0o700)
        staged = []
        seen = set()
        try:
            for index, output in enumerate(outputs):
                if not isinstance(output, dict):
                    raise ValidationError("each output must be an object")
                allowed = {
                    "name", "filename", "output_port", "selector", "group_key", "variant_key", "generation_id",
                    "kind", "digest", "media_type", "size", "data_base64", "ordinal", "role",
                    "is_primary", "duration_seconds", "durability", "producer", "provenance",
                    "regeneration", "coverage",
                }
                unknown = sorted(set(output) - allowed)
                if unknown:
                    raise ValidationError("output contains unsupported fields", details={"fields": unknown})
                digest_value = output.get("digest")
                if not isinstance(digest_value, str) or not digest_value.startswith("sha256:"):
                    raise ValidationError("each output requires a sha256 digest")
                digest = digest_value.removeprefix("sha256:")
                if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise ValidationError("each output requires a valid SHA-256 digest")
                if digest in seen:
                    raise ValidationError("outputs must not contain duplicate digests")
                seen.add(digest)
                kind = output.get("kind", "object")
                if not isinstance(kind, str) or kind not in {"object", "document", "value"}:
                    raise ValidationError("output kind is invalid")
                name = output.get("name", "output")
                if not isinstance(name, str) or not name or len(name) > 512:
                    raise ValidationError("output name must be a non-empty string")
                filename = _canonical_managed_output_filename(output.get("filename", name))
                media_type = output.get("media_type", "application/octet-stream")
                if not isinstance(media_type, str) or not media_type or len(media_type) > 255 or any(ord(char) < 32 for char in media_type):
                    raise ValidationError("output media_type is invalid")
                declared_size = output.get("size")
                if declared_size is not None and (isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size < 0 or declared_size > OBJECT_MAX_BYTES):
                    raise ValidationError("output size must be an integer between 0 and 64 MiB")
                data_field = output.get("data_base64")
                stage_path = None
                if data_field is not None:
                    if not isinstance(data_field, str):
                        raise ValidationError("output data_base64 is invalid")
                    try:
                        data = base64.b64decode(data_field, validate=True)
                    except (ValueError, TypeError) as exc:
                        raise ValidationError("output data_base64 is invalid") from exc
                    if len(data) > OBJECT_MAX_BYTES:
                        raise ValidationError("output exceeds 64 MiB object limit")
                    actual_digest = sha256_bytes(data)
                    if actual_digest != digest:
                        raise ConflictError("output content hash does not match declared digest", details={"expected": digest_value, "actual": "sha256:" + actual_digest})
                    if declared_size is not None and declared_size != len(data):
                        raise ValidationError("output size does not match staged bytes")
                    stage_path = stage_dir / f"{index:08d}.stage"
                    with open(stage_path, "xb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    size = len(data)
                else:
                    root_fd = prefix_fd = file_fd = -1
                    try:
                        try:
                            root_fd, prefix_fd = self._cas_prefix_fds(digest, create=False)
                        except (FileNotFoundError, OSError) as exc:
                            raise ConflictError(
                                "output must be staged or published to runtime CAS before settlement",
                                details={"digest": digest_value},
                            ) from exc
                        try:
                            file_fd = os.open(
                                digest[2:],
                                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=prefix_fd,
                            )
                        except OSError as exc:
                            raise ConflictError(
                                "output must be staged or published to runtime CAS before settlement",
                                details={"digest": digest_value},
                            ) from exc
                        size = int(os.fstat(file_fd).st_size)
                        if size > OBJECT_MAX_BYTES:
                            raise ValidationError("output exceeds 64 MiB object limit")
                        self._verify_open_file(file_fd, digest, size, label="CAS object")
                    finally:
                        if file_fd >= 0:
                            os.close(file_fd)
                        if prefix_fd >= 0:
                            os.close(prefix_fd)
                        if root_fd >= 0:
                            os.close(root_fd)
                    if declared_size is not None and declared_size != size:
                        raise ValidationError("output size does not match CAS bytes")
                ordinal = output.get("ordinal")
                if ordinal is not None and (isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0):
                    raise ValidationError("output ordinal must be a non-negative integer")
                role = output.get("role")
                if role is not None and (not isinstance(role, str) or not role or len(role) > 255 or any(ord(char) < 32 for char in role)):
                    raise ValidationError("output role is invalid")
                is_primary = output.get("is_primary")
                if is_primary is not None and not isinstance(is_primary, bool):
                    raise ValidationError("output is_primary must be a boolean")
                duration_seconds = output.get("duration_seconds")
                if duration_seconds is not None and (
                    isinstance(duration_seconds, bool)
                    or not isinstance(duration_seconds, (int, float))
                    or not math.isfinite(float(duration_seconds))
                    or float(duration_seconds) <= 0
                ):
                    raise ValidationError("output duration_seconds must be a positive finite number")
                output_port = output.get("output_port", name)
                if not isinstance(output_port, str) or not output_port or len(output_port) > 255 or any(ord(char) < 32 for char in output_port):
                    raise ValidationError("output_port is invalid")
                selector = output.get("selector")
                if selector is not None:
                    if not isinstance(selector, dict) or set(selector) != {"group_key", "variant_key"}:
                        raise ValidationError("output selector requires exactly group_key and variant_key")
                    if "group_key" not in output:
                        output["group_key"] = selector["group_key"]
                    if "variant_key" not in output:
                        output["variant_key"] = selector["variant_key"]
                group_key = output.get("group_key", "default")
                if not isinstance(group_key, str) or not group_key or len(group_key) > 255 or any(ord(char) < 32 for char in group_key):
                    raise ValidationError("output group_key is invalid")
                variant_key = output.get("variant_key", str(ordinal if ordinal is not None else 0))
                if not isinstance(variant_key, str) or len(variant_key) > 255 or any(ord(char) < 32 for char in variant_key):
                    raise ValidationError("output variant_key is invalid")
                generation_id = output.get("generation_id")
                if generation_id is not None and (not isinstance(generation_id, str) or not generation_id or len(generation_id) > 255):
                    raise ValidationError("output generation_id is invalid")
                durability = output.get("durability", "durable")
                if durability not in MANAGED_DURABILITIES:
                    raise ValidationError("output durability is invalid")
                if durability == "temporary" and is_primary is True:
                    raise ValidationError("primary outputs must be durable")
                producer = output.get("producer", {})
                provenance = output.get("provenance", {})
                if not isinstance(producer, dict) or not isinstance(provenance, dict):
                    raise ValidationError("output producer and provenance must be objects")
                regeneration = output.get("regeneration")
                if regeneration is not None:
                    regeneration = _validate_regeneration(regeneration)
                coverage = output.get("coverage")
                if coverage is not None:
                    coverage = _validate_coverage(coverage)
                existing = self.store.conn.execute("SELECT size, media_type, original_name FROM objects WHERE digest=?", (digest,)).fetchone()
                if existing:
                    if int(existing["size"]) != size or existing["media_type"] != media_type:
                        raise ConflictError("output metadata does not match existing object", details={"digest": digest_value})
                    if project_id and not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone():
                        has_project_owner = self.store.conn.execute(
                            "SELECT 1 FROM project_objects WHERE digest=? LIMIT 1", (digest,)
                        ).fetchone()
                        if has_project_owner or not self._is_authorized_generic_output(
                            digest,
                            size,
                            media_type,
                            name=name,
                            output_port=output_port,
                            filename=filename,
                            recorded_filename=existing["original_name"],
                            attempt_row=attempt_row,
                            task_row=task_row,
                            project_id=project_id,
                            lease_body=lease_body,
                        ):
                            raise ConflictError("output object is outside the task project", details={"project_id": project_id, "digest": digest_value})
                elif project_id and stage_path is None and not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone():
                    raise ConflictError("output object is outside the task project", details={"project_id": project_id, "digest": digest_value})
                normalized = {
                    "name": name, "kind": kind, "digest": digest_value,
                    "media_type": media_type, "size": size,
                }
                # Keep the established settlement result wire stable.  The
                # association table/readback carries the defaulted filename,
                # port, group, and variant identity; echo an extended field
                # only when the producer explicitly supplied it.
                if "filename" in output:
                    normalized["filename"] = filename
                if "output_port" in output:
                    normalized["output_port"] = output_port
                if selector is not None:
                    normalized["selector"] = {"group_key": group_key, "variant_key": variant_key}
                if "group_key" in output:
                    normalized["group_key"] = group_key
                if "variant_key" in output:
                    normalized["variant_key"] = variant_key
                if generation_id is not None:
                    normalized["generation_id"] = generation_id
                if ordinal is not None:
                    normalized["ordinal"] = ordinal
                if role is not None:
                    normalized["role"] = role
                if is_primary is not None:
                    normalized["is_primary"] = is_primary
                if duration_seconds is not None:
                    normalized["duration_seconds"] = duration_seconds
                if durability != "durable":
                    normalized["durability"] = durability
                if producer:
                    normalized["producer"] = producer
                if provenance:
                    normalized["provenance"] = provenance
                if regeneration is not None:
                    normalized["regeneration"] = regeneration
                if coverage is not None:
                    normalized["coverage"] = coverage
                staged.append({
                    "digest": digest, "path": stage_path, "size": size, "media_type": media_type,
                    "name": name, "filename": filename, "output": normalized,
                    "output_port": output_port, "group_key": group_key, "variant_key": variant_key,
                    "generation_id": generation_id, "durability": durability, "producer": producer,
                    "provenance": provenance, "regeneration": regeneration, "coverage": coverage,
                })
            return {"stage_dir": stage_dir, "attempt_id": attempt_id, "items": staged, "outputs": [item["output"] for item in staged]}
        except Exception:
            self._discard_staged_outputs({"stage_dir": stage_dir, "items": staged})
            raise


    @staticmethod
    def _verify_open_file(file_fd, digest, expected_size, *, label):
        """Hash one already-open file without reopening its pathname."""
        try:
            initial = os.fstat(file_fd)
            if not stat.S_ISREG(initial.st_mode):
                raise ConflictError(f"{label} must be a regular file")
            if initial.st_size != expected_size:
                raise ConflictError(f"{label} size does not match staged metadata")
            os.lseek(file_fd, 0, os.SEEK_SET)
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            final = os.fstat(file_fd)
        except OSError as exc:
            raise ConflictError(f"{label} is unavailable") from exc
        if (
            final.st_dev != initial.st_dev
            or final.st_ino != initial.st_ino
            or final.st_size != expected_size
            or hasher.hexdigest() != digest
        ):
            raise ConflictError(f"{label} hash or size does not match staged metadata")
        return initial

    def _cas_prefix_fds(self, digest, *, create):
        """Open a CAS digest prefix below descriptors, never through a path."""
        root_fd = _open_directory_chain(self.cas.root)
        try:
            prefix = digest[:2]
            if create:
                prefix_fd = _mkdir_chain_at(root_fd, prefix)
            else:
                prefix_fd = os.open(
                    prefix,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
            try:
                if not stat.S_ISDIR(os.fstat(prefix_fd).st_mode):
                    raise ConflictError("CAS destination directory is invalid")
            except Exception:
                os.close(prefix_fd)
                raise
            return root_fd, prefix_fd
        except Exception:
            os.close(root_fd)
            raise

    @staticmethod
    def _copy_open_file_at(source_fd, destination_fd, destination_name, digest, expected_size, *, label):
        """Copy verified bytes to a private file, then atomically link it."""
        temporary_name = f".{destination_name}.{os.getpid()}-{uuid.uuid4().hex}.tmp"
        temporary_fd = -1
        linked = False
        try:
            initial = RuntimeService._verify_open_file(source_fd, digest, expected_size, label=label)
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=destination_fd,
            )
            os.lseek(source_fd, 0, os.SEEK_SET)
            hasher = hashlib.sha256()
            copied = 0
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                copied += len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(temporary_fd, view)
                    view = view[written:]
            final = os.fstat(source_fd)
            if (
                final.st_dev != initial.st_dev
                or final.st_ino != initial.st_ino
                or copied != expected_size
                or hasher.hexdigest() != digest
            ):
                raise ConflictError(f"{label} hash or size does not match staged metadata")
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            RuntimeService._verify_file_at(
                destination_fd, temporary_name, digest, expected_size, label="temporary CAS object",
            )
            try:
                os.stat(destination_name, dir_fd=destination_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ConflictError("CAS destination appeared during publication")
            os.link(
                temporary_name,
                destination_name,
                src_dir_fd=destination_fd,
                dst_dir_fd=destination_fd,
                follow_symlinks=False,
            )
            linked = True
            os.unlink(temporary_name, dir_fd=destination_fd)
        except OSError as exc:
            raise ConflictError(f"{label} is unavailable") from exc
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            try:
                os.unlink(temporary_name, dir_fd=destination_fd)
            except OSError:
                pass
        RuntimeService._verify_file_at(destination_fd, destination_name, digest, expected_size, label="CAS object")
        return initial

    @staticmethod
    def _verify_file_at(directory_fd, name, digest, expected_size, *, label):
        try:
            file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except OSError as exc:
            raise ConflictError(f"{label} is unavailable") from exc
        try:
            RuntimeService._verify_open_file(file_fd, digest, expected_size, label=label)
        finally:
            os.close(file_fd)

    @staticmethod
    def _unlink_stage_entry(stage_fd, name, expected_stat=None):
        try:
            current = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if expected_stat is not None and (
                current.st_dev != expected_stat.st_dev or current.st_ino != expected_stat.st_ino
            ):
                return
            os.unlink(name, dir_fd=stage_fd)
        except FileNotFoundError:
            pass

    def _unlink_cas_destination(self, digest, *, create_prefix=False):
        """Unlink a CAS object relative to a descriptor-pinned prefix."""
        root_fd = prefix_fd = -1
        try:
            try:
                root_fd, prefix_fd = self._cas_prefix_fds(digest, create=create_prefix)
            except FileNotFoundError:
                return False
            try:
                os.unlink(digest[2:], dir_fd=prefix_fd)
            except FileNotFoundError:
                return False
            os.fsync(prefix_fd)
            return True
        finally:
            if prefix_fd >= 0:
                os.close(prefix_fd)
            if root_fd >= 0:
                os.close(root_fd)
    def _publish_staged_outputs(self, staged, *, project_id=None):
        """Publish already validated bytes as part of the settlement transaction."""
        staged.setdefault("published", [])
        candidate_entries = []
        task_id = None
        attempt_id = staged.get("attempt_id")
        if attempt_id:
            row = self.store.conn.execute("SELECT task_id FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            task_id = row["task_id"] if row else None

        stage_identity = None
        stage_fd = -1
        cas_handles = {}
        try:
            if any(item["path"] is not None for item in staged["items"]):
                stage_identity, stage_fd, _ = _pin_directory(staged["stage_dir"])

            for item in staged["items"]:
                digest = item["digest"]
                root_fd, prefix_fd = self._cas_prefix_fds(digest, create=True)
                cas_handles[digest] = (root_fd, prefix_fd)
                destination_name = digest[2:]
                try:
                    os.stat(destination_name, dir_fd=prefix_fd, follow_symlinks=False)
                    destination_exists = True
                except FileNotFoundError:
                    destination_exists = False
                except OSError as exc:
                    raise ConflictError("CAS destination is unavailable") from exc
                if item["path"] is not None and not destination_exists:
                    candidate_entries.append({"digest": digest})

            if candidate_entries:
                staged["journal_path"] = self._begin_cas_publication_journal(
                    "settlement", candidate_entries, project_id=project_id or "unscoped", task_id=task_id,
                )

            for item in staged["items"]:
                digest = item["digest"]
                _root_fd, prefix_fd = cas_handles[digest]
                destination_name = digest[2:]
                if item["path"] is not None:
                    source_name = item["path"].name
                    try:
                        source_fd = os.open(
                            source_name,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=stage_fd,
                        )
                    except OSError as exc:
                        raise ConflictError("staged output is unavailable") from exc
                    try:
                        source_stat = self._verify_open_file(
                            source_fd, digest, item["size"], label="staged output",
                        )
                        try:
                            destination_exists = os.stat(
                                destination_name, dir_fd=prefix_fd, follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            destination_exists = None
                        except OSError as exc:
                            raise ConflictError("CAS destination is unavailable") from exc
                        if destination_exists is not None:
                            self._verify_file_at(
                                prefix_fd, destination_name, digest, item["size"], label="CAS object",
                            )
                        else:
                            self._copy_open_file_at(
                                source_fd, prefix_fd, destination_name, digest, item["size"],
                                label="staged output",
                            )
                            staged["published"].append(digest)
                            os.fsync(prefix_fd)
                        self._unlink_stage_entry(stage_fd, source_name, source_stat)
                    finally:
                        os.close(source_fd)
                else:
                    self._verify_file_at(
                        prefix_fd, destination_name, digest, item["size"], label="CAS object",
                    )
                self.store.conn.execute(
                    "INSERT OR IGNORE INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                    (digest, item["size"], item["media_type"], item["name"], now()),
                )
                if project_id:
                    self.store.conn.execute(
                        "INSERT OR IGNORE INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, 'managed', ?)",
                        (project_id, digest, now()),
                    )
        finally:
            if stage_fd >= 0:
                os.close(stage_fd)
            if stage_identity is not None:
                _close_pinned(stage_identity)
            for root_fd, prefix_fd in cas_handles.values():
                os.close(prefix_fd)
                os.close(root_fd)


    def _discard_staged_outputs(self, staged):
        stage_dir = staged.get("stage_dir") if isinstance(staged, dict) else None
        committed = bool(staged.get("committed")) if isinstance(staged, dict) else False

        if stage_dir is not None:
            stage_identity = None
            stage_fd = -1
            try:
                stage_identity, stage_fd, stage_stat = _pin_directory(stage_dir)
            except (OSError, ConflictError):
                # Never fall back to pathname unlinking when the staging
                # directory cannot be descriptor-pinned.
                pass
            else:
                try:
                    try:
                        for entry in os.scandir(stage_fd):
                            entry_stat = entry.stat(follow_symlinks=False)
                            if stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
                                os.unlink(entry.name, dir_fd=stage_fd)
                        os.fsync(stage_fd)
                    except OSError:
                        pass
                    parent_fd = stage_identity.get("_parent_fd")
                    if parent_fd is not None:
                        try:
                            current = os.stat(
                                stage_dir.name, dir_fd=int(parent_fd), follow_symlinks=False,
                            )
                            if (
                                stat.S_ISDIR(current.st_mode)
                                and current.st_dev == stage_stat.st_dev
                                and current.st_ino == stage_stat.st_ino
                            ):
                                os.rmdir(stage_dir.name, dir_fd=int(parent_fd))
                                os.fsync(int(parent_fd))
                        except OSError:
                            pass
                finally:
                    os.close(stage_fd)
                    _close_pinned(stage_identity)

        if not committed:
            for digest in (staged.get("published", []) if isinstance(staged, dict) else []):
                try:
                    if len(digest) == 64 and all(char in "0123456789abcdef" for char in digest):
                        self._unlink_cas_destination(digest)
                except (FileNotFoundError, OSError, ConflictError):
                    continue

    def _checkpoint_row(self, checkpoint_id=None, attempt_id=None):
        if checkpoint_id:
            row = self.store.conn.execute("SELECT * FROM recovery_checkpoints WHERE id=?", (checkpoint_id,)).fetchone()
            if row and attempt_id is not None and row["attempt_id"] != attempt_id:
                raise LeaseError("checkpoint is bound to a different attempt")
        else:
            row = self.store.conn.execute("SELECT * FROM recovery_checkpoints WHERE attempt_id=? ORDER BY created_at DESC LIMIT 1", (attempt_id,)).fetchone()
        if not row:
            raise NotFoundError("recovery checkpoint not found")
        attempt = self.store.conn.execute("SELECT task_id, executor_id, lease_id, fence FROM attempts WHERE id=?", (row["attempt_id"],)).fetchone()
        if not attempt or attempt["task_id"] != row["task_id"] or attempt["executor_id"] != row["executor_id"] or attempt["lease_id"] != row["lease_id"] or int(attempt["fence"]) != int(row["fence"]):
            raise ConflictError("recovery checkpoint identity is inconsistent")
        return row

    def _reboot_authorized(self, body, attempt_id, expected_nonce=None, *, allow_consumed=False):
        """Validate durable, attempt-bound recovery authorization.

        A nonce supplied by a caller is not sufficient by itself.  It must be
        the nonce persisted by ``prepare_reboot`` for this exact attempt and
        must still be within its short validity window.
        """
        attempt = self.store.conn.execute("SELECT recovery_nonce, recovery_nonce_expires_at, recovery_nonce_used FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        nonce = attempt["recovery_nonce"] if attempt else None
        if "authorization_nonce" in body:
            raise ValidationError("authorization_nonce is not supported; use authorization")
        authorization = body.get("authorization")
        supplied = body.get("nonce")
        if not nonce:
            raise ValidationError("prepare_reboot is required before recovery")
        if attempt["recovery_nonce_used"] and not allow_consumed:
            raise ConflictError("recovery authorization has already been consumed")
        if attempt["recovery_nonce_expires_at"] and attempt["recovery_nonce_expires_at"] <= now():
            raise ValidationError("recovery authorization has expired")
        if not supplied or not authorization or str(supplied) != str(nonce) or str(authorization) != str(nonce) or (expected_nonce is not None and str(expected_nonce) != str(nonce)):
            raise ValidationError("recovery nonce authorization is required")
        return nonce

    def _validate_attempt_lease(self, row, body, current, *, require_epoch=True, allow_expired=False):
        """Validate the complete attempt fence before a mutating side effect."""
        if require_epoch:
            self.store._validate_runtime_epoch(
                body.get("runtime_epoch"),
                identity="executor",
                identity_id=row["executor_id"] if row else None,
                required=True,
            )
        if not row or row["settled"] or int(row["runtime_epoch"]) != current:
            raise LeaseError("attempt lease is stale or already settled")
        try:
            supplied_fence = int(body.get("fence", 0))
        except (TypeError, ValueError) as exc:
            raise LeaseError("attempt fence is invalid") from exc
        if row["lease_id"] != body.get("lease_id") or int(row["fence"]) != supplied_fence:
            raise LeaseError("attempt lease is stale or already settled")
        if not allow_expired and row["lease_expires_at"]:
            try:
                if datetime.fromisoformat(row["lease_expires_at"]) <= datetime.now(timezone.utc):
                    raise LeaseError("attempt lease has expired")
            except ValueError as exc:
                raise LeaseError("attempt lease deadline is invalid") from exc
    @_verified_mutation
    def prepare_reboot(self, body=None, *, identity=None):
        """Issue a one-shot nonce for an attempt's recovery handshake."""
        raw_body = {} if body is None else body
        _require_runtime_epoch_for_lease(raw_body)
        body = _wire_object(
            raw_body,
            required=("attempt_id", "lease_id", "fence", "runtime_epoch"),
            allowed=("attempt_id", "lease_id", "fence", "runtime_epoch"),
        )
        attempt_id = _wire_string(body, "attempt_id")
        _wire_string(body, "lease_id")
        _wire_integer(body, "fence")
        _wire_integer(body, "runtime_epoch", positive=True)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            if not row or row["settled"]:
                raise LeaseError("attempt lease is stale or already settled")
            current = self.store._current_runtime_epoch()
            self._validate_attempt_lease(row, body, current)
            with self.store._transaction():
                current_row = self.store.conn.execute("SELECT recovery_nonce, recovery_nonce_expires_at, recovery_nonce_used FROM attempts WHERE id=?", (attempt_id,)).fetchone()
                if current_row["recovery_nonce"] and not current_row["recovery_nonce_used"] and (not current_row["recovery_nonce_expires_at"] or current_row["recovery_nonce_expires_at"] > now()):
                    nonce = current_row["recovery_nonce"]
                    expires_at = current_row["recovery_nonce_expires_at"]
                else:
                    nonce = new_id() + new_id()
                    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(timespec="milliseconds")
                    self.store.conn.execute("UPDATE attempts SET recovery_nonce=?, recovery_nonce_expires_at=?, recovery_nonce_used=0 WHERE id=? AND settled=0", (nonce, expires_at, attempt_id))
        expires_in = max(0, int((datetime.fromisoformat(expires_at) - datetime.now(timezone.utc)).total_seconds()))
        return {"attempt_id": attempt_id, "task_id": row["task_id"], "executor_id": row["executor_id"], "runtime_epoch": current, "nonce": nonce, "expires_in_seconds": expires_in}

    @_verified_mutation
    def checkpoint_attempt(self, attempt_id, body, *, identity=None):
        """Persist a bounded, fsync'd R1 checkpoint before a reboot request."""
        body = _wire_object(
            body,
            required=("lease_id", "fence", "nonce", "authorization", "runtime_epoch"),
            allowed=("lease_id", "fence", "nonce", "authorization", "runtime_epoch", "checkpoint", "state"),
        )
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValidationError("attempt_id is required")
        _wire_string(body, "lease_id")
        _wire_integer(body, "fence")
        _wire_string(body, "nonce")
        _wire_string(body, "authorization")
        _wire_integer(body, "runtime_epoch", positive=True)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            current = self.store._current_runtime_epoch()
            self._validate_attempt_lease(row, body, current)
            nonce = self._reboot_authorized(body, attempt_id)
            payload = body.get("checkpoint", body.get("state", {}))
            if not isinstance(payload, (dict, list)):
                raise ValidationError("checkpoint must be an object or array")
            durable_bytes = durable_json_bytes(payload)
            if len(durable_bytes) > CHECKPOINT_MAX_BYTES:
                raise ValidationError("recovery checkpoint exceeds 1 MiB bound")
            # A repeated request with the same durable authorization and bytes
            # is idempotent.  A different payload is a conflict, never a new
            # checkpoint that could be resumed accidentally.
            existing = self.store.conn.execute("SELECT * FROM recovery_checkpoints WHERE attempt_id=? AND nonce=? ORDER BY created_at DESC LIMIT 1", (attempt_id, nonce)).fetchone()
            if existing:
                existing_bytes = Path(existing["checkpoint_path"]).read_bytes()
                if sha256_bytes(existing_bytes) != existing["checkpoint_digest"] or json.loads(existing_bytes.decode("utf-8")) != payload:
                    raise ConflictError("recovery checkpoint authorization already binds different bytes")
                return {"checkpoint_id": existing["id"], "attempt_id": existing["attempt_id"], "task_id": existing["task_id"], "runtime_epoch": existing["runtime_epoch"], "nonce": nonce, "digest": "sha256:" + existing["checkpoint_digest"], "size": existing["checkpoint_size"], "state": existing["state"], "path": existing["checkpoint_path"]}
            checkpoint_id = new_id()
            path = self.store.root / "checkpoints" / f"{checkpoint_id}.json"
            root_identity, root_fd, _ = _pin_directory(self.store.root)
            checkpoints_fd = -1
            try:
                checkpoints_fd = _mkdir_chain_at(root_fd, "checkpoints")
                _write_bytes_at(checkpoints_fd, f"{checkpoint_id}.json", durable_bytes)
                os.fsync(checkpoints_fd)
            finally:
                if checkpoints_fd >= 0:
                    os.close(checkpoints_fd)
                os.close(root_fd)
                _close_pinned(root_identity)
            if durable_bytes != durable_json_bytes(payload):
                raise ConflictError("checkpoint serializer changed while writing")
            digest = sha256_bytes(durable_bytes)
            # atomic_json_write fsyncs the file; fsync the containing directory
            # as well so the rename survives a sudden power loss.
            timestamp = now()
            with self.store._transaction():
                self.store.conn.execute("INSERT INTO recovery_checkpoints(id, attempt_id, task_id, executor_id, runtime_epoch, lease_id, fence, nonce, checkpoint_path, checkpoint_digest, checkpoint_size, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'durable', ?, ?)", (checkpoint_id, attempt_id, row["task_id"], row["executor_id"], current, row["lease_id"], row["fence"], nonce, str(path), digest, len(durable_bytes), timestamp, timestamp))
            return {"checkpoint_id": checkpoint_id, "attempt_id": attempt_id, "task_id": row["task_id"], "runtime_epoch": current, "nonce": nonce, "digest": "sha256:" + digest, "size": len(durable_bytes), "state": "durable", "path": str(path)}

    create_checkpoint = checkpoint_attempt

    def request_reboot(self, body, *, identity=None):
        """Execute only an allowlisted reboot command after durable checkpointing."""
        body = _wire_object(
            body,
            required=("nonce", "authorization", "runtime_epoch"),
            allowed=("checkpoint_id", "attempt_id", "nonce", "authorization", "runtime_epoch", "command"),
        )
        _wire_string(body, "nonce")
        _wire_string(body, "authorization")
        _wire_integer(body, "runtime_epoch", positive=True)
        for field in ("checkpoint_id", "attempt_id"):
            if field in body and body[field] is not None:
                _wire_string(body, field)
        if "command" in body and body["command"] is not None:
            _wire_string(body, "command")
        # Claim and consume the one-shot authorization in the same SQLite
        # transaction as the durable-state transition.  The executor is
        # intentionally called after commit (it may block or terminate the
        # process), but no competing request can pass the claim meanwhile.
        with self.store._mutex:
            self._assert_mutation_admitted()
            current = self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", required=True)
            row = self._checkpoint_row(body.get("checkpoint_id"), body.get("attempt_id"))
            self._assert_attempt_identity(row, identity)
            if row["state"] in {"executed", "resumed"} and row["recovery_receipt_json"]:
                # A completed request is safely replayable, but still require
                # the exact original nonce and authorization.
                self._reboot_authorized(body, row["attempt_id"], row["nonce"], allow_consumed=True)
                return json.loads(row["recovery_receipt_json"])
            self._reboot_authorized(body, row["attempt_id"], row["nonce"])
            command = str(body.get("command") or "reboot")
            if command not in self.reboot_allowlist:
                raise ValidationError("reboot command is not allowlisted", details={"command": command, "allowlist": sorted(self.reboot_allowlist)})
            if int(row["runtime_epoch"]) != self.store._current_runtime_epoch():
                raise LeaseError("reboot checkpoint belongs to a stale runtime epoch")
            attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (row["attempt_id"],)).fetchone()
            self._validate_attempt_lease(attempt, {**body, "lease_id": row["lease_id"], "fence": row["fence"]}, current)
            checkpoint_bytes = Path(row["checkpoint_path"]).read_bytes()
            if sha256_bytes(checkpoint_bytes) != row["checkpoint_digest"]:
                raise ConflictError("recovery checkpoint digest mismatch")
            checkpoint = json.loads(checkpoint_bytes.decode("utf-8"))
            if row["state"] != "durable":
                raise ConflictError("reboot has already been requested", details={"state": row["state"]})
            if self.reboot_executor is None:
                raise ConflictError("reboot executor is unavailable; tests must inject a safe executor")
            timestamp = now()
            with self.store._transaction():
                consumed = self.store.conn.execute("UPDATE attempts SET recovery_nonce_used=1 WHERE id=? AND recovery_nonce_used=0", (row["attempt_id"],))
                if consumed.rowcount != 1:
                    raise ConflictError("recovery authorization has already been consumed")
                claimed = self.store.conn.execute("UPDATE recovery_checkpoints SET state='reboot_requested', updated_at=? WHERE id=? AND state='durable'", (timestamp, row["id"]))
                if claimed.rowcount != 1:
                    raise ConflictError("reboot has already been requested", details={"state": row["state"]})
        executor = self.reboot_executor
        import inspect
        try:
            signature = inspect.signature(executor)
        except (TypeError, ValueError):
            # Some extension/callable objects do not expose a signature.  A
            # single positional invocation is the only safe fallback; never
            # retry after a TypeError raised by the executor itself.
            call = lambda: executor(command, checkpoint)
        else:
            try:
                signature.bind(command=command, checkpoint=checkpoint)
            except TypeError:
                signature.bind(command, checkpoint)
                call = lambda: executor(command, checkpoint)
            else:
                call = lambda: executor(command=command, checkpoint=checkpoint)
        try:
            outcome = call()
        except Exception as exc:
            failure = {"type": "runtime.recovery.receipt", "version": 1, "checkpoint_id": row["id"], "attempt_id": row["attempt_id"], "task_id": row["task_id"], "runtime_epoch": current, "command": command, "status": "failed", "error": {"type": type(exc).__name__, "message": str(exc)}}
            with self.store._mutex:
                with self.store._transaction():
                    self.store.conn.execute("UPDATE recovery_checkpoints SET state='executor_failed', recovery_receipt_json=?, updated_at=? WHERE id=? AND state='reboot_requested'", (canonical_json(failure), now(), row["id"]))
            raise
        receipt = {"type": "runtime.recovery.receipt", "version": 1, "checkpoint_id": row["id"], "attempt_id": row["attempt_id"], "task_id": row["task_id"], "runtime_epoch": self.store._current_runtime_epoch(), "command": command, "status": "executed", "executor_result": outcome}
        with self.store._mutex:
            with self.store._transaction():
                self.store.conn.execute("UPDATE recovery_checkpoints SET state='executed', recovery_receipt_json=?, updated_at=? WHERE id=? AND state='reboot_requested'", (canonical_json(receipt), now(), row["id"]))
        return receipt

    @_verified_mutation
    def resume_attempt(self, body, *, identity=None):
        body = _wire_object(
            body,
            required=("nonce", "authorization", "runtime_epoch"),
            allowed=("checkpoint_id", "attempt_id", "nonce", "authorization", "runtime_epoch"),
        )
        _wire_string(body, "nonce")
        _wire_string(body, "authorization")
        _wire_integer(body, "runtime_epoch", positive=True)
        for field in ("checkpoint_id", "attempt_id"):
            if field in body and body[field] is not None:
                _wire_string(body, field)
        def attempt_resource(attempt):
            task_value = self.store.get_task(attempt["task_id"])
            admitted_spec, generation_intent = public_task_spec(task_value["task"].get("spec") or {})
            if task_value["task"].get("generation_intent") is not None:
                generation_intent = task_value["task"]["generation_intent"]
            resource = {
                "attempt_id": attempt["id"],
                "task_id": attempt["task_id"],
                "project_id": task_value["run"].get("project_id"),
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "lease_expires_at": attempt["lease_expires_at"],
                "runtime_epoch": attempt["runtime_epoch"],
                "input_object_ids": list(admitted_spec.get("input_object_ids") or []),
                "spec": admitted_spec,
            }
            if generation_intent is not None:
                resource["generation_intent"] = generation_intent
            return resource

        with self.store._mutex:
            current = self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", required=True)
            row = self._checkpoint_row(body.get("checkpoint_id"), body.get("attempt_id"))
            self._assert_attempt_identity(row, identity)
            # request_reboot consumes the one-shot authorization.  The exact
            # consumed token remains the authorization for this checkpoint's
            # one successful resume; it is not a newly reusable nonce.
            self._reboot_authorized(body, row["attempt_id"], row["nonce"], allow_consumed=True)
            if row["state"] == "resumed" and row["recovery_receipt_json"]:
                receipt = json.loads(row["recovery_receipt_json"])
                attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (receipt["attempt_id"],)).fetchone()
                if attempt:
                    return {"receipt": receipt, "attempt": attempt_resource(attempt)}
            if row["state"] not in {"recovered", "reboot_requested", "executed"}:
                raise ConflictError("checkpoint is not ready for resume", details={"state": row["state"]})
            checkpoint_bytes = Path(row["checkpoint_path"]).read_bytes()
            if sha256_bytes(checkpoint_bytes) != row["checkpoint_digest"]:
                raise ConflictError("recovery checkpoint digest mismatch")
            checkpoint = json.loads(checkpoint_bytes.decode("utf-8"))
            # Claim this exact task.  Never use claim_next here: a mismatch
            # must not consume an unrelated queued task.
            lease_id = new_id()
            claim = self.store._claim_task(row["task_id"], row["executor_id"], lease_id, runtime_epoch=current)
            task = claim["task"]
            if task.get("status") != "running" or task.get("id") != row["task_id"]:
                raise ConflictError("checkpoint task is not queued for resume")
            attempt_id = new_id()
            with self.store._transaction():
                self.store.conn.execute("INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, ?, ?, ?, 0, ?)", (attempt_id, row["task_id"], lease_id, task["lease_fence"], row["executor_id"], task["lease_expires_at"], current))
                self.store.conn.execute("UPDATE tasks SET attempt_id=? WHERE id=? AND status='running'", (attempt_id, row["task_id"]))
            resumed_attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            receipt = {"type": "runtime.recovery.receipt", "version": 1, "checkpoint_id": row["id"], "attempt_id": resumed_attempt["id"], "task_id": row["task_id"], "runtime_epoch": current, "command": "resume", "status": "resumed", "checkpoint_digest": "sha256:" + row["checkpoint_digest"], "checkpoint": checkpoint}
            with self.store._transaction():
                self.store.conn.execute("UPDATE recovery_checkpoints SET state='resumed', recovery_receipt_json=?, updated_at=? WHERE id=? AND state IN ('recovered', 'reboot_requested', 'executed')", (canonical_json(receipt), now(), row["id"]))
            return {"receipt": receipt, "attempt": attempt_resource(resumed_attempt)}

    resume = resume_attempt

    @_verified_mutation
    def heartbeat_attempt(self, attempt_id, body, *, idempotency_key=None, identity=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        _require_runtime_epoch_for_lease(body)
        body = _wire_object(
            body,
            required=("lease_id", "fence", "runtime_epoch"),
            allowed=("lease_id", "fence", "runtime_epoch", "lease_seconds"),
        )
        _wire_string(body, "lease_id")
        # Fence zero is deliberately accepted as a typed stale fence. The
        # lease validator must classify it as LeaseError, not ValidationError.
        _wire_integer(body, "fence")
        _wire_integer(body, "runtime_epoch", positive=True)
        if "lease_seconds" in body and (
            isinstance(body["lease_seconds"], bool)
            or not isinstance(body["lease_seconds"], int)
            or body["lease_seconds"] <= 0
        ):
            raise ValidationError("lease_seconds must be a positive integer")
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            current = self.store._current_runtime_epoch()
            self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", identity_id=row["executor_id"] if row else None, required=True)
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone() if row else None
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0] if task else "unscoped"
            request_hash = hashlib.sha256(canonical_json({"attempt_id": attempt_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("attempt.heartbeat", attempt_id, idempotency_key, request_hash, project_id=project_id or "unscoped")
            if replay is not None:
                return replay
            self._validate_attempt_lease(row, body, current)
            recorded = None
            def record(value):
                nonlocal recorded
                expires = value["task"].get("lease_expires_at")
                self.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expires, attempt_id))
                result = {"attempt_id": attempt_id, "task_id": row["task_id"], "lease_id": row["lease_id"], "fence": row["fence"], "lease_expires_at": expires, "runtime_epoch": self.store._current_runtime_epoch()}
                recorded = self._command_record("attempt.heartbeat", attempt_id, idempotency_key, request_hash, result, project_id=project_id or "unscoped")
            self.store.heartbeat_task(row["task_id"], row["lease_id"], fence=row["fence"], lease_seconds=body.get("lease_seconds", 30), record=record)
            return recorded

    @_verified_mutation
    def fail_attempt(self, attempt_id, body, *, idempotency_key=None, identity=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        _require_runtime_epoch_for_lease(body)
        body = _wire_object(
            body,
            required=("lease_id", "fence", "runtime_epoch"),
            allowed=("lease_id", "fence", "runtime_epoch", "error", "reason"),
        )
        _wire_string(body, "lease_id")
        # A typed fence of zero is stale lease state, not malformed wire.
        _wire_integer(body, "fence")
        _wire_integer(body, "runtime_epoch", positive=True)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            if not row:
                raise LeaseError("attempt lease is stale or already settled")
            current = self.store._current_runtime_epoch()
            self.store._validate_runtime_epoch(body["runtime_epoch"], identity="executor", identity_id=row["executor_id"], required=True)
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone() if row else None
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0] if task else "unscoped"
            request_hash = hashlib.sha256(canonical_json({"attempt_id": attempt_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("attempt.fail", attempt_id, idempotency_key, request_hash, project_id=project_id or "unscoped")
            if replay is not None:
                return replay
            self._validate_attempt_lease(row, body, current)
            if "reason" in body:
                raise ValidationError("reason is not supported; use error")
            failure = body.get("error") or {"code": "executor_failed"}
            recorded = None
            def record(value, *, event_ids=(), primary_stream_id=None, resulting_stream_seq=None):
                nonlocal recorded
                recorded = self._command_record("attempt.fail", attempt_id, idempotency_key, request_hash, self._task_resource(value), project_id=project_id or "unscoped", event_ids=event_ids, primary_stream_id=primary_stream_id, resulting_stream_seq=resulting_stream_seq)
            self.store.fail_task(row["task_id"], row["lease_id"], failure, fence=row["fence"], attempt_id=attempt_id, record=record)
            return recorded

    def events_page(self, aggregate_id=None, *, cursor=None, limit=50):
        rows = self.store.conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        if aggregate_id:
            rows = [row for row in rows if aggregate_id in (row["task_id"], row["run_id"])]
        scope = f"events:{aggregate_id or '*'}"
        return _page_rows(
            rows, scope=scope, cursor=cursor, limit=limit,
            key_fn=lambda row: (str(row["id"]),),
            resource_fn=lambda row: {"event_id": str(row["id"]), "sequence": int(row["id"]), "cursor": str(row["id"]), "event_type": row["kind"], "aggregate_type": "task" if row["task_id"] else "run", "aggregate_id": row["task_id"] or row["run_id"], "payload": json.loads(row["payload_json"]), "occurred_at": row["created_at"]},
        )
