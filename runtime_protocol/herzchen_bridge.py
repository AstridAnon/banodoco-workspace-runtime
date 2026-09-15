"""Bind the shared Herzchen contracts to the existing Runtime owner.

This is deliberately an adapter, not a second persistence layer.  Runtime's
``RealmStore`` remains the only transaction, CAS, receipt, and event writer.
Herzchen supplies the neutral operation/identity/receipt/event/host contracts;
the adapter projects Runtime results into those contracts and delegates all
mutations back to the admitted ``RuntimeService``.

The product repository does not vendor Herzchen.  The import is therefore
optional at module import time and fails closed when a caller requests the
shared binding without the controller's pinned Herzchen installation.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import json
from typing import Any, Mapping, Optional

from .util import new_id, now


class HerzchenUnavailable(RuntimeError):
    """The shared Herzchen contract package is not available to this process."""


try:  # Keep the Runtime importable in its normal standalone distribution.
    from herzchen.content import ContentCommandHandler
    from herzchen.extensions import ExtensionCommandService
    from herzchen.adapters import HerzchenHostAdapter
    from herzchen.contracts import (
        AuthenticatedActor,
        CommandReceipt,
        DomainContribution,
        EventEnvelope,
        ReceiptStatus,
        ResourceRef,
        canonical_json,
        validate_replay,
    )
    from herzchen.kernel.operations import (
        OPERATION_SCHEMA_REVISION,
        OperationManager,
        OperationRequest,
        request_digest,
    )
    from herzchen.kernel.store import (
        IdentityRecord,
        RuntimeOperationOwner as HerzchenRuntimeOperationOwner,
        RuntimeOperationReader as HerzchenRuntimeOperationReader,
        StoreAdmissionError,
        issue_operation_owner,
    )
    _HERZCHEN_IMPORT_ERROR: Optional[BaseException] = None
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by standalone installs
    ContentCommandHandler = ExtensionCommandService = None  # type: ignore[assignment]
    HerzchenHostAdapter = None  # type: ignore[assignment]
    AuthenticatedActor = CommandReceipt = DomainContribution = EventEnvelope = ReceiptStatus = ResourceRef = None  # type: ignore[assignment]
    canonical_json = validate_replay = None  # type: ignore[assignment]
    OPERATION_SCHEMA_REVISION = "fnd-04.operation.v1"
    OperationManager = None  # type: ignore[assignment]
    OperationRequest = None  # type: ignore[assignment]
    request_digest = None  # type: ignore[assignment]
    IdentityRecord = None  # type: ignore[assignment]
    HerzchenRuntimeOperationOwner = HerzchenRuntimeOperationReader = StoreAdmissionError = issue_operation_owner = None  # type: ignore[assignment]
    _HERZCHEN_IMPORT_ERROR = exc


def _require_herzchen() -> None:
    if _HERZCHEN_IMPORT_ERROR is not None:
        raise HerzchenUnavailable(
            "the pinned Herzchen contract package is required for the shared Runtime binding"
        ) from _HERZCHEN_IMPORT_ERROR


@dataclass(frozen=True)
class RuntimeReceiptBinding:
    """A shared receipt projection plus the unchanged Runtime receipt.

    The projection is intentionally not persisted.  ``runtime_receipt`` is
    the authoritative receipt returned by Runtime's command ledger, including
    its request hash, transaction id, and event ids.
    """

    shared_receipt: Any
    runtime_receipt: Mapping[str, Any]


class RuntimeOperationBindingError(RuntimeError):
    """The shared request/receipt binding was not completed by Runtime."""


_RUNTIME_OPERATION_COMMAND = "herzchen.operation"
_RUNTIME_OPERATION_STREAM = "operations"


def _runtime_descriptor_digest(descriptors: tuple[Any, ...]) -> str:
    """Match FND's canonical descriptor digest without importing its internals."""
    ordered = sorted(descriptors, key=lambda descriptor: descriptor.domain_id)
    return hashlib.sha256(canonical_json([descriptor.to_dict() for descriptor in ordered]).encode("utf-8")).hexdigest()


if HerzchenRuntimeOperationOwner is not None:

    class _RuntimeOperationReader(HerzchenRuntimeOperationReader):
        """Finite read-only view over the existing Runtime owner."""

        __slots__ = ("_owner",)

        def __init__(self, owner: "_RuntimeOperationOwner") -> None:
            self._owner = owner

        @property
        def authority(self) -> str:
            return self._owner.authority

        @property
        def domain_descriptor_digest(self) -> str:
            return self._owner.domain_descriptor_digest

        def registered_domains(self) -> tuple[Any, ...]:
            return self._owner.registered_domains()

        def get_identity(self, ref: Any) -> Any:
            return self._owner.get_identity(ref)

        def get_receipt(self, logical_request_key: str) -> Any:
            return self._owner.get_receipt(logical_request_key)

        def list_events(self, *, stream: str | None = None) -> tuple[Any, ...]:
            return self._owner.list_events(stream=stream)


    class _RuntimeTransaction:
        """Identity wrapper for one already-open Runtime transaction/savepoint."""

        __slots__ = ("owner", "connection")

        def __init__(self, owner: "_RuntimeOperationOwner") -> None:
            self.owner = owner
            self.connection = owner._store.conn


    class _RuntimeOperationOwner(HerzchenRuntimeOperationOwner):
        """FND owner capability backed by Runtime's existing SQLite authority."""

        __slots__ = ("_runtime", "_store", "_authority", "_actor", "reader", "_domains", "_domain_digest")

        def __init__(self, runtime: Any, *, authority: str, actor: Any) -> None:
            self._runtime = runtime
            self._store = getattr(runtime, "store")
            self._authority = authority
            self._actor = actor
            self._domains = (
                DomainContribution(
                    "runtime.operation",
                    "v1",
                    "Runtime",
                    ("operation", "runtime.project", "runtime.task"),
                    (),
                    (),
                    ("task.admit",),
                    ("operation.prepared", "operation.outcome"),
                    "runtime.operation.v1",
                    ("runtime.task",),
                ),
            )
            self._domain_digest = _runtime_descriptor_digest(self._domains)
            self.reader = _RuntimeOperationReader(self)

        @property
        def authority(self) -> str:
            return self._authority

        @property
        def domain_descriptor_digest(self) -> str:
            return self._domain_digest

        def registered_domains(self) -> tuple[Any, ...]:
            return self._domains

        @contextmanager
        def transaction(self):
            with self._store._transaction():
                yield _RuntimeTransaction(self)

        def _require_transaction(self, transaction: Any) -> _RuntimeTransaction:
            if not isinstance(transaction, _RuntimeTransaction) or transaction.owner is not self:
                raise RuntimeOperationBindingError("FND operation mutation must use the active Runtime owner transaction")
            if not self._store.conn.in_transaction:
                raise RuntimeOperationBindingError("Runtime owner transaction is no longer active")
            return transaction

        def _operation_row(self, logical_request_key: str, *, target_id: str | None = None):
            if target_id is None:
                return self._store.conn.execute(
                    "SELECT rowid, * FROM command_idempotency WHERE command_kind=? AND idempotency_key=? ORDER BY rowid DESC LIMIT 1",
                    (_RUNTIME_OPERATION_COMMAND, logical_request_key),
                ).fetchone()
            return self._store.conn.execute(
                "SELECT rowid, * FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=? ORDER BY rowid DESC LIMIT 1",
                (_RUNTIME_OPERATION_COMMAND, target_id, logical_request_key),
            ).fetchone()

        @staticmethod
        def _operation_body(row: Any) -> Mapping[str, Any]:
            if row is None:
                return {}
            value = json.loads(row["result_json"])
            return value if isinstance(value, Mapping) else {}

        def _operation_event(self, row: Any) -> Any:
            body = self._operation_body(row)
            event_id = str(body.get("event_id"))
            event = self._store.conn.execute("SELECT * FROM events WHERE id=?", (int(event_id),)).fetchone()
            if event is None:
                raise RuntimeOperationBindingError("Runtime operation event lineage is missing")
            metadata = json.loads(event["payload_json"]).get("__herzchen__")
            if not isinstance(metadata, Mapping):
                raise RuntimeOperationBindingError("Runtime operation event metadata is missing")
            return self._event_from_metadata(event, metadata)

        def _event_from_metadata(self, event: Any, metadata: Mapping[str, Any]) -> Any:
            return EventEnvelope(
                str(event["id"]),
                self.authority,
                str(metadata["stream"]),
                ResourceRef.from_dict(metadata["subject"]),
                str(metadata["schema_revision"]),
                str(metadata["event_type"]),
                int(event["id"]),
                AuthenticatedActor.from_dict(metadata["actor"]),
                str(metadata["operation"]),
                metadata.get("correlation_id"),
                metadata.get("causation_id"),
                str(event["created_at"]),
                str(event["created_at"]),
                tuple(ResourceRef.from_dict(value) for value in metadata.get("before_refs", ())),
                tuple(ResourceRef.from_dict(value) for value in metadata.get("after_refs", ())),
                metadata.get("effects", {}),
            )

        def _validate_envelope(self, envelope: Any, *, event_type: str, target: Any) -> None:
            if envelope.target != target or target.authority != self.authority or target.kind != "operation":
                raise RuntimeOperationBindingError("Runtime operation target is outside the admitted owner domain")
            if envelope.context.actor != self._actor:
                raise RuntimeOperationBindingError("Runtime operation actor is not the admitted Runtime owner actor")
            if envelope.operation == "task.admit":
                expected_event = "operation.prepared"
            elif envelope.operation == "operation.outcome":
                expected_event = "operation.outcome"
            else:
                raise RuntimeOperationBindingError("Runtime operation name is not admitted")
            if event_type != expected_event:
                raise RuntimeOperationBindingError("Runtime operation event is not admitted for the operation")
            if not isinstance(envelope.payload, Mapping) or envelope.payload.get("record_type") != "operation":
                raise RuntimeOperationBindingError("Runtime operation payload is not an admitted operation record")
            payload_key = envelope.payload.get("logical_request_key")
            expected_key = envelope.context.logical_request_key
            if envelope.operation == "operation.outcome":
                expected_key = expected_key.split(":outcome", 1)[0]
            if payload_key != expected_key:
                raise RuntimeOperationBindingError("Runtime operation logical key is not bound to its envelope")
            if not isinstance(envelope.payload.get("request_digest"), str):
                raise RuntimeOperationBindingError("Runtime operation payload is missing its canonical request digest")

        def _task_for_operation(self, envelope: Any) -> Any:
            request_payload = envelope.payload.get("request_payload")
            project_id = request_payload.get("project") if isinstance(request_payload, Mapping) else None
            if not project_id:
                raise RuntimeOperationBindingError("Runtime operation is missing its project owner")
            row = self._store.conn.execute(
                "SELECT r.id AS run_id, t.id AS task_id FROM runs r JOIN tasks t ON t.run_id=r.id WHERE r.project_id=? AND r.idempotency_key=?",
                (str(project_id), envelope.context.logical_request_key.split(":outcome", 1)[0]),
            ).fetchone()
            if row is None:
                raise RuntimeOperationBindingError("Runtime operation has no admitted Runtime task owner")
            return row

        def mutate(self, envelope: Any, *, event_type: str, result_ref: Any = None, before_refs: tuple[Any, ...] = (), after_refs: tuple[Any, ...] = (), effects: Mapping[str, Any] | None = None, stream: str | None = None, event_schema_revision: str = "fnd-03.event.v1", occurred_at: str | None = None, no_op: bool = False, transaction: Any = None) -> Any:
            tx = self._require_transaction(transaction)
            target = result_ref if result_ref is not None else envelope.target
            self._validate_envelope(envelope, event_type=event_type, target=envelope.target)
            if stream != _RUNTIME_OPERATION_STREAM:
                raise RuntimeOperationBindingError("Runtime operation stream is not admitted")
            prior = self.get_receipt(envelope.context.logical_request_key)
            if prior is not None:
                validate_replay(prior, envelope)
                return replace(prior, replayed=True)
            task = self._task_for_operation(envelope)
            operation_effects = dict(effects or {})
            metadata = {
                "stream": _RUNTIME_OPERATION_STREAM,
                "subject": envelope.target.to_dict(),
                "schema_revision": event_schema_revision,
                "event_type": event_type,
                "actor": envelope.context.actor.to_dict(),
                "operation": envelope.operation,
                "correlation_id": envelope.context.correlation_id,
                "causation_id": envelope.context.causation_id,
                "before_refs": [ref.to_dict() for ref in before_refs],
                "after_refs": [ref.to_dict() for ref in after_refs],
                "effects": operation_effects,
            }
            event_id = self._store._append_event(task["run_id"], task["task_id"], event_type, {"__herzchen__": metadata})
            operation_result = {
                "record_type": "operation",
                "event_id": str(event_id),
                "event_type": event_type,
                "operation": envelope.operation,
                "schema_revision": envelope.schema_revision,
                "logical_request_key": envelope.context.logical_request_key,
                "request_digest": envelope.context.request_digest,
                "target": envelope.target.to_dict(),
                "effects": operation_effects,
            }
            txn_id = self._store._record_command_receipt(
                _RUNTIME_OPERATION_COMMAND,
                envelope.target.id,
                envelope.context.logical_request_key,
                envelope.context.request_digest,
                operation_result,
                project_id=str(envelope.payload["request_payload"]["project"]),
                event_ids=(event_id,),
                primary_stream_id=task["run_id"],
                resulting_stream_seq=int(event_id),
            )
            row = self._operation_row(envelope.context.logical_request_key, target_id=envelope.target.id)
            return CommandReceipt(
                envelope.context.logical_request_key,
                envelope.context.request_digest,
                envelope.operation,
                envelope.target,
                ReceiptStatus.NOOP if no_op else ReceiptStatus.COMMITTED,
                transaction_id=txn_id,
                event_ids=(str(event_id),),
                result_ref=target,
                replayed=False,
                observed_revision=target.revision,
            )

        def get_identity(self, ref: Any) -> Any:
            if not isinstance(ref, ResourceRef) or ref.authority != self.authority or ref.kind != "operation":
                return None
            row = self._store.conn.execute(
                "SELECT rowid, * FROM command_idempotency WHERE command_kind=? AND aggregate_id=? ORDER BY rowid DESC LIMIT 1",
                (_RUNTIME_OPERATION_COMMAND, ref.id),
            ).fetchone()
            if row is None:
                return None
            body = self._operation_body(row)
            event = self._operation_event(row)
            effects = dict(event.effects)
            revision = body.get("target", {}).get("revision") or "rev-{}".format(int(effects.get("version", 1)))
            payload = {
                "record_type": "operation",
                "operation": body.get("operation", "task.admit"),
                "schema_revision": body.get("schema_revision", OPERATION_SCHEMA_REVISION),
                "adapter_ref": effects.get("adapter_ref"),
                "request_actor": effects.get("request_actor"),
                "logical_request_key": effects.get("logical_request_key", ref.id),
                "request_digest": effects.get("request_digest", row["request_hash"]),
                "request_payload": effects.get("request_payload", {}),
                "physical_invocation_ref": effects.get("physical_invocation_ref"),
                "external_owner_ref": effects.get("external_owner_ref"),
                "expected_revision": effects.get("expected_revision"),
                "expected_version": effects.get("expected_version"),
                "edit_token": effects.get("edit_token"),
                "correlation_id": effects.get("correlation_id"),
                "causation_id": effects.get("causation_id"),
                "state": effects.get("state", "prepared"),
                "result": effects.get("result", {}),
            }
            return IdentityRecord(
                ResourceRef(self.authority, "operation", ref.id, revision),
                int(effects.get("version", 1)),
                payload,
                None,
                str(row["created_at"]),
                str(row["created_at"]),
            )

        def get_receipt(self, logical_request_key: str) -> Any:
            row = self._operation_row(logical_request_key)
            if row is None:
                return None
            body = self._operation_body(row)
            target = ResourceRef.from_dict(body["target"])
            effects = body.get("effects", {})
            return CommandReceipt(
                logical_request_key,
                str(row["request_hash"]),
                str(body.get("operation", "task.admit")),
                target,
                ReceiptStatus.COMMITTED,
                transaction_id=str(row["txn_id"]),
                event_ids=tuple(str(value) for value in json.loads(row["event_ids_json"] or "[]")),
                result_ref=target,
                observed_revision=target.revision,
            )

        def list_events(self, *, stream: str | None = None) -> tuple[Any, ...]:
            rows = self._store.conn.execute("SELECT * FROM events ORDER BY id").fetchall()
            values = []
            for row in rows:
                payload = json.loads(row["payload_json"])
                metadata = payload.get("__herzchen__") if isinstance(payload, Mapping) else None
                if not isinstance(metadata, Mapping):
                    continue
                if stream is not None and metadata.get("stream") != stream:
                    continue
                values.append(self._event_from_metadata(row, metadata))
            return tuple(values)

        def lookup_replay(self, envelope: Any) -> Any:
            prior = self.get_receipt(envelope.context.logical_request_key)
            if prior is not None:
                validate_replay(prior, envelope)
            return prior

        def event_lineage(self, receipt: Any) -> tuple[Any, ...]:
            wanted = set(receipt.event_ids)
            return tuple(event for event in self.list_events() if event.event_id in wanted)


def _contract_json(value: Any) -> Any:
    """Convert shared contract records to the Runtime JSON boundary."""
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _contract_json(value.to_dict())
    if isinstance(value, Mapping):
        return {str(key): _contract_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_contract_json(child) for child in value]
    return value


class _RuntimeGenericReader(HerzchenRuntimeOperationReader if HerzchenRuntimeOperationReader is not None else object):
    """Finite read view supplied to DAT content/extension consumers."""

    __slots__ = ("_writer",)

    def __init__(self, writer: "_RuntimeGenericWriter") -> None:
        self._writer = writer

    @property
    def authority(self) -> str:
        return self._writer.authority

    def get_identity(self, ref: Any) -> Any:
        return self._writer.get_identity(ref)

    def get_reference(self, ref: Any) -> Any:
        return self._writer.get_reference(ref)

    def list_events(self, *, stream: str | None = None) -> tuple[Any, ...]:
        return ()


class _RuntimeGenericWriter:
    """DAT writer seam backed by the already-open Runtime RealmStore.

    This adapter deliberately contains no connection of its own.  Generic
    content identities, immutable revisions, references, and domain admission
    live in Runtime's canonical SQLite realm and share its transaction and
    command receipt boundary.  Core project/shot/document edits are delegated
    to RuntimeService commands so those domains retain their existing owners.
    """

    __slots__ = ("bridge", "runtime", "store", "authority", "reader")

    def __init__(self, bridge: "RuntimeHerzchenBridge") -> None:
        self.bridge = bridge
        self.runtime = bridge.runtime
        self.store = getattr(bridge, "runtime").store
        self.authority = bridge.authority
        self.reader = _RuntimeGenericReader(self)

    @contextmanager
    def transaction(self):
        with self.store._transaction():
            yield self

    def _require_transaction(self, transaction: Any) -> None:
        if transaction is not None and transaction is not self and transaction is not True:
            raise RuntimeOperationBindingError("generic DAT mutation used an unknown Runtime transaction")
        if not self.store.conn.in_transaction:
            raise RuntimeOperationBindingError("generic DAT mutation requires the active Runtime transaction")

    @staticmethod
    def _revision_key(ref: Any) -> str:
        return "" if ref.revision is None else str(ref.revision)

    def _row_for(self, ref: Any) -> Any:
        return self.store.conn.execute(
            "SELECT * FROM herzchen_identities WHERE authority=? AND kind=? AND id=? AND revision=?",
            (ref.authority, ref.kind, ref.id, self._revision_key(ref)),
        ).fetchone()

    def _head_row(self, ref: Any) -> Any:
        return self.store.conn.execute(
            "SELECT i.* FROM herzchen_identity_heads h JOIN herzchen_identities i "
            "ON i.authority=h.authority AND i.kind=h.kind AND i.id=h.id AND i.revision=h.revision "
            "WHERE h.authority=? AND h.kind=? AND h.id=?",
            (ref.authority, ref.kind, ref.id),
        ).fetchone()

    def _identity_from_row(self, row: Any) -> Any:
        if row is None:
            return None
        return IdentityRecord(
            ResourceRef(str(row["authority"]), str(row["kind"]), str(row["id"]), str(row["revision"]) or None),
            int(row["version"]),
            json.loads(row["payload_json"]),
            row["edit_token"],
            str(row["created_at"]),
            str(row["updated_at"]),
        )

    def _core_identity(self, ref: Any) -> Any:
        if ref.authority != self.authority:
            return None
        try:
            if ref.kind == "runtime.project":
                value = self.runtime.get_project(ref.id)
                version = int(value["version"])
                payload = {"record_type": "runtime.project", "metadata": dict(value.get("metadata") or {}), "value": value}
            elif ref.kind == "runtime.shot":
                value = self.runtime.get_project_shot_by_id(ref.id) if hasattr(self.runtime, "get_project_shot_by_id") else None
                if value is None:
                    row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (ref.id,)).fetchone()
                    if row is None:
                        return None
                    value = self.runtime._project_shot_resource(row)
                version = int(value["version"])
                payload = {"record_type": "runtime.shot", "metadata": dict(value.get("metadata") or {}), "value": value}
            elif ref.kind == "runtime.task":
                value = self.runtime.get_task(ref.id)
                task = value.get("task", value) if isinstance(value, Mapping) else value
                version = int(task.get("version", 1)) if isinstance(task, Mapping) else 1
                payload = {"record_type": "runtime.task", "metadata": {}, "value": value}
            else:
                return None
        except Exception:
            return None
        current_ref = ResourceRef(self.authority, ref.kind, ref.id, f"runtime-v{version}")
        if ref.revision is not None and ref.revision != current_ref.revision:
            return None
        return IdentityRecord(current_ref, version, payload, None, str(value.get("created_at", "")) if isinstance(value, Mapping) else "", str(value.get("updated_at", "")) if isinstance(value, Mapping) else "")

    def get_identity(self, ref: Any) -> Any:
        if not isinstance(ref, ResourceRef):
            return None
        core = self._core_identity(ref)
        if core is not None:
            return core
        row = self._row_for(ref) if ref.revision is not None else self._head_row(ref)
        return self._identity_from_row(row)

    def get_reference(self, ref: Any) -> Any:
        if not isinstance(ref, ResourceRef):
            return None
        row = self.store.conn.execute(
            "SELECT 1 FROM herzchen_references WHERE authority=? AND kind=? AND id=? AND revision=?",
            (ref.authority, ref.kind, ref.id, self._revision_key(ref)),
        ).fetchone()
        return ref if row is not None else None

    def consumer(self) -> _RuntimeGenericReader:
        return self.reader

    def registered_domains(self) -> tuple[Any, ...]:
        return tuple(
            DomainContribution.from_dict(json.loads(row["descriptor_json"]))
            for row in self.store.conn.execute("SELECT descriptor_json FROM herzchen_domains ORDER BY domain_id").fetchall()
        )

    def register_domain(self, contribution: Any, **_: Any) -> Any:
        descriptor = _contract_json(contribution)
        domain_id = str(contribution.domain_id)
        existing = self.store.conn.execute("SELECT descriptor_json FROM herzchen_domains WHERE domain_id=?", (domain_id,)).fetchone()
        if existing is not None:
            if json.loads(existing["descriptor_json"]) != descriptor:
                raise RuntimeOperationBindingError("Runtime DAT domain admission differs from the persisted descriptor")
            return contribution
        self.store.conn.execute(
            "INSERT INTO herzchen_domains(domain_id, descriptor_json, created_at) VALUES (?, ?, ?)",
            (domain_id, canonical_json(descriptor), now()),
        )
        return contribution

    def _project_id_for_ref(self, ref: Any, payload: Mapping[str, Any] | None = None) -> str | None:
        if ref.kind == "runtime.project":
            return ref.id
        if ref.kind == "runtime.shot":
            row = self.store.conn.execute("SELECT project_id FROM project_shots WHERE id=?", (ref.id,)).fetchone()
            return None if row is None else str(row["project_id"])
        if ref.kind == "runtime.task":
            row = self.store.conn.execute("SELECT r.project_id FROM tasks t JOIN runs r ON r.id=t.run_id WHERE t.id=?", (ref.id,)).fetchone()
            return None if row is None else str(row["project_id"])
        if payload:
            document = payload.get("document")
            scope = getattr(document, "authoring_scope", None)
            if isinstance(scope, ResourceRef):
                return scope.id
            if isinstance(scope, Mapping):
                return str(scope.get("id")) if scope.get("id") else None
            raw = payload.get("project_id")
            if raw:
                return str(raw)
        row = self.store.conn.execute("SELECT project_id FROM project_documents WHERE id=?", (ref.id,)).fetchone()
        return None if row is None else str(row["project_id"])

    def _runtime_receipt(self, result: Any, *, kind: str, aggregate_id: str, key: str, project_id: str | None) -> Mapping[str, Any] | None:
        if isinstance(result, Mapping) and isinstance(result.get("receipt"), Mapping):
            return result["receipt"]
        if project_id:
            return self.runtime.committed_receipt(kind, aggregate_id, key, project_id=project_id)
        return None

    def _store_generic_receipt(self, envelope: Any, result: Any, *, runtime_receipt: Mapping[str, Any] | None, project_id: str | None, result_ref: Any, replayed: bool = False) -> Any:
        command_kind = "herzchen." + str(envelope.operation)
        aggregate_id = str(envelope.target.id)
        key = str(envelope.context.logical_request_key)
        event_ids = tuple(str(item) for item in (runtime_receipt or {}).get("event_ids", ()))
        transaction_id = str((runtime_receipt or {}).get("receipt_id") or ("txn-" + new_id()))
        stored_result = {
            "target": envelope.target,
            "result_ref": result_ref,
            "data": result,
            "transaction_id": transaction_id,
        }
        if not replayed:
            existing = self.store.conn.execute(
                "SELECT request_hash FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
                (command_kind, aggregate_id, key),
            ).fetchone()
            if existing is None:
                project_seq = (runtime_receipt or {}).get("project_seq") or (None, None)
                self.store.conn.execute(
                    "INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at, txn_id, first_project_seq, last_project_seq, event_ids_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (command_kind, aggregate_id, key, envelope.context.request_digest, canonical_json(stored_result), now(), transaction_id, project_seq[0], project_seq[-1], canonical_json(list(event_ids))),
                )
        status = ReceiptStatus.COMMITTED
        return CommandReceipt(
            key,
            envelope.context.request_digest,
            envelope.operation,
            envelope.target,
            status,
            transaction_id=transaction_id,
            event_ids=event_ids,
            result_ref=result_ref,
            replayed=replayed,
            observed_revision=result_ref.revision if isinstance(result_ref, ResourceRef) else envelope.target.revision,
        )

    def get_receipt(self, logical_request_key: str) -> Any:
        row = self.store.conn.execute(
            "SELECT * FROM command_idempotency WHERE command_kind LIKE 'herzchen.%' AND idempotency_key=? ORDER BY rowid DESC LIMIT 1",
            (logical_request_key,),
        ).fetchone()
        if row is None:
            return None
        body = json.loads(row["result_json"])
        target = ResourceRef.from_dict(body["target"])
        result_ref = ResourceRef.from_dict(body["result_ref"]) if body.get("result_ref") else None
        return CommandReceipt(
            logical_request_key,
            str(row["request_hash"]),
            str(row["command_kind"])[len("herzchen."):],
            target,
            ReceiptStatus.COMMITTED,
            transaction_id=str(row["txn_id"]),
            event_ids=tuple(str(value) for value in json.loads(row["event_ids_json"] or "[]")),
            result_ref=result_ref,
            observed_revision=result_ref.revision if result_ref is not None else target.revision,
        )

    def _put_row(self, ref: Any, payload: Mapping[str, Any], *, version: int, edit_token: str | None = None) -> Any:
        stamp = now()
        revision = self._revision_key(ref)
        encoded = canonical_json(_contract_json(payload))
        self.store.conn.execute(
            "INSERT OR REPLACE INTO herzchen_identities(authority, kind, id, revision, version, payload_json, edit_token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM herzchen_identities WHERE authority=? AND kind=? AND id=? AND revision=?), ?), ?)",
            (ref.authority, ref.kind, ref.id, revision, int(version), encoded, edit_token, ref.authority, ref.kind, ref.id, revision, stamp, stamp),
        )
        return self.get_identity(ref)

    def _put_head(self, ref: Any, payload: Mapping[str, Any], *, version: int, edit_token: str | None = None) -> Any:
        self._put_row(ref, payload, version=version, edit_token=edit_token)
        revision = self._revision_key(ref)
        self.store.conn.execute(
            "INSERT OR REPLACE INTO herzchen_identity_heads(authority, kind, id, revision, version, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (ref.authority, ref.kind, ref.id, revision, int(version), now()),
        )
        return self.get_identity(ResourceRef(ref.authority, ref.kind, ref.id))

    def put_identity(self, ref: Any, payload: Mapping[str, Any], *, version: int = 1, transaction: Any = None, **_: Any) -> Any:
        self._require_transaction(transaction)
        return self._put_row(ref, payload, version=version)

    def revise_identity(self, current_ref: Any, payload: Mapping[str, Any], *, revision: str, expected_revision: str | None = None, expected_version: int | None = None, expected_edit_token: str | None = None, transaction: Any = None, **_: Any) -> Any:
        self._require_transaction(transaction)
        current = self.get_identity(current_ref)
        if current is None:
            raise RuntimeOperationBindingError("generic identity to revise was not found")
        if expected_revision is not None and current.ref.revision != expected_revision:
            raise RuntimeOperationBindingError("generic identity revision conflict")
        if expected_version is not None and current.version != expected_version:
            raise RuntimeOperationBindingError("generic identity version conflict")
        next_ref = ResourceRef(current.ref.authority, current.ref.kind, current.ref.id, revision)
        return self._put_head(next_ref, payload, version=current.version + 1, edit_token=expected_edit_token)

    def put_reference(self, ref: Any, *, transaction: Any = None) -> Any:
        self._require_transaction(transaction)
        self.store.conn.execute(
            "INSERT OR IGNORE INTO herzchen_references(authority, kind, id, revision, created_at) VALUES (?, ?, ?, ?, ?)",
            (ref.authority, ref.kind, ref.id, self._revision_key(ref), now()),
        )
        return ref

    def _delegate_core(self, envelope: Any) -> tuple[Any, Mapping[str, Any] | None, str | None]:
        payload = envelope.payload
        project_id = self._project_id_for_ref(envelope.target, payload)
        key = str(envelope.context.logical_request_key)
        operation = str(envelope.operation)
        if operation == "dat.content.document.create":
            document = payload["document"]
            revision = payload["revision"]
            project_id = self._project_id_for_ref(envelope.target, payload)
            result = self.runtime.create_document(project_id, {"document_id": document.ref.id, "kind": document.role, "content": revision.content}, idempotency_key=key)
            return result.get("data", result) if isinstance(result, Mapping) else result, self._runtime_receipt(result, kind="document.create", aggregate_id=document.ref.id, key=key, project_id=project_id), project_id
        if operation == "dat.content.revision.append":
            document = payload["document"]
            revision = payload["revision"]
            current = self.runtime.get_document(project_id, document.ref.id)
            result = self.runtime.update_document(project_id, document.ref.id, {"expected_version": int(current["version"]), "content": revision.content, "kind": document.role}, idempotency_key=key)
            return result.get("data", result) if isinstance(result, Mapping) else result, self._runtime_receipt(result, kind="document.update", aggregate_id=document.ref.id, key=key, project_id=project_id), project_id
        if operation.startswith("dat.extensions.metadata."):
            subject = envelope.target
            next_payload = payload
            if subject.kind == "runtime.project":
                result = self.runtime.update_project(subject.id, {"expected_version": int(envelope.context.expected_version), "metadata": next_payload.get("metadata", {})}, idempotency_key=key)
                return result, self._runtime_receipt(result, kind="project.update", aggregate_id=subject.id, key=key, project_id=project_id), project_id
            if subject.kind == "runtime.shot":
                result = self.runtime.update_project_shot(project_id, subject.id, {"expected_version": int(envelope.context.expected_version), "metadata": next_payload.get("metadata", {})}, idempotency_key=key)
                return result.get("data", result) if isinstance(result, Mapping) else result, self._runtime_receipt(result, kind="shot.update", aggregate_id=subject.id, key=key, project_id=project_id), project_id
            version = int(envelope.context.expected_version or 0) + 1
            self._put_head(subject, next_payload, version=version)
            return next_payload, None, project_id
        return payload, None, project_id

    def mutate(self, envelope: Any, *, result_ref: Any = None, before_refs: tuple[Any, ...] = (), after_refs: tuple[Any, ...] = (), effects: Mapping[str, Any] | None = None, transaction: Any = None, identity_payload: Mapping[str, Any] | None = None, **_: Any) -> Any:
        self._require_transaction(transaction)
        prior = self.get_receipt(envelope.context.logical_request_key)
        if prior is not None:
            if prior.request_digest != envelope.context.request_digest:
                raise RuntimeOperationBindingError("generic logical request key was reused with changed input")
            return replace(prior, replayed=True)
        result, runtime_receipt, project_id = self._delegate_core(envelope)
        final_ref = result_ref or envelope.target
        if identity_payload is not None and isinstance(final_ref, ResourceRef) and final_ref.revision is not None:
            version = int(envelope.context.expected_version or 0) + 1
            self._put_head(envelope.target, identity_payload, version=max(1, version))
        if envelope.operation in {"dat.content.link", "dat.content.unlink"}:
            association = envelope.payload.get("association")
            if association is not None:
                self._put_row(envelope.target, {"record_type": "dat.content.association", "association": _contract_json(association), "active": envelope.operation.endswith("link")}, version=1)
                self.store.conn.execute("INSERT OR IGNORE INTO herzchen_references(authority, kind, id, revision, created_at) VALUES (?, ?, ?, ?, ?)", (envelope.target.authority, envelope.target.kind, envelope.target.id, "", now()))
        return self._store_generic_receipt(envelope, result, runtime_receipt=runtime_receipt, project_id=project_id, result_ref=final_ref)


@dataclass
class RuntimeTaskOperationBinding:
    """One shared task request bound to Runtime's existing owner transaction.

    The qualified Herzchen ``OperationManager`` is issued a finite Runtime
    owner capability.  Its operation identity, event lineage, and receipt are
    recorded through Runtime's existing command/event authority in the same
    owner transaction as task admission.  It never opens a second store or
    writer.
    """

    bridge: "RuntimeHerzchenBridge"
    request: Any
    target: Any
    _receipt_binding: RuntimeReceiptBinding | None = None
    operation_record: Any | None = None

    @property
    def request_digest(self) -> str:
        return str(self.request.request_digest)

    @property
    def receipt_binding(self) -> RuntimeReceiptBinding | None:
        return self._receipt_binding

    def bind_receipt(self, runtime_receipt: Mapping[str, Any], *, replayed: bool = False) -> RuntimeReceiptBinding:
        if self._receipt_binding is not None:
            raise RuntimeOperationBindingError("Runtime shared receipt binding was invoked twice")
        binding = self.bridge.receipt(
            runtime_receipt,
            request=self.request,
            target=self.target,
            replayed=replayed,
        )
        if binding is None:
            raise RuntimeOperationBindingError("Runtime committed task receipt could not be projected")
        self._receipt_binding = binding
        return binding

    def require_bound(self) -> RuntimeReceiptBinding:
        if self._receipt_binding is None:
            raise RuntimeOperationBindingError(
                "Runtime task mutation bypassed the shared Herzchen receipt binding"
            )
        return self._receipt_binding

    def record_operation(self, transaction: Any) -> Any:
        if self.operation_record is not None:
            raise RuntimeOperationBindingError("Runtime shared operation was recorded twice")
        self.operation_record = self.bridge.operation_manager.prepare(
            self.request,
            transaction=transaction,
        )
        if self.operation_record.receipt is None:
            raise RuntimeOperationBindingError("Runtime shared operation did not return a durable receipt")
        return self.operation_record


class RuntimeHerzchenBridge:
    """Thin shared-contract ports over one admitted ``RuntimeService`` owner."""

    def __init__(
        self,
        runtime: Any,
        *,
        authority: str | None = None,
        actor_id: str = "astrid-runtime",
        credential_ref: str = "runtime-owner",
    ) -> None:
        _require_herzchen()
        if runtime is None or not hasattr(runtime, "store"):
            raise TypeError("runtime must be an admitted RuntimeService-like owner")
        self.runtime = runtime
        realm_id = str(getattr(runtime, "realm", {}).get("id", "runtime"))
        self.authority = authority or f"runtime-{realm_id}"
        self.actor_id = actor_id
        self.credential_ref = credential_ref
        if HerzchenRuntimeOperationOwner is None or OperationManager is None:
            raise HerzchenUnavailable("the installed Herzchen package lacks the Runtime owner capability")
        self._operation_owner = _RuntimeOperationOwner(
            runtime,
            authority=self.authority,
            actor=self.actor,
        )
        self._operation_owner_capability = issue_operation_owner(self._operation_owner)
        self.operation_manager = OperationManager(self._operation_owner)
        if ContentCommandHandler is None or ExtensionCommandService is None:
            raise HerzchenUnavailable("the installed Herzchen package lacks DAT content/extension contracts")
        self._generic_writer = _RuntimeGenericWriter(self)
        self.content = None
        self.extensions = None
        self.generic_contract_error = None
        try:
            self.content = ContentCommandHandler(self._generic_writer)
            self.extensions = ExtensionCommandService(self._generic_writer)
        except StoreAdmissionError as exc:
            # Keep the already-proven operation bridge usable while the
            # installed shared command facade lacks the foreign Runtime
            # domain-owner capability.  Do not counterfeit DAT support or
            # widen the local adapter into a second Store.
            self.generic_contract_error = HerzchenUnavailable(
                "the installed Herzchen command facade cannot issue DAT ports over the Runtime owner"
            )
            self.content = None
            self.extensions = None

    @property
    def actor(self) -> Any:
        return AuthenticatedActor(self.authority, self.actor_id, self.credential_ref)

    def _ref(self, kind: str, value: str, *, revision: str | None = None) -> Any:
        return ResourceRef(self.authority, kind, str(value), revision)

    def project_ref(self, project_id: str) -> Any:
        """Resolve the stable canonical Runtime project identity.

        Operation identity must replay after unrelated project edits, so the
        operation target is deliberately unpinned.  Runtime's own command
        receipt retains the concrete project sequence/version facts.
        """
        project = self.runtime.get_project(project_id)
        return self._ref("runtime.project", project["id"])

    def task_ref(self, task_id: str) -> Any:
        task = self.runtime.get_task(task_id)
        task_value = task.get("task", task) if isinstance(task, Mapping) else task
        task_id_value = task_value.get("id", task_id) if isinstance(task_value, Mapping) else task_id
        version = task_value.get("version") if isinstance(task_value, Mapping) else None
        revision = f"runtime-v{int(version)}" if isinstance(version, int) else None
        return self._ref("runtime.task", str(task_id_value), revision=revision)

    def object_ref(self, object_id: str) -> Any:
        canonical = str(object_id)
        return self._ref("runtime.object", canonical.removeprefix("sha256:"))

    def operation(
        self,
        operation: str,
        *,
        logical_request_key: str,
        target: Any,
        payload: Mapping[str, Any],
        project_id: str | None = None,
        physical_invocation_id: str | None = None,
    ) -> Any:
        """Create Herzchen's typed operation request without writing it.

        Runtime remains the writer.  The shared request object fixes the
        operation identity and context used by the consumer boundary; the
        Runtime command ledger records the actual mutation and receipt.
        """
        if not isinstance(target, ResourceRef):
            raise TypeError("target must be a Herzchen ResourceRef")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        adapter_ref = self._ref("runtime.adapter", "astrid-runtime")
        external_owner = self.project_ref(project_id) if project_id is not None else None
        physical = (
            self._ref("runtime.invocation", physical_invocation_id)
            if physical_invocation_id is not None
            else None
        )
        seed_digest = request_digest({"operation": operation, "payload": dict(payload)})
        request = OperationRequest(
            operation,
            OPERATION_SCHEMA_REVISION,
            adapter_ref,
            self.actor,
            logical_request_key,
            seed_digest,
            dict(payload),
            physical_invocation_ref=physical,
            external_owner_ref=external_owner,
        )
        return request.canonicalized(target)

    def task_operation(self, body: Mapping[str, Any]) -> RuntimeTaskOperationBinding:
        """Admit one task request identity before Runtime opens its writer tx."""
        if not isinstance(body, Mapping):
            raise TypeError("task body must be a mapping")
        project_id = body.get("project")
        idempotency_key = body.get("idempotency_key")
        if not project_id or not idempotency_key:
            raise RuntimeOperationBindingError(
                "shared task binding requires project and idempotency_key"
            )
        target = self._ref("operation", str(idempotency_key))
        request = self.operation(
            "task.admit",
            logical_request_key=str(idempotency_key),
            target=target,
            payload=dict(body),
            project_id=str(project_id),
        )
        return RuntimeTaskOperationBinding(self, request, target)

    def receipt(
        self,
        result: Mapping[str, Any] | None,
        *,
        request: Any,
        target: Any | None = None,
        replayed: bool | None = None,
    ) -> RuntimeReceiptBinding | None:
        """Project a Runtime command receipt into Herzchen's receipt contract."""
        if not isinstance(result, Mapping):
            return None
        runtime_receipt = result.get("receipt")
        if runtime_receipt is None and "receipt_id" in result:
            runtime_receipt = result
        if not isinstance(runtime_receipt, Mapping):
            return None
        if target is None:
            raise TypeError("target is required when projecting a Runtime receipt")
        event_ids = tuple(str(value) for value in runtime_receipt.get("event_ids", ()))
        raw_status = runtime_receipt.get("status", "committed")
        try:
            status = ReceiptStatus(raw_status)
        except ValueError as exc:
            raise ValueError(f"unsupported Runtime receipt status: {raw_status!r}") from exc
        runtime_replayed = runtime_receipt.get("replayed", False)
        if not isinstance(runtime_replayed, bool):
            raise ValueError("Runtime receipt replayed field must be boolean when present")
        if replayed is not None:
            if not isinstance(replayed, bool):
                raise TypeError("replayed must be boolean when supplied")
            runtime_replayed = replayed
        project_seq = runtime_receipt.get("project_seq")
        observed_revision = None
        if isinstance(project_seq, (list, tuple)) and project_seq:
            observed_revision = f"runtime-seq-{int(project_seq[-1])}"
        transaction_id = runtime_receipt.get("receipt_id", runtime_receipt.get("transaction_id"))
        error_code = runtime_receipt.get("error_code")
        unknown_reason = runtime_receipt.get("unknown_reason")
        if status == ReceiptStatus.FAILED and not error_code:
            raise ValueError("failed Runtime receipts require error_code")
        if status == ReceiptStatus.UNKNOWN and not unknown_reason:
            raise ValueError("unknown Runtime receipts require unknown_reason")
        if status == ReceiptStatus.COMMITTED and not transaction_id:
            raise ValueError("committed Runtime receipts require receipt_id or transaction_id")
        shared = CommandReceipt(
            request.logical_request_key,
            request.request_digest,
            request.operation,
            target,
            status,
            transaction_id=str(transaction_id) if transaction_id is not None else None,
            event_ids=event_ids,
            result_ref=target if status in (ReceiptStatus.COMMITTED, ReceiptStatus.NOOP) else None,
            error_code=str(error_code) if error_code is not None else None,
            replayed=runtime_replayed,
            observed_revision=observed_revision,
            unknown_reason=str(unknown_reason) if unknown_reason is not None else None,
        )
        return RuntimeReceiptBinding(shared, dict(runtime_receipt))

    def events(self, aggregate_id: str | None = None, *, cursor: str | None = None, limit: int = 50) -> Mapping[str, Any]:
        """Read Runtime's authoritative event page without creating a ledger."""
        return self.runtime.events_page(aggregate_id, cursor=cursor, limit=limit)

    # These are intentionally boring delegations.  They are the shared
    # consumer ports; validation, transaction scope, CAS publication,
    # idempotency, and lease fencing remain RuntimeService algorithms.
    def ingest(self, project_id: str, data: bytes, *, media_type: str, original_name: str | None, idempotency_key: str) -> Mapping[str, Any]:
        return self.runtime.ingest(
            project_id,
            data,
            media_type=media_type,
            original_name=original_name,
            idempotency_key=idempotency_key,
        )

    def read_object(self, object_id: str) -> Any:
        return self.runtime.object(object_id)

    def admit_task(self, body: Mapping[str, Any], *, enforce_readiness: bool = False) -> Mapping[str, Any]:
        """Route the production task caller through the owner binding."""
        binding = self.task_operation(body)
        with self._operation_owner.transaction() as transaction:
            result = self.runtime._create_task_from_shared(
                dict(body),
                enforce_readiness=enforce_readiness,
                shared_operation=binding,
            )
            binding.record_operation(transaction)
            return result

    def claim_next(self, body: Mapping[str, Any], *, idempotency_key: str) -> Mapping[str, Any]:
        return self.runtime.claim_next(dict(body), idempotency_key=idempotency_key)

    def settle_attempt(self, attempt_id: str, body: Mapping[str, Any], *, idempotency_key: str) -> Mapping[str, Any]:
        return self.runtime.settle_attempt(attempt_id, dict(body), idempotency_key=idempotency_key)

    def fail_attempt(self, attempt_id: str, body: Mapping[str, Any], *, idempotency_key: str) -> Mapping[str, Any]:
        return self.runtime.fail_attempt(attempt_id, dict(body), idempotency_key=idempotency_key)

    def event_projection(self, event: Mapping[str, Any]) -> Any:
        """Expose one Runtime event as a typed Herzchen read projection."""
        aggregate_type = str(event.get("aggregate_type") or "runtime.aggregate")
        subject = self._ref(f"runtime.{aggregate_type}", str(event["aggregate_id"]))
        timestamp = str(event.get("occurred_at") or "")
        return EventEnvelope(
            str(event["event_id"]),
            self.authority,
            "runtime.events",
            subject,
            "runtime.events.v1",
            str(event["event_type"]),
            int(event["sequence"]),
            self.actor,
            str(event["event_type"]),
            None,
            None,
            timestamp,
            timestamp,
            effects=dict(event.get("payload") or {}),
        )

    def host_adapter(self, port: Any, *, owner: str, source: str, worktree: str, launcher: str, requested_model: str = "gpt-5.6-luna", requested_reasoning: str = "medium") -> Any:
        """Bind Herzchen's host adapter to an injected port; no queue is owned."""
        _require_herzchen()
        return HerzchenHostAdapter(
            port,
            owner=owner,
            source=source,
            worktree=worktree,
            launcher=launcher,
            requested_model=requested_model,
            requested_reasoning=requested_reasoning,
        )
