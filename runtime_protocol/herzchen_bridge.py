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

from dataclasses import dataclass
from typing import Any, Mapping, Optional


class HerzchenUnavailable(RuntimeError):
    """The shared Herzchen contract package is not available to this process."""


try:  # Keep the Runtime importable in its normal standalone distribution.
    from herzchen.adapters import HerzchenHostAdapter
    from herzchen.contracts import (
        AuthenticatedActor,
        CommandReceipt,
        EventEnvelope,
        ReceiptStatus,
        ResourceRef,
    )
    from herzchen.kernel.operations import (
        OPERATION_SCHEMA_REVISION,
        OperationRequest,
        request_digest,
    )
    _HERZCHEN_IMPORT_ERROR: Optional[BaseException] = None
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by standalone installs
    HerzchenHostAdapter = None  # type: ignore[assignment]
    AuthenticatedActor = CommandReceipt = EventEnvelope = ReceiptStatus = ResourceRef = None  # type: ignore[assignment]
    OPERATION_SCHEMA_REVISION = "fnd-04.operation.v1"
    OperationRequest = None  # type: ignore[assignment]
    request_digest = None  # type: ignore[assignment]
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


@dataclass
class RuntimeTaskOperationBinding:
    """One shared task request bound to Runtime's existing owner transaction.

    Herzchen's qualified ``OperationManager`` owns a Herzchen ``Store`` and
    cannot be pointed at Runtime's task schema.  This small owner-side seam
    therefore carries only the common request identity and typed receipt
    contract into Runtime's already-authoritative transaction.  It never
    opens a second store or writes a second operation ledger.
    """

    bridge: "RuntimeHerzchenBridge"
    request: Any
    target: Any
    _receipt_binding: RuntimeReceiptBinding | None = None

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
        target = self.project_ref(str(project_id))
        request = self.operation(
            "task.admit",
            logical_request_key=str(idempotency_key),
            target=target,
            payload=dict(body),
            project_id=target.id,
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
        return self.runtime._create_task_from_shared(
            dict(body),
            enforce_readiness=enforce_readiness,
            shared_operation=binding,
        )

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
