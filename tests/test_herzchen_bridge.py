"""CPU proof for the Runtime-owned Herzchen consumer binding."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from herzchen.adapters import HerzchenHostAdapter
from herzchen.contracts import HostPort, ResourceRef
from runtime_protocol.herzchen_bridge import RuntimeHerzchenBridge, RuntimeOperationBindingError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def test_runtime_owner_consumes_shared_contracts_without_second_store() -> None:
    with TemporaryDirectory() as temporary:
        root = Path(temporary) / "realm"
        RealmStore.initialize(root, realm_id="bridge-realm").close()
        runtime = RuntimeService(root, realm_id="bridge-realm")
        try:
            bridge = RuntimeHerzchenBridge(runtime)
            assert runtime.herzchen is bridge or type(runtime.herzchen) is type(bridge)
            project = bridge.runtime.create_project(
                {"name": "Herzchen bridge", "slug": "herzchen-bridge"},
                idempotency_key="bridge-project-1",
            )
            project_ref = bridge.project_ref(project["id"])
            assert project_ref.id == project["id"]
            assert project_ref.authority == "runtime-bridge-realm"

            request = bridge.operation(
                "project.create",
                logical_request_key="bridge-project-1",
                target=project_ref,
                payload={"slug": "herzchen-bridge", "name": "Herzchen bridge", "metadata": {}},
                project_id=project["id"],
            )
            assert request.external_owner_ref == project_ref
            assert request.request_digest

            runtime_receipt = runtime.committed_receipt(
                "project.create",
                project["id"],
                "bridge-project-1",
                project_id=project["id"],
            )
            binding = bridge.receipt({"receipt": runtime_receipt}, request=request, target=project_ref)
            assert binding is not None
            assert binding.shared_receipt.transaction_id == runtime_receipt["receipt_id"]
            assert binding.runtime_receipt["request_hash"] == runtime_receipt["request_hash"]

            replay = bridge.receipt(
                {
                    "receipt_id": runtime_receipt["receipt_id"],
                    "request_hash": runtime_receipt["request_hash"],
                    "event_ids": [],
                    "status": "committed",
                    "replayed": True,
                },
                request=request,
                target=project_ref,
            )
            assert replay is not None and replay.shared_receipt.replayed is True
            failed = bridge.receipt(
                {"receipt_id": "failure-1", "status": "failed", "error_code": "runtime_failed"},
                request=request,
                target=project_ref,
            )
            assert failed is not None and failed.shared_receipt.status.value == "failed"
            unknown = bridge.receipt(
                {"receipt_id": "unknown-1", "status": "unknown", "unknown_reason": "transport_lost"},
                request=request,
                target=project_ref,
            )
            assert unknown is not None and unknown.shared_receipt.status.value == "unknown"

            task_result = bridge.admit_task(
                {
                    "capability_id": "bridge.cpu",
                    "project": project["id"],
                    "idempotency_key": "bridge-task-1",
                    "spec": {"inputs": {}},
                }
            )
            task_id = task_result["task"]["id"]
            receipt = runtime.committed_receipt(
                "task.create",
                project["id"],
                "bridge-task-1",
                project_id=project["id"],
            )
            expected_request = bridge.task_operation(
                {
                    "capability_id": "bridge.cpu",
                    "project": project["id"],
                    "idempotency_key": "bridge-task-1",
                    "spec": {"inputs": {}},
                }
            )
            assert receipt is not None
            assert receipt["request_hash"] == expected_request.request_digest
            events = bridge.events(task_id)
            assert events["items"]
            projected = bridge.event_projection(events["items"][0])
            assert projected.event_id == events["items"][0]["event_id"]
            assert projected.subject.id == task_id

            content = bridge.ingest(
                project["id"],
                b"shared-cas-input",
                media_type="application/octet-stream",
                original_name="input.bin",
                idempotency_key="bridge-object-1",
            )
            content_data = content["data"]
            object_ref = bridge.object_ref(content_data["object_id"])
            assert object_ref.id == content_data["object_id"].removeprefix("sha256:")
            stored, bytes_value = bridge.read_object(content_data["object_id"])
            assert stored["digest"] == object_ref.id
            assert bytes_value == b"shared-cas-input"

            host = bridge.host_adapter(
                HostPort(),
                owner="astrid-runtime",
                source="cpu-fixture",
                worktree=temporary,
                launcher="/bin/false",
            )
            assert isinstance(host, HerzchenHostAdapter)
            assert not hasattr(bridge, "store")
        finally:
            runtime.close()


def test_runtime_shared_projection_failure_rolls_back_and_replay_binds_once() -> None:
    with TemporaryDirectory() as temporary:
        root = Path(temporary) / "realm"
        RealmStore.initialize(root, realm_id="binding-realm").close()
        runtime = RuntimeService(root, realm_id="binding-realm")
        try:
            project = runtime.create_project(
                {"name": "Binding", "slug": "binding"},
                idempotency_key="binding-project-1",
            )
            body = {
                "capability_id": "binding.cpu",
                "project": project["id"],
                "idempotency_key": "binding-task-1",
                "spec": {"inputs": {}},
            }
            original_receipt = runtime.herzchen.receipt

            def fail_projection(*args, **kwargs):
                raise ValueError("injected shared projection failure")

            runtime.herzchen.receipt = fail_projection
            try:
                runtime.create_task(body)
            except ValueError as exc:
                assert "injected shared projection failure" in str(exc)
            else:
                raise AssertionError("shared projection failure unexpectedly committed")
            assert runtime.store.conn.execute(
                "SELECT 1 FROM runs WHERE idempotency_key=?", (body["idempotency_key"],)
            ).fetchone() is None
            assert runtime.committed_receipt(
                "task.create", project["id"], body["idempotency_key"], project_id=project["id"]
            ) is None

            runtime.herzchen.receipt = original_receipt
            first = runtime.create_task(body)
            second = runtime.create_task(body)
            assert first["task"]["id"] == second["task"]["id"]
            receipt = runtime.committed_receipt(
                "task.create", project["id"], body["idempotency_key"], project_id=project["id"]
            )
            assert receipt is not None
            assert receipt["request_hash"] == runtime.herzchen.task_operation(body).request_digest
        finally:
            runtime.close()


def test_runtime_store_rejects_a_bypassed_shared_binding_before_commit() -> None:
    with TemporaryDirectory() as temporary:
        root = Path(temporary) / "realm"
        RealmStore.initialize(root, realm_id="bypass-realm").close()
        runtime = RuntimeService(root, realm_id="bypass-realm")
        try:
            project = runtime.create_project(
                {"name": "Bypass", "slug": "bypass"},
                idempotency_key="bypass-project-1",
            )

            class Bypass:
                request_digest = "sha256:shared-bypass"

                def bind_receipt(self, *args, **kwargs):
                    return None

                def require_bound(self):
                    raise RuntimeOperationBindingError("test bypass")

            try:
                runtime.store.create_task(
                    "bypass.cpu",
                    {"input_object_ids": [], "schema_version": "1", "spec": {"inputs": {}}},
                    project["id"],
                    "bypass-task-1",
                    None,
                    "sha256:bypass",
                    _shared_operation=Bypass(),
                )
            except RuntimeOperationBindingError as exc:
                assert str(exc) == "test bypass"
            else:
                raise AssertionError("Runtime accepted a mutation that bypassed shared binding")
            assert runtime.store.conn.execute(
                "SELECT 1 FROM runs WHERE idempotency_key='bypass-task-1'"
            ).fetchone() is None
        finally:
            runtime.close()


def test_bridge_source_does_not_admit_a_parallel_store_or_raw_database() -> None:
    source = Path(__file__).parents[1] / "runtime_protocol" / "herzchen_bridge.py"
    text = source.read_text(encoding="utf-8")
    assert "from herzchen.kernel import Store" not in text
    assert "sqlite3" not in text
    assert "runtime.store" not in text
