from __future__ import annotations

import base64
import hashlib
import sqlite3

import pytest

from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.service import RuntimeService


CHILD_CAPABILITY = "test.child"
CONTINUATION_CAPABILITY = "test.continuation"


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _setup(service: RuntimeService, slug: str = "continuations") -> tuple[str, str]:
    project = service.create_project({"slug": slug, "name": "Continuations"})
    child_digest = _digest(CHILD_CAPABILITY)
    continuation_digest = _digest(CONTINUATION_CAPABILITY)
    service.register_capability({"capability_id": CHILD_CAPABILITY, "definition_digest": child_digest})
    service.register_capability({"capability_id": CONTINUATION_CAPABILITY, "definition_digest": continuation_digest})
    service.register_executor(
        {"executor_id": "continuation-executor", "capabilities": [CHILD_CAPABILITY, CONTINUATION_CAPABILITY], "max_concurrency": 4},
        idempotency_key="continuation-executor-register",
    )
    return project["id"], continuation_digest


def _child(service: RuntimeService, project_id: str, key: str):
    return service.create_task(
        {
            "project": project_id,
            "capability_id": CHILD_CAPABILITY,
            "capability_digest": _digest(CHILD_CAPABILITY),
            "input_object_ids": [],
            "spec": {"child": key},
            "idempotency_key": key,
        }
    )


def _continuation_body(project_id: str, continuation_digest: str, child_ids: list[str]):
    return {
        "project": project_id,
        "capability_id": CONTINUATION_CAPABILITY,
        "capability_digest": continuation_digest,
        "input_object_ids": [],
        "spec": {
            "runtime_dependencies": {
                "edges": [
                    {
                        "from_task_id": task_id,
                        "to": "self",
                        "requires_event": "task.succeeded",
                        "fence": "runtime_task",
                    }
                    for task_id in child_ids
                ],
                "aggregation": {"kind": "ordered_cas_inputs"},
            }
        },
        "idempotency_key": "two-child-continuation",
    }


def _claim(service: RuntimeService, capability: str, key: str):
    return service.claim_next(
        {
            "executor_id": "continuation-executor",
            "capability_ids": [capability],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=key,
    )


def _claim_children(service: RuntimeService, child_ids: list[str], prefix: str):
    attempts = [
        _claim(service, CHILD_CAPABILITY, f"{prefix}-{index}")
        for index in range(len(child_ids))
    ]
    by_task_id = {attempt["task_id"]: attempt for attempt in attempts}
    assert set(by_task_id) == set(child_ids)
    return by_task_id


def _settle(service: RuntimeService, attempt: dict, key: str, payload: bytes, *, duration_seconds: float | None = None):
    output = {
        "digest": _digest(payload),
        "data_base64": base64.b64encode(payload).decode("ascii"),
    }
    if duration_seconds is not None:
        output["duration_seconds"] = duration_seconds
    return service.settle_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"],
            "runtime_epoch": attempt["runtime_epoch"],
            "outputs": [output],
        },
        idempotency_key=key,
    )


def _event_pages(service: RuntimeService, run_id: str):
    events = []
    cursor = None
    while True:
        page = service.events_page(run_id, cursor=cursor, limit=1)
        events.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            return events


def test_out_of_order_completion_admits_once_in_declared_order_and_paginates(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        project_id, continuation_digest = _setup(service)
        first = _child(service, project_id, "child-first")
        second = _child(service, project_id, "child-second")
        child_ids = [first["task"]["id"], second["task"]["id"]]
        continuation = service.create_task(_continuation_body(project_id, continuation_digest, child_ids))
        continuation_id = continuation["task"]["id"]
        assert continuation["task"]["waiting_reason"] == "waiting_for_dependencies"

        attempts = _claim_children(service, child_ids, "claim-child")
        _settle(service, attempts[child_ids[1]], "settle-second", b"second-output", duration_seconds=2.5)
        assert service.task(continuation_id)["task"]["waiting_reason"] == "waiting_for_dependencies"
        settled = _settle(service, attempts[child_ids[0]], "settle-first", b"first-output", duration_seconds=1.25)
        assert _settle(service, attempts[child_ids[0]], "settle-first", b"first-output", duration_seconds=1.25) == settled
        with pytest.raises(ConflictError, match="different input"):
            _settle(service, attempts[child_ids[0]], "settle-first", b"changed-output")

        ready = service.task(continuation_id)["task"]
        assert ready.get("waiting_reason") is None
        assert ready["spec"]["input_object_ids"] == [_digest(b"first-output"), _digest(b"second-output")]
        resolved = ready["spec"]["spec"]["runtime_dependencies"]["resolved_children"]
        assert [item["task_id"] for item in resolved] == child_ids
        assert [item["ordinal"] for item in resolved] == [0, 1]
        assert [item["outputs"][0]["duration_seconds"] for item in resolved] == [1.25, 2.5]

        events = _event_pages(service, continuation["run"]["id"])
        assert [event["event_type"] for event in events] == ["task.admitted", "task.continuation_admitted"]
        assert events[-1]["payload"]["children"] == resolved
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM continuation_admissions WHERE continuation_task_id=?", (continuation_id,)
        ).fetchone()[0] == 1

        claimed = _claim(service, CONTINUATION_CAPABILITY, "claim-continuation")
        assert claimed["task_id"] == continuation_id
        assert claimed["input_object_ids"] == [_digest(b"first-output"), _digest(b"second-output")]
    finally:
        service.close()


def test_replay_conflict_and_restart_at_continuation_admission(tmp_path):
    root = tmp_path / "realm"
    service = RuntimeService(root)
    project_id, continuation_digest = _setup(service, "restart")
    first = _child(service, project_id, "restart-first")
    second = _child(service, project_id, "restart-second")
    child_ids = [first["task"]["id"], second["task"]["id"]]
    body = _continuation_body(project_id, continuation_digest, child_ids)
    continuation = service.create_task(body)
    assert service.create_task(body) == continuation
    with pytest.raises(ConflictError, match="different input"):
        service.create_task(_continuation_body(project_id, continuation_digest, list(reversed(child_ids))))

    attempts = _claim_children(service, child_ids, "restart-claim-child")
    first_attempt = attempts[child_ids[0]]
    _settle(service, attempts[child_ids[1]], "restart-settle-second", b"restart-second")
    service.store.conn.execute(
        "CREATE TRIGGER abort_continuation_admission BEFORE INSERT ON continuation_admissions "
        "BEGIN SELECT RAISE(ABORT, 'injected continuation admission failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected continuation"):
        _settle(service, first_attempt, "restart-settle-first", b"restart-first")
    assert service.task(first["task"]["id"])["task"]["status"] == "running"
    assert service.task(continuation["task"]["id"])["task"]["waiting_reason"] == "waiting_for_dependencies"
    service.store.conn.execute("DROP TRIGGER abort_continuation_admission")
    stale_attempt = dict(first_attempt)
    service.close()

    service = RuntimeService(root)
    try:
        with pytest.raises(LeaseError):
            _settle(service, stale_attempt, "restart-stale-settlement", b"restart-first")
        service.register_executor(
            {
                "executor_id": "continuation-executor",
                "capabilities": [CHILD_CAPABILITY, CONTINUATION_CAPABILITY],
                "max_concurrency": 4,
                "runtime_epoch": service.health()["runtime_epoch"],
            },
            idempotency_key="continuation-executor-reconnect",
        )
        recovered = _claim(service, CHILD_CAPABILITY, "restart-reclaim-first")
        assert recovered["task_id"] == first["task"]["id"]
        _settle(service, recovered, "restart-settle-recovered", b"restart-first")
        continuation_id = continuation["task"]["id"]
        assert service.task(continuation_id)["task"].get("waiting_reason") is None
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM continuation_admissions WHERE continuation_task_id=?", (continuation_id,)
        ).fetchone()[0] == 1
    finally:
        service.close()


def test_failure_cancel_selected_retry_and_stale_settlement(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        project_id, continuation_digest = _setup(service, "retry")
        first = _child(service, project_id, "retry-first")
        second = _child(service, project_id, "retry-second")
        continuation = service.create_task(
            _continuation_body(project_id, continuation_digest, [first["task"]["id"], second["task"]["id"]])
        )
        child_ids = [first["task"]["id"], second["task"]["id"]]
        attempts = _claim_children(service, child_ids, "retry-claim-child")
        first_attempt = attempts[child_ids[0]]
        second_attempt = attempts[child_ids[1]]
        _settle(service, first_attempt, "retry-settle-first", b"retry-first")
        service.fail_attempt(
            second_attempt["attempt_id"],
            {
                "lease_id": second_attempt["lease_id"],
                "fence": second_attempt["fence"],
                "runtime_epoch": second_attempt["runtime_epoch"],
                "error": {"code": "selected-retry"},
            },
            idempotency_key="retry-fail-second",
        )
        continuation_id = continuation["task"]["id"]
        assert service.task(continuation_id)["task"]["waiting_reason"] == "dependency_failed"
        service.retry_run(
            second["run"]["id"],
            {"selected_task_ids": [second["task"]["id"]]},
            idempotency_key="retry-selected-second",
        )
        assert service.task(continuation_id)["task"]["waiting_reason"] == "waiting_for_dependencies"
        retried = _claim(service, CHILD_CAPABILITY, "retry-reclaim-second")
        _settle(service, retried, "retry-settle-second", b"retry-second")
        assert service.task(continuation_id)["task"].get("waiting_reason") is None

        cancelled_first = _child(service, project_id, "cancel-first")
        cancelled_second = _child(service, project_id, "cancel-second")
        cancelled_continuation = service.create_task(
            {
                **_continuation_body(
                    project_id,
                    continuation_digest,
                    [cancelled_first["task"]["id"], cancelled_second["task"]["id"]],
                ),
                "idempotency_key": "cancel-continuation",
            }
        )
        cancel_child_ids = [cancelled_first["task"]["id"], cancelled_second["task"]["id"]]
        cancel_attempts = _claim_children(service, cancel_child_ids, "cancel-claim-child")
        cancel_attempt = cancel_attempts[cancel_child_ids[0]]
        other_attempt = cancel_attempts[cancel_child_ids[1]]
        service.cancel_task_canonical(cancel_attempt["task_id"], {}, idempotency_key="cancel-child")
        with pytest.raises(LeaseError):
            _settle(service, cancel_attempt, "cancel-stale-settlement", b"cancel-first")
        _settle(service, other_attempt, "cancel-settle-other", b"cancel-second")
        cancelled_continuation_id = cancelled_continuation["task"]["id"]
        assert service.task(cancelled_continuation_id)["task"]["waiting_reason"] == "dependency_cancelled"
        service.retry_task(cancel_attempt["task_id"], {}, idempotency_key="cancel-retry-child")
        recovered = _claim(service, CHILD_CAPABILITY, "cancel-reclaim-first")
        _settle(service, recovered, "cancel-settle-recovered", b"cancel-first")
        assert service.task(cancelled_continuation_id)["task"].get("waiting_reason") is None
    finally:
        service.close()
