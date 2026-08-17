from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app import security as security_module
from app.recovery import AgentTombstoneStore, RecoveryConflict


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def identity() -> dict[str, object]:
    return {
        "projectId": 11,
        "targetId": 22,
        "conversationId": "conversation-1",
        "runId": "runtime-run-1",
        "nodeRunId": "node-run-1",
        "workflowId": "workflow-1",
        "workflowRevision": 7,
        "workflowDigest": DIGEST_A,
        "outerNodeId": "ledger-agent",
        "policyRevision": "java-authoritative-v1",
        "requestDigest": DIGEST_B,
        "stateVersion": 9,
        "ledgerDigest": "sha256:" + "c" * 64,
    }


def test_checkpoint_is_idempotent_and_persists_only_finite_metadata(
    tmp_path: Path,
) -> None:
    store = AgentTombstoneStore(tmp_path)
    request = {**identity(), "pendingTaskIds": [102, 101]}

    created = store.checkpoint(request)
    replay = store.checkpoint(request)

    assert created["status"] == "WAITING_TASKS"
    assert replay["reason"] == "CHECKPOINT_EXISTS"
    path = next(tmp_path.glob("project-*/*.json"))
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["pendingTaskIds"] == [101, 102]
    forbidden = {"prompt", "messages", "evidence", "reasoning", "token"}
    assert forbidden.isdisjoint(persisted)
    assert "conversation-1" not in path.name


def test_terminal_callbacks_are_idempotent_and_unlock_only_after_all_tasks(
    tmp_path: Path,
) -> None:
    store = AgentTombstoneStore(tmp_path)
    store.checkpoint({**identity(), "pendingTaskIds": [101, 102]})
    first = {
        **identity(),
        "callbackId": "callback-101",
        "taskId": 101,
        "taskStatus": "SUCCESS",
        "resultDigest": DIGEST_A,
    }

    waiting = store.resume(first)
    replay = store.resume(first)
    ready = store.resume(
        {
            **identity(),
            "callbackId": "callback-102",
            "taskId": 102,
            "taskStatus": "TIMEOUT",
            "resultDigest": DIGEST_B,
        }
    )

    assert waiting["status"] == "WAITING_TASKS"
    assert replay == waiting
    assert ready["status"] == "CONTINUATION_READY"
    assert ready["completedTaskIds"] == [101, 102]
    assert ready["remainingTaskIds"] == []


def test_duplicate_callback_id_with_different_body_is_rejected(tmp_path: Path) -> None:
    store = AgentTombstoneStore(tmp_path)
    store.checkpoint({**identity(), "pendingTaskIds": [101]})
    callback = {
        **identity(),
        "callbackId": "callback-101",
        "taskId": 101,
        "taskStatus": "SUCCESS",
        "resultDigest": DIGEST_A,
    }
    store.resume(callback)

    with pytest.raises(RecoveryConflict) as error:
        store.resume({**callback, "taskStatus": "FAILED"})

    assert error.value.code == "CALLBACK_CONFLICT"


def test_workflow_drift_is_fail_closed_without_mutating_checkpoint(
    tmp_path: Path,
) -> None:
    store = AgentTombstoneStore(tmp_path)
    store.checkpoint({**identity(), "pendingTaskIds": [101]})

    result = store.resume(
        {
            **identity(),
            "workflowDigest": "sha256:" + "d" * 64,
            "callbackId": "callback-101",
            "taskId": 101,
            "taskStatus": "SUCCESS",
            "resultDigest": DIGEST_A,
        }
    )

    assert result["status"] == "STALE"
    assert result["reason"] == "STALE_WORKFLOW"
    persisted = json.loads(
        next(tmp_path.glob("project-*/*.json")).read_text(encoding="utf-8")
    )
    assert persisted["status"] == "WAITING_TASKS"
    assert persisted["taskResults"] == {}


def test_capacity_rejects_new_checkpoint_without_deleting_active_waiters(
    tmp_path: Path,
) -> None:
    store = AgentTombstoneStore(tmp_path, max_records_per_project=16)
    requests = []
    for index in range(16):
        request = {
            **identity(),
            "runId": f"runtime-run-{index:02d}",
            "nodeRunId": f"node-run-{index:02d}",
            "pendingTaskIds": [1000 + index],
        }
        requests.append(request)
        store.checkpoint(request)

    with pytest.raises(RecoveryConflict) as error:
        store.checkpoint(
            {
                **identity(),
                "runId": "runtime-run-new",
                "nodeRunId": "node-run-new",
                "pendingTaskIds": [2000],
            }
        )

    assert error.value.code == "RECOVERY_CAPACITY"
    assert len(list(tmp_path.glob("project-*/*.json"))) == 16
    assert all(
        store._path(store._identity(request)).exists() for request in requests
    )


def test_capacity_removes_completed_record_before_active_waiters(
    tmp_path: Path,
) -> None:
    store = AgentTombstoneStore(tmp_path, max_records_per_project=16)
    completed = {
        **identity(),
        "runId": "runtime-run-done",
        "nodeRunId": "node-run-done",
        "pendingTaskIds": [3000],
    }
    store.checkpoint(completed)
    store.resume(
        {
            **completed,
            "callbackId": "callback-done",
            "taskId": 3000,
            "taskStatus": "SUCCESS",
            "resultDigest": DIGEST_A,
        }
    )
    active = []
    for index in range(15):
        request = {
            **identity(),
            "runId": f"runtime-run-active-{index:02d}",
            "nodeRunId": f"node-run-active-{index:02d}",
            "pendingTaskIds": [4000 + index],
        }
        active.append(request)
        store.checkpoint(request)

    new_request = {
        **identity(),
        "runId": "runtime-run-final",
        "nodeRunId": "node-run-final",
        "pendingTaskIds": [5000],
    }
    store.checkpoint(new_request)

    assert not store._path(store._identity(completed)).exists()
    assert all(
        store._path(store._identity(request)).exists() for request in active
    )
    assert store._path(store._identity(new_request)).exists()


def test_checkpoint_and_resume_endpoints_require_project_hmac_and_are_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "runtime-token-at-least-24-characters"
    secret = "project-signing-secret-at-least-32-characters"
    monkeypatch.setattr(
        security_module,
        "settings",
        replace(
            security_module.settings,
            token=token,
            project_signing_secret=secret,
        ),
    )
    monkeypatch.setattr(main_module, "recovery_store", AgentTombstoneStore(tmp_path))
    client = TestClient(main_module.app)

    def headers(scope: str) -> dict[str, str]:
        expires_at = int(time.time()) + 60
        return {
            "X-AI-Runtime-Token": token,
            "X-AI-Project-Authorization": (
                security_module.project_authorization_value(11, scope, expires_at)
            ),
        }

    checkpoint = {**identity(), "pendingTaskIds": [101]}
    assert client.post(
        "/agent/checkpoint", json=checkpoint, headers=headers("agent")
    ).status_code == 403
    created = client.post(
        "/agent/checkpoint", json=checkpoint, headers=headers("agent-resume")
    )
    assert created.status_code == 200
    callback = {
        **identity(),
        "callbackId": "callback-101",
        "taskId": 101,
        "taskStatus": "SUCCESS",
        "resultDigest": DIGEST_A,
    }
    first = client.post(
        "/agent/resume", json=callback, headers=headers("agent-resume")
    )
    replay = client.post(
        "/agent/resume", json=callback, headers=headers("agent-resume")
    )
    assert first.status_code == 200
    assert first.json()["status"] == "CONTINUATION_READY"
    assert replay.json() == first.json()
