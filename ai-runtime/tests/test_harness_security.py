from __future__ import annotations

import asyncio
import json
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import graph as graph_module
from app import indexing as indexing_module
from app.graph import SecurityAgentRuntime
from app.indexing import ProjectIndexStore
from app.model import PlannerOutputError, parse_planner_output
from app.schemas import AgentRequest, AuthorizationContext, IndexProjectRequest


@pytest.fixture(autouse=True)
def legacy_harness_path(monkeypatch):
    """Keep the pre-RAG Planner/Harness suite as the feature-off regression path."""
    monkeypatch.setattr(
        graph_module,
        "settings",
        replace(graph_module.settings, rag_enabled=False),
    )


def _collect(runtime: SecurityAgentRuntime, request: AgentRequest) -> list[dict]:
    async def run() -> list[dict]:
        return [event async for event in runtime.stream(request)]

    return asyncio.run(run())


def _authorization(project_id: int, target_id: int) -> dict:
    authorization = {
        "status": "ACTIVE",
        "targetIds": [target_id],
        "allowedTools": [
            "retrieve_project_context",
            "nmap_service_scan",
            "http_headers",
        ],
        "allowedPorts": "80,443",
        "approved": True,
        "validFrom": "2020-01-01T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
        "quota": {"maxActions": 20, "usedActions": 0},
        "policyRevision": "test-policy-v1",
    }
    if "projectId" in AuthorizationContext.model_fields:
        authorization["projectId"] = project_id
    return authorization


def _request(
    project_id: int = 41,
    target_id: int = 51,
    *,
    max_retries: int = 1,
    conversation_id: str | None = "conversation-a",
) -> AgentRequest:
    return AgentRequest(
        projectId=project_id,
        targetId=target_id,
        conversationId=conversation_id,
        runId="security-test-run",
        maxRetries=max_retries,
        messages=[{"role": "user", "content": "扫描目标服务"}],
        authorization=_authorization(project_id, target_id),
    )


def _valid_plan() -> dict:
    return {
        "summary": "执行受控服务探测",
        "answer": "已生成受控计划。",
        "intent": "plan",
        "actions": [
            {
                "tool": "nmap_service_scan",
                "parameters": {"ports": "80", "mode": "quick"},
                "risk": "SAFE",
                "requiresApproval": False,
                "group": 0,
            }
        ],
    }


def _nested_object(depth: int) -> dict:
    value: dict = {"leaf": "value"}
    for _ in range(depth):
        value = {"next": value}
    return value


@pytest.mark.parametrize(
    "model_output",
    [
        'prefix {"summary":"x","answer":"x","intent":"answer","actions":[]}',
        '```json\n{"summary":"x","answer":"x","intent":"answer","actions":[]}\n```',
        '{"summary":"first","summary":"second","answer":"x","intent":"answer","actions":[]}',
        json.dumps(
            {
                "summary": "x",
                "answer": "x",
                "intent": "answer",
                "actions": [],
                "unexpected": True,
            }
        ),
        json.dumps(
            {
                "summary": "x",
                "answer": "x",
                "intent": "plan",
                "actions": [
                    {
                        "tool": "shell",
                        "parameters": {"command": "whoami"},
                        "risk": "SAFE",
                        "requiresApproval": False,
                    }
                ],
            }
        ),
        json.dumps(
            {
                "summary": "x",
                "answer": "x",
                "intent": "plan",
                "actions": [
                    {
                        "tool": "nmap_service_scan",
                        "parameters": {"ports": "80", "mode": "quick"},
                        "risk": "SAFE",
                        "requiresApproval": "false",
                    }
                ],
            }
        ),
        json.dumps(
            {
                "summary": "x",
                "answer": "x",
                "intent": "plan",
                "actions": [
                    _valid_plan()["actions"][0],
                    {
                        "tool": "tcp_ports",
                        "parameters": {"ports": 80},
                        "risk": "SAFE",
                        "requiresApproval": False,
                    },
                ],
            }
        ),
        json.dumps(
            {
                "summary": "x",
                "answer": "x",
                "intent": "plan",
                "actions": [
                    {
                        "tool": "retrieve_project_context",
                        "parameters": {},
                        "risk": "SAFE",
                        "requiresApproval": False,
                    }
                ],
            }
        ),
        json.dumps({"answer": "x", "intent": "answer", "actions": []}),
        json.dumps(
            {
                "summary": "x",
                "answer": "x",
                "intent": "answer",
                "actions": [],
                "unexpected": _nested_object(12),
            }
        ),
        "{" + '"summary":"' + ("x" * 50_001) + '"}',
    ],
    ids=[
        "surrounding-prose",
        "markdown-fence",
        "duplicate-key",
        "unknown-field",
        "unknown-tool",
        "wrong-boolean-type",
        "mixed-valid-invalid",
        "missing-tool-parameter",
        "missing-required-field",
        "excessive-nesting",
        "oversized-output",
    ],
)
def test_planner_schema_rejects_ambiguous_or_partly_invalid_output(model_output):
    with pytest.raises(PlannerOutputError):
        parse_planner_output(model_output)


def test_guard_rejects_an_entire_mixed_plan(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = _request().model_dump(mode="json")
    state = {
        "request": request,
        "runId": request["runId"],
        "retryCount": 0,
        "plan": {
            "actions": [
                {**_valid_plan()["actions"][0], "actionId": "allowed-action"},
                {
                    "tool": "http_headers",
                    "parameters": {"targetId": 999},
                    "risk": "SAFE",
                    "requiresApproval": False,
                    "group": 0,
                    "actionId": "denied-action",
                },
            ]
        },
    }

    guarded = asyncio.run(runtime._guard_node(state))

    assert guarded["guardedActions"] == []
    assert guarded["authorizationDecision"]["actions"] == []
    assert guarded["event"]["data"]["status"] == "DENIED"
    assert any("授权目标" in item for item in guarded["guardViolations"])


class _FakePlannerChain:
    def __init__(self, content: str) -> None:
        self.content = content

    async def ainvoke(self, _request: dict) -> SimpleNamespace:
        return SimpleNamespace(content=self.content)


def _install_fake_llm(runtime: SecurityAgentRuntime, payload: dict) -> None:
    runtime.planner._llm_requested = True
    runtime.planner._chain_load_attempted = True
    runtime.planner._planner_chain = _FakePlannerChain(json.dumps(payload))


def test_actionable_mock_llm_traverses_guard_and_creates_only_a_proposal(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    _install_fake_llm(runtime, _valid_plan())

    events = _collect(runtime, _request())

    plan = next(event for event in events if event["type"] == "plan")
    guard = next(event for event in events if event["type"] == "authorization_guard")
    finish = events[-1]
    assert plan["data"]["source"] == "langchain"
    assert plan["data"]["actionCount"] == 1
    assert guard["data"]["status"] == "AUTHORIZED"
    assert finish["data"]["status"] == "COMPLETED"
    assert finish["data"]["review"]["proposalCount"] == 1
    proposal = finish["data"]["review"]["proposals"][0]
    assert proposal["executed"] is False
    assert proposal["executionBoundary"] == "JAVA_AUTHORIZED_EXECUTOR"
    assert proposal["actionId"]
    assert proposal["decisionDigest"]


def test_malicious_mixed_llm_plan_fails_closed_without_proposals(
    tmp_path, monkeypatch
):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    malicious = _valid_plan()
    malicious["actions"].append(
        {
            "tool": "shell",
            "parameters": {"command": "whoami"},
            "risk": "SAFE",
            "requiresApproval": False,
            "group": 0,
        }
    )
    _install_fake_llm(runtime, malicious)
    proposal_tool = runtime.tools["propose_authorized_action"]
    original_invoke = proposal_tool.__class__.invoke
    proposal_calls = 0

    def reject_proposal(tool, payload, *args, **kwargs):
        nonlocal proposal_calls
        if tool is proposal_tool:
            proposal_calls += 1
            raise AssertionError(f"rejected plan reached proposal tool: {payload}")
        return original_invoke(tool, payload, *args, **kwargs)

    monkeypatch.setattr(proposal_tool.__class__, "invoke", reject_proposal)

    events = _collect(runtime, _request())

    plan = next(event for event in events if event["type"] == "plan")
    guard = next(event for event in events if event["type"] == "authorization_guard")
    assert proposal_calls == 0
    assert plan["data"]["source"] == "langchain-rejected"
    assert plan["data"]["actionCount"] == 0
    assert guard["data"]["status"] == "NOT_APPLICABLE"
    assert events[-1]["data"]["review"]["proposalCount"] == 0


def test_retry_invokes_only_failed_sibling_and_counts_once(
    tmp_path, monkeypatch
):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))

    async def sibling_plan(_request: dict) -> dict:
        return {
            "summary": "并行执行两个受控动作",
            "answer": "已生成受控计划。",
            "intent": "plan",
            "source": "test-planner",
            "actions": [
                _valid_plan()["actions"][0],
                {
                    "tool": "http_headers",
                    "parameters": {},
                    "risk": "SAFE",
                    "requiresApproval": False,
                    "group": 0,
                },
            ],
        }

    monkeypatch.setattr(runtime.planner, "plan", sibling_plan)
    proposal_tool = runtime.tools["propose_authorized_action"]
    original_invoke = proposal_tool.__class__.invoke
    calls: Counter[str] = Counter()

    def flaky_sibling(tool, payload, *args, **kwargs):
        if tool is not proposal_tool:
            return original_invoke(tool, payload, *args, **kwargs)
        tool_code = payload["tool_code"]
        calls[tool_code] += 1
        if tool_code == "nmap_service_scan" and calls[tool_code] == 1:
            raise RuntimeError("transient failure")
        return {
            "executed": False,
            "executionBoundary": "JAVA_AUTHORIZED_EXECUTOR",
            "toolCode": tool_code,
        }

    monkeypatch.setattr(proposal_tool.__class__, "invoke", flaky_sibling)

    events = _collect(runtime, _request(max_retries=1))

    retry_events = [event for event in events if event["type"] == "retry"]
    completed_retest = [
        event
        for event in events
        if event["node"] == "retest"
        and event["data"].get("status") == "COMPLETED"
    ]
    assert calls == Counter({"nmap_service_scan": 2, "http_headers": 1})
    assert [event["data"]["retryCount"] for event in retry_events] == [1]
    assert completed_retest[-1]["data"]["retryCount"] == 1
    assert events[-1]["data"]["status"] == "COMPLETED"
    assert events[-1]["data"]["review"]["proposalCount"] == 2


def test_permanent_failure_attempts_exactly_once_plus_retry_budget(
    tmp_path, monkeypatch
):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))

    async def one_action_plan(_request: dict) -> dict:
        return {**_valid_plan(), "source": "test-planner"}

    monkeypatch.setattr(runtime.planner, "plan", one_action_plan)
    proposal_tool = runtime.tools["propose_authorized_action"]
    original_invoke = proposal_tool.__class__.invoke
    attempts = 0

    def always_fail(tool, payload, *args, **kwargs):
        nonlocal attempts
        if tool is proposal_tool:
            attempts += 1
            raise RuntimeError("permanent failure")
        return original_invoke(tool, payload, *args, **kwargs)

    monkeypatch.setattr(proposal_tool.__class__, "invoke", always_fail)

    events = _collect(runtime, _request(max_retries=2))

    retry_events = [event for event in events if event["type"] == "retry"]
    assert attempts == 3
    assert [event["data"]["retryCount"] for event in retry_events] == [1, 2]
    assert events[-1]["data"]["status"] == "FAILED"


def test_conversation_documents_are_isolated_during_retrieval(tmp_path, monkeypatch):
    store = ProjectIndexStore(tmp_path)
    monkeypatch.setattr(indexing_module, "_load_llama_api", lambda: None)
    payload = IndexProjectRequest(
        projectId=61,
        documents=[
            {
                "id": "shared",
                "title": "共享项目资料",
                "text": "needle 项目级基线",
                "source": "project",
            },
            {
                "id": "conversation-a",
                "title": "会话 A 摘要",
                "text": "needle only-a-secret",
                "source": "conversation",
                "metadata": {
                    "conversationId": "conversation-a",
                    "targetId": "610",
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                },
            },
            {
                "id": "conversation-b",
                "title": "会话 B 摘要",
                "text": "needle only-b-secret",
                "source": "conversation",
                "metadata": {
                    "conversationId": "conversation-b",
                    "targetId": "610",
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                },
            },
        ],
    )
    store.index_project(payload.projectId, payload.documents)

    visible_to_a = {
        item["title"]
        for item in store.query(61, "needle", 10, conversation_id="conversation-a")
    }
    visible_without_conversation = {
        item["title"] for item in store.query(61, "needle", 10)
    }

    assert visible_to_a == {"共享项目资料", "会话 A 摘要"}
    assert visible_without_conversation == {"共享项目资料"}
