from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import importlib.util
import json
import sys
import threading
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest
import uvicorn

from app import main as main_module
from app import graph as graph_module
from app import model as model_module
from app import security as security_module
from app.graph import (
    RUNTIME_LEDGER_GENESIS_DIGEST,
    SecurityAgentRuntime,
    envelope_runtime_event,
    verify_runtime_event_chain,
)
from app import indexing as indexing_module
from app.indexing import ProjectIndexStore
from app.schemas import AgentRequest, IndexProjectRequest
import runtime_server


@pytest.fixture(autouse=True)
def legacy_runtime_graph_path(monkeypatch):
    """Exercise the original Planner/Harness behavior with RAG explicitly off."""
    monkeypatch.setattr(
        graph_module,
        "settings",
        replace(graph_module.settings, rag_enabled=False),
    )


def _collect(runtime: SecurityAgentRuntime, request: AgentRequest) -> list[dict]:
    async def run() -> list[dict]:
        return [event async for event in runtime.stream(request)]

    return asyncio.run(run())


@pytest.fixture
def runtime_headers(monkeypatch):
    token = "test-runtime-token-at-least-24-characters"
    signing_secret = "test-project-signing-secret-at-least-32-characters"
    monkeypatch.setattr(
        security_module,
        "settings",
        replace(
            security_module.settings,
            token=token,
            project_signing_secret=signing_secret,
        ),
    )

    def headers(project_id: int | None = None, scope: str | None = None) -> dict:
        result = {"X-AI-Runtime-Token": token}
        if project_id is not None and scope is not None:
            expires_at = int(time.time()) + 60
            result["X-AI-Project-Authorization"] = (
                security_module.project_authorization_value(
                    project_id, scope, expires_at
                )
            )
        return result

    return headers


def test_optional_model_stacks_are_lazy_on_startup():
    assert "langchain_openai" not in sys.modules
    assert "llama_index.core" not in sys.modules


def test_optional_module_probe_handles_missing_parent(monkeypatch):
    def missing_parent(_module_name: str):
        raise ModuleNotFoundError("optional package is absent")

    monkeypatch.setattr(importlib.util, "find_spec", missing_parent)

    assert indexing_module._module_available("missing.child") is False


def test_llama_import_failure_reports_lexical_degraded(tmp_path, monkeypatch):
    store = ProjectIndexStore(tmp_path)
    monkeypatch.setattr(indexing_module, "LLAMA_INDEX_AVAILABLE", True)
    monkeypatch.setattr(indexing_module, "_load_llama_api", lambda: None)
    payload = IndexProjectRequest(
        projectId=8,
        documents=[
            {
                "id": "fallback-doc",
                "title": "降级资料",
                "text": "向量模块导入失败时保留词法检索。",
                "source": "project",
            }
        ],
    )

    result = store.index_project(payload.projectId, payload.documents)

    assert result["engine"] == "lexical-fallback"
    assert result["status"] == "DEGRADED"


def test_empty_project_query_does_not_load_llama(tmp_path, monkeypatch):
    store = ProjectIndexStore(tmp_path)

    def unexpected_load():
        raise AssertionError("empty projects must not load LlamaIndex")

    monkeypatch.setattr(indexing_module, "_load_llama_api", unexpected_load)

    assert store.query(404, "anything") == []


def test_project_caches_are_bounded_lru(tmp_path, monkeypatch):
    store = ProjectIndexStore(
        tmp_path,
        document_cache_chars=1_000,
        document_cache_projects=1,
        index_cache_projects=2,
    )
    monkeypatch.setattr(indexing_module, "_load_llama_api", lambda: None)

    for project_id in (1, 2):
        payload = IndexProjectRequest(
            projectId=project_id,
            documents=[
                {
                    "id": f"doc-{project_id}",
                    "title": f"项目 {project_id}",
                    "text": f"项目 {project_id} 的缓存资料",
                    "source": "project",
                }
            ],
        )
        store.index_project(payload.projectId, payload.documents)

    assert list(store._documents) == [2]
    assert store.list_documents(1)[0]["id"] == "doc-1"
    assert list(store._documents) == [1]

    store._cache_index(1, object())
    store._cache_index(2, object())
    assert store._get_cached_index(1) is not None
    store._cache_index(3, object())
    assert list(store._indexes) == [1, 3]


def test_failed_llama_load_updates_availability(monkeypatch):
    monkeypatch.setattr(indexing_module, "LLAMA_INDEX_AVAILABLE", True)
    monkeypatch.setattr(indexing_module, "_llama_load_attempted", True)
    monkeypatch.setattr(indexing_module, "_llama_api", None)

    assert indexing_module.llama_index_available() is False


def test_configured_llm_plans_through_compiled_harness(tmp_path, monkeypatch):
    pytest.importorskip("langchain_core")
    from langchain_core.messages import AIMessage
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.runnables import RunnableLambda

    fake_response = AIMessage(
        content=json.dumps(
            {
                "summary": "模型计划已生成",
                "answer": "已通过模型理解当前请求。",
                "intent": "answer",
                "actions": [],
            },
            ensure_ascii=False,
        )
    )

    def fake_chat_openai(**_kwargs):
        return RunnableLambda(lambda _prompt: fake_response)

    monkeypatch.setattr(
        model_module,
        "settings",
        SimpleNamespace(
            llm_enabled=True,
            api_key="test-api-key",
            model="fake-model",
            base_url="https://example.invalid/v1",
            llm_timeout_seconds=1,
        ),
    )
    monkeypatch.setattr(model_module, "LANGCHAIN_AVAILABLE", True)
    load_calls = 0

    def load_fake_langchain():
        nonlocal load_calls
        load_calls += 1
        return ChatPromptTemplate, fake_chat_openai

    monkeypatch.setattr(model_module, "_load_langchain_api", load_fake_langchain)
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=7,
        messages=[{"role": "user", "content": "总结当前授权范围"}],
        authorization={"status": "PAUSED"},
    )

    assert runtime.health["llmConfigured"] is True
    assert runtime.health["llmLoaded"] is False
    assert load_calls == 0

    events = _collect(runtime, request)
    plan = next(event for event in events if event["type"] == "plan")

    assert runtime.health["graphCompiled"] is True
    assert runtime.health["llmConfigured"] is True
    assert runtime.health["llmLoaded"] is True
    assert load_calls == 1
    assert plan["data"]["source"] == "langchain"
    assert plan["data"]["answer"] == "已通过模型理解当前请求。"


def test_health_index_scan_does_not_block_event_loop(monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def slow_stats():
        started.set()
        assert release.wait(5)
        return {"engineAvailable": True, "projects": []}

    monkeypatch.setattr(main_module.index_store, "stats", slow_stats)

    async def run():
        health_task = asyncio.create_task(main_module.health())
        assert await asyncio.to_thread(started.wait, 5)
        await asyncio.sleep(0)
        assert health_task.done() is False
        release.set()
        result = await health_task
        assert result["index"]["projects"] == []

    asyncio.run(run())


def test_concurrent_project_appends_preserve_every_document(tmp_path, monkeypatch):
    store = ProjectIndexStore(tmp_path)
    monkeypatch.setattr("app.indexing._load_llama_api", lambda: None)

    def append_document(index: int) -> None:
        payload = IndexProjectRequest(
            projectId=9,
            replace=False,
            documents=[
                {
                    "id": f"concurrent-{index}",
                    "title": f"并发资料 {index}",
                        "text": f"项目资料内容 {index}",
                        "source": "conversation",
                        "metadata": {
                            "conversationId": "concurrent-session",
                            "targetId": "91",
                            "createdAt": datetime.now(timezone.utc).isoformat(),
                        },
                }
            ],
        )
        store.index_project(payload.projectId, payload.documents, False)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append_document, range(32)))

    documents = store.list_documents(9)
    assert len(documents) == 32
    assert {item["id"] for item in documents} == {
        f"concurrent-{index}" for index in range(32)
    }


def test_index_and_safe_retrieval(tmp_path, monkeypatch):
    store = ProjectIndexStore(tmp_path)
    payload = IndexProjectRequest(
        projectId=1,
        documents=[
            {
                "title": "授权范围",
                "text": "目标 10.0.0.8 仅允许 80 和 443 端口",
                "source": "project",
            }
        ],
    )
    result = store.index_project(payload.projectId, payload.documents, True)
    assert result["documentCount"] == 1
    assert len(result["sha256"]) == 64
    references = store.query(1, "授权端口", 3)
    assert references


def test_index_http_endpoints_return_operation_status(
    tmp_path, monkeypatch, runtime_headers
):
    monkeypatch.setattr(main_module, "index_store", ProjectIndexStore(tmp_path))

    with TestClient(main_module.app) as client:
        indexed = client.post(
            "/index/project",
            headers=runtime_headers(17, "index-write"),
            json={
                "projectId": 17,
                "replace": True,
                "documents": [
                    {
                        "title": "授权范围",
                        "text": "仅允许 80 和 443 端口",
                        "source": "project",
                    }
                ],
            },
        )
        appended = client.post(
            "/index/project/17/documents",
            headers=runtime_headers(17, "index-write"),
            json={
                "documents": [
                    {
                        "title": "会话结论",
                        "text": "优先低风险检查",
                        "source": "conversation",
                        "metadata": {
                            "conversationId": "session-17",
                            "targetId": "171",
                            "createdAt": datetime.now(timezone.utc).isoformat(),
                        },
                    }
                ]
            },
        )

    assert indexed.status_code == 200
    assert indexed.json()["status"] == "INDEXED"
    assert indexed.json()["documentCount"] == 1
    assert appended.status_code == 200
    assert appended.json()["status"] == "APPENDED"
    assert appended.json()["documentCount"] == 2


def test_single_memory_delete_cannot_remove_project_documents(
    tmp_path, monkeypatch, runtime_headers
):
    store = ProjectIndexStore(tmp_path)
    monkeypatch.setattr(main_module, "index_store", store)
    payload = IndexProjectRequest(
        projectId=18,
        documents=[
            {
                "id": "project-baseline",
                "title": "项目基线",
                "text": "必须保留的项目级资料",
                "source": "project",
            },
            {
                "id": "conversation-note",
                "title": "会话摘要",
                "text": "可以删除的会话记忆",
                "source": "conversation",
                "metadata": {
                    "conversationId": "session-18",
                    "targetId": "181",
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                },
            },
        ],
    )
    store.index_project(payload.projectId, payload.documents, True)

    with TestClient(main_module.app) as client:
        missing_source = client.delete(
            "/index/project/18/documents/project-baseline",
            headers=runtime_headers(18, "index-write"),
        )
        rejected = client.delete(
            "/index/project/18/documents/project-baseline?source=conversation",
            headers=runtime_headers(18, "index-write"),
        )
        deleted = client.delete(
            "/index/project/18/documents/conversation-note?source=conversation",
            headers=runtime_headers(18, "index-write"),
        )

    assert missing_source.status_code == 422
    assert rejected.status_code == 200
    assert rejected.json()["deleted"] is False
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert {item["id"] for item in store.list_documents(18)} == {"project-baseline"}


def test_runtime_bearer_token_cannot_forge_project_authorization(runtime_headers):
    headers = runtime_headers()
    expires_at = int(time.time()) + 60
    message = f"v1:17:index-write:{expires_at}"
    forged_signature = hmac.new(
        headers["X-AI-Runtime-Token"].encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers["X-AI-Project-Authorization"] = f"{message}:{forged_signature}"

    with TestClient(main_module.app) as client:
        response = client.post(
            "/index/project",
            headers=headers,
            json={
                "projectId": 17,
                "documents": [
                    {"title": "forged", "text": "must be rejected", "source": "project"}
                ],
                "replace": True,
            },
        )

    assert response.status_code == 403


def test_windowed_runtime_starts_without_standard_streams(tmp_path, monkeypatch):
    options: dict = {}

    def configure_only(runtime_app, **kwargs):
        options.update(kwargs)
        uvicorn.Config(runtime_app, **kwargs)

    monkeypatch.setattr(
        runtime_server,
        "parse_args",
        lambda: argparse.Namespace(
            host="127.0.0.1",
            port=18090,
            data_dir=tmp_path,
            token_file=None,
            project_signing_secret_file=None,
            log_level="warning",
            version=False,
        ),
    )
    monkeypatch.setattr(uvicorn, "run", configure_only)
    monkeypatch.setenv("AI_RUNTIME_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AI_RUNTIME_HOST", "127.0.0.1")
    monkeypatch.setenv("AI_RUNTIME_PORT", "18090")
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)

    assert runtime_server.main() == 0
    assert options["log_config"] is None


def test_public_graph_exposes_only_ledger_agent_black_box(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    graph = runtime.graph_structure()
    assert graph["version"] == 3
    assert [node["id"] for node in graph["nodes"]] == ["ledger-agent"]
    assert [(edge["source"], edge["target"]) for edge in graph["edges"]] == [
        ("__start__", "ledger-agent"),
        ("ledger-agent", "__end__"),
    ]
    assert "compiled" not in graph
    assert "route" not in json.dumps(graph)


def test_internal_graph_is_available_only_from_explicit_debug_structure(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    graph = runtime.internal_graph_structure()
    assert [node["id"] for node in graph["nodes"]] == [
        "engage",
        "recon",
        "map",
        "validate",
        "impact",
        "retest",
        "report",
        "finish",
    ]
    assert [(edge["source"], edge["target"]) for edge in graph["edges"]] == [
        ("__start__", "engage"),
        ("engage", "recon"),
        ("recon", "map"),
        ("map", "validate"),
        ("validate", "impact"),
        ("impact", "retest"),
        ("retest", "report"),
        ("report", "finish"),
        ("finish", "__end__"),
    ]
    assert graph_module.TOOL_STAGE["nuclei_scan"] == "validate"
    assert graph_module.TOOL_STAGE["afrog_scan"] == "validate"
    assert graph_module.TOOL_STAGE["xray_scan"] == "validate"


def test_debug_graph_endpoint_requires_switch_and_runtime_token(
    monkeypatch, runtime_headers
):
    if not graph_module.LANGGRAPH_AVAILABLE:
        pytest.skip("langgraph not available in this environment")
    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        disabled = client.get("/agent/graph/debug", headers=runtime_headers())
        assert disabled.status_code == 404

        monkeypatch.setattr(
            main_module,
            "settings",
            replace(main_module.settings, internal_graph_debug=True),
        )
        unauthorized = client.get("/agent/graph/debug")
        authorized = client.get("/agent/graph/debug", headers=runtime_headers())

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.json()["compiled"] is not None


def test_v3_runtime_event_chain_is_contiguous_and_tamper_evident():
    request = {
        "workflowDigest": "sha256:" + ("a" * 64),
        "outerNodeId": "ledger-agent-01",
        "nodeRunId": "node-run-01",
        "authorization": {"policyRevision": "policy-v3"},
    }
    first = envelope_runtime_event(
        {
            "eventId": "7eb1031e-0c2c-4876-a231-b36d84fa792d",
            "type": "route",
            "node": "route",
            "message": "routed",
            "timestamp": "2026-08-08T00:00:00+00:00",
            "data": {"status": "ROUTED"},
        },
        request,
        "run-v3-0001",
        1,
        RUNTIME_LEDGER_GENESIS_DIGEST,
    )
    second = envelope_runtime_event(
        {
            "eventId": "99ee4d78-6da7-4344-a350-3379ee623a5e",
            "type": "finish",
            "node": "finish",
            "message": "finished",
            "timestamp": "2026-08-08T00:00:01+00:00",
            "data": {"status": "COMPLETED"},
        },
        request,
        "run-v3-0001",
        2,
        first["ledgerEntryDigest"],
    )

    assert verify_runtime_event_chain([first, second])
    tampered = json.loads(json.dumps([first, second]))
    tampered[0]["data"]["status"] = "DENIED"
    assert not verify_runtime_event_chain(tampered)
    tampered = json.loads(json.dumps([first, second]))
    tampered[1]["ledgerSequence"] = 3
    assert not verify_runtime_event_chain(tampered)


def test_v3_public_event_strips_sensitive_runtime_payloads():
    event = envelope_runtime_event(
        {
            "eventId": "1a5b43b8-90f1-4b82-b3fc-5362ce7ef19d",
            "type": "evidence",
            "node": "retrieve",
            "message": "retrieved",
            "timestamp": "2026-08-08T00:00:00+00:00",
            "data": {
                "status": "READY",
                "prompt": "private prompt marker",
                "snippet": "private evidence body marker",
                "chainOfThought": "private reasoning marker",
                "token": "private credential marker",
                "items": [
                    {
                        "evidenceId": "ev-1",
                        "contentDigest": "sha256:x",
                        "evidenceBody": "nested private evidence marker",
                    }
                ],
            },
        },
        {"authorization": {"policyRevision": "policy-v3"}},
        "run-v3-0002",
        1,
    )
    serialized = json.dumps(event, ensure_ascii=False)

    assert "private prompt marker" not in serialized
    assert "private evidence body marker" not in serialized
    assert "private reasoning marker" not in serialized
    assert "private credential marker" not in serialized
    assert "nested private evidence marker" not in serialized
    assert event["data"]["items"][0]["evidenceId"] == "ev-1"
    assert verify_runtime_event_chain([event])


def test_project_question_uses_guarded_retrieval_not_saved_workflow(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=7,
        targetId=11,
        messages=[{"role": "user", "content": "介绍一下项目"}],
        workflow=[
            {
                "nodeId": "nmap-qa-01",
                "tool": "nmap_service_scan",
                "parameters": {},
                "risk": "SAFE",
                "group": 0,
            }
        ],
        authorization={
            "status": "ACTIVE",
            "targetIds": [11],
            "allowedTools": ["nmap_service_scan"],
        },
    )

    plan = asyncio.run(runtime.planner.plan(request.model_dump(mode="json")))

    assert plan["actions"] == []
    assert plan["intent"] == "answer"


def test_explicit_scan_can_activate_saved_workflow(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=8,
        targetId=12,
        messages=[{"role": "user", "content": "请扫描端口和服务"}],
        workflow=[
            {
                "nodeId": "nmap-run-01",
                "tool": "nmap_service_scan",
                "parameters": {},
                "risk": "SAFE",
                "group": 0,
            }
        ],
        authorization={
            "status": "ACTIVE",
            "targetIds": [12],
            "allowedTools": ["nmap_service_scan"],
        },
    )

    plan = asyncio.run(runtime.planner.plan(request.model_dump(mode="json")))

    assert [action["tool"] for action in plan["actions"]] == ["nmap_service_scan"]


def test_informational_question_does_not_require_active_project(tmp_path, monkeypatch):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=2,
        messages=[{"role": "user", "content": "总结项目资料"}],
        authorization={
            "status": "PAUSED",
            "allowedTools": ["retrieve_project_context"],
            "quota": {"maxActions": 10, "usedActions": 0},
        },
    )
    events = _collect(runtime, request)
    assert [event["type"] for event in events][:3] == [
        "route",
        "plan",
        "authorization_guard",
    ]
    assert events[2]["data"]["status"] == "NOT_APPLICABLE"
    assert events[-1]["data"]["status"] == "COMPLETED"


def test_local_runtime_explains_project_report_without_actions(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=22,
        targetId=33,
        messages=[{"role": "user", "content": "项目报告在哪里导出？"}],
        authorization={"status": "PAUSED"},
    )

    plan = asyncio.run(runtime.planner.plan(request.model_dump(mode="json")))

    assert plan["actions"] == []
    assert "项目报告" in plan["answer"]


def test_unsupported_high_risk_request_fails_closed(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=3,
        targetId=7,
        messages=[{"role": "user", "content": "进行后渗透和提权验证"}],
        authorization={
            "status": "ACTIVE",
            "targetIds": [7],
            "allowedTools": ["exploit_validation"],
            "allowedPorts": "1-65535",
            "validFrom": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
            "approved": False,
            "quota": {"maxActions": 10, "usedActions": 0},
        },
    )
    events = _collect(runtime, request)
    plan = next(event for event in events if event["type"] == "plan")
    assert plan["data"]["source"] == "local-rules"
    assert plan["data"]["intent"] == "clarify"
    assert plan["data"]["actionCount"] == 0
    assert not any(event["type"] == "approval_required" for event in events)
    assert events[-1]["data"]["review"]["proposalCount"] == 0


def test_external_tool_is_only_a_java_proposal(tmp_path, monkeypatch):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=4,
        targetId=9,
        messages=[{"role": "user", "content": "探测端口和服务"}],
        authorization={
            "status": "ACTIVE",
            "targetIds": [9],
            "allowedTools": ["nmap_service_scan"],
            "allowedPorts": "80,443",
            "validFrom": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
            "approved": True,
            "quota": {"maxActions": 10, "usedActions": 0},
        },
    )
    events = _collect(runtime, request)
    finish = events[-1]["data"]
    proposals = finish["review"]["proposals"]
    assert proposals and proposals[0]["executed"] is False
    assert proposals[0]["executionBoundary"] == "JAVA_AUTHORIZED_EXECUTOR"


def test_failed_stage_retries_through_guard_and_retest(tmp_path, monkeypatch):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    calls = {"count": 0}

    def flaky_proposal(payload):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("temporary failure")
        return {
            "executed": False,
            "executionBoundary": "JAVA_AUTHORIZED_EXECUTOR",
            "tool": payload["tool_code"],
        }

    proposal_tool = runtime.tools["propose_authorized_action"]
    original_invoke = proposal_tool.__class__.invoke

    def invoke_with_transient_failure(tool, payload, *args, **kwargs):
        if tool is proposal_tool:
            return flaky_proposal(payload)
        return original_invoke(tool, payload, *args, **kwargs)

    monkeypatch.setattr(
        proposal_tool.__class__, "invoke", invoke_with_transient_failure
    )
    request = AgentRequest(
        projectId=6,
        targetId=10,
        maxRetries=1,
        messages=[{"role": "user", "content": "探测端口和服务"}],
        workflow=[
            {
                "nodeId": "nmap-retry-01",
                "tool": "nmap_service_scan",
                "parameters": {},
                "risk": "SAFE",
                "group": 0,
            },
            {
                "nodeId": "http-retry-01",
                "tool": "http_security_check",
                "parameters": {"check": "cors"},
                "risk": "SAFE",
                "group": 1,
                "dependsOnNodeIds": ["nmap-retry-01"],
            },
        ],
        authorization={
            "status": "ACTIVE",
            "targetIds": [10],
            "allowedTools": ["nmap_service_scan", "http_security_check"],
            "allowedPorts": "80,443",
            "validFrom": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
            "approved": True,
            "quota": {"maxActions": 10, "usedActions": 0},
        },
    )
    events = _collect(runtime, request)
    # The validation stage succeeds after mapping fails, but it must not erase
    # the earlier failure; retest therefore invokes the failed mapping action.
    assert calls["count"] == 3
    assert any(
        event["type"] == "retry" and event["node"] == "retest" for event in events
    )
    assert any(
        event["type"] == "authorization_guard" and event["node"] == "retest"
        for event in events
    )
    assert events[-1]["data"]["status"] == "COMPLETED"


def test_guard_denies_external_tool_when_authorized_target_snapshot_is_empty(
    tmp_path, monkeypatch
):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=5,
        targetId=9,
        messages=[{"role": "user", "content": "探测端口和服务"}],
        authorization={
            "status": "ACTIVE",
            "targetIds": [],
            "allowedTools": ["nmap_service_scan"],
            "allowedPorts": "80,443",
            "validFrom": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
            "approved": True,
            "quota": {"maxActions": 10, "usedActions": 0},
        },
    )
    events = _collect(runtime, request)
    guard = next(event for event in events if event["type"] == "authorization_guard")
    assert guard["data"]["status"] == "DENIED"
    assert "授权快照不包含任何项目目标" in guard["data"]["violations"]
    assert events[-1]["data"]["status"] == "DENIED"


def test_natural_scan_intents_create_actions(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    cases = {
        "对目标进行漏扫": {"nuclei_scan"},
        "扫描啊": {"nmap_service_scan", "http_headers"},
        "目前有什么功能就扫描什么": {"nmap_service_scan", "nuclei_scan"},
        "扫描端口": {"nmap_service_scan"},
    }
    for prompt, expected in cases.items():
        request = AgentRequest(
            projectId=9,
            targetId=19,
            messages=[{"role": "user", "content": prompt}],
            authorization={
                "status": "ACTIVE",
                "targetIds": [19],
                "allowedTools": [
                    "nmap_service_scan",
                    "tcp_ports",
                    "http_headers",
                    "http_security_check",
                    "tls_config",
                    "nuclei_scan",
                    "retrieve_project_context",
                ],
                "allowedPorts": "80,443",
                "approved": True,
                "validFrom": "2020-01-01T00:00:00Z",
                "expiresAt": "2099-01-01T00:00:00Z",
                "quota": {"maxActions": 20, "usedActions": 0},
            },
        )
        plan = asyncio.run(runtime.planner.plan(request.model_dump(mode="json")))
        tools = {action["tool"] for action in plan["actions"]}
        assert expected <= tools, prompt


def test_how_to_scan_stays_informational(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=10,
        targetId=20,
        messages=[{"role": "user", "content": "怎么扫描端口？"}],
        authorization={
            "status": "ACTIVE",
            "targetIds": [20],
            "allowedTools": ["nmap_service_scan"],
        },
    )
    plan = asyncio.run(runtime.planner.plan(request.model_dump(mode="json")))
    assert plan["actions"] == []
    assert plan.get("intent") == "answer"


def test_stream_error_does_not_expose_python_exception(
    monkeypatch, runtime_headers
):
    async def broken_stream(_request):
        if False:
            yield None
        raise RuntimeError("private-python-detail https://internal.invalid")

    monkeypatch.setattr(main_module.agent_runtime, "stream", broken_stream)
    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        response = client.post(
            "/agent/stream",
            headers=runtime_headers(1, "agent"),
            json={
                "projectId": 1,
                "messages": [{"role": "user", "content": "检查项目"}],
            },
        )

    assert response.status_code == 200
    assert "本地智能服务处理失败" in response.text
    assert "RUNTIME_PROCESSING_FAILED" in response.text
    assert "RuntimeError" not in response.text
    assert "private-python-detail" not in response.text
    assert "internal.invalid" not in response.text
    data_line = next(
        line for line in response.text.splitlines() if line.startswith("data:")
    )
    error_event = json.loads(data_line.removeprefix("data:"))
    assert error_event["contractVersion"] == 3
    assert error_event["ledgerSequence"] == 1
    assert error_event["innerStep"] == "runtime"
    assert verify_runtime_event_chain([error_event])


def test_http_error_does_not_expose_python_exception(
    monkeypatch, runtime_headers
):
    def broken_index(*_args, **_kwargs):
        raise RuntimeError("private-index-detail C:\\sensitive\\index")

    monkeypatch.setattr(main_module.index_store, "index_project", broken_index)
    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        response = client.post(
            "/index/project",
            headers=runtime_headers(1, "index-write"),
            json={
                "projectId": 1,
                "documents": [{"title": "资料", "text": "内容", "source": "project"}],
            },
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "本地智能服务处理失败，请稍后重试"}
    assert "RuntimeError" not in response.text
    assert "private-index-detail" not in response.text
    assert "sensitive" not in response.text


def test_request_validation_error_is_chinese(runtime_headers):
    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        response = client.post(
            "/index/project", headers=runtime_headers(), json={}
        )

    assert response.status_code == 422
    assert response.json() == {"detail": "请求参数格式不正确"}
    assert "Field required" not in response.text
