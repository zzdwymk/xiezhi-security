from __future__ import annotations

import argparse
import asyncio
import sys

from fastapi.testclient import TestClient
import uvicorn

from app import main as main_module
from app.graph import SecurityAgentRuntime
from app.indexing import ProjectIndexStore
from app.schemas import AgentRequest, IndexProjectRequest
import runtime_server


def _collect(runtime: SecurityAgentRuntime, request: AgentRequest) -> list[dict]:
    async def run() -> list[dict]:
        return [event async for event in runtime.stream(request)]

    return asyncio.run(run())


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


def test_index_http_endpoints_return_operation_status(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "index_store", ProjectIndexStore(tmp_path))
    headers = (
        {"X-AI-Runtime-Token": main_module.settings.token}
        if main_module.settings.token
        else {}
    )

    with TestClient(main_module.app) as client:
        indexed = client.post(
            "/index/project",
            headers=headers,
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
            headers=headers,
            json={
                "documents": [
                    {
                        "title": "会话结论",
                        "text": "优先低风险检查",
                        "source": "conversation",
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


def test_graph_exposes_red_team_lifecycle(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    graph = runtime.graph_structure()
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


def test_saved_workflow_does_not_override_informational_intent(tmp_path):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    request = AgentRequest(
        projectId=7,
        targetId=11,
        messages=[{"role": "user", "content": "介绍一下项目"}],
        workflow=[
            {"tool": "nmap_service_scan", "parameters": {}, "risk": "SAFE", "group": 0}
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
            {"tool": "nmap_service_scan", "parameters": {}, "risk": "SAFE", "group": 0}
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
    assert [event["type"] for event in events][:2] == ["plan", "authorization_guard"]
    assert events[1]["data"]["status"] == "NOT_APPLICABLE"
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


def test_high_risk_requires_approval(tmp_path, monkeypatch):
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
    event_types = [event["type"] for event in events]
    assert "approval_required" in event_types
    assert events[-1]["data"]["status"] == "APPROVAL_REQUIRED"


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
            {"tool": "nmap_service_scan", "parameters": {}, "risk": "SAFE", "group": 0},
            {
                "tool": "http_security_check",
                "parameters": {"check": "cors"},
                "risk": "SAFE",
                "group": 1,
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


def test_stream_error_does_not_expose_python_exception(monkeypatch):
    async def broken_stream(_request):
        if False:
            yield None
        raise RuntimeError("private-python-detail https://internal.invalid")

    monkeypatch.setattr(main_module.agent_runtime, "stream", broken_stream)
    headers = (
        {"X-AI-Runtime-Token": main_module.settings.token}
        if main_module.settings.token
        else {}
    )

    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        response = client.post(
            "/agent/stream",
            headers=headers,
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


def test_http_error_does_not_expose_python_exception(monkeypatch):
    def broken_index(*_args, **_kwargs):
        raise RuntimeError("private-index-detail C:\\sensitive\\index")

    monkeypatch.setattr(main_module.index_store, "index_project", broken_index)
    headers = (
        {"X-AI-Runtime-Token": main_module.settings.token}
        if main_module.settings.token
        else {}
    )

    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        response = client.post(
            "/index/project",
            headers=headers,
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


def test_request_validation_error_is_chinese():
    headers = (
        {"X-AI-Runtime-Token": main_module.settings.token}
        if main_module.settings.token
        else {}
    )

    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        response = client.post("/index/project", headers=headers, json={})

    assert response.status_code == 422
    assert response.json() == {"detail": "请求参数格式不正确"}
    assert "Field required" not in response.text
