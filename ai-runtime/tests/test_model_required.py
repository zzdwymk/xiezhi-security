from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app import graph as graph_module
from app import main as main_module
from app.graph import SecurityAgentRuntime
from app.indexing import ProjectIndexStore
from app.model import AgentPlanner, ModelNotConfiguredError
from app.schemas import AgentRequest


class ReplyChain:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def ainvoke(self, payload):
        self.calls.append(payload)
        if isinstance(self.response, BaseException):
            raise self.response
        return SimpleNamespace(content=json.dumps(self.response))


def configured_planner():
    planner = AgentPlanner(None)
    planner._llm_requested = True
    planner._chain_load_attempted = True
    return planner


@pytest.mark.parametrize("rag_enabled", [True, False])
@pytest.mark.parametrize("message", ["你好", "有哪些功能", "请分析项目审计日志", "扫描端口"])
def test_missing_model_never_completes_or_generates_actions(tmp_path, monkeypatch, rag_enabled, message):
    monkeypatch.setattr(graph_module, "settings", replace(graph_module.settings, rag_enabled=rag_enabled))
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    runtime.planner._llm_requested = False
    request = AgentRequest(projectId=1, messages=[{"role": "user", "content": message}])

    async def collect():
        return [event async for event in runtime.stream(request)]

    final = asyncio.run(collect())[-1]["data"]
    assert final["status"] == "FAILED"
    assert final["terminationReason"] == "MODEL_NOT_CONFIGURED"
    assert final["llmCallCount"] == 0
    assert final["plan"]["actions"] == []
    assert "未配置" in final["answer"]


def test_planner_count_excludes_local_work_and_initialization_errors():
    runtime = object.__new__(SecurityAgentRuntime)
    state = {"request": {"budget": {"maxLlmCalls": 2}}, "llmCallCount": 0}
    planner = AgentPlanner(None)
    planner._llm_requested = False

    async def local_only():
        return {"status": "LOCAL_CHECK"}

    async def run():
        _, count = await runtime._bounded_planner_call(state, local_only)
        assert count == 0
        with pytest.raises(ModelNotConfiguredError) as caught:
            await runtime._bounded_planner_call(state, planner.route, {"messages": [{"role": "user", "content": "你好"}]})
        assert runtime._failed_llm_call_count(state, caught.value) == 0

    asyncio.run(run())


def test_legacy_plan_keeps_only_model_selected_actions_even_with_larger_workflow():
    planner = configured_planner()
    action = {"tool": "nmap_service_scan", "parameters": {"ports": "443", "mode": "service"},
              "risk": "SAFE", "requiresApproval": False, "group": 0}
    chain = planner._planner_chain = ReplyChain({"summary": "仅检查443", "answer": "仅检查用户选定端口。", "intent": "plan", "actions": [action]})
    result = asyncio.run(planner.plan({"projectId": 1, "messages": [{"role": "user", "content": "只检查443端口"}],
                                     "workflow": [{"nodeId": "port", "tool": "nmap_service_scan", "parameters": {"ports": "80,443"}},
                                                  {"nodeId": "http", "tool": "http_headers", "parameters": {}}]}))
    assert result["source"] == "langchain"
    assert result["actions"] == [action]
    assert len(chain.calls) == 1


def test_model_health_is_unverified_until_a_provider_response_and_resets_after_failure(tmp_path, monkeypatch):
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    planner = runtime.planner = configured_planner()
    chain = planner._planner_chain = ReplyChain({"summary": "说明", "answer": "来自模型的回答", "intent": "answer", "actions": []})
    monkeypatch.setattr(main_module, "agent_runtime", runtime)
    initial = asyncio.run(main_module.health())
    assert initial["modelConfigured"] is True
    assert initial["modelVerified"] is False and initial["modelStatus"] == "UNVERIFIED"
    assert chain.calls == []
    request = {"projectId": 1, "messages": [{"role": "user", "content": "解释HTTP"}]}
    asyncio.run(planner.plan(request))
    verified = asyncio.run(main_module.health())
    assert verified["modelVerified"] is True and verified["modelStatus"] == "VERIFIED"
    chain.response = RuntimeError("provider unavailable")
    asyncio.run(planner.plan(request))
    failed = asyncio.run(main_module.health())
    assert failed["modelVerified"] is False and failed["modelStatus"] == "FAILED"


def test_legacy_model_failure_is_a_failed_turn_not_a_successful_local_answer(tmp_path, monkeypatch):
    monkeypatch.setattr(graph_module, "settings", replace(graph_module.settings, rag_enabled=False))
    runtime = SecurityAgentRuntime(ProjectIndexStore(tmp_path))
    runtime.planner = configured_planner()
    chain = runtime.planner._planner_chain = ReplyChain(RuntimeError("provider unavailable"))
    request = AgentRequest(projectId=1, messages=[{"role": "user", "content": "有哪些功能"}])

    async def collect():
        return [event async for event in runtime.stream(request)]

    final = asyncio.run(collect())[-1]["data"]
    assert final["status"] == "FAILED" and final["plannerSource"] == "langchain-rejected"
    assert final["llmCallCount"] == len(chain.calls) == 1
    assert final["plan"]["actions"] == []
