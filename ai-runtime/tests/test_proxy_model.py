from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from app import model


def test_proxy_responses_wire_contract():
    # Keep optional imports out of the main pytest process so startup laziness
    # remains independently verifiable by test_runtime.
    result = subprocess.run(
        [sys.executable, "-c",
         "import runpy, pytest; "
         "module = runpy.run_path(" + repr(str(Path(__file__).resolve())) + "); "
         "module['_check_proxy_responses_wire_contract'](pytest.MonkeyPatch())"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _check_proxy_responses_wire_contract(monkeypatch):
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI

    captured = []
    answer = {"intent": "GENERAL_QA", "needsRetrieval": False, "publicReasonCode": "GENERAL_KNOWLEDGE"}

    def handle(request):
        captured.append(request)
        event = {"type": "response.output_text.delta", "output_index": 0,
                 "content_index": 0, "item_id": "msg_1", "sequence_number": 1,
                 "delta": json.dumps(answer)}
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"},
                              text="event: response.output_text.delta\ndata: " + json.dumps(event) + "\n\n")

    transport = httpx.MockTransport(handle)
    def create_model(**kwargs):
        return ChatOpenAI(**kwargs, http_client=httpx.Client(transport=transport),
                          http_async_client=httpx.AsyncClient(transport=transport))

    monkeypatch.setattr(model, "settings", replace(model.settings, llm_enabled=True,
                        api_key="", proxy_mode=True, api_mode="responses",
                        model="gpt-5.6-sol", base_url="http://127.0.0.1:15721/v1"))
    monkeypatch.setattr(model, "_load_langchain_api", lambda: (ChatPromptTemplate, create_model))
    planner = model.AgentPlanner(None)
    assert planner.status["llmConfigured"] is True
    result = asyncio.run(planner.route({"projectId": 1, "messages": [{"role": "user", "content": "解释 HTTP 请求头"}]}))
    assert result == answer
    request = captured[0]
    assert request.url.path == "/v1/responses"
    payload = json.loads(request.content)
    assert payload["model"] == "gpt-5.6-sol"
    assert payload["store"] is False
    assert payload["stream"] is True
    assert "temperature" not in payload
    assert payload["instructions"] == model.INTENT_SYSTEM_PROMPT.format()
    assert all(item["role"] == "user" for item in payload["input"])
    assert request.headers["originator"] == "codex_cli_rs"
    assert request.headers["OpenAI-Beta"] == "responses=experimental"
    assert request.headers["User-Agent"] == "codex_cli_rs/secbox"
    assert "解释 HTTP 请求头" in json.dumps(payload, ensure_ascii=False)


def test_model_initialization_failure_never_becomes_rule_fallback(monkeypatch):
    monkeypatch.setattr(model, "settings", replace(model.settings, llm_enabled=True, api_key="", proxy_mode=True))
    monkeypatch.setattr(model, "_load_langchain_api", lambda: None)
    planner = model.AgentPlanner(None)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="Model initialization failed"):
            asyncio.run(planner.route({"messages": [{"role": "user", "content": "解释 HTTP"}]}))
    assert planner.status["llmConfigured"] is False


def test_general_question_without_model_preserves_general_contract(monkeypatch):
    monkeypatch.setattr(model, "settings", replace(model.settings, llm_enabled=False, api_key="", proxy_mode=False))
    planner = model.AgentPlanner(None)
    result = asyncio.run(planner.grounded_plan(
        {"projectId": 1, "messages": [{"role": "user", "content": "解释 HTTP 请求头"}], "workflow": []},
        {"projectId": 1, "targetId": None, "conversationId": None, "query": "HTTP", "round": 0,
         "retrievalMethod": "bm25", "indexRevision": "sha256:" + "0" * 64, "items": []},
        {"intent": "GENERAL_QA", "needsRetrieval": False, "publicReasonCode": "GENERAL_KNOWLEDGE"},
    ))
    assert result["intent"] == "answer"
    assert result["knowledgeMode"] == "GENERAL"
    assert result["actions"] == result["evidenceRefs"] == []
    assert "未配置" in result["answer"]
    assert "工作流" not in result["answer"]
