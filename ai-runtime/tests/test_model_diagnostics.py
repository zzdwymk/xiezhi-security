import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app import diagnostics
from app.graph import SecurityAgentRuntime
from app.model import AgentPlanner, PlannerOutputError


def _planner(outputs):
    class Chain:
        calls = []
        async def ainvoke(self, payload):
            self.calls.append(payload)
            return SimpleNamespace(content=json.dumps(outputs[len(self.calls) - 1]))
    planner = AgentPlanner(None)
    planner._llm_requested = True
    planner._chain_load_attempted = True
    planner._auto_intent_chain = Chain()
    return planner


def _request():
    return {"executionIntent": "AUTO", "currentUserRequest": "PRIVATE_CURRENT_USER_REQUEST",
            "messages": [{"role": "user", "content": "PRIVATE_CONTEXT"}]}


def _bounded(planner):
    runtime = object.__new__(SecurityAgentRuntime)
    return asyncio.run(runtime._bounded_planner_call({"runId": "diagnostic-test-run", "request": {}}, planner.route, _request()))


def test_retry_and_final_schema_rule_are_logged_without_raw_input_or_custom_names(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    monkeypatch.setattr("sys.stderr", None)
    invalid = {"intent": "CLARIFY", "needsRetrieval": "PRIVATE_VALUE", "publicReasonCode": "AMBIGUOUS_REQUEST",
               "executionDecision": "CLARIFY", "PRIVATE_CUSTOM_FIELD": "PRIVATE_MODEL_REASONING"}
    inconsistent = {"intent": "CLARIFY", "needsRetrieval": False, "publicReasonCode": "AMBIGUOUS_REQUEST",
                    "executionDecision": "PLAN_ONLY"}
    planner = _planner([invalid, inconsistent])
    with pytest.raises(PlannerOutputError):
        _bounded(planner)
    text = (tmp_path / "diagnostics/model-contract.jsonl").read_text(encoding="utf-8")
    entries = [json.loads(line) for line in text.splitlines()]
    assert [(item["stage"], item["outcome"], item["category"], item["attempt"]) for item in entries] == [
        ("ROUTE", "RETRY_REQUESTED", "SCHEMA", 1), ("ROUTE", "REJECTED", "SCHEMA", 2)]
    assert entries[0]["errors"][0]["path"] == ["needsRetrieval"]
    assert entries[1]["errors"][0]["rule"] == "CLARIFY_INTENT_MISMATCH"
    assert entries[0]["runId"] == entries[1]["runId"] == "diagnostic-test-run"
    assert "PRIVATE_" not in text
    assert "PRIVATE_" not in planner._auto_intent_chain.calls[1]["contract_repair_feedback"]


def test_successful_repair_has_a_distinct_outcome_and_clears_run_context(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    valid = {"intent": "CLARIFY", "needsRetrieval": False, "publicReasonCode": "AMBIGUOUS_REQUEST",
             "executionDecision": "CLARIFY"}
    result, count = _bounded(_planner([{}, valid]))
    assert result == valid and count == 2
    diagnostics.record_diagnostic("GROUNDED", "REJECTED", "SEMANTIC", [{"path": [], "type": "semantic_constraint",
        "rule": "ACTION_ROUTE_CONFLICT", "input": "PRIVATE", "msg": "PRIVATE"}])
    text = (tmp_path / "diagnostics/model-contract.jsonl").read_text(encoding="utf-8")
    entries = [json.loads(line) for line in text.splitlines()]
    assert entries[1]["outcome"] == "REPAIRED"
    assert entries[2]["runId"] == ""
    assert entries[2]["errors"][0]["rule"] == "ACTION_ROUTE_CONFLICT"
    assert "PRIVATE" not in text


def test_diagnostic_writer_is_bounded_and_rejects_untrusted_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    monkeypatch.setattr(diagnostics, "MAX_LOG_BYTES", 700)
    for _ in range(20):
        diagnostics.record_diagnostic("ROUTE", "REJECTED", "SCHEMA", [{
            "path": ["PRIVATE_FIELD", 100000, "executionDecision"], "type": "PRIVATE_TYPE",
            "rule": "PRIVATE_RULE", "input": "PRIVATE_INPUT"}])
    files = list((tmp_path / "diagnostics").glob("*.jsonl"))
    assert len(files) == 2
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE" not in text and "<unknown-field>" in text
        assert path.stat().st_size <= 700


def test_diagnostic_write_failure_does_not_replace_the_valid_result(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    (tmp_path / "diagnostics").write_text("blocked directory", encoding="utf-8")
    valid = {"intent": "CLARIFY", "needsRetrieval": False, "publicReasonCode": "AMBIGUOUS_REQUEST",
             "executionDecision": "CLARIFY"}
    assert _bounded(_planner([{}, valid]))[0] == valid


def test_unknown_evidence_is_a_semantic_rejection_without_a_model_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    planner = _planner([{"summary": "answer", "answer": "PRIVATE_MODEL_ANSWER", "intent": "answer",
                         "knowledgeMode": "PROJECT_EVIDENCE", "evidenceRefs": ["private-unknown-ref"], "actions": []}])
    planner._grounded_chain = planner._auto_intent_chain
    request = {**_request(), "projectId": 1, "targetId": 2}
    evidence = {"projectId": 1, "targetId": 2, "conversationId": None, "query": "known facts", "round": 0,
                "retrievalMethod": "bm25", "indexRevision": "sha256:" + "a" * 64, "items": []}
    route = {"intent": "PROJECT_QA", "needsRetrieval": True, "retrievalQuery": "known facts",
             "publicReasonCode": "PROJECT_CONTEXT_REQUIRED", "executionDecision": "PLAN_ONLY"}
    runtime = object.__new__(SecurityAgentRuntime)
    with pytest.raises(PlannerOutputError, match="unknown references"):
        asyncio.run(runtime._bounded_planner_call({"runId": "semantic-test-run", "request": {}},
            planner.grounded_plan, request, evidence, route))
    lines = (tmp_path / "diagnostics/model-contract.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(planner._grounded_chain.calls) == 1
    entry = json.loads(lines[0])
    assert entry["category"] == "SEMANTIC" and entry["stage"] == "GROUNDED"
    assert entry["errors"][0]["rule"] == "UNKNOWN_GROUNDED_REFERENCE"
    assert "PRIVATE" not in lines[0] and "private-unknown-ref" not in lines[0]
