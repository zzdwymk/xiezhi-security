"""Bounded fresh generation after invalid grounding; never repair IDs or execute output."""
import asyncio
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

import test_model_contracts as fixtures
from app import diagnostics, graph
from app.model import PlannerOutputError, contract_repair_budget


def prepared(*outputs):
    planner = fixtures._model_planner()
    chain = planner._grounded_chain = fixtures._ScriptedContractChain(*outputs)
    return planner, chain


def generate(planner, evidence=None):
    return planner.grounded_plan(fixtures._request(), evidence or fixtures._bundle(),
                                 fixtures._decision_for_route("ACTION_PLAN"))


def invalid_reference(location="action", value="PRIVATE_INVALID_REFERENCE"):
    output = fixtures._grounded_output()
    if location == "top":
        output["evidenceRefs"].append(value)
    else:
        output["actions"][0]["evidenceRefs"].append(value)
    return output


@pytest.mark.parametrize("location", ["top", "action"])
@pytest.mark.parametrize("invalid", ["finding-298", "doc-1", "service-scan-01", "ev-other-session", "PRIVATE_INVALID_REFERENCE"])
def test_only_fresh_fully_valid_model_output_can_recover(location, invalid):
    first = invalid_reference(location, invalid)
    before = deepcopy(first)
    valid = fixtures._grounded_output()
    valid["answer"] = "Fresh model answer; not copied from rejected response"
    planner, chain = prepared(first, valid)
    result = asyncio.run(generate(planner))
    assert len(chain.calls) == 2
    assert result["answer"] == valid["answer"]
    assert first == before
    first_input, second_input = chain.calls
    assert {k: v for k, v in first_input.items() if k != "contract_repair_feedback"} == {
        k: v for k, v in second_input.items() if k != "contract_repair_feedback"}
    feedback = second_input["contract_repair_feedback"]
    assert "UNKNOWN_GROUNDED_REFERENCE" in feedback
    assert invalid not in feedback or invalid in {"doc-1", "service-scan-01"}  # trusted schema may name its real node
    assert "allowedEvidenceIds" in feedback and "ev-1" in feedback and "ev-2" in feedback
    assert result["evidenceRefs"] == valid["evidenceRefs"]


@pytest.mark.parametrize("second", ["unknown-reference", "unknown-node", "bad-parameters", "schema"])
def test_second_rejection_never_gets_a_third_attempt_or_partial_plan(second):
    bad = invalid_reference() if second == "unknown-reference" else fixtures._grounded_output()
    if second == "unknown-node":
        bad["actions"][0]["workflowNodeId"] = "outside-node"
    elif second == "bad-parameters":
        bad["actions"][0]["parameters"] = {"command": "outside-command"}
    elif second == "schema":
        bad.pop("intent")
    planner, chain = prepared(invalid_reference(), bad, fixtures._grounded_output())
    with pytest.raises(PlannerOutputError):
        asyncio.run(generate(planner))
    assert len(chain.calls) == 2


def test_reference_recovery_cannot_add_a_third_call_after_schema_correction():
    planner, chain = prepared("not-json", invalid_reference(), fixtures._grounded_output())
    with pytest.raises(PlannerOutputError, match="unknown references"):
        asyncio.run(generate(planner))
    assert len(chain.calls) == 2


def test_zero_repair_budget_and_empty_evidence_do_not_regenerate():
    for evidence in [fixtures._bundle(), {**fixtures._bundle(), "items": []}]:
        planner, chain = prepared(invalid_reference(), fixtures._grounded_output())
        with contract_repair_budget(0), pytest.raises(PlannerOutputError, match="unknown references"):
            asyncio.run(generate(planner, evidence))
        assert len(chain.calls) == 1
    planner, chain = prepared(invalid_reference(), fixtures._grounded_output())
    with pytest.raises(PlannerOutputError, match="unknown references"):
        asyncio.run(generate(planner, {**fixtures._bundle(), "items": []}))
    assert len(chain.calls) == 1


def test_graph_total_model_call_budget_still_limits_reference_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    runtime = object.__new__(graph.SecurityAgentRuntime)
    planner, chain = prepared(invalid_reference(), fixtures._grounded_output())
    with pytest.raises(PlannerOutputError, match="unknown references"):
        asyncio.run(runtime._bounded_planner_call({"runId": "budget-ref", "llmCallCount": 2,
            "request": {"budget": {"maxLlmCalls": 3}}}, planner.grounded_plan,
            fixtures._request(), fixtures._bundle(), fixtures._decision_for_route("ACTION_PLAN")))
    assert len(chain.calls) == 1


def test_graph_shared_timeout_covers_both_generation_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    monkeypatch.setattr(graph, "settings", replace(graph.settings, llm_timeout_seconds=0.1))
    planner, _ = prepared()
    class SlowChain:
        calls = 0
        async def ainvoke(self, payload):
            self.calls += 1
            await asyncio.sleep(0.06)
            return SimpleNamespace(content=json.dumps(invalid_reference() if self.calls == 1 else fixtures._grounded_output()))
    chain = planner._grounded_chain = SlowChain()
    runtime = object.__new__(graph.SecurityAgentRuntime)
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(runtime._bounded_planner_call({"runId": "timeout-ref", "request": {}}, planner.grounded_plan,
            fixtures._request(), fixtures._bundle(), fixtures._decision_for_route("ACTION_PLAN")))
    assert chain.calls == 2


def test_first_invalid_attempt_stays_in_diagnostics_after_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    planner, _ = prepared(invalid_reference(), fixtures._grounded_output())
    runtime = object.__new__(graph.SecurityAgentRuntime)
    result, calls = asyncio.run(runtime._bounded_planner_call({"runId": "ref-diag", "request": {}}, planner.grounded_plan,
        fixtures._request(), fixtures._bundle(), fixtures._decision_for_route("ACTION_PLAN")))
    assert calls == 2 and result["actions"]
    text = (tmp_path / "diagnostics/model-contract.jsonl").read_text(encoding="utf-8")
    rows = [json.loads(line) for line in text.splitlines()]
    assert [(r["outcome"], r["category"], r["attempt"]) for r in rows] == [
        ("RETRY_REQUESTED", "SEMANTIC", 1), ("REPAIRED", "NONE", 2)]
    assert rows[0]["errors"][0]["rule"] == "UNKNOWN_GROUNDED_REFERENCE"
    assert "PRIVATE_INVALID_REFERENCE" not in text


def test_failed_reference_regeneration_has_specific_terminal_reason_and_no_actions(tmp_path, monkeypatch):
    monkeypatch.setattr(diagnostics, "settings", replace(diagnostics.settings, data_dir=tmp_path))
    planner, chain = prepared(invalid_reference(), invalid_reference())
    runtime = object.__new__(graph.SecurityAgentRuntime)
    runtime.planner = planner
    result = asyncio.run(runtime._grounded_generation_node({"runId": "ref-failed", "request": fixtures._request(),
        "activeEvidence": fixtures._bundle(), "intentDecision": fixtures._decision_for_route("ACTION_PLAN")}))
    assert result["terminalStatus"] == "FAILED"
    assert result["terminationReason"] == "GROUNDED_REFERENCE_INVALID"
    assert result["plan"]["actions"] == []
    assert result["llmCallCount"] == len(chain.calls) == 2
