from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.model import AgentPlanner, PlannerOutputError, build_workflow_capability_manifest


class FakeChain:
    def __init__(self, *outputs):
        self.outputs = list(outputs)
        self.calls = []

    async def ainvoke(self, payload):
        self.calls.append(payload)
        return SimpleNamespace(content=json.dumps(self.outputs.pop(0)))


def request(maximum=4, used=0):
    return {
        "projectId": 7,
        "targetId": 9,
        "messages": [{"role": "user", "content": "Prepare an authorized check plan."}],
        "authorization": {
            "status": "ACTIVE",
            "allowedTools": ["http_headers"],
            "allowedPorts": "80,443",
            "quota": {"maxActions": maximum, "usedActions": used},
        },
        "workflow": [
            {"nodeId": f"headers-{index}", "tool": "http_headers", "parameters": {},
             "risk": "SAFE", "requiresApproval": False, "group": index,
             "dependsOnNodeIds": [f"headers-{index - 1}"] if index > 0 else []}
            for index in range(6)
        ],
    }


def evidence():
    return {
        "projectId": 7, "targetId": 9, "conversationId": None,
        "query": "Authorized target", "round": 0, "retrievalMethod": "bm25",
        "indexRevision": "sha256:" + "a" * 64,
        "items": [{"evidenceId": "ev-1", "documentId": "doc-1", "title": "Scope",
                   "source": "target", "snippet": "Ports 80 and 443 are authorized.",
                   "score": 1.0, "targetId": 9, "contentDigest": "sha256:" + "b" * 64}],
    }


def route():
    return {"intent": "ACTION_PLAN", "needsRetrieval": True,
            "retrievalQuery": "Authorized target", "publicReasonCode": "AUTHORIZED_ACTION_REQUEST"}


def output(count):
    return {
        "summary": "Check plan", "answer": "This batch is a proposal, not executed.",
        "intent": "plan", "knowledgeMode": "PROJECT_EVIDENCE", "evidenceRefs": ["ev-1"],
        "actions": [{"workflowNodeId": f"headers-{index}", "parameters": {},
                     "evidenceRefs": ["ev-1"]} for index in range(count)],
    }


def planner_with(chain, grounded=True):
    planner = AgentPlanner(index_store=None)
    planner._llm_requested = True
    planner._chain_load_attempted = True
    if grounded:
        planner._grounded_chain = chain
    else:
        planner._planner_chain = chain
    return planner


def supplied_contract(call):
    return json.loads(call["contract_output_requirements"].split(
        "BEGIN_SERVER_OUTPUT_CONTRACT\n", 1)[1].split("\nEND_SERVER_OUTPUT_CONTRACT", 1)[0])


@pytest.mark.parametrize("maximum,used,remaining", [(4, 0, 4), (4, 3, 1), (4, 4, 0), (4, 7, 0), (20, 0, 8)])
def test_capability_limit_and_dependency_requirements_use_current_remaining_quota(maximum, used, remaining):
    manifest = build_workflow_capability_manifest(request(maximum, used))
    assert manifest["maxActions"] == remaining
    for index, node in enumerate(manifest["nodes"]):
        assert node["planningRequirements"]["requiredActionCount"] == index + 1
        assert node["planningRequirements"]["exceedsActionLimit"] == (index + 1 > remaining)


def test_legacy_request_without_quota_keeps_the_eight_action_contract():
    req = request()
    del req["authorization"]["quota"]
    assert build_workflow_capability_manifest(req)["maxActions"] == 8


@pytest.mark.parametrize("decision", ["EXECUTE", "PLAN_ONLY"])
def test_six_action_model_proposal_gets_one_fresh_quota_bounded_generation_not_truncation(decision):
    rejected = output(6)
    chain = FakeChain(rejected, output(4))
    planner = planner_with(chain)
    result = asyncio.run(planner.grounded_plan(request(), evidence(), {**route(), "executionDecision": decision}))
    assert len(result["actions"]) == 4
    assert len(rejected["actions"]) == 6
    assert len(chain.calls) == 2
    for call in chain.calls:
        assert supplied_contract(call)["expectedSchema"]["properties"]["actions"]["maxItems"] == 4
        assert '"maxActions":4' in call["workflow_capabilities"]
    feedback = chain.calls[1]["contract_repair_feedback"]
    assert '"path":["actions"],"type":"too_long"' in feedback
    assert "This batch is a proposal" not in feedback


def test_repeated_over_quota_output_fails_closed_without_silently_creating_a_partial_plan():
    chain = FakeChain(output(6), output(6))
    planner = planner_with(chain)
    with pytest.raises(PlannerOutputError, match="current action quota"):
        asyncio.run(planner.grounded_plan(request(), evidence(), route()))
    assert len(chain.calls) == 2


def test_occupied_target_advertises_only_one_action_to_the_model():
    chain = FakeChain(output(1))
    result = asyncio.run(planner_with(chain).grounded_plan(request(4, 3), evidence(), route()))
    assert len(result["actions"]) == 1
    assert supplied_contract(chain.calls[0])["expectedSchema"]["properties"]["actions"]["maxItems"] == 1


def test_zero_remaining_quota_still_allows_an_explanation_without_actions():
    clarification = {"summary": "Quota occupied", "answer": "Wait for capacity or adjust the plan.",
                     "intent": "clarify", "knowledgeMode": "INSUFFICIENT_EVIDENCE",
                     "evidenceRefs": [], "actions": []}
    chain = FakeChain(clarification)
    result = asyncio.run(planner_with(chain).grounded_plan(request(4, 4), evidence(), route()))
    assert result["actions"] == []
    assert supplied_contract(chain.calls[0])["expectedSchema"]["properties"]["actions"]["maxItems"] == 0


def test_quota_does_not_block_pure_questions_or_change_their_zero_action_schema():
    answer = {"summary": "General answer", "answer": "HTTP is an application protocol.",
              "intent": "answer", "knowledgeMode": "GENERAL", "evidenceRefs": [], "actions": []}
    chain = FakeChain(answer)
    bundle = evidence()
    bundle["items"] = []
    general = {"intent": "GENERAL_QA", "needsRetrieval": False, "publicReasonCode": "GENERAL_KNOWLEDGE"}
    result = asyncio.run(planner_with(chain).grounded_plan(request(4, 4), bundle, general))
    assert result["answer"] == answer["answer"]
    assert supplied_contract(chain.calls[0])["expectedSchema"]["properties"]["actions"]["maxItems"] == 0


def test_legacy_planner_also_uses_the_combined_quota_without_changing_user_input():
    tools = ["tcp_ports", "nmap_service_scan", "http_headers", "site_crawl", "tls_config", "dir_scan"]
    excessive = {"summary": "Check plan", "answer": "Plan only", "intent": "plan",
                 "actions": [{"tool": tool, "parameters": {}, "risk": "SAFE",
                              "requiresApproval": False, "group": index} for index, tool in enumerate(tools)]}
    valid = deepcopy(excessive)
    valid["actions"] = valid["actions"][:4]
    chain = FakeChain(excessive, valid)
    req = request()
    result = asyncio.run(planner_with(chain, grounded=False).plan(req))
    assert len(result["actions"]) == 4
    assert len(chain.calls) == 2
    assert chain.calls[0]["message"] == chain.calls[1]["message"]
    assert supplied_contract(chain.calls[0])["expectedSchema"]["properties"]["actions"]["maxItems"] == 4
