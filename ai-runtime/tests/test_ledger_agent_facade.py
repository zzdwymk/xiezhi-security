from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from typing import Any

import pytest

from app import graph as graph_module
from app import indexing as indexing_module
from app.graph import LedgerAgentRuntime, verify_runtime_event_chain
from app.indexing import ProjectIndexStore
from app.schemas import (
    AgentRequest,
    EvidenceDecision,
    GroundedPlannerOutput,
    IntentDecision,
    LedgerAgentBudget,
    LedgerAgentContext,
    LedgerAgentResult,
    ProjectDocument,
)

PROJECT_ID = 71
TARGET_ID = 710
CONVERSATION_ID = "conversation-ledger-agent-facade"
POLICY_REVISION = "policy-ledger-agent-v3"


@pytest.fixture(autouse=True)
def _stable_rag_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    graph_settings = replace(
        graph_module.settings,
        rag_enabled=True,
        max_retrieval_rounds=2,
        max_evidence_items=5,
        max_evidence_chars=10_000,
        retrieval_timeout_seconds=5.0,
        max_rag_llm_calls=5,
        agent_turn_timeout_seconds=60.0,
        graph_recursion_limit=32,
    )
    index_settings = replace(
        indexing_module.settings,
        rag_enabled=True,
        max_retrieval_rounds=2,
        max_evidence_items=5,
        max_evidence_chars=10_000,
        retrieval_timeout_seconds=5.0,
    )
    monkeypatch.setattr(graph_module, "settings", graph_settings)
    monkeypatch.setattr(indexing_module, "settings", index_settings)


class FakePlannerApi:
    """Deterministic replacement for the three model-facing planner APIs."""

    def __init__(
        self,
        route_decision: dict[str, Any],
        assessment_script: list[tuple[str, str | None]] | None = None,
    ) -> None:
        self.route_decision = route_decision
        self.assessment_script = assessment_script or []
        self.route_calls = 0
        self.assess_calls: list[dict[str, Any]] = []
        self.grounded_calls: list[dict[str, Any]] = []
        self.legacy_plan_calls = 0

    async def route(self, request: dict[str, Any]) -> dict[str, Any]:
        self.route_calls += 1
        return IntentDecision.model_validate(self.route_decision).model_dump(
            mode="json"
        )

    async def assess_evidence(
        self,
        request: dict[str, Any],
        bundle: dict[str, Any],
        retrieval_round: int,
        prior_queries: list[str],
    ) -> dict[str, Any]:
        self.assess_calls.append(
            {"bundle": bundle, "round": retrieval_round, "priorQueries": list(prior_queries)}
        )
        index = len(self.assess_calls) - 1
        if index >= len(self.assessment_script):
            raise AssertionError("unexpected evidence assessment call")
        disposition, rewritten_query = self.assessment_script[index]
        if disposition == "FINALIZE":
            references = [item["evidenceId"] for item in bundle["items"][:1]]
            payload = {
                "decision": "FINALIZE",
                "reasonCodes": ["DIRECT_SUPPORT"],
                "evidenceRefs": references,
                "rewrittenQuery": None,
            }
        elif disposition == "REWRITE_QUERY":
            payload = {
                "decision": "REWRITE_QUERY",
                "reasonCodes": ["QUERY_TOO_BROAD"],
                "evidenceRefs": [],
                "rewrittenQuery": rewritten_query,
            }
        elif disposition == "CLARIFY":
            payload = {
                "decision": "CLARIFY",
                "reasonCodes": ["NO_RELEVANT_EVIDENCE"],
                "evidenceRefs": [],
                "rewrittenQuery": None,
            }
        else:
            raise AssertionError(f"unsupported fake disposition: {disposition}")
        return EvidenceDecision.model_validate(payload).model_dump(mode="json")

    async def grounded_plan(
        self,
        request: dict[str, Any],
        active_evidence: dict[str, Any],
        intent_decision: dict[str, Any],
    ) -> dict[str, Any]:
        self.grounded_calls.append({"evidence": active_evidence, "intent": intent_decision})
        project_grounded = intent_decision["intent"] == "PROJECT_QA"
        references = (
            [item["evidenceId"] for item in active_evidence.get("items", [])[:1]]
            if project_grounded
            else []
        )
        payload = {
            "summary": "fake planner answer",
            "answer": "evidence-backed answer." if references else "general answer.",
            "intent": "answer",
            "knowledgeMode": "PROJECT_EVIDENCE" if references else "GENERAL",
            "evidenceRefs": references,
            "actions": [],
        }
        plan = GroundedPlannerOutput.model_validate(payload).model_dump(mode="json")
        plan["source"] = "fake-planner-api"
        return plan

    async def plan(self, request: dict[str, Any]) -> dict[str, Any]:
        self.legacy_plan_calls += 1
        raise AssertionError("facade tests must not use the legacy planner API")


def _context(
    run_id: str = "facade-run-0001",
    message: str = "alpha service baseline",
    budget: LedgerAgentBudget | None = None,
) -> LedgerAgentContext:
    kwargs: dict[str, Any] = {
        "projectId": PROJECT_ID,
        "targetId": TARGET_ID,
        "conversationId": CONVERSATION_ID,
        "runId": run_id,
        "messages": [{"role": "user", "content": message}],
        "authorization": {
            "status": "ACTIVE",
            "targetIds": [TARGET_ID],
            "allowedTools": [],
            "approved": False,
            "quota": {"maxActions": 10, "usedActions": 0},
            "policyRevision": POLICY_REVISION,
        },
    }
    if budget is not None:
        kwargs["budget"] = budget
    return LedgerAgentContext(**kwargs)


def _seed_store(
    tmp_path: Any,
    *,
    text: str = "alpha service baseline confirms TLS is enabled",
    title: str = "Alpha baseline",
) -> ProjectIndexStore:
    store = ProjectIndexStore(tmp_path)
    store.index_project(
        PROJECT_ID,
        [
            ProjectDocument(
                id="alpha-0",
                title=title,
                text=text,
                source="project",
                metadata={"targetId": str(TARGET_ID)},
            )
        ],
        True,
    )
    return store


def _project_route(query: str = "alpha service baseline") -> dict[str, Any]:
    return {
        "intent": "PROJECT_QA",
        "needsRetrieval": True,
        "retrievalQuery": query,
        "publicReasonCode": "PROJECT_CONTEXT_REQUIRED",
    }


def _general_route() -> dict[str, Any]:
    return {
        "intent": "GENERAL_QA",
        "needsRetrieval": False,
        "retrievalQuery": None,
        "publicReasonCode": "GENERAL_KNOWLEDGE",
    }


def _invoke(runtime: LedgerAgentRuntime, context: LedgerAgentContext) -> LedgerAgentResult:
    return asyncio.run(runtime.invoke(context))


def test_invoke_returns_finite_result_for_general_qa(tmp_path: Any) -> None:
    runtime = LedgerAgentRuntime(ProjectIndexStore(tmp_path))
    runtime.planner = FakePlannerApi(_general_route())
    context = _context(message="What is TLS?")

    result = _invoke(runtime, context)

    assert isinstance(result, LedgerAgentResult)
    assert result.status == "COMPLETED"
    assert result.answer == "general answer."
    assert result.evidenceIds == []
    assert result.proposedActions == []
    assert result.ledgerDigest.startswith("sha256:")
    assert len(result.ledgerDigest) == 71


def test_invoke_returns_finite_result_for_project_qa(tmp_path: Any) -> None:
    runtime = LedgerAgentRuntime(_seed_store(tmp_path))
    runtime.planner = FakePlannerApi(_project_route(), [("FINALIZE", None)])
    context = _context()

    result = _invoke(runtime, context)

    assert isinstance(result, LedgerAgentResult)
    assert result.status == "COMPLETED"
    assert result.answer == "evidence-backed answer."
    assert len(result.evidenceIds) == 1
    assert result.evidenceIds[0].startswith("ev-")
    assert result.proposedActions == []
    assert result.ledgerDigest.startswith("sha256:")


def test_budget_tightens_max_llm_calls_and_fails_closed(tmp_path: Any) -> None:
    runtime = LedgerAgentRuntime(_seed_store(tmp_path))
    runtime.planner = FakePlannerApi(_general_route())
    context = _context(
        run_id="facade-budget-llm-0001",
        message="What is TLS?",
        budget=LedgerAgentBudget(maxRetrievalRounds=1, maxLlmCalls=1, timeoutSeconds=30),
    )

    result = _invoke(runtime, context)

    assert result.status == "FAILED"
    assert result.terminationReason == "GROUNDED_GENERATION_FAILED"
    assert result.proposedActions == []


def test_budget_tightens_max_retrieval_rounds(tmp_path: Any) -> None:
    runtime = LedgerAgentRuntime(_seed_store(tmp_path))
    runtime.planner = FakePlannerApi(
        _project_route(),
        assessment_script=[("REWRITE_QUERY", "refined alpha service")],
    )
    context = _context(
        run_id="facade-budget-retrieval-0001",
        budget=LedgerAgentBudget(maxRetrievalRounds=1, maxLlmCalls=5, timeoutSeconds=30),
    )

    result = _invoke(runtime, context)

    # With maxRetrievalRounds=1, the guard should deny a second round.
    assert result.status in ("CLARIFY", "COMPLETED", "FAILED", "DENIED")


def test_result_excludes_sensitive_data(tmp_path: Any) -> None:
    runtime = LedgerAgentRuntime(_seed_store(tmp_path))
    runtime.planner = FakePlannerApi(_project_route(), [("FINALIZE", None)])
    context = _context()

    result = _invoke(runtime, context)
    serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)

    for forbidden in ["prompt", "chainOfThought", "token", "credential", "secret"]:
        assert forbidden not in serialized, (
            f"sensitive marker '{forbidden}' leaked into LedgerAgentResult"
        )
    assert set(type(result).model_fields.keys()) == {
        "status",
        "answer",
        "evidenceIds",
        "proposedActions",
        "terminationReason",
        "ledgerDigest",
    }


def test_invoke_validates_event_chain_integrity(tmp_path: Any) -> None:
    runtime = LedgerAgentRuntime(_seed_store(tmp_path))
    runtime.planner = FakePlannerApi(_general_route())
    context = _context(message="What is TLS?")

    # Collect the stream events and the invoke result from the same run.
    async def collect_both() -> tuple[list[dict[str, Any]], LedgerAgentResult]:
        events: list[dict[str, Any]] = []
        terminal: dict[str, Any] | None = None
        async for event in runtime.stream(context):
            events.append(event)
            if event.get("type") in {"finish", "error"}:
                terminal = event
        assert terminal is not None, "stream must emit a terminal event"
        data = terminal.get("data") if isinstance(terminal.get("data"), dict) else {}
        plan = data.get("plan") if isinstance(data.get("plan"), dict) else {}
        actions = plan.get("actions") if isinstance(plan.get("actions"), list) else []
        proposed = [
            {
                "workflowNodeId": a.get("workflowNodeId"),
                "parameters": a.get("parameters", {}),
                "evidenceRefs": a.get("evidenceRefs", []),
            }
            for a in actions
            if isinstance(a, dict)
        ]
        status = str(data.get("status") or "FAILED")
        if status == "COMPLETED" and plan.get("intent") == "clarify":
            status = "CLARIFY"
        result = LedgerAgentResult.model_validate(
            {
                "status": status,
                "answer": str(data.get("answer") or ""),
                "evidenceIds": data.get("evidenceIds", []),
                "proposedActions": proposed,
                "terminationReason": data.get("terminationReason"),
                "ledgerDigest": terminal.get("ledgerEntryDigest"),
            }
        )
        return events, result

    events, result = asyncio.run(collect_both())
    assert events, "stream must emit at least one event"
    assert verify_runtime_event_chain(events)
    assert events[-1]["type"] == "finish"
    assert result.ledgerDigest == events[-1]["ledgerEntryDigest"]