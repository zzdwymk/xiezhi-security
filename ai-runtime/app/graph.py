from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import secrets
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, TypedDict

from .authorization import (
    parse_instant,
    port_intervals,
    ports_allowed,
    requested_port_intervals,
)
from .config import settings
from .model import AgentPlanner, HIGH_RISK_TOOLS, PlannerOutputError
from .schemas import (
    EvidenceBundle,
    LedgerAgentContext,
    LedgerAgentResult,
)
from .tools import build_agent_tools

try:
    from langgraph.graph import END, START, StateGraph

    LANGGRAPH_AVAILABLE = True
except Exception:  # pragma: no cover
    END = "__end__"  # type: ignore[assignment]
    START = "__start__"  # type: ignore[assignment]
    StateGraph = None  # type: ignore[assignment]
    LANGGRAPH_AVAILABLE = False


class AgentState(TypedDict, total=False):
    request: dict[str, Any]
    intentDecision: dict[str, Any]
    retrievalRound: int
    retrievalQueries: list[str]
    retrievalActionId: str
    retrievalGuardStatus: str
    retrievalGuardError: str | None
    retrievalCount: int
    evidenceBundles: list[dict[str, Any]]
    activeEvidence: dict[str, Any]
    evidenceDecision: dict[str, Any]
    llmCallCount: int
    terminationReason: str | None
    terminalStatus: str | None
    plan: dict[str, Any]
    guardedActions: list[dict[str, Any]]
    guardViolations: list[str]
    approvalActions: list[dict[str, Any]]
    toolResults: list[dict[str, Any]]
    executorError: str | None
    retryCount: int
    maxRetries: int
    review: dict[str, Any]
    final: dict[str, Any]
    event: dict[str, Any]
    events: list[dict[str, Any]]
    failedActions: list[dict[str, Any]]
    authorizationDecision: dict[str, Any]
    runId: str


RED_TEAM_STAGE_IDS = (
    "engage",
    "recon",
    "map",
    "validate",
    "impact",
    "retest",
    "report",
    "finish",
)

TOOL_STAGE = {
    "retrieve_project_context": "recon",
    "tcp_ports": "map",
    "nmap_service_scan": "map",
    "http_headers": "map",
    "tls_config": "map",
    "http_security_check": "validate",
    "nuclei_scan": "validate",
}

CONTRACT_VERSION = 3
RUNTIME_LEDGER_GENESIS_DIGEST = "sha256:" + ("0" * 64)
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SENSITIVE_EVENT_DATA_KEYS = {
    "apikey",
    "authorization",
    "chainofthought",
    "content",
    "cot",
    "credential",
    "credentials",
    "evidencetext",
    "evidencebody",
    "evidencecontent",
    "fullevidence",
    "prompt",
    "originalprompt",
    "userprompt",
    "rawprompt",
    "rawevidence",
    "reasoning",
    "secret",
    "snippet",
    "systemprompt",
    "text",
    "token",
    "accesstoken",
    "refreshtoken",
    "password",
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sanitize_public_event_data(value: Any) -> Any:
    """Remove payload classes that must never cross the public/Ledger boundary."""
    if isinstance(value, dict):
        return {
            str(key): _sanitize_public_event_data(item)
            for key, item in value.items()
            if re.sub(r"[^a-z]", "", str(key).casefold())
            not in _SENSITIVE_EVENT_DATA_KEYS
        }
    if isinstance(value, list):
        return [_sanitize_public_event_data(item) for item in value]
    return value


def runtime_event_digest(
    event: dict[str, Any], previous_digest: str = RUNTIME_LEDGER_GENESIS_DIGEST
) -> str:
    """Hash a finite public event projection for Java to verify before persistence.

    This is a runtime candidate chain, not the authoritative Java Ledger digest.
    """
    if not _DIGEST_PATTERN.fullmatch(previous_digest):
        raise ValueError("previous runtime event digest is invalid")
    public_fields = (
        "eventId",
        "type",
        "node",
        "innerStep",
        "message",
        "timestamp",
        "data",
        "contractVersion",
        "runId",
        "workflowDigest",
        "outerNodeId",
        "nodeRunId",
        "stateVersion",
        "ledgerSequence",
        "policyRevision",
    )
    payload = {
        "previousLedgerEntryDigest": previous_digest,
        "event": {key: event.get(key) for key in public_fields},
    }
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def verify_runtime_event_chain(events: list[dict[str, Any]]) -> bool:
    """Verify sequence, immutable run context, and candidate digest continuity."""
    if not events:
        return False
    previous_digest = RUNTIME_LEDGER_GENESIS_DIGEST
    context: tuple[Any, ...] | None = None
    event_ids: set[str] = set()
    for expected_sequence, event in enumerate(events, start=1):
        current_context = (
            event.get("contractVersion"),
            event.get("runId"),
            event.get("workflowDigest"),
            event.get("outerNodeId"),
            event.get("nodeRunId"),
            event.get("policyRevision"),
        )
        if context is None:
            context = current_context
        event_id = event.get("eventId")
        workflow_digest = event.get("workflowDigest")
        if (
            current_context != context
            or event.get("contractVersion") != CONTRACT_VERSION
            or type(event.get("stateVersion")) is not int
            or type(event.get("ledgerSequence")) is not int
            or event.get("stateVersion") != expected_sequence
            or event.get("ledgerSequence") != expected_sequence
            or event.get("innerStep") != event.get("node")
            or not isinstance(event_id, str)
            or event_id in event_ids
            or not isinstance(workflow_digest, str)
            or not _DIGEST_PATTERN.fullmatch(workflow_digest)
            or not isinstance(event.get("runId"), str)
            or not event.get("runId")
            or not isinstance(event.get("outerNodeId"), str)
            or not event.get("outerNodeId")
            or not isinstance(event.get("nodeRunId"), str)
            or not event.get("nodeRunId")
            or not isinstance(event.get("innerStep"), str)
            or not event.get("innerStep")
        ):
            return False
        try:
            uuid.UUID(event_id)
            timestamp = str(event.get("timestamp", "")).replace("Z", "+00:00")
            datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            return False
        event_ids.add(event_id)
        try:
            expected_digest = runtime_event_digest(event, previous_digest)
        except (TypeError, ValueError):
            return False
        if not hmac.compare_digest(
            str(event.get("ledgerEntryDigest", "")), expected_digest
        ):
            return False
        previous_digest = expected_digest
    return True


def _runtime_context(
    request: dict[str, Any], run_id: str
) -> tuple[str, str, str]:
    workflow_digest = str(request.get("workflowDigest") or "")
    if not _DIGEST_PATTERN.fullmatch(workflow_digest):
        workflow_digest = "sha256:" + hashlib.sha256(
            _canonical_json({"workflow": request.get("workflow", [])})
        ).hexdigest()
    outer_node_id = str(request.get("outerNodeId") or "ledger-agent")
    node_run_id = str(request.get("nodeRunId") or "")
    if not node_run_id:
        seed = {
            "runId": run_id,
            "workflowDigest": workflow_digest,
            "outerNodeId": outer_node_id,
        }
        node_run_id = "node-run-" + hashlib.sha256(_canonical_json(seed)).hexdigest()[:32]
    return workflow_digest, outer_node_id, node_run_id


def envelope_runtime_event(
    event: dict[str, Any],
    request: dict[str, Any],
    run_id: str,
    sequence: int,
    previous_digest: str = RUNTIME_LEDGER_GENESIS_DIGEST,
) -> dict[str, Any]:
    if sequence <= 0:
        raise ValueError("runtime event sequence must be positive")
    workflow_digest, outer_node_id, node_run_id = _runtime_context(request, run_id)
    result = dict(event)
    inner_step = str(result.get("node") or "runtime")
    result["node"] = inner_step
    result["innerStep"] = inner_step
    result["data"] = _sanitize_public_event_data(result.get("data", {}))
    result["contractVersion"] = CONTRACT_VERSION
    result["runId"] = run_id
    result["workflowDigest"] = workflow_digest
    result["outerNodeId"] = outer_node_id
    result["nodeRunId"] = node_run_id
    result["stateVersion"] = sequence
    result["ledgerSequence"] = sequence
    result["policyRevision"] = str(
        request.get("authorization", {}).get(
            "policyRevision", "java-authoritative-v1"
        )
    )
    result["ledgerEntryDigest"] = runtime_event_digest(result, previous_digest)
    return result


def _event(
    event_type: str, node: str, message: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "eventId": str(uuid.uuid4()),
        "type": event_type,
        "node": node,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
    }


class LedgerAgentRuntime:
    """Black-box LedgerAgent runtime; it can propose actions but never execute them."""

    def __init__(self, index_store: Any) -> None:
        self.index_store = index_store
        self.planner = AgentPlanner(index_store)
        self.tools = build_agent_tools(index_store)
        self._decision_secret = secrets.token_bytes(32)
        self.graph = self._build_graph() if LANGGRAPH_AVAILABLE else None

    @property
    def health(self) -> dict[str, Any]:
        return {
            "langGraphAvailable": LANGGRAPH_AVAILABLE,
            "graphCompiled": self.graph is not None,
            "nodes": ["ledger-agent"],
            "workflowVersion": 3,
            **self.planner.status,
        }

    def graph_structure(self) -> dict[str, Any]:
        """Public graph: the bounded runtime is one opaque outer DAG node."""
        return {
            "version": 3,
            "preset": "ledger-agent-black-box",
            "nodes": [
                {
                    "id": "ledger-agent",
                    "label": "LedgerAgent",
                    "kind": "ledger-agent",
                    "phase": "agent",
                    "desc": "受限证据检索、决策与动作提案",
                    "removable": False,
                }
            ],
            "edges": [
                {"source": "__start__", "target": "ledger-agent", "conditional": False},
                {"source": "ledger-agent", "target": "__end__", "conditional": False},
            ],
            "source": "outer-dag",
        }

    def internal_graph_structure(self) -> dict[str, Any]:
        """Expose the workflow topology for the visual editor.

        The node/edge list mirrors the compiled graph; when LangGraph is
        available we also attach the *real* compiled structure so the UI can
        prove it renders the actual agent rather than a hand-drawn diagram.
        """
        nodes = [
            {
                "id": "engage",
                "label": "任务启动与范围确认",
                "kind": "engagement",
                "phase": "engagement",
                "desc": "绑定项目、目标、授权时间窗、停止条件和资源配额",
                "removable": False,
            },
            {
                "id": "recon",
                "label": "侦察与情报整理",
                "kind": "recon",
                "phase": "recon",
                "desc": "优先复用项目资料和公开情报，减少不必要探测",
                "removable": False,
            },
            {
                "id": "map",
                "label": "资产与服务发现",
                "kind": "mapping",
                "phase": "mapping",
                "desc": "在授权范围内识别资产、端口、服务、版本和基础指纹",
                "removable": False,
            },
            {
                "id": "validate",
                "label": "漏洞验证与受控利用",
                "kind": "validation",
                "phase": "validation",
                "desc": "以最小影响方式验证风险并保留可复核证据",
                "removable": False,
            },
            {
                "id": "impact",
                "label": "权限与影响评估",
                "kind": "impact",
                "phase": "impact",
                "desc": "评估攻击路径和业务影响；高风险动作在此等待人工审批",
                "removable": False,
            },
            {
                "id": "retest",
                "label": "清理与复测",
                "kind": "retest",
                "phase": "retest",
                "desc": "清理测试痕迹、复测修复结果并记录扫描 Diff",
                "removable": False,
            },
            {
                "id": "report",
                "label": "报告交付",
                "kind": "report",
                "phase": "report",
                "desc": "汇总证据链、风险结论、整改建议和审计记录",
                "removable": False,
            },
            {
                "id": "finish",
                "label": "任务结束",
                "kind": "finish",
                "phase": "report",
                "desc": "归档本轮状态并明确后续动作",
                "removable": False,
            },
        ]
        edges = [
            {"source": "__start__", "target": "engage", "conditional": False},
            {"source": "engage", "target": "recon", "conditional": False},
            {"source": "recon", "target": "map", "conditional": False},
            {"source": "map", "target": "validate", "conditional": False},
            {"source": "validate", "target": "impact", "conditional": False},
            {"source": "impact", "target": "retest", "conditional": False},
            {"source": "retest", "target": "report", "conditional": False},
            {"source": "report", "target": "finish", "conditional": False},
            {"source": "finish", "target": "__end__", "conditional": False},
        ]
        compiled: dict[str, Any] | None = None
        if self.graph is not None:
            try:
                g = self.graph.get_graph()
                compiled = {
                    "nodes": list(g.nodes.keys()),
                    "edges": [
                        {
                            "source": e.source,
                            "target": e.target,
                            "conditional": bool(getattr(e, "conditional", False)),
                        }
                        for e in g.edges
                    ],
                }
            except Exception:
                compiled = None
        return {
            "version": 3,
            "preset": "red-team-lifecycle",
            "nodes": nodes,
            "edges": edges,
            "compiled": compiled,
            "source": "langgraph" if compiled else "static",
            # Older clients can keep interpreting event types such as plan/tool/review;
            # only the public stage names changed.
            "legacyNodeAliases": {
                "planner": "engage",
                "authorization_guard": "engage",
                "executor": "validate",
                "approval_required": "impact",
                "retry": "retest",
                "reviewer": "report",
            },
        }

    def _build_graph(self) -> Any:
        builder = StateGraph(AgentState)
        builder.add_node("route", self._route_node)
        builder.add_node("retrieval_guard", self._retrieval_guard_node)
        builder.add_node("retrieve", self._retrieve_node)
        builder.add_node("assess", self._assess_node)
        builder.add_node("rewrite", self._rewrite_node)
        builder.add_node("grounded_generation", self._grounded_generation_node)
        builder.add_node("engage", self._engage_node)
        builder.add_node("recon", self._recon_node)
        builder.add_node("map", self._map_node)
        builder.add_node("validate", self._validate_node)
        builder.add_node("impact", self._impact_node)
        builder.add_node("retest", self._retest_stage_node)
        builder.add_node("report", self._report_node)
        builder.add_node("finish", self._finish_node)
        builder.add_edge(START, "route")
        builder.add_conditional_edges(
            "route",
            self._route_after_intent,
            {
                "retrieve": "retrieval_guard",
                "generate": "grounded_generation",
                "engage": "engage",
            },
        )
        builder.add_conditional_edges(
            "retrieval_guard",
            self._route_after_retrieval_guard,
            {"retrieve": "retrieve", "engage": "engage"},
        )
        builder.add_edge("retrieve", "assess")
        builder.add_conditional_edges(
            "assess",
            self._route_after_assessment,
            {
                "rewrite": "rewrite",
                "generate": "grounded_generation",
                "engage": "engage",
            },
        )
        builder.add_edge("rewrite", "retrieval_guard")
        builder.add_edge("grounded_generation", "engage")
        builder.add_edge("engage", "recon")
        builder.add_edge("recon", "map")
        builder.add_edge("map", "validate")
        builder.add_edge("validate", "impact")
        builder.add_edge("impact", "retest")
        builder.add_edge("retest", "report")
        builder.add_edge("report", "finish")
        builder.add_edge("finish", END)
        return builder.compile()

    @staticmethod
    def _normalize_query(value: str) -> str:
        normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
        return " ".join(normalized.split())

    @staticmethod
    def _clarify_plan(reason: str, *, failed: bool = False) -> dict[str, Any]:
        return {
            "summary": "当前无法形成有证据支撑的结论",
            "answer": reason,
            "intent": "clarify",
            "knowledgeMode": "INSUFFICIENT_EVIDENCE",
            "evidenceRefs": [],
            "actions": [],
            "source": "harness-fail-closed" if failed else "harness-clarify",
        }

    @staticmethod
    def _empty_evidence(state: AgentState) -> dict[str, Any]:
        request = state.get("request", {})
        messages = request.get("messages", [])
        query = "general"
        if messages and isinstance(messages[-1], dict):
            query = str(messages[-1].get("content") or "general").strip()[:2000]
        return {
            "projectId": request.get("projectId"),
            "targetId": request.get("targetId"),
            "conversationId": request.get("conversationId"),
            "query": query or "general",
            "round": 0,
            "retrievalMethod": "bm25",
            "indexRevision": "sha256:" + hashlib.sha256(b"").hexdigest(),
            "items": [],
        }

    async def _bounded_planner_call(
        self, state: AgentState, method: Any, *args: Any
    ) -> tuple[Any, int]:
        call_count = state.get("llmCallCount", 0) + 1
        request_budget = state.get("request", {}).get("budget", {})
        max_llm_calls = min(
            settings.max_rag_llm_calls,
            int(request_budget.get("maxLlmCalls", settings.max_rag_llm_calls)),
        )
        if call_count > max_llm_calls:
            raise PlannerOutputError("LLM call budget exceeded")
        result = await asyncio.wait_for(
            method(*args), timeout=settings.llm_timeout_seconds
        )
        return result, call_count

    async def _route_node(self, state: AgentState) -> AgentState:
        try:
            if not settings.rag_enabled:
                plan, call_count = await self._bounded_planner_call(
                    state, self.planner.plan, state["request"]
                )
                routed = {
                    "intent": "ACTION_PLAN"
                    if plan.get("actions")
                    else ("CLARIFY" if plan.get("intent") == "clarify" else "GENERAL_QA"),
                    "needsRetrieval": bool(plan.get("actions")),
                    "publicReasonCode": "AUTHORIZED_ACTION_REQUEST"
                    if plan.get("actions")
                    else (
                        "AMBIGUOUS_REQUEST"
                        if plan.get("intent") == "clarify"
                        else "GENERAL_KNOWLEDGE"
                    ),
                }
                data = {"status": "RAG_DISABLED", **routed}
                return {
                    "intentDecision": routed,
                    "plan": plan,
                    "llmCallCount": call_count,
                    "terminationReason": "RAG_DISABLED",
                    "event": _event(
                        "route", "engage", "RAG 已关闭，使用兼容 Planner 路径", data
                    ),
                }
            routed, call_count = await self._bounded_planner_call(
                state, self.planner.route, state["request"]
            )
            queries = (
                [str(routed["retrievalQuery"])] if routed.get("needsRetrieval") else []
            )
            return {
                "intentDecision": routed,
                "retrievalRound": 0,
                "retrievalQueries": queries,
                "llmCallCount": call_count,
                "event": _event(
                    "route",
                    "engage",
                    "已完成严格意图路由",
                    {"status": "ROUTED", **routed},
                ),
            }
        except Exception:
            plan = self._clarify_plan("意图路由未通过严格契约，请调整请求后重试。", failed=True)
            routed = {
                "intent": "CLARIFY",
                "needsRetrieval": False,
                "publicReasonCode": "AMBIGUOUS_REQUEST",
            }
            return {
                "intentDecision": routed,
                "plan": plan,
                "llmCallCount": min(
                    state.get("llmCallCount", 0) + 1, settings.max_rag_llm_calls
                ),
                "terminationReason": "ROUTE_FAILED",
                "terminalStatus": "FAILED",
                "event": _event(
                    "route",
                    "engage",
                    "意图路由失败，已安全停止",
                    {"status": "FAILED", **routed},
                ),
            }

    def _route_after_intent(self, state: AgentState) -> str:
        if state.get("plan") or state.get("terminationReason") == "RAG_DISABLED":
            return "engage"
        if state.get("intentDecision", {}).get("needsRetrieval"):
            return "retrieve"
        if state.get("intentDecision", {}).get("intent") == "CLARIFY":
            return "engage"
        return "generate"

    async def _retrieval_guard_node(self, state: AgentState) -> AgentState:
        request = state.get("request", {})
        queries = list(state.get("retrievalQueries", []))
        round_number = state.get("retrievalRound", 0)
        violations: list[str] = []
        query = queries[-1] if queries else ""
        normalized = self._normalize_query(query)
        if not isinstance(request.get("projectId"), int) or request.get("projectId", 0) <= 0:
            violations.append("缺少有效项目作用域")
        if not normalized or len(query) > 2000:
            violations.append("检索查询为空或超过长度限制")
        request_budget = request.get("budget", {})
        max_retrieval_rounds = min(
            settings.max_retrieval_rounds,
            int(
                request_budget.get(
                    "maxRetrievalRounds", settings.max_retrieval_rounds
                )
            ),
        )
        if round_number < 0 or round_number >= max_retrieval_rounds:
            violations.append("检索轮次超过限制")
        if state.get("retrievalCount", 0) >= max_retrieval_rounds:
            violations.append("检索次数超过限制")
        used_evidence_chars = sum(
            len(str(item.get("snippet") or ""))
            for bundle in state.get("evidenceBundles", [])
            for item in bundle.get("items", [])
            if isinstance(item, dict)
        )
        if used_evidence_chars >= settings.max_evidence_chars:
            violations.append("证据上下文字符预算已耗尽")
        if len({self._normalize_query(item) for item in queries}) != len(queries):
            violations.append("检索查询与历史查询重复")
        action_payload = {
            "runId": state.get("runId", ""),
            "projectId": request.get("projectId"),
            "targetId": request.get("targetId"),
            "conversationId": request.get("conversationId"),
            "round": round_number,
            "query": normalized,
        }
        action_id = hashlib.sha256(
            json.dumps(
                action_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:32]
        if violations:
            empty = self._empty_evidence(state)
            empty["query"] = query or "invalid"
            empty["round"] = min(max(round_number, 0), 1)
            empty["indexRevision"] = None
            return {
                "retrievalActionId": action_id,
                "retrievalGuardStatus": "DENIED",
                "retrievalGuardError": "；".join(violations),
                "terminationReason": "RETRIEVAL_GUARD_DENIED",
                "terminalStatus": "DENIED",
                "plan": self._clarify_plan("检索请求未通过作用域或预算校验。", failed=True),
                "event": _event(
                    "evidence",
                    "recon",
                    "项目证据检索未通过防御性守卫",
                    self._evidence_event_data(empty, "DENIED", action_id),
                ),
            }
        return {
            "retrievalActionId": action_id,
            "retrievalGuardStatus": "AUTHORIZED",
            "retrievalGuardError": None,
        }

    def _route_after_retrieval_guard(self, state: AgentState) -> str:
        return "retrieve" if state.get("retrievalGuardStatus") == "AUTHORIZED" else "engage"

    @staticmethod
    def _evidence_event_data(
        bundle: dict[str, Any], status: str, action_id: str
    ) -> dict[str, Any]:
        return {
            "status": status,
            "retrievalActionId": action_id,
            "projectId": bundle.get("projectId"),
            "targetId": bundle.get("targetId"),
            "conversationId": bundle.get("conversationId"),
            "query": bundle.get("query"),
            "round": bundle.get("round"),
            "retrievalMethod": bundle.get("retrievalMethod"),
            "indexRevision": bundle.get("indexRevision"),
            "items": [
                {
                    "evidenceId": item.get("evidenceId"),
                    "documentId": item.get("documentId"),
                    "source": item.get("source"),
                    "title": item.get("title"),
                    "score": item.get("score"),
                    "targetId": item.get("targetId"),
                    "contentDigest": item.get("contentDigest"),
                }
                for item in bundle.get("items", [])
                if isinstance(item, dict)
            ],
        }

    async def _retrieve_node(self, state: AgentState) -> AgentState:
        request = state["request"]
        round_number = state.get("retrievalRound", 0)
        query = state.get("retrievalQueries", [""])[-1]
        used_chars = sum(
            len(str(item.get("snippet") or ""))
            for bundle in state.get("evidenceBundles", [])
            for item in bundle.get("items", [])
            if isinstance(item, dict)
        )
        remaining_chars = max(settings.max_evidence_chars - used_chars, 0)
        retrieval_invoked = False
        try:
            if remaining_chars <= 0:
                raise PlannerOutputError("evidence character budget exceeded")
            retrieval_invoked = True
            bundle = await asyncio.wait_for(
                asyncio.to_thread(
                    self.index_store.evidence_bundle,
                    request["projectId"],
                    query,
                    round_number,
                    request.get("conversationId"),
                    request.get("targetId"),
                    settings.max_evidence_items,
                    remaining_chars,
                ),
                timeout=settings.retrieval_timeout_seconds,
            )
            bundle = EvidenceBundle.model_validate(bundle).model_dump(mode="json")
        except (PlannerOutputError, asyncio.TimeoutError, ValueError, OSError):
            empty = self._empty_evidence(state)
            empty["query"] = query
            empty["round"] = round_number
            empty["indexRevision"] = None
            return {
                "retrievalCount": state.get("retrievalCount", 0)
                + int(retrieval_invoked),
                "terminationReason": "RETRIEVAL_FAILED",
                "terminalStatus": "FAILED",
                "plan": self._clarify_plan("项目资料检索失败，未生成无来源结论。", failed=True),
                "event": _event(
                    "evidence",
                    "recon",
                    "项目证据检索失败，已安全停止",
                    self._evidence_event_data(
                        empty, "FAILED", state.get("retrievalActionId", "")
                    ),
                ),
            }
        bundles = [*state.get("evidenceBundles", []), bundle]
        status = "READY" if bundle.get("items") else "EMPTY"
        sources = sorted(
            {
                str(item.get("source") or "project")
                for item in bundle.get("items", [])
                if isinstance(item, dict)
            }
        )
        evidence_message = f"第 {round_number + 1} 轮项目证据检索完成：{len(bundle.get('items', []))} 条"
        if sources:
            evidence_message += "，来源 " + "、".join(sources)
        return {
            "retrievalCount": state.get("retrievalCount", 0) + 1,
            "evidenceBundles": bundles,
            "activeEvidence": bundle,
            "event": _event(
                "evidence",
                "recon",
                evidence_message,
                self._evidence_event_data(
                    bundle, status, state.get("retrievalActionId", "")
                ),
            ),
        }

    async def _assess_node(self, state: AgentState) -> AgentState:
        if state.get("terminationReason") == "RETRIEVAL_FAILED":
            return {}
        bundle = state.get("activeEvidence") or self._empty_evidence(state)
        try:
            decision, call_count = await self._bounded_planner_call(
                state,
                self.planner.assess_evidence,
                state["request"],
                bundle,
                state.get("retrievalRound", 0),
                list(state.get("retrievalQueries", [])),
            )
        except Exception:
            return {
                "llmCallCount": min(
                    state.get("llmCallCount", 0) + 1, settings.max_rag_llm_calls
                ),
                "terminationReason": "EVIDENCE_ASSESSMENT_FAILED",
                "terminalStatus": "FAILED",
                "plan": self._clarify_plan("证据评估未通过严格契约，已安全停止。", failed=True),
            }
        update: AgentState = {
            "evidenceDecision": decision,
            "llmCallCount": call_count,
        }
        if decision.get("decision") == "REWRITE_QUERY":
            rewritten = str(decision.get("rewrittenQuery") or "")
            normalized = self._normalize_query(rewritten)
            prior = {self._normalize_query(item) for item in state.get("retrievalQueries", [])}
            if state.get("retrievalRound", 0) != 0:
                update.update(
                    {
                        "evidenceDecision": {
                            "decision": "CLARIFY",
                            "reasonCodes": decision.get("reasonCodes", []),
                            "evidenceRefs": [],
                        },
                        "terminationReason": "REWRITE_LIMIT_REACHED",
                        "plan": self._clarify_plan(
                            "两轮项目检索仍不足以支持可靠结论，请补充更具体的项目信息。"
                        ),
                    }
                )
            elif not normalized or len(rewritten) > 2000 or normalized in prior:
                update.update(
                    {
                        "evidenceDecision": {
                            "decision": "CLARIFY",
                            "reasonCodes": decision.get("reasonCodes", []),
                            "evidenceRefs": [],
                        },
                        "terminationReason": "REWRITE_REJECTED",
                        "plan": self._clarify_plan(
                            "证据不足且查询改写无实质变化，请补充更具体的项目信息。"
                        ),
                        "event": _event(
                            "rewrite",
                            "recon",
                            "查询改写未通过去重或预算校验",
                            {
                                "status": "REJECTED",
                                "decision": "REWRITE_QUERY",
                                "evidenceRefs": [],
                                "fromRound": state.get("retrievalRound", 0),
                                "toRound": state.get("retrievalRound", 0),
                                "reasonCodes": decision.get("reasonCodes", []),
                                "rewrittenQuery": rewritten[:2000],
                            },
                        ),
                    }
                )
        elif decision.get("decision") == "CLARIFY":
            update.update(
                {
                    "terminationReason": "EVIDENCE_INSUFFICIENT",
                    "plan": self._clarify_plan(
                        "当前项目资料不足以支持可靠结论，请补充项目事实或缩小问题范围。"
                    ),
                }
            )
        return update

    def _route_after_assessment(self, state: AgentState) -> str:
        if state.get("plan") or state.get("terminationReason"):
            return "engage"
        decision = state.get("evidenceDecision", {}).get("decision")
        if decision == "REWRITE_QUERY":
            return "rewrite"
        if decision == "FINALIZE":
            return "generate"
        return "engage"

    async def _rewrite_node(self, state: AgentState) -> AgentState:
        decision = state.get("evidenceDecision", {})
        query = str(decision.get("rewrittenQuery") or "").strip()
        next_round = state.get("retrievalRound", 0) + 1
        return {
            "retrievalRound": next_round,
            "retrievalQueries": [*state.get("retrievalQueries", []), query],
            "event": _event(
                "rewrite",
                "recon",
                "证据不足，执行一次受限查询改写",
                {
                    "status": "APPLIED",
                    "decision": "REWRITE_QUERY",
                    "evidenceRefs": [],
                    "fromRound": next_round - 1,
                    "toRound": next_round,
                    "reasonCodes": decision.get("reasonCodes", []),
                    "rewrittenQuery": query,
                },
            ),
        }

    async def _grounded_generation_node(self, state: AgentState) -> AgentState:
        active_evidence = state.get("activeEvidence") or self._empty_evidence(state)
        try:
            plan, call_count = await self._bounded_planner_call(
                state,
                self.planner.grounded_plan,
                state["request"],
                active_evidence,
                state["intentDecision"],
            )
            return {"plan": plan, "llmCallCount": call_count}
        except Exception:
            return {
                "llmCallCount": min(
                    state.get("llmCallCount", 0) + 1, settings.max_rag_llm_calls
                ),
                "terminationReason": "GROUNDED_GENERATION_FAILED",
                "terminalStatus": "FAILED",
                "plan": self._clarify_plan("有依据的回答未通过严格契约，已安全停止。", failed=True),
            }

    async def _engage_node(self, state: AgentState) -> AgentState:
        """Start a red-team engagement and perform the hard pre-execution guard.

        Planner/guard remain implementation details of this stage.  Their legacy event
        types are intentionally retained so existing Java/UI consumers do not break,
        while ``node`` and ``stage`` identify the user-facing red-team phase.
        """
        plan_update = (
            self._prepare_plan_update(state, state["plan"])
            if isinstance(state.get("plan"), dict)
            else await self._planner_node(state)
        )
        working: AgentState = dict(state)
        working.update(plan_update)
        # A plan with no actions is a conversational answer/clarification.  Do not turn an
        # expired or paused project into an authorization error merely because the user asked
        # for an explanation; the strict guard is only meaningful when a tool action exists.
        if not working.get("plan", {}).get("actions"):
            guard_update = {
                "guardedActions": [],
                "guardViolations": [],
                "approvalActions": [],
                "event": _event(
                    "authorization_guard",
                    "authorization_guard",
                    "本轮为说明或问答，不需要执行授权校验",
                    {
                        "status": "NOT_APPLICABLE",
                        "executionRequired": False,
                    },
                ),
            }
        else:
            guard_update = await self._guard_node(working)
        plan_event = self._stage_event(
            plan_update["event"], "engage", "planner", "任务启动阶段已形成测试计划"
        )
        guard_event = self._stage_event(
            guard_update["event"], "engage", "authorization_guard", None
        )
        return {
            "plan": plan_update.get("plan", {}),
            "guardedActions": guard_update.get("guardedActions", []),
            "guardViolations": guard_update.get("guardViolations", []),
            "approvalActions": guard_update.get("approvalActions", []),
            "authorizationDecision": guard_update.get("authorizationDecision", {}),
            "events": [plan_event, guard_event],
        }

    async def _planner_node(self, state: AgentState) -> AgentState:
        plan = await self.planner.plan(state["request"])
        return self._prepare_plan_update(state, plan)

    def _prepare_plan_update(
        self, state: AgentState, plan: dict[str, Any]
    ) -> AgentState:
        actions: list[dict[str, Any]] = []
        for action in plan.get("actions", []):
            if not isinstance(action, dict):
                continue
            normalized = dict(action)
            normalized.setdefault("group", 0)
            action_payload = {
                "runId": state.get("runId", ""),
                "workflowNodeId": normalized.get("workflowNodeId"),
                "tool": normalized.get("tool"),
                "parameters": normalized.get("parameters", {}),
            }
            normalized["actionId"] = hashlib.sha256(
                json.dumps(
                    action_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:32]
            actions.append(normalized)
        plan = {**plan, "actions": actions}
        return {
            "plan": plan,
            "event": _event(
                "plan",
                "planner",
                "Planner 已生成项目级执行计划",
                {
                    "summary": plan.get("summary"),
                    "answer": plan.get("answer"),
                    "intent": plan.get("intent"),
                    "knowledgeMode": plan.get("knowledgeMode", "GENERAL"),
                    "evidenceRefs": plan.get("evidenceRefs", []),
                    "actionCount": len(plan.get("actions", [])),
                    "source": plan.get("source"),
                    "warning": plan.get("modelWarning"),
                    # Full step list for the desktop "执行 Plan" checklist.
                    "actions": plan.get("actions", []),
                    "steps": [
                        {
                            "toolCode": str(action.get("tool") or ""),
                            "tool": str(action.get("tool") or ""),
                            **(
                                {
                                    "workflowNodeId": str(action["workflowNodeId"]),
                                    "group": int(action.get("group", 0) or 0),
                                    "dependsOnNodeIds": list(
                                        action.get("dependsOnNodeIds") or []
                                    ),
                                }
                                if action.get("workflowNodeId")
                                else {}
                            ),
                            "title": str(
                                action.get("title") or action.get("tool") or "受控步骤"
                            ),
                            "reason": str(
                                action.get("reason")
                                or (
                                    f"风险 {action.get('risk', 'SAFE')}"
                                    if action.get("risk")
                                    else ""
                                )
                                or "受控工具步骤"
                            ),
                            "risk": str(action.get("risk") or "SAFE"),
                            "requiresApproval": bool(
                                action.get("requiresApproval")
                                or action.get("requires_approval")
                            ),
                            "parameters": (
                                action.get("parameters")
                                if isinstance(action.get("parameters"), dict)
                                else {}
                            ),
                            "status": "pending",
                        }
                        for action in (plan.get("actions") or [])
                        if isinstance(action, dict)
                        and str(action.get("tool") or "").strip()
                    ],
                },
            ),
        }

    async def _guard_node(self, state: AgentState) -> AgentState:
        request = state["request"]
        authorization = request.get("authorization", {})
        now = datetime.now(timezone.utc)
        violations: list[str] = []
        guarded: list[dict[str, Any]] = []
        approvals: list[dict[str, Any]] = []
        checks = {
            "project": bool(request.get("projectId")),
            "status": str(authorization.get("status", "")).upper() == "ACTIVE",
            "timeWindow": True,
            "target": True,
            "ports": True,
            "tools": True,
            "approval": True,
            "quota": True,
        }
        if not checks["project"]:
            violations.append("缺少有效的安全评估项目")
        if not checks["status"]:
            violations.append("项目授权状态不是 ACTIVE")
        valid_from = parse_instant(authorization.get("validFrom"))
        expires_at = parse_instant(authorization.get("expiresAt"))
        if valid_from is None or expires_at is None:
            checks["timeWindow"] = False
            violations.append("授权快照缺少有效的开始或结束时间")
        elif valid_from >= expires_at:
            checks["timeWindow"] = False
            violations.append("授权快照的时间窗无效")
        elif now < valid_from:
            checks["timeWindow"] = False
            violations.append("授权时间窗尚未开始")
        elif now >= expires_at:
            checks["timeWindow"] = False
            violations.append("项目授权已过期")
        allowed_tools = {str(tool) for tool in authorization.get("allowedTools", [])}
        allowed_targets = {
            int(target)
            for target in authorization.get("targetIds", [])
            if str(target).isdigit()
        }
        try:
            allowed_ports = port_intervals(authorization.get("allowedPorts"))
        except ValueError:
            allowed_ports = []
            checks["ports"] = False
            violations.append("授权快照包含无效端口表达式")
        quota = authorization.get("quota", {})
        remaining = max(
            int(quota.get("maxActions", 0)) - int(quota.get("usedActions", 0)), 0
        )
        actions = state.get("plan", {}).get("actions", [])
        if len(actions) > remaining:
            checks["quota"] = False
            violations.append(
                f"资源配额不足：计划 {len(actions)} 个动作，剩余 {remaining} 个"
            )
        for action in actions:
            tool_code = str(action.get("tool", ""))
            params = (
                action.get("parameters")
                if isinstance(action.get("parameters"), dict)
                else {}
            )
            target_id = params.get("targetId", request.get("targetId"))
            action_violations: list[str] = []
            if tool_code not in allowed_tools:
                checks["tools"] = False
                action_violations.append(f"工具 {tool_code} 不在项目白名单")
            if tool_code != "retrieve_project_context":
                try:
                    normalized_target_id = int(target_id)
                except (TypeError, ValueError):
                    normalized_target_id = None
                if not allowed_targets:
                    checks["target"] = False
                    action_violations.append("授权快照不包含任何项目目标")
                elif (
                    normalized_target_id is None
                    or normalized_target_id not in allowed_targets
                ):
                    checks["target"] = False
                    action_violations.append(f"工具 {tool_code} 缺少项目内授权目标")
                try:
                    requested = requested_port_intervals(params)
                except ValueError:
                    requested = []
                    checks["ports"] = False
                    action_violations.append(f"工具 {tool_code} 的端口参数格式无效")
                if not allowed_ports:
                    checks["ports"] = False
                    action_violations.append(f"工具 {tool_code} 缺少授权端口快照")
                elif not action_violations and not ports_allowed(requested, allowed_ports):
                    checks["ports"] = False
                    action_violations.append(f"工具 {tool_code} 请求的端口超出授权范围")
            if action_violations:
                violations.extend(action_violations)
                # A denied action must never be downgraded to an approval request.
                continue
            needs_approval = (
                bool(action.get("requiresApproval"))
                or tool_code in HIGH_RISK_TOOLS
                or str(action.get("risk", "")).upper() == "HIGH"
            )
            if needs_approval and not bool(authorization.get("approved")):
                checks["approval"] = False
                approvals.append({**action, "targetId": target_id})
                continue
            guarded.append({**action, "targetId": target_id})
        # Do not partially execute a plan containing a denied or pending action.
        if violations or approvals:
            guarded = []
        status = (
            "DENIED"
            if violations
            else ("APPROVAL_REQUIRED" if approvals else "AUTHORIZED")
        )
        decision = self._create_decision(request, guarded)
        return {
            "guardedActions": guarded,
            "guardViolations": violations,
            "approvalActions": approvals,
            "authorizationDecision": decision,
            "event": _event(
                "authorization_guard",
                "authorization_guard",
                f"授权守卫检查完成：{status}",
                {
                    "status": status,
                    "checks": checks,
                    "violations": violations,
                    "approvalCount": len(approvals),
                    "retryCount": state.get("retryCount", 0),
                },
            ),
        }

    def _create_decision(
        self, request: dict[str, Any], actions: list[dict[str, Any]]
    ) -> dict[str, Any]:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        payload = {
            "projectId": request.get("projectId"),
            "targetId": request.get("targetId"),
            "policyRevision": str(
                request.get("authorization", {}).get("policyRevision", "java-authoritative-v1")
            ),
            "expiresAt": expires_at.isoformat(),
            "actions": actions,
        }
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            **payload,
            "actionDigest": hashlib.sha256(canonical).hexdigest(),
            "token": hmac.new(self._decision_secret, canonical, hashlib.sha256).hexdigest(),
        }

    def _decision_allows(
        self, state: AgentState, actions: list[dict[str, Any]]
    ) -> bool:
        decision = state.get("authorizationDecision")
        if not isinstance(decision, dict):
            return False
        expires_at = parse_instant(decision.get("expiresAt"))
        if expires_at is None or datetime.now(timezone.utc) >= expires_at:
            return False
        payload = {
            "projectId": state.get("request", {}).get("projectId"),
            "targetId": state.get("request", {}).get("targetId"),
            "policyRevision": str(decision.get("policyRevision", "")),
            "expiresAt": decision.get("expiresAt"),
            "actions": state.get("guardedActions", []),
        }
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        expected_digest = hashlib.sha256(canonical).hexdigest()
        expected_token = hmac.new(
            self._decision_secret, canonical, hashlib.sha256
        ).hexdigest()
        allowed_ids = {
            str(action.get("actionId")) for action in payload["actions"]
        }
        requested_ids = {str(action.get("actionId")) for action in actions}
        return (
            requested_ids <= allowed_ids
            and hmac.compare_digest(str(decision.get("actionDigest", "")), expected_digest)
            and hmac.compare_digest(str(decision.get("token", "")), expected_token)
        )

    def _stage_event(
        self,
        event: dict[str, Any],
        stage: str,
        legacy_node: str,
        message: str | None = None,
    ) -> dict[str, Any]:
        """Annotate a legacy event with the public red-team stage."""
        result = dict(event)
        result["node"] = stage
        if message:
            result["message"] = message
        data = dict(result.get("data") or {})
        data.setdefault("stage", stage)
        data.setdefault("legacyNode", legacy_node)
        result["data"] = data
        return result

    def _stage_progress(
        self, stage: str, status: str, message: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = dict(data or {})
        payload.update({"stage": stage, "status": status})
        return _event("stage", stage, message, payload)

    def _actions_for_stage(self, state: AgentState, stage: str) -> list[dict[str, Any]]:
        return [
            action
            for action in state.get("guardedActions", [])
            if TOOL_STAGE.get(str(action.get("tool", "")), "impact") == stage
        ]

    def _route_after_guard(self, state: AgentState) -> str:
        if state.get("guardViolations"):
            return "finish"
        if state.get("approvalActions"):
            return "approval_required"
        return "executor"

    async def _executor_node(
        self,
        state: AgentState,
        stage: str = "validate",
        action_ids: set[str] | None = None,
    ) -> AgentState:
        request = state["request"]
        actions = self._actions_for_stage(state, stage)
        if action_ids is not None:
            actions = [
                action
                for action in state.get("guardedActions", [])
                if str(action.get("actionId", "")) in action_ids
            ]

        if state.get("guardViolations") or state.get("approvalActions"):
            reason = (
                "授权范围未通过，阶段保持未执行"
                if state.get("guardViolations")
                else "等待人工审批，阶段保持未执行"
            )
            return {
                "event": self._stage_progress(
                    stage,
                    "SKIPPED",
                    reason,
                    {
                        "legacyNode": "executor",
                        "actionCount": len(actions),
                    },
                ),
            }
        if not actions:
            return {
                "event": self._stage_progress(
                    stage,
                    "SKIPPED",
                    "本阶段没有匹配的受控动作",
                    {
                        "legacyNode": "executor",
                    },
                ),
            }
        if not self._decision_allows(state, actions):
            return {
                "executorError": "授权决定无效或已过期",
                "failedActions": list(actions),
                "event": self._stage_progress(
                    stage,
                    "FAILED",
                    "授权决定摘要无效，阶段保持未执行",
                    {"legacyNode": "executor", "actionCount": len(actions)},
                ),
            }

        async def run_action(action: dict[str, Any]) -> dict[str, Any]:
            if action["tool"] == "retrieve_project_context":
                query = str(action.get("parameters", {}).get("query", "项目资料"))
                references = await asyncio.to_thread(
                    self.tools["retrieve_project_context"].invoke,
                    {
                        "project_id": int(request["projectId"]),
                        "query": query,
                        "top_k": 5,
                        "conversation_id": request.get("conversationId"),
                        "target_id": request.get("targetId"),
                    },
                )
                return {
                    "actionId": action.get("actionId"),
                    "tool": action["tool"],
                    "executed": True,
                    "references": references,
                }
            proposal = await asyncio.to_thread(
                self.tools["propose_authorized_action"].invoke,
                {
                    "project_id": int(request["projectId"]),
                    "tool_code": action["tool"],
                    "target_id": action.get("targetId"),
                    "parameters": action.get("parameters", {}),
                    "risk": action.get("risk", "SAFE"),
                    "action_id": str(action.get("actionId", "")),
                    "policy_revision": str(
                        state.get("authorizationDecision", {}).get(
                            "policyRevision", ""
                        )
                    ),
                    "decision_digest": str(
                        state.get("authorizationDecision", {}).get(
                            "actionDigest", ""
                        )
                    ),
                },
            )
            return {
                "actionId": action.get("actionId"),
                "tool": action["tool"],
                "executed": False,
                "proposal": proposal,
            }

        try:
            # Actions carry a topological "group" (level) derived from the
            # workflow edges. Levels run in order; steps within a level run
            # concurrently — so manually-connected chains stay sequential while
            # sibling branches run in parallel. The guard already validated
            # every action, so parallelism never widens the authorization boundary.
            groups: dict[int, list[dict[str, Any]]] = {}
            for action in actions:
                groups.setdefault(int(action.get("group", 0) or 0), []).append(action)
            results: list[dict[str, Any]] = []
            failed: list[dict[str, Any]] = []
            for level in sorted(groups):
                level_results = await asyncio.gather(
                    *(run_action(action) for action in groups[level]),
                    return_exceptions=True,
                )
                for action, result in zip(groups[level], level_results, strict=True):
                    if isinstance(result, BaseException):
                        failed.append(action)
                    else:
                        results.append(result)
            combined = list(state.get("toolResults", [])) + results
            return {
                "toolResults": combined,
                "executorError": (
                    "受控工具执行失败"
                    if failed or state.get("executorError")
                    else None
                ),
                "failedActions": list(state.get("failedActions", [])) + failed,
                "event": _event(
                    "tool",
                    stage,
                    "红队阶段已完成受控工具处理",
                    {
                        "stage": stage,
                        "legacyNode": "executor",
                        "resultCount": len(results),
                        "failedCount": len(failed),
                        "totalResultCount": len(combined),
                        "localExecutions": sum(
                            1 for item in results if item.get("executed")
                        ),
                        "javaProposals": sum(
                            1 for item in results if not item.get("executed")
                        ),
                        "levels": len(groups),
                        "parallel": any(len(items) > 1 for items in groups.values()),
                    },
                ),
            }
        except Exception:
            failed_actions = list(state.get("failedActions", [])) + actions
            return {
                "executorError": "受控工具执行失败",
                "failedActions": failed_actions,
                "event": _event(
                    "tool",
                    stage,
                    "红队阶段执行失败，稍后进入复测与重试判断",
                    {
                        "stage": stage,
                        "legacyNode": "executor",
                        "status": "FAILED",
                    },
                ),
            }

    async def _recon_node(self, state: AgentState) -> AgentState:
        return await self._executor_node(state, "recon")

    async def _map_node(self, state: AgentState) -> AgentState:
        return await self._executor_node(state, "map")

    async def _validate_node(self, state: AgentState) -> AgentState:
        return await self._executor_node(state, "validate")

    async def _impact_node(self, state: AgentState) -> AgentState:
        if state.get("guardViolations"):
            return {
                "event": self._stage_progress(
                    "impact",
                    "SKIPPED",
                    "授权范围未通过，影响评估未执行",
                    {
                        "legacyNode": "approval_required",
                    },
                ),
            }
        if state.get("approvalActions"):
            update = await self._approval_node(state)
            return {
                "event": self._stage_event(
                    update["event"], "impact", "approval_required", None
                ),
            }
        return await self._executor_node(state, "impact")

    async def _retest_stage_node(self, state: AgentState) -> AgentState:
        """Close the loop and retry failed actions only after a fresh guard check."""
        if not state.get("executorError"):
            return {
                "event": self._stage_progress(
                    "retest",
                    "COMPLETED",
                    "已记录清理与复测入口；当前没有失败动作需要重试",
                    {
                        "legacyNode": "retry",
                        "retryCount": state.get("retryCount", 0),
                    },
                ),
            }

        working: AgentState = dict(state)
        events: list[dict[str, Any]] = []
        failed = list(state.get("failedActions", []))
        max_retries = state.get("maxRetries", settings.max_retries)
        while (
            working.get("executorError")
            and working.get("retryCount", 0) < max_retries
            and failed
        ):
            retry_update = await self._retry_node(working)
            working.update(retry_update)
            retry_event = retry_update.get("event")
            if retry_event:
                events.append(self._stage_event(retry_event, "retest", "retry", None))
            # Re-enter the complete guard before every retry.  No stale approval or
            # target snapshot is allowed to flow directly into a tool proposal.
            guard_update = await self._guard_node(working)
            working.update(guard_update)
            events.append(
                self._stage_event(
                    guard_update["event"], "retest", "authorization_guard", None
                )
            )
            if working.get("guardViolations") or working.get("approvalActions"):
                break
            working["executorError"] = None
            working["failedActions"] = []
            retry_ids = {str(action.get("actionId", "")) for action in failed}
            retry_update = await self._executor_node(
                working, "retest", action_ids=retry_ids
            )
            working.update(retry_update)
            if retry_update.get("event"):
                events.append(retry_update["event"])
            failed = list(working.get("failedActions", []))

        if working.get("executorError") and not events:
            events.append(
                self._stage_progress(
                    "retest",
                    "FAILED",
                    "复测阶段未能重试失败动作",
                    {
                        "legacyNode": "retry",
                        "retryCount": working.get("retryCount", 0),
                    },
                )
            )
        if not working.get("executorError"):
            events.append(
                self._stage_progress(
                    "retest",
                    "COMPLETED",
                    "复测阶段已完成",
                    {
                        "legacyNode": "retry",
                        "retryCount": working.get("retryCount", 0),
                    },
                )
            )
        return {
            "retryCount": working.get("retryCount", 0),
            "executorError": working.get("executorError"),
            "failedActions": working.get("failedActions", []),
            "guardedActions": working.get(
                "guardedActions", state.get("guardedActions", [])
            ),
            "guardViolations": working.get(
                "guardViolations", state.get("guardViolations", [])
            ),
            "approvalActions": working.get(
                "approvalActions", state.get("approvalActions", [])
            ),
            "toolResults": working.get("toolResults", state.get("toolResults", [])),
            "events": events,
        }

    async def _report_node(self, state: AgentState) -> AgentState:
        update = await self._reviewer_node(state)
        return {
            "review": update.get("review", {}),
            "event": self._stage_event(
                update["event"], "report", "reviewer", "报告阶段已复核证据并准备交付"
            ),
        }

    def _route_after_executor(self, state: AgentState) -> str:
        if state.get("executorError") and state.get("retryCount", 0) < state.get(
            "maxRetries", settings.max_retries
        ):
            return "retry"
        return "reviewer"

    async def _retry_node(self, state: AgentState) -> AgentState:
        retry_count = state.get("retryCount", 0) + 1
        return {
            "retryCount": retry_count,
            "executorError": None,
            "event": _event(
                "retry",
                "retry",
                "工具处理将重试；重试前重新校验完整授权快照",
                {"retryCount": retry_count},
            ),
        }

    async def _approval_node(self, state: AgentState) -> AgentState:
        actions = state.get("approvalActions", [])
        return {
            "event": _event(
                "approval_required",
                "approval_required",
                "计划包含需要人工审批的安全动作，已暂停执行",
                {
                    "actions": [
                        {
                            "tool": item.get("tool"),
                            "risk": item.get("risk"),
                            "targetId": item.get("targetId"),
                        }
                        for item in actions
                    ],
                    "executed": False,
                },
            ),
        }

    async def _reviewer_node(self, state: AgentState) -> AgentState:
        results = state.get("toolResults", [])
        proposals = [item["proposal"] for item in results if item.get("proposal")]
        references = [ref for item in results for ref in item.get("references", [])]
        review = {
            "status": "FAILED" if state.get("executorError") else "REVIEWED",
            "referenceCount": len(references),
            "proposalCount": len(proposals),
            "references": references[:10],
            "proposals": proposals,
        }
        return {
            "review": review,
            "event": _event(
                "review",
                "reviewer",
                "Reviewer 已复核执行结果与证据",
                {
                    "status": review["status"],
                    "referenceCount": len(references),
                    "proposalCount": len(proposals),
                },
            ),
        }

    async def _finish_node(self, state: AgentState) -> AgentState:
        violations = state.get("guardViolations", [])
        approvals = state.get("approvalActions", [])
        review = state.get("review", {})
        if violations:
            status = "DENIED"
        elif approvals:
            status = "APPROVAL_REQUIRED"
        elif state.get("executorError"):
            status = "FAILED"
        elif state.get("terminalStatus") in {"FAILED", "DENIED"}:
            status = str(state["terminalStatus"])
        else:
            status = "COMPLETED"
        plan = state.get("plan", {})
        answer = str(plan.get("answer", "智能体流程未返回有效回答。"))
        evidence_ids = {
            str(reference)
            for reference in plan.get("evidenceRefs", [])
            if str(reference)
        }
        for action in plan.get("actions", []):
            if isinstance(action, dict):
                evidence_ids.update(
                    str(reference)
                    for reference in action.get("evidenceRefs", [])
                    if str(reference)
                )
        bundles = state.get("evidenceBundles", [])
        active_evidence = state.get("activeEvidence", {}) if bundles else {}
        final = {
            "status": status,
            "answer": answer,
            "plan": plan,
            "review": review,
            "violations": violations,
            "retrievalRoundCount": state.get("retrievalCount", 0),
            "evidenceIds": sorted(evidence_ids),
            "indexRevision": active_evidence.get("indexRevision"),
            "plannerSource": str(plan.get("source") or "unknown"),
            "terminationReason": state.get("terminationReason"),
        }
        return {
            "final": final,
            "event": _event("finish", "finish", f"智能体流程结束：{status}", final),
        }

    async def stream(
        self, request: LedgerAgentContext
    ) -> AsyncIterator[dict[str, Any]]:
        run_id = request.runId or str(uuid.uuid4())
        request_payload = request.model_dump(mode="json")
        initial: AgentState = {
            "request": request_payload,
            "runId": run_id,
            "retryCount": 0,
            "maxRetries": (
                request.maxRetries
                if request.maxRetries is not None
                else settings.max_retries
            ),
            "toolResults": [],
            "guardViolations": [],
            "approvalActions": [],
            "events": [],
            "failedActions": [],
            "retrievalRound": 0,
            "retrievalQueries": [],
            "retrievalCount": 0,
            "evidenceBundles": [],
            "llmCallCount": 0,
            "terminationReason": None,
            "terminalStatus": None,
        }
        previous_digest = RUNTIME_LEDGER_GENESIS_DIGEST
        timeout_seconds = min(
            settings.agent_turn_timeout_seconds, request.budget.timeoutSeconds
        )
        state_version = 0
        try:
            async with asyncio.timeout(timeout_seconds):
                if self.graph is None:
                    async for event in self._fallback_stream(initial):
                        state_version += 1
                        enveloped = envelope_runtime_event(
                            event,
                            request_payload,
                            run_id,
                            state_version,
                            previous_digest,
                        )
                        previous_digest = enveloped["ledgerEntryDigest"]
                        yield enveloped
                else:
                    async for update in self.graph.astream(
                        initial,
                        config={"recursion_limit": settings.graph_recursion_limit},
                        stream_mode="updates",
                    ):
                        if not isinstance(update, dict):
                            continue
                        for node_update in update.values():
                            if not isinstance(node_update, dict):
                                continue
                            for event in self._events_from_update(node_update):
                                state_version += 1
                                enveloped = envelope_runtime_event(
                                    event,
                                    request_payload,
                                    run_id,
                                    state_version,
                                    previous_digest,
                                )
                                previous_digest = enveloped["ledgerEntryDigest"]
                                yield enveloped
        except TimeoutError:
            state_version += 1
            yield envelope_runtime_event(
                _event(
                    "error",
                    "runtime",
                    "智能体本轮处理超过时间预算，已安全停止",
                    {"status": "FAILED", "errorCode": "TURN_TIMEOUT"},
                ),
                request_payload,
                run_id,
                state_version,
                previous_digest,
            )

    async def invoke(self, context: LedgerAgentContext) -> LedgerAgentResult:
        """Return the finite facade result while preserving the same verified event stream."""
        terminal: dict[str, Any] | None = None
        async for event in self.stream(context):
            if event.get("type") in {"finish", "error"}:
                terminal = event
        if terminal is None:
            raise RuntimeError("LedgerAgent stream ended without a terminal event")

        data = terminal.get("data") if isinstance(terminal.get("data"), dict) else {}
        plan = data.get("plan") if isinstance(data.get("plan"), dict) else {}
        actions = plan.get("actions") if isinstance(plan.get("actions"), list) else []
        proposed_actions = [
            {
                "workflowNodeId": action.get("workflowNodeId"),
                "parameters": action.get("parameters", {}),
                "evidenceRefs": action.get("evidenceRefs", []),
            }
            for action in actions
            if isinstance(action, dict)
        ]
        status = str(data.get("status") or "FAILED")
        if status == "COMPLETED" and plan.get("intent") == "clarify":
            status = "CLARIFY"
        termination_reason = data.get("terminationReason")
        return LedgerAgentResult.model_validate(
            {
                "status": status,
                "answer": str(data.get("answer") or ""),
                "evidenceIds": data.get("evidenceIds", []),
                "proposedActions": proposed_actions,
                "terminationReason": (
                    termination_reason
                    if isinstance(termination_reason, str) and termination_reason
                    else None
                ),
                "ledgerDigest": terminal.get("ledgerEntryDigest"),
            }
        )

    def _events_from_update(
        self, update: AgentState | dict[str, Any]
    ) -> list[dict[str, Any]]:
        events = update.get("events") if isinstance(update.get("events"), list) else []
        if events:
            return [event for event in events if isinstance(event, dict)]
        event = update.get("event")
        return [event] if isinstance(event, dict) else []

    async def _fallback_stream(
        self, state: AgentState
    ) -> AsyncIterator[dict[str, Any]]:
        """Deterministic fallback for a partially installed development environment."""
        route_update = await self._route_node(state)
        state.update(route_update)
        for event in self._events_from_update(route_update):
            yield event
        route = self._route_after_intent(state)
        if route == "retrieve":
            while True:
                guard_update = await self._retrieval_guard_node(state)
                state.update(guard_update)
                for event in self._events_from_update(guard_update):
                    yield event
                if self._route_after_retrieval_guard(state) != "retrieve":
                    break
                retrieve_update = await self._retrieve_node(state)
                state.update(retrieve_update)
                for event in self._events_from_update(retrieve_update):
                    yield event
                assess_update = await self._assess_node(state)
                state.update(assess_update)
                for event in self._events_from_update(assess_update):
                    yield event
                next_step = self._route_after_assessment(state)
                if next_step == "rewrite":
                    rewrite_update = await self._rewrite_node(state)
                    state.update(rewrite_update)
                    for event in self._events_from_update(rewrite_update):
                        yield event
                    continue
                if next_step == "generate":
                    generate_update = await self._grounded_generation_node(state)
                    state.update(generate_update)
                break
        elif route == "generate":
            generate_update = await self._grounded_generation_node(state)
            state.update(generate_update)
        nodes = (
            self._engage_node,
            self._recon_node,
            self._map_node,
            self._validate_node,
            self._impact_node,
            self._retest_stage_node,
            self._report_node,
            self._finish_node,
        )
        for node in nodes:
            update = await node(state)
            state.update(update)
            for event in self._events_from_update(update):
                yield event


# Compatibility alias for tests and integrations that still import the previous implementation name.
SecurityAgentRuntime = LedgerAgentRuntime


def encode_sse(event: dict[str, Any]) -> str:
    event_type = re.sub(r"[^a-zA-Z0-9_-]", "_", str(event.get("type", "message")))
    return f"id: {event.get('eventId', '')}\nevent: {event_type}\ndata: {json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n\n"
