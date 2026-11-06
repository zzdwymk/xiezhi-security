"""Bounded local diagnostics containing only server-owned classifications."""
from __future__ import annotations

import json
import re
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, get_args

from pydantic_core import ErrorType

from .config import settings
from .schemas import AutoIntentDecision, EvidenceDecision, GroundedPlannerOutput, PlannerOutput

MAX_LOG_BYTES = 256 * 1024
_lock = threading.Lock()
_run_id: ContextVar[str] = ContextVar("diagnostic_run_id", default="")
RULE_MESSAGES = {
    "intent and needsRetrieval are inconsistent": "INTENT_RETRIEVAL_MISMATCH",
    "intent and publicReasonCode are inconsistent": "INTENT_REASON_MISMATCH",
    "retrieval intent requires retrievalQuery": "RETRIEVAL_QUERY_REQUIRED",
    "non-retrieval intent cannot include retrievalQuery": "RETRIEVAL_QUERY_FORBIDDEN",
    "only ACTION_PLAN may request execution": "EXECUTE_REQUIRES_ACTION_PLAN",
    "CLARIFY execution decision requires CLARIFY intent": "CLARIFY_DECISION_MISMATCH",
    "CLARIFY intent cannot authorize execution or a plan": "CLARIFY_INTENT_MISMATCH",
    "decision and reasonCodes are inconsistent": "EVIDENCE_REASON_MISMATCH",
    "FINALIZE requires refs and no rewrittenQuery": "FINALIZE_FIELDS_MISMATCH",
    "REWRITE_QUERY requires only rewrittenQuery": "REWRITE_FIELDS_MISMATCH",
    "CLARIFY cannot include refs or rewrittenQuery": "CLARIFY_FIELDS_MISMATCH",
    "plan intent requires at least one action": "PLAN_REQUIRES_ACTION",
    "only plan intent can include actions": "ACTIONS_REQUIRE_PLAN",
    "GENERAL knowledge mode cannot cite evidence": "GENERAL_EVIDENCE_FORBIDDEN",
    "INSUFFICIENT_EVIDENCE must produce only clarification": "INSUFFICIENT_REQUIRES_CLARIFY",
    "PROJECT_EVIDENCE requires evidenceRefs": "PROJECT_REQUIRES_EVIDENCE",
    "grounded actions require evidenceRefs": "ACTION_REQUIRES_EVIDENCE",
    "action evidenceRefs must be declared by the output": "ACTION_EVIDENCE_UNDECLARED",
    "plan cannot contain duplicate workflow nodes": "DUPLICATE_WORKFLOW_NODE",
    "evidenceRefs values must be unique": "DUPLICATE_EVIDENCE_REF",
    "action evidenceRefs values must be unique": "DUPLICATE_ACTION_EVIDENCE_REF",
    "reasonCodes values must be unique": "DUPLICATE_REASON_CODE",
    "grounded output conflicts with answer route": "ANSWER_ROUTE_CONFLICT",
    "grounded output conflicts with action route": "ACTION_ROUTE_CONFLICT",
    "grounded output conflicts with clarify route": "CLARIFY_ROUTE_CONFLICT",
    "grounded output used evidence without a knowledge route": "KNOWLEDGE_ROUTE_CONFLICT",
    "grounded output conflicts with routed contract": "ROUTED_CONTRACT_CONFLICT",
    "retrieval route clarification requires INSUFFICIENT_EVIDENCE": "RETRIEVAL_CLARIFY_MODE_MISMATCH",
    "grounded planner contains unknown references": "UNKNOWN_GROUNDED_REFERENCE",
    "evidence decision contains unknown references": "UNKNOWN_EVIDENCE_REFERENCE",
    "workflow action references an unknown node": "UNKNOWN_WORKFLOW_NODE",
    "workflow action references a runtime-only node": "RUNTIME_ONLY_WORKFLOW_NODE",
    "workflow action dependency closure is incomplete": "INCOMPLETE_DEPENDENCY_CLOSURE",
    "workflow action parameters do not match the selected node": "WORKFLOW_PARAMETER_MISMATCH",
    "workflow action contains a duplicate node": "DUPLICATE_WORKFLOW_NODE",
    "AUTO requires an independent current user request": "AUTO_CURRENT_REQUEST_REQUIRED",
    "LLM call budget exceeded": "MODEL_CALL_BUDGET_EXCEEDED",
}
_rules = frozenset(RULE_MESSAGES.values()) | {"UNSPECIFIED"}
_types = frozenset(get_args(ErrorType)) | {
    "output_size", "bare_json_object", "strict_json", "nesting_depth",
    "semantic_constraint", "schema_validation", "unknown",
}


def rule_for_message(message: str) -> str:
    return RULE_MESSAGES.get(message.removeprefix("Value error, "), "UNSPECIFIED")


@lru_cache(maxsize=1)
def _schema_names() -> frozenset[str]:
    names: set[str] = set()
    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"properties", "$defs"} and isinstance(item, dict):
                    names.update(item)
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    for contract in (AutoIntentDecision, EvidenceDecision, GroundedPlannerOutput, PlannerOutput):
        collect(contract.model_json_schema())
    return frozenset(names)


@contextmanager
def diagnostic_scope(run_id: Any):
    safe_id = run_id if isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id) else ""
    token = _run_id.set(safe_id)
    try:
        yield
    finally:
        _run_id.reset(token)


def record_diagnostic(stage: str, outcome: str, category: str, errors=(), attempt: int = 1) -> None:
    if stage not in {"ROUTE", "EVIDENCE", "GROUNDED", "LEGACY", "UNKNOWN", "TURN"}:
        return
    if outcome not in {"RETRY_REQUESTED", "RETRY_BUDGET_EXHAUSTED", "REPAIRED", "REJECTED"}:
        return
    if category not in {"JSON", "SCHEMA", "SEMANTIC", "PROVIDER", "TIMEOUT", "BUDGET", "INTERNAL", "NONE"}:
        return
    names = _schema_names()
    safe_errors = []
    for item in list(errors)[:12]:
        if not isinstance(item, dict):
            continue
        path = item.get("path") if isinstance(item.get("path"), list) else []
        safe_errors.append({
            "path": [part if type(part) is int and 0 <= part <= 1000 else
                     part if isinstance(part, str) and part in names else "<unknown-field>" for part in path[:12]],
            "type": item.get("type") if isinstance(item.get("type"), str) and item.get("type") in _types else "unknown",
            "rule": item.get("rule") if isinstance(item.get("rule"), str) and item.get("rule") in _rules else "UNSPECIFIED",
        })
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "runId": _run_id.get(),
             "stage": stage, "outcome": outcome, "category": category,
             "attempt": min(max(attempt if type(attempt) is int else 1, 0), 8), "errors": safe_errors}
    _append(entry)


# Nodes the outer agent graph can have completed before a turn ends. A timeout is only
# diagnosable if the log says how far the turn got, never what the model said.
_COMPLETED_NODES = frozenset(
    {"route", "retrieval_guard", "retrieve", "assess_evidence", "generate", "engage", "review"}
)


def record_vendor_diagnostic(event: dict[str, Any]) -> None:
    """Record a vendor-side (ai-runtime) outcome as one bounded diagnostic line.

    Only fixed enumerations, small integers and a whitelist of graph node names may cross this
    boundary; prompts, evidence bodies and model output never reach the file.
    """
    if not isinstance(event, dict):
        return
    code = event.get("code")
    if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", code):
        return
    completed = event.get("completedNodes")
    nodes = sorted(n for n in completed if isinstance(n, str) and n in _COMPLETED_NODES) if isinstance(completed, list) else []

    def bounded_int(value: Any, maximum: int) -> int:
        return min(max(value if type(value) is int else 0, 0), maximum)

    _append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "runId": _run_id.get(),
        "stage": "TURN",
        "outcome": "REJECTED",
        "category": "TIMEOUT",
        "attempt": 0,
        "errors": [],
        "vendor": {
            "code": code,
            "completedNodes": nodes[:8],
            "elapsedSeconds": bounded_int(event.get("elapsedSeconds"), 3600),
            "budgetSeconds": bounded_int(event.get("budgetSeconds"), 3600),
            "llmCallCount": bounded_int(event.get("llmCallCount"), 16),
            "modelCalls": bounded_int(event.get("modelCalls"), 16),
        },
    })


def _append(entry: dict[str, Any]) -> None:
    encoded = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
    # Windowed PyInstaller processes have no stderr. Keep at most two small local
    # files; diagnostic I/O must never change the turn's authorization/result.
    try:
        with _lock:
            directory = settings.data_dir / "diagnostics"
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / "model-contract.jsonl"
            if path.exists() and path.stat().st_size + len(encoded.encode("utf-8")) > MAX_LOG_BYTES:
                path.replace(directory / "model-contract.previous.jsonl")
            with path.open("a", encoding="utf-8") as stream:
                stream.write(encoded)
    except OSError:
        pass
