"""Bounded presentation-only progress, separate from the trusted runtime ledger."""
from __future__ import annotations

import asyncio
from contextlib import suppress
from contextvars import ContextVar
from typing import Any, AsyncIterator, Callable

_STAGES = {"ROUTING", "RETRIEVING", "EVIDENCE_READY", "ASSESSING", "ASSESSED", "GENERATING", "CONTRACT_RETRY",
           "AUTHORIZING", "MODEL_CALL"}
_DECISIONS = {"FINALIZE", "REWRITE_QUERY", "CLARIFY"}
_REASONS = {
    "FINALIZE": {"DIRECT_SUPPORT", "PARTIAL_SUPPORT"},
    "REWRITE_QUERY": {"PARTIAL_SUPPORT", "NO_RELEVANT_EVIDENCE", "QUERY_TOO_BROAD"},
    "CLARIFY": {"NO_RELEVANT_EVIDENCE", "CONFLICTING_EVIDENCE", "SCOPE_MISMATCH"},
}
_GUARD_REASONS = {"REWRITE_LIMIT_REACHED", "REWRITE_REJECTED"}
# Model-call observability: which planner stage the call belongs to, how it ended and how long
# it took. Every value is a finite enumeration or a bounded integer, so this channel can say
# "waiting on the model, 18 s of a 60 s limit" without ever carrying prompt or evidence text.
_MODEL_STAGES = {"ROUTE", "EVIDENCE", "GROUNDED", "LEGACY", "SUMMARY", "CONTRACT"}
_MODEL_OUTCOMES = {"STARTED", "SUCCEEDED", "TIMEOUT", "FAILED"}
_MAX_ATTEMPT = 8
_MAX_ELAPSED_MS = 600_000
_MAX_TIMEOUT_MS = 240_000
_listener: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar("public_progress", default=None)


def emit_progress(
    stage: str, *, count: int | None = None, decision: str | None = None,
    model_decision: str | None = None, reason_codes: list[str] | None = None,
    assessment_source: str | None = None, guard_reason: str | None = None,
) -> None:
    listener = _listener.get()
    if listener is None or stage not in _STAGES:
        return
    payload: dict[str, Any] = {"stage": stage}
    if type(count) is int and 0 <= count <= 10:
        payload["count"] = count
    if isinstance(decision, str) and decision in _DECISIONS:
        payload["decision"] = decision
    if any(value is not None for value in (model_decision, reason_codes, assessment_source, guard_reason)):
        # Only validated finite assessment facts may cross this UI channel.
        # Reject the entire hint rather than relabel a guard decision as the
        # model's original decision or leak a free-form reason.
        if (stage != "ASSESSED" or not isinstance(model_decision, str) or model_decision not in _DECISIONS
                or not isinstance(decision, str) or decision not in _DECISIONS
                or not isinstance(assessment_source, str) or assessment_source not in {"MODEL", "LOCAL_RULE"}
                or not isinstance(reason_codes, list) or not 1 <= len(reason_codes) <= 4
                or any(not isinstance(reason, str) or reason not in _REASONS[model_decision]
                       for reason in reason_codes)
                or len(set(reason_codes)) != len(reason_codes)):
            return
        if guard_reason is not None:
            if (not isinstance(guard_reason, str) or guard_reason not in _GUARD_REASONS or model_decision != "REWRITE_QUERY"
                    or decision != "CLARIFY"):
                return
            payload["guardReason"] = guard_reason
        elif model_decision != decision:
            return
        payload.update(modelDecision=model_decision, reasonCodes=list(reason_codes),
                       assessmentSource=assessment_source)
    listener(payload)


def emit_model_call(stage: str, outcome: str, *, attempt: int = 0,
                    elapsed_ms: int | None = None, timeout_ms: int | None = None) -> None:
    """Publish one bounded model-call observation for the chat's connection indicator.

    ``STARTED`` carries the per-call limit; the terminal outcomes carry the measured duration so
    the UI can show "responded in 18 s" or "timed out after 60 s". Any value outside the finite
    ranges drops the whole hint rather than leaking a free-form field.
    """
    listener = _listener.get()
    if listener is None:
        return
    if stage not in _MODEL_STAGES or outcome not in _MODEL_OUTCOMES:
        return
    if type(attempt) is not int or not 0 <= attempt <= _MAX_ATTEMPT:
        return
    payload: dict[str, Any] = {"stage": "MODEL_CALL", "modelStage": stage, "outcome": outcome, "attempt": attempt}
    if outcome == "STARTED":
        if timeout_ms is None:
            return
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= _MAX_TIMEOUT_MS:
            return
        payload["timeoutMs"] = timeout_ms
    else:
        if elapsed_ms is None:
            return
        if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= _MAX_ELAPSED_MS:
            return
        payload["elapsedMs"] = elapsed_ms
    listener(payload)


async def with_public_progress(events: AsyncIterator[dict[str, Any]]) -> AsyncIterator[tuple[str, Any]]:
    queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=64)
    progress_count = 0

    def publish(payload: dict[str, Any]) -> None:
        nonlocal progress_count
        if progress_count >= 32 or queue.full():
            return
        progress_count += 1
        queue.put_nowait(("progress", payload))

    async def pump() -> None:
        token = _listener.set(publish)
        try:
            async for event in events:
                await queue.put(("event", event))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await queue.put(("error", error))
        else:
            await queue.put(("done", None))
        finally:
            _listener.reset(token)

    producer = asyncio.create_task(pump())
    try:
        while True:
            kind, payload = await queue.get()
            if kind == "done":
                break
            if kind == "error":
                raise payload
            yield kind, payload
    finally:
        producer.cancel()
        with suppress(asyncio.CancelledError):
            await producer
