"""Compaction trigger: only when the raw conversation outgrows the budget, and only once.

Summarizing is expensive and lossy, so it must fire exactly when it is worth it and exactly once
per turn even though several stages render the same conversation.
"""

from __future__ import annotations

import asyncio

import pytest

from app.model import (
    AgentPlanner,
    _COMPACT_TRIGGER_CHARS,
    _conversation_exceeds_compaction_budget,
)


def _turns(count: int, size: int) -> list[dict]:
    out: list[dict] = []
    for i in range(count):
        out.append({"role": "user", "content": f"turn-{i}-" + "x" * size})
        out.append({"role": "assistant", "content": f"reply-{i}-" + "y" * size})
    return out


def test_short_conversation_does_not_trigger_compaction():
    assert not _conversation_exceeds_compaction_budget(_turns(2, 100))


def test_long_conversation_triggers_compaction():
    assert _conversation_exceeds_compaction_budget(_turns(20, 2000))


def test_system_messages_do_not_count_toward_the_trigger():
    messages = [{"role": "system", "content": "z" * (_COMPACT_TRIGGER_CHARS * 2)}]
    messages.extend(_turns(1, 50))
    assert not _conversation_exceeds_compaction_budget(messages)


class _CountingPlanner(AgentPlanner):
    """Planner whose summary call is counted instead of hitting a model."""

    def __init__(self) -> None:  # noqa: D401 - test double
        super().__init__(index_store=None)
        self.summary_calls = 0

    async def summarize_conversation(self, conversation: str, target_id=None):  # type: ignore[override]
        self.summary_calls += 1
        return {"userIntents": [" summarizes once "]}


def test_summary_is_generated_once_per_request_and_reused():
    planner = _CountingPlanner()
    request = {"messages": _turns(20, 2000), "targetId": 9}

    # Two stages render the same request; the digest must be produced only once.
    first = asyncio.run(planner._conversation_for_prompt(request))
    second = asyncio.run(planner._conversation_for_prompt(request))

    assert planner.summary_calls == 1
    assert " summarizes once " in first or "summarizes once" in first
    assert first == second


def test_persisted_summary_is_reused_instead_of_recomputed():
    planner = _CountingPlanner()
    request = {
        "messages": _turns(20, 2000),
        "targetId": 9,
        "conversationSummary": {"userIntents": ["来自服务端的摘要"]},
    }

    rendered = asyncio.run(planner._conversation_for_prompt(request))

    assert planner.summary_calls == 0
    assert "来自服务端的摘要" in rendered


def test_short_conversation_never_calls_the_summarizer():
    planner = _CountingPlanner()
    request = {"messages": _turns(1, 20), "targetId": 9}
    asyncio.run(planner._conversation_for_prompt(request))
    assert planner.summary_calls == 0
