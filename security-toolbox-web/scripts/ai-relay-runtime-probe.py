"""Isolated real-runtime client for the loopback relay integration test."""
from __future__ import annotations

import asyncio
import json

from app.model import AgentPlanner


async def main() -> None:
    planner = AgentPlanner(None)
    assert planner.status["llmConfigured"] is True
    request = {
        "projectId": 1,
        "messages": [{"role": "user", "content": "Explain HTTP response headers."}],
        "workflow": [],
    }
    routed = await planner.route(request)
    assert routed["intent"] == "GENERAL_QA"
    assert routed["needsRetrieval"] is False
    evidence = {
        "projectId": 1, "targetId": None, "conversationId": None,
        "query": "HTTP headers", "round": 0, "retrievalMethod": "bm25",
        "indexRevision": "sha256:" + "0" * 64, "items": [],
    }
    result = await planner.grounded_plan(request, evidence, routed)
    assert result["intent"] == "answer"
    assert result["knowledgeMode"] == "GENERAL"
    assert result["actions"] == result["evidenceRefs"] == []
    assert result["answer"] == "HTTP response headers describe the response."
    assert result["source"] == "langchain-grounded"
    # The third request starts round-robin at A again, proving its cooldown is
    # honored rather than merely observing the second request start at B.
    assert (await planner.route(request))["intent"] == "GENERAL_QA"
    print(json.dumps({"ok": True, "modelCalls": 3, "source": result["source"]}))


if __name__ == "__main__":
    asyncio.run(main())
