from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

try:
    from langchain_core.tools import tool

    LANGCHAIN_TOOLS_AVAILABLE = True
except Exception:  # pragma: no cover
    tool = None  # type: ignore[assignment]
    LANGCHAIN_TOOLS_AVAILABLE = False


class _FallbackTool:
    def __init__(self, function: Callable[..., Any]) -> None:
        self.function = function
        self.name = function.__name__

    def invoke(self, arguments: dict[str, Any]) -> Any:
        return self.function(**arguments)


def build_agent_tools(index_store: Any) -> dict[str, Any]:
    def retrieve_project_context(
        project_id: int, query: str, top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Retrieve only documents already indexed for an authorized project."""
        return index_store.query(project_id, query, top_k)

    def propose_authorized_action(
        project_id: int,
        tool_code: str,
        target_id: int | None = None,
        parameters: dict[str, Any] | None = None,
        risk: str = "SAFE",
    ) -> dict[str, Any]:
        """Create a non-executing action proposal for the Java authorization boundary."""
        payload = {
            "projectId": project_id,
            "targetId": target_id,
            "toolCode": tool_code,
            "parameters": parameters or {},
            "risk": risk,
            "executionBoundary": "JAVA_AUTHORIZED_EXECUTOR",
        }
        proposal_id = hashlib.sha256(
            json.dumps(
                payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()[:24]
        return {"proposalId": proposal_id, **payload, "executed": False}

    if LANGCHAIN_TOOLS_AVAILABLE and tool is not None:
        retrieve_tool = tool(retrieve_project_context)
        proposal_tool = tool(propose_authorized_action)
    else:
        retrieve_tool = _FallbackTool(retrieve_project_context)
        proposal_tool = _FallbackTool(propose_authorized_action)
    return {
        "retrieve_project_context": retrieve_tool,
        "propose_authorized_action": proposal_tool,
    }
