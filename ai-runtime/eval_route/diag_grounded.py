"""复现桌面端 ACTION_PLAN grounded 生成，打印最终发给 Java 的 actions。"""
import asyncio
import json
import sys

sys.path.insert(0, ".")

from app.model import AgentPlanner


async def main() -> None:
    planner = AgentPlanner(index_store=None)
    # 模拟桌面注入的基线工作流（与 Java defaultBaselineSteps 一致）
    workflow = [
        {"nodeId": "baseline-http-headers", "tool": "http_headers", "parameters": {},
         "risk": "SAFE", "requiresApproval": False, "group": 0, "dependsOnNodeIds": []},
        {"nodeId": "baseline-http-security-check", "tool": "http_security_check", "parameters": {},
         "risk": "SAFE", "requiresApproval": False, "group": 0, "dependsOnNodeIds": []},
        {"nodeId": "baseline-site-crawl", "tool": "site_crawl", "parameters": {},
         "risk": "SAFE", "requiresApproval": False, "group": 0, "dependsOnNodeIds": []},
        {"nodeId": "baseline-dir-scan", "tool": "dir_scan", "parameters": {},
         "risk": "SAFE", "requiresApproval": False, "group": 1,
         "dependsOnNodeIds": ["baseline-site-crawl"]},
    ]
    request = {
        "projectId": 1,
        "targetId": 1,
        "conversationId": "diag-1",
        "runId": "diag-1",
        "executionIntent": "AUTO",
        "currentUserRequest": "这个项目怎么打",
        "messages": [{"role": "user", "content": "这个项目怎么打"}],
        "authorization": {"status": "ACTIVE", "allowedTools": [
            "http_headers", "http_security_check", "site_crawl", "dir_scan",
        ], "allowedPorts": "80,443", "approved": False},
        "workflow": workflow,
        "workflowId": "wf-diag",
        "workflowRevision": 1,
        "workflowDigest": "sha256:" + "a" * 64,
        "conversationState": {"projectId": 1, "targetId": 1, "latestPlan": None,
                              "planAvailable": False, "scopeMatches": True,
                              "deliveryPending": False, "recentTurns": []},
    }
    bundle = {
        "projectId": 1, "targetId": 1, "conversationId": "diag-1", "query": "当前授权目标基础资产与安全评估能力",
        "round": 0, "retrievalMethod": "bm25",
        "indexRevision": "sha256:" + "b" * 64,
        "items": [{
            "evidenceId": "ev-diag-1", "documentId": "doc-1", "title": "目标授权上下文（基线）",
            "source": "project", "snippet": "授权目标：http://192.168.222.150，允许端口 80,443",
            "score": 1.0, "targetId": None,
            "contentDigest": "sha256:" + "c" * 64,
        }],
    }
    route = {"intent": "ACTION_PLAN", "needsRetrieval": True,
             "retrievalQuery": "当前授权目标基础资产与安全评估能力",
             "publicReasonCode": "AUTHORIZED_ACTION_REQUEST",
             "executionDecision": "PLAN_ONLY", "planRelation": "NEW"}
    try:
        result = await planner.grounded_plan(request, bundle, route)
        print("INTENT:", result.get("intent"))
        print("SUMMARY:", str(result.get("summary"))[:200])
        print("ACTIONS SENT TO JAVA:")
        print(json.dumps(result.get("actions", []), ensure_ascii=False, indent=2))
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
