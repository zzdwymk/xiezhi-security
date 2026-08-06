from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, TypedDict

from .authorization import parse_instant, port_intervals, ports_allowed, requested_ports
from .config import settings
from .model import AgentPlanner, HIGH_RISK_TOOLS
from .schemas import AgentRequest
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


class SecurityAgentRuntime:
    """LangGraph orchestration with a hard authorization boundary."""

    def __init__(self, index_store: Any) -> None:
        self.index_store = index_store
        self.planner = AgentPlanner(index_store)
        self.tools = build_agent_tools(index_store)
        self.graph = self._build_graph() if LANGGRAPH_AVAILABLE else None

    @property
    def health(self) -> dict[str, Any]:
        return {
            "langGraphAvailable": LANGGRAPH_AVAILABLE,
            "graphCompiled": self.graph is not None,
            "nodes": list(RED_TEAM_STAGE_IDS),
            "workflowVersion": 2,
            **self.planner.status,
        }

    def graph_structure(self) -> dict[str, Any]:
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
            "version": 2,
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
        builder.add_node("engage", self._engage_node)
        builder.add_node("recon", self._recon_node)
        builder.add_node("map", self._map_node)
        builder.add_node("validate", self._validate_node)
        builder.add_node("impact", self._impact_node)
        builder.add_node("retest", self._retest_stage_node)
        builder.add_node("report", self._report_node)
        builder.add_node("finish", self._finish_node)
        builder.add_edge(START, "engage")
        builder.add_edge("engage", "recon")
        builder.add_edge("recon", "map")
        builder.add_edge("map", "validate")
        builder.add_edge("validate", "impact")
        builder.add_edge("impact", "retest")
        builder.add_edge("retest", "report")
        builder.add_edge("report", "finish")
        builder.add_edge("finish", END)
        return builder.compile()

    async def _engage_node(self, state: AgentState) -> AgentState:
        """Start a red-team engagement and perform the hard pre-execution guard.

        Planner/guard remain implementation details of this stage.  Their legacy event
        types are intentionally retained so existing Java/UI consumers do not break,
        while ``node`` and ``stage`` identify the user-facing red-team phase.
        """
        plan_update = await self._planner_node(state)
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
            "events": [plan_event, guard_event],
        }

    async def _planner_node(self, state: AgentState) -> AgentState:
        plan = await self.planner.plan(state["request"])
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
                    "actionCount": len(plan.get("actions", [])),
                    "source": plan.get("source"),
                    "warning": plan.get("modelWarning"),
                    # Full step list for the desktop "执行 Plan" checklist.
                    "actions": plan.get("actions", []),
                    "steps": [
                        {
                            "toolCode": str(action.get("tool") or ""),
                            "tool": str(action.get("tool") or ""),
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
        allowed_ports = port_intervals(authorization.get("allowedPorts"))
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
                requested = requested_ports(params)
                if not allowed_ports:
                    checks["ports"] = False
                    action_violations.append(f"工具 {tool_code} 缺少授权端口快照")
                elif not ports_allowed(requested, allowed_ports):
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
        return {
            "guardedActions": guarded,
            "guardViolations": violations,
            "approvalActions": approvals,
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
        actions_override: list[dict[str, Any]] | None = None,
    ) -> AgentState:
        request = state["request"]
        actions = (
            list(actions_override)
            if actions_override is not None
            else self._actions_for_stage(state, stage)
        )

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

        async def run_action(action: dict[str, Any]) -> dict[str, Any]:
            if action["tool"] == "retrieve_project_context":
                query = str(action.get("parameters", {}).get("query", "项目资料"))
                references = await asyncio.to_thread(
                    self.tools["retrieve_project_context"].invoke,
                    {
                        "project_id": int(request["projectId"]),
                        "query": query,
                        "top_k": 5,
                    },
                )
                return {
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
                },
            )
            return {"tool": action["tool"], "executed": False, "proposal": proposal}

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
            for level in sorted(groups):
                level_results = await asyncio.gather(
                    *(run_action(action) for action in groups[level])
                )
                results.extend(level_results)
            combined = list(state.get("toolResults", [])) + results
            return {
                "toolResults": combined,
                # A successful sibling/later stage must not erase an earlier
                # failure; the retest stage owns the accumulated retry decision.
                "executorError": state.get("executorError"),
                "failedActions": list(state.get("failedActions", [])),
                "event": _event(
                    "tool",
                    stage,
                    "红队阶段已完成受控工具处理",
                    {
                        "stage": stage,
                        "legacyNode": "executor",
                        "resultCount": len(results),
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
            retry_count = working.get("retryCount", 0) + 1
            working["retryCount"] = retry_count
            retry_event = (await self._retry_node(working)).get("event")
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
            working["guardedActions"] = failed
            working["executorError"] = None
            working["failedActions"] = []
            retry_update = await self._executor_node(
                working, "retest", actions_override=failed
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
            answer = "当前请求未通过授权守卫，未执行任何工具。\n\n" + "\n".join(
                f"- {item}" for item in violations
            )
        elif approvals:
            status = "APPROVAL_REQUIRED"
            answer = "计划包含需要人工审批的动作，已暂停执行。审批后重新提交时仍会重新校验项目、目标、端口、工具、时间窗和配额。"
        elif state.get("executorError"):
            status = "FAILED"
            answer = "受控工具处理失败，已达到重试上限；未执行未授权命令。"
        else:
            status = "COMPLETED"
            answer = str(state.get("plan", {}).get("answer", "已完成项目级分析。"))
            if review.get("references"):
                answer += "\n\n已结合项目资料进行检索，引用来源：\n" + "\n".join(
                    f"- {item.get('title', '项目资料')}（{item.get('source', 'project')}）"
                    for item in review["references"][:5]
                )
            if review.get("proposals"):
                answer += f"\n\n已生成 {len(review['proposals'])} 个受控工具提案，需由 Java 授权执行器再次校验后派发。"
        final = {
            "status": status,
            "answer": answer,
            "plan": state.get("plan", {}),
            "review": review,
            "violations": violations,
        }
        return {
            "final": final,
            "event": _event("finish", "finish", f"智能体流程结束：{status}", final),
        }

    async def stream(self, request: AgentRequest) -> AsyncIterator[dict[str, Any]]:
        initial: AgentState = {
            "request": request.model_dump(mode="json"),
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
        }
        if self.graph is None:
            async for event in self._fallback_stream(initial):
                yield event
            return
        async for update in self.graph.astream(initial, stream_mode="updates"):
            if not isinstance(update, dict):
                continue
            for node_update in update.values():
                if not isinstance(node_update, dict):
                    continue
                for event in self._events_from_update(node_update):
                    yield event

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


def encode_sse(event: dict[str, Any]) -> str:
    event_type = re.sub(r"[^a-zA-Z0-9_-]", "_", str(event.get("type", "message")))
    return f"id: {event.get('eventId', '')}\nevent: {event_type}\ndata: {json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n\n"
