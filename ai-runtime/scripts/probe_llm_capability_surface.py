"""Probe: what capability surface does the LLM actually receive?

This reproduces the exact manifest the planner sees, using the real
build_workflow_capability_manifest() and the real workflow the Java backend ships
as its default (legacyDefaultSpec / runtime-default preset).

Run: python scripts/probe_llm_capability_surface.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.model import (  # noqa: E402
    EXTERNAL_WORKFLOW_TOOLS,
    HIGH_RISK_TOOLS,
    SAFE_TOOLS,
    _workflow_steps,
    build_workflow_capability_manifest,
)

# Mirrors AgentWorkflowSpecService.legacyDefaultSpec(): it now lists every executable tool.
DEFAULT_WORKFLOW_STEPS = [
    ("context", "retrieve_project_context", 0, "SAFE", False, {}),
    ("service-scan", "nmap_service_scan", 1, "SAFE", False, {}),
    ("port-probe", "tcp_ports", 1, "SAFE", False, {}),
    ("headers", "http_headers", 1, "SAFE", False, {}),
    ("tls", "tls_config", 1, "SAFE", False, {}),
    ("dir-scan", "dir_scan", 2, "CAUTION", True, {}),
    ("http-security", "http_security_check", 2, "SAFE", False, {}),
    ("nuclei", "nuclei_scan", 3, "CAUTION", True, {}),
    ("afrog", "afrog_scan", 3, "CAUTION", True, {"allPocs": True}),
    ("xray", "xray_scan", 3, "CAUTION", True, {"allPocs": True}),
    ("zap-scan", "zap_scan", 3, "CAUTION", True, {}),
    ("fscan", "fscan_scan", 3, "CAUTION", True, {}),
    ("msf", "msf_scan", 4, "CAUTION", True, {}),
    ("sqlmap", "sqlmap_scan", 4, "CAUTION", True, {}),
    ("zap-fuzz", "zap_fuzz", 4, "CAUTION", True, {}),
]


def workflow_payload():
    return [
        {
            "nodeId": node_id,
            "tool": tool,
            "parameters": params,
            "risk": risk,
            "requiresApproval": approval,
            "group": group,
            "dependsOnNodeIds": [] if node_id == "context" else ["context"],
        }
        for node_id, tool, group, risk, approval, params in DEFAULT_WORKFLOW_STEPS
    ]


def main() -> int:
    request = {"workflow": workflow_payload()}
    manifest = build_workflow_capability_manifest(request)
    visible_tools = [node["tool"] for node in manifest["nodes"]]

    print("=" * 78)
    print("A. 平台能力注册表（Java CapabilityRegistry）")
    print("=" * 78)
    print("  数量：206（14 SecurityTool + 24 核心 + 168 端点 + 1 invoke_endpoint）")
    print("  来源：运行期从 Controller 自动派生，是平台的真实能力全集")
    print()

    print("=" * 78)
    print("B. Python SAFE_TOOLS（LLM 侧的硬编码白名单）")
    print("=" * 78)
    print(f"  数量：{len(SAFE_TOOLS)}")
    print(f"  内容：{', '.join(sorted(SAFE_TOOLS))}")
    print()

    print("=" * 78)
    print("C. 本轮 LLM 实际收到的 workflow_capabilities（默认工作流）")
    print("=" * 78)
    print(f"  数量：{len(manifest['nodes'])}")
    print(f"  内容：{', '.join(visible_tools)}")
    print()

    print("=" * 78)
    print("D. 差距分析")
    print("=" * 78)
    registry_total = 206
    llm_visible = len(manifest["nodes"])
    can_see_but_not_in_workflow = sorted(SAFE_TOOLS - EXTERNAL_WORKFLOW_TOOLS)
    never_reachable = sorted(EXTERNAL_WORKFLOW_TOOLS - set(visible_tools))
    blocked_by_guard = sorted(HIGH_RISK_TOOLS)

    print(f"  注册表 {registry_total} 项  →  SAFE_TOOLS {len(SAFE_TOOLS)} 项  →  "
          f"本轮可见 {llm_visible} 项")
    print(f"  覆盖率：{llm_visible / registry_total * 100:.1f}%  "
          f"（相对注册表）/ {llm_visible / len(EXTERNAL_WORKFLOW_TOOLS) * 100:.1f}%"
          f"（相对可派发工具）")
    print()
    print(f"  · 仅存在于 SAFE_TOOLS 但不在 manifest 的工具：{can_see_but_not_in_workflow or '无'}")
    print(f"    → 它们是 retrieve_project_context 一类，不产生动作，属预期")
    print()
    print(f"  · 在 SAFE_TOOLS 但默认工作流没有节点、因此本轮不可选的工具：{never_reachable or '无'}")
    if never_reachable:
        for tool in never_reachable:
            print(f"      - {tool}: 需要用户在“红队工作流”页面手动添加节点后才能被选中")
    print()
    print(f"  · 在 manifest 中但护栏会额外拦截的（HIGH_RISK）：{blocked_by_guard}")
    print()

    print("=" * 78)
    print("E. 结论")
    print("=" * 78)
    print("  1. LLM 的“能力视野”= 当前工作流快照里的可执行节点，不是 206 项注册表。")
    print("  2. 注册表里 168 个端点能力 + invoke_endpoint + 24 个核心能力，")
    print("     LLM 一种都调不到——它们不在 SAFE_TOOLS，也不在 _PARAMETER_SCHEMAS。")
    print("  3. 在 SAFE_TOOLS 里的工具，如果默认工作流没有节点，本轮也选不了。")
    print("  4. 因此“动态发现项目内自带的所有功能”在当前架构下不成立：")
    print("     LLM 看到的是固定快照，且该快照由 Java 侧的 8-9 个默认节点 + 用户手工编排决定。")
    print()
    print(f"  dir_scan 是否已进入 LLM 视野：{'是' if 'dir_scan' in visible_tools else '否'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
