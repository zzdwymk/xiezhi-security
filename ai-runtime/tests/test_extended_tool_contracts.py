from __future__ import annotations

import asyncio
import json

import pytest
from pydantic import ValidationError

from app.graph import SecurityAgentRuntime
from app.model import (
    GROUNDED_SYSTEM_PROMPT,
    PlannerOutputError,
    build_workflow_capability_manifest,
    parse_planner_output,
    validate_workflow_action_closure,
)
from app.schemas import FscanParameters, MsfParameters, WorkflowStep, ZapParameters


def _step(tool: str, parameters: dict) -> dict:
    return {
        "nodeId": tool + "-01", "tool": tool, "parameters": parameters,
        "risk": "CAUTION", "requiresApproval": True, "group": 1,
        "dependsOnNodeIds": [],
    }


@pytest.mark.parametrize("tool,parameters", [
    ("nuclei_scan", {}),
    ("nuclei_scan", {"allPocs": True}),
    ("nuclei_scan", {"pocCodes": ["NU-" + "A" * 24]}),
    ("zap_scan", {"spider": False, "strength": "LOW"}),
    ("fscan_scan", {"ports": "80", "vulnMode": "SAFE"}),
    ("msf_scan", {"module": "auxiliary/scanner/http/http_version", "options": {"THREADS": "1"}}),
    ("msf_scan", {"modules": ["auxiliary/scanner/http/http_version", "auxiliary/scanner/ssl/ssl_version"]}),
])
def test_added_tools_round_trip_snapshot_patch_and_legacy_contract(tool, parameters):
    step = _step(tool, parameters)
    manifest = build_workflow_capability_manifest({"workflow": [step]})
    assert manifest["nodes"][0]["tool"] == tool
    normalized = validate_workflow_action_closure([
        {"workflowNodeId": step["nodeId"], "parameters": {}, "evidenceRefs": ["ev-1"]},
    ], [step])
    assert normalized[0]["parameters"] == parameters
    assert normalized[0]["requiresApproval"] is True
    parsed = parse_planner_output(json.dumps({
        "summary": "范围内规划", "answer": "等待审批", "intent": "plan",
        "actions": [{"tool": tool, "parameters": parameters, "risk": "CAUTION", "requiresApproval": True}],
    }))
    assert parsed["actions"][0]["parameters"] == parameters


@pytest.mark.parametrize("parameters", [
    {"allPocs": False}, {"allPocs": "true"}, {"pocCodes": []},
    {"allPocs": True, "pocCodes": ["NU-" + "A" * 24]},
    {"pocCodes": ["https://example.invalid/template.yaml"]},
    {"templates": "/arbitrary/path"},
])
def test_nuclei_workflow_rejects_invalid_selection_without_widening(parameters):
    with pytest.raises(ValidationError):
        WorkflowStep.model_validate(_step("nuclei_scan", parameters))


@pytest.mark.parametrize("model,parameters", [
    (ZapParameters, {"spider": "false"}),
    (ZapParameters, {"strength": "low"}),
    (ZapParameters, {"command": "ignored"}),
    (FscanParameters, {"ports": 80}),
    (FscanParameters, {"vulnMode": "UNKNOWN"}),
    (MsfParameters, {}),
    (MsfParameters, {"module": "auxiliary/scanner/http/http_version", "modules": ["auxiliary/scanner/http/http_version"]}),
    (MsfParameters, {"modules": ["auxiliary/scanner/http/http_version"] * 2}),
    (MsfParameters, {"module": "auxiliary/../payload"}),
    (MsfParameters, {"module": "auxiliary/scanner/http/http_version;exit"}),
    (MsfParameters, {"module": "post/windows/gather/hashdump"}),
    (MsfParameters, {"module": "auxiliary/scanner/http/http_version", "options": {"RHOSTS": "other-host"}}),
    (MsfParameters, {"module": "auxiliary/scanner/http/http_version", "options": {"CMD": "anything"}}),
    (MsfParameters, {"module": "auxiliary/scanner/http/http_version", "options": {"THREADS": 1}}),
    (MsfParameters, {"module": "auxiliary/scanner/http/http_version", "options": {"THREADS": "1\nexit"}}),
])
def test_added_tool_contracts_reject_type_confusion_and_command_or_scope_overrides(model, parameters):
    with pytest.raises(ValidationError):
        model.model_validate(parameters)


def test_msf_workflow_can_defer_module_but_action_cannot():
    step = _step("msf_scan", {})
    WorkflowStep.model_validate(step)
    with pytest.raises(PlannerOutputError, match="selected node"):
        validate_workflow_action_closure([
            {"workflowNodeId": step["nodeId"], "parameters": {}, "evidenceRefs": []},
        ], [step])


def test_msf_existing_header_configuration_is_inherited_without_mixing_selection_fields():
    module = "auxiliary/scanner/http/http_header"
    configured = {"modules": [module], "options": {"HTTP_METHOD": "HEAD", "TARGETURI": "/"}}
    step = _step("msf_scan", configured)
    guidance = build_workflow_capability_manifest({"workflow": [step]})["runtimeContract"]["msfParameterPatch"]
    assert "parameters={}" in guidance
    assert "已配置 modules 时不得追加 module" in guidance
    proposal = {"workflowNodeId": step["nodeId"], "parameters": {}, "evidenceRefs": ["ev-1"]}
    action = validate_workflow_action_closure([proposal], [step])[0]
    assert action["parameters"] == configured
    assert action["requiresApproval"] is True
    assert proposal["parameters"] == {}
    # Equivalent names do not justify silently deleting one of two conflicting fields.
    for patch in ({"module": module}, {"module": module, "modules": None}):
        with pytest.raises(PlannerOutputError, match="selected node"):
            validate_workflow_action_closure([{**proposal, "parameters": patch}], [step])


def test_empty_zap_defaults_accept_user_patch_without_url_or_approval_node():
    step = _step("zap_scan", {})
    manifest = build_workflow_capability_manifest({"workflow": [step]})
    contract = manifest["runtimeContract"]
    assert "无需工作流审批节点" in contract["approval"]
    assert "授权 targetId" in contract["targetBinding"]
    assert "不是参数值白名单" in contract["parameterPatch"]
    assert "没有 Metasploit 模块目录检索工具" in contract["moduleDiscovery"]
    proposed = validate_workflow_action_closure([
        {"workflowNodeId": step["nodeId"], "parameters": {"spider": False, "strength": "LOW"},
         "evidenceRefs": ["ev-1"]},
    ], [step])[0]
    assert proposed["parameters"] == {"spider": False, "strength": "LOW"}
    assert proposed["requiresApproval"] is True
    assert proposed["dependsOnNodeIds"] == []
    with pytest.raises(PlannerOutputError):
        validate_workflow_action_closure([
            {"workflowNodeId": step["nodeId"], "parameters": {"url": "http://other-host"},
             "evidenceRefs": ["ev-1"]},
        ], [step])


@pytest.mark.parametrize("tool,parameters", [
    ("zap_scan", {"strength": "LOW"}),
    ("fscan_scan", {"ports": "80", "vulnMode": "SAFE"}),
    ("msf_scan", {"module": "auxiliary/scanner/http/http_version"}),
])
def test_added_tools_still_require_target_tool_and_approval_authorization(tool, parameters):
    runtime = SecurityAgentRuntime(None)
    authorization = {
        "status": "ACTIVE", "targetIds": [9], "allowedTools": [tool],
        "allowedPorts": "80", "approved": False,
        "validFrom": "2020-01-01T00:00:00Z", "expiresAt": "2099-01-01T00:00:00Z",
        "quota": {"maxActions": 5, "usedActions": 0},
    }
    request = {"projectId": 7, "targetId": 9, "authorization": authorization}
    action = {"tool": tool, "parameters": parameters, "risk": "CAUTION", "requiresApproval": True}
    state = {"request": request, "plan": {"actions": [action]}}
    pending = asyncio.run(runtime._guard_node(state))
    assert pending["guardedActions"] == []
    assert len(pending["approvalActions"]) == 1
    authorization["allowedTools"] = []
    denied = asyncio.run(runtime._guard_node(state))
    assert denied["guardedActions"] == denied["approvalActions"] == []
    assert denied["guardViolations"]
    authorization.update(allowedTools=[tool], approved=True)
    approved = asyncio.run(runtime._guard_node(state))
    assert len(approved["guardedActions"]) == 1
    request["targetId"] = 10
    assert asyncio.run(runtime._guard_node(state))["guardedActions"] == []


def test_grounded_prompt_formats_for_both_chat_and_responses():
    # Responses formats root instructions directly; ChatPromptTemplate also treats
    # literal JSON braces as placeholders. A literal {} must therefore be escaped.
    rendered = GROUNDED_SYSTEM_PROMPT.format()
    assert "parameters={}" in rendered

