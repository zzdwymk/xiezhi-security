from pathlib import Path
import re

import pytest
from pydantic import TypeAdapter, ValidationError

from app import model
from app.graph import TOOL_STAGE
from app.model import build_workflow_capability_manifest, validate_workflow_action_closure
from app.schemas import PlanAction, WorkflowStep, ZapFuzzParameters


PARAMETERS = {
    "fuzzRequestUrl": "http://127.0.0.1/form",
    "fuzzPostBody": "id=1&label=original",
    "fuzzTargetField": "id",
    "fuzzPayload": " literal value ",
}


def test_catalog_matches_java_and_all_python_contract_surfaces():
    catalog = (Path(__file__).resolve().parents[2] / "security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiToolCatalog.java").read_text(encoding="utf-8")
    java_codes = set(re.findall(r'"([a-z_]+)"', catalog))
    assert java_codes == model.SAFE_TOOLS
    assert set(WorkflowStep._PARAMETER_MODELS) == model.SAFE_TOOLS
    assert set(model._ACTION_PARAMETER_MODELS) == model.EXTERNAL_WORKFLOW_TOOLS
    assert set(model._PARAMETER_SCHEMAS) == model.EXTERNAL_WORKFLOW_TOOLS
    assert set(TOOL_STAGE) == model.SAFE_TOOLS
    action_codes = set(TypeAdapter(PlanAction).json_schema()["discriminator"]["mapping"])
    assert action_codes == model.SAFE_TOOLS


def test_zap_workflow_inherits_original_fields_and_forces_approval():
    workflow = [{"nodeId": "zap-field", "tool": "zap_fuzz", "parameters": PARAMETERS,
                 "requiresApproval": False, "risk": "SAFE", "group": 0}]
    manifest = build_workflow_capability_manifest({"workflow": workflow})
    assert manifest["nodes"][0]["serverSummary"]["requiresApproval"] is True
    assert "单次" in manifest["runtimeContract"]["zapSingleMutation"]
    actions = validate_workflow_action_closure([
        {"workflowNodeId": "zap-field", "parameters": {}, "evidenceRefs": ["ev-1"]}], workflow)
    assert actions[0]["tool"] == "zap_fuzz"
    assert actions[0]["requiresApproval"] is True
    assert actions[0]["parameters"] == {**PARAMETERS, "method": "POST"}
    patched = validate_workflow_action_closure([
        {"workflowNodeId": "zap-field", "parameters": {"fuzzPayload": "replacement"}, "evidenceRefs": []}], workflow)
    assert patched[0]["parameters"] == {**PARAMETERS, "method": "POST", "fuzzPayload": "replacement"}


def test_zap_saved_node_can_defer_fields_but_final_action_cannot():
    WorkflowStep.model_validate({"nodeId": "zap-field", "tool": "zap_fuzz", "parameters": {}})
    with pytest.raises(ValidationError):
        ZapFuzzParameters.model_validate({})
    with pytest.raises(ValidationError):
        TypeAdapter(PlanAction).validate_python({"tool": "zap_fuzz", "parameters": PARAMETERS,
                                                "risk": "SAFE", "requiresApproval": False})


@pytest.mark.parametrize("patch", [
    {"fuzzRequestUrl": "/relative?id=1"}, {"fuzzRequestUrl": "file:///tmp/test"},
    {"fuzzRequestUrl": "https://u:p@host/path"}, {"fuzzRequestUrl": "http://host/#"},
    {"fuzzRequestUrl": "http://host:0/"}, {"fuzzRequestUrl": "http://host:65536/"},
    {"method": "get"}, {"method": "DELETE"}, {"method": "GET"},
    {"fuzzPayload": 1}, {"fuzzPayload": ""}, {"fuzzPayload": "a" * 1001},
    {"fuzzPayload": "line\r\nHeader: x"}, {"fuzzTargetField": " "},
    {"fuzzTargetField": "f" * 129}, {"fuzzPostBody": "x" * 4001},
    {"fuzzTargetField": "missing"}, {"fuzzPostBody": "id=1&id=2"},
    {"fuzzPostBody": "id=%xx"}, {"fuzzPostBody": ""},
    {"payloadFile": "/tmp/wordlist"}, {"command": "run"},
    {"__resolvedWebBases": ["http://host"]},
])
def test_zap_rejects_unbounded_or_expanded_parameters(patch):
    with pytest.raises(ValidationError):
        ZapFuzzParameters.model_validate({**PARAMETERS, **patch})


def test_zap_get_uses_query_and_empty_body_without_changing_literal_payload():
    value = ZapFuzzParameters.model_validate({**PARAMETERS, "method": "GET", "fuzzPostBody": "",
                                             "fuzzRequestUrl": "http://127.0.0.1/?id=1"})
    assert value.fuzzPayload == " literal value "
