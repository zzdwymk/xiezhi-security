"""Drift guard: the Python tool contract must match the Java catalog.

The Java ``AiToolCatalog`` is the single source of truth. The Python runtime keeps a static
contract because Pydantic ``Literal`` types are a schema-level security boundary (the model cannot
emit an unknown tool code), but a hand-maintained copy drifts.

Before this guard existed, adding ``dir_scan`` to the Java side alone produced:

    ValidationError: 'dir_scan' not in 'retrieve_project_context' | ... | 'zap_fuzz'
    -> PlannerOutputError: workflow snapshot does not match its schema

i.e. every AI turn failed with a schema error, not just the new tool being unavailable.
These tests turn that runtime failure into a test failure.

Run: python -m pytest tests/test_tool_catalog_drift.py -q
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.graph import TOOL_STAGE
from app.model import EXTERNAL_WORKFLOW_TOOLS, SAFE_TOOLS, _ACTION_PARAMETER_MODELS, _PARAMETER_SCHEMAS
from app.schemas import (
    EmptyToolParameters,
    GroundedParameterPatch,
    PlanAction,
    WorkflowStep,
    WorkflowToolParameters,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
JAVA_CATALOG = (
    REPO_ROOT
    / "security-toolbox-server"
    / "src"
    / "main"
    / "java"
    / "com"
    / "bachelor"
    / "toolbox"
    / "ai"
    / "AiToolCatalog.java"
)


def java_runtime_codes() -> list[str]:
    """Extract RUNTIME_CODES from AiToolCatalog.java without running Java."""
    source = JAVA_CATALOG.read_text(encoding="utf-8")
    match = re.search(r"EXECUTABLE_CODES\s*=\s*List\.of\((.*?)\);", source, re.S)
    if match is None:
        pytest.fail("cannot locate EXECUTABLE_CODES in AiToolCatalog.java")
    executable = re.findall(r'"([a-z_]+)"', match.group(1))
    if not executable:
        pytest.fail("EXECUTABLE_CODES parsed to an empty list")
    return ["retrieve_project_context", *executable]


def test_java_catalog_file_exists() -> None:
    assert JAVA_CATALOG.is_file(), f"missing Java catalog at {JAVA_CATALOG}"


def test_safe_tools_matches_java_executable_codes() -> None:
    java_codes = set(java_runtime_codes())
    assert SAFE_TOOLS == java_codes, (
        "SAFE_TOOLS drifted from AiToolCatalog.EXECUTABLE_CODES; "
        f"only in python: {sorted(SAFE_TOOLS - java_codes)}, "
        f"only in java: {sorted(java_codes - SAFE_TOOLS)}"
    )


def test_external_workflow_tools_excludes_context_retrieval() -> None:
    assert EXTERNAL_WORKFLOW_TOOLS == SAFE_TOOLS - {"retrieve_project_context"}


def test_workflow_step_literal_covers_every_code() -> None:
    literal = WorkflowStep.model_fields["tool"].annotation
    allowed = set(typing_args(literal))
    assert allowed == set(java_runtime_codes()), (
        "WorkflowStep.tool Literal drifted; "
        f"missing from Literal: {sorted(set(java_runtime_codes()) - allowed)}"
    )


def test_parameter_schema_table_covers_every_executable_tool() -> None:
    for code in java_runtime_codes():
        if code == "retrieve_project_context":
            continue
        assert code in _PARAMETER_SCHEMAS, f"missing _PARAMETER_SCHEMAS[{code!r}]"
        assert code in _ACTION_PARAMETER_MODELS, f"missing _ACTION_PARAMETER_MODELS[{code!r}]"


def test_tool_stage_covers_every_code() -> None:
    assert set(TOOL_STAGE) == set(java_runtime_codes()), (
        "TOOL_STAGE drifted; "
        f"missing: {sorted(set(java_runtime_codes()) - set(TOOL_STAGE))}"
    )


def test_every_tool_has_exactly_one_plan_action() -> None:
    actions = typing_args(PlanAction.__origin__ if hasattr(PlanAction, "__origin__") else PlanAction)
    action_tools: list[str] = []
    for action in actions:
        field = action.model_fields["tool"].annotation
        action_tools.extend(typing_args(field))
    assert sorted(action_tools) == sorted(java_runtime_codes()), (
        "PlanAction union drifted; "
        f"only in union: {sorted(set(action_tools) - set(java_runtime_codes()))}, "
        f"missing: {sorted(set(java_runtime_codes()) - set(action_tools))}"
    )


def test_workflow_parameter_union_accepts_every_tool_parameters() -> None:
    """Every tool needs a parameters model that WorkflowStep will accept.

    Action-level and workflow-level models are deliberately distinct for some tools:
    ``http_security_check`` is ``HttpSecurityParameters`` (``check`` mandatory) in a plan action,
    but ``WorkflowHttpSecurityParameters`` (``check`` optional, deferred to a patch) in a saved
    node. The workflow union must therefore be checked against the *workflow* model of each tool,
    which is what WorkflowStep.parameters actually resolves.
    """
    workflow_models = WorkflowStep._PARAMETER_MODELS
    accepted = set(typing_args(WorkflowToolParameters))
    for code in java_runtime_codes():
        if code == "retrieve_project_context":
            continue
        model = workflow_models[code]
        assert model in accepted, (
            f"{model.__name__} for {code!r} is not accepted by WorkflowToolParameters; "
            "WorkflowStep validation would reject it"
        )


def test_grounded_patch_union_is_not_empty() -> None:
    """The planner patch union must stay populated.

    Deliberately *not* asserting a per-tool mapping here: ``GroundedParameterPatch`` is the
    planner's patch type and several tools intentionally use a narrower or different model
    (``SqlmapParameterPatch`` vs ``WorkflowSqlmapParameters``). Enforcing identity or inheritance
    would encode a guess about that design into a test, and the guess was already wrong twice while
    writing this file. Coverage of each tool is asserted where it is actually enforced:
    ``WorkflowStep._PARAMETER_MODELS`` and ``WorkflowToolParameters``.
    """
    accepted = set(typing_args(GroundedParameterPatch))
    assert accepted, "GroundedParameterPatch has no members"
    # Every tool that only needs shape-neutral parameters must still resolve to a union member.
    for code, model in WorkflowStep._PARAMETER_MODELS.items():
        if code == "retrieve_project_context":
            continue
        if model is EmptyToolParameters:
            assert model in accepted, f"{code!r} uses EmptyToolParameters, missing from patch union"


def test_dir_scan_bounds_match_java_spec() -> None:
    """The two sides must agree on the operator-facing concurrency/depth bounds."""
    schema = _PARAMETER_SCHEMAS["dir_scan"]["properties"]
    assert schema["concurrency"]["minimum"] == 1
    assert schema["concurrency"]["maximum"] == 50
    assert schema["depth"]["minimum"] == 0
    assert schema["depth"]["maximum"] == 3

    java_spec = (
        REPO_ROOT
        / "security-toolbox-server"
        / "src"
        / "main"
        / "java"
        / "com"
        / "bachelor"
        / "toolbox"
        / "ai"
        / "ToolParameterSpec.java"
    ).read_text(encoding="utf-8")
    assert "DIR_SCAN_MAX_CONCURRENCY = 50" in java_spec
    assert "DIR_SCAN_MAX_DEPTH = 3" in java_spec


def typing_args(annotation) -> list:
    """Return the union members of an Annotated/Union type."""
    origin = getattr(annotation, "__origin__", None)
    if origin is not None and hasattr(annotation, "__args__"):
        # Annotated[X, Field(...)] -> use X
        if str(origin).endswith("Annotated"):
            return typing_args(annotation.__args__[0])
        return list(annotation.__args__)
    return []


def java_strict_parameters_switches() -> tuple[set[str], set[str]]:
    """Extract the tool codes handled by both strictParameters switches in Java."""
    source = (
        REPO_ROOT
        / "security-toolbox-server"
        / "src"
        / "main"
        / "java"
        / "com"
        / "bachelor"
        / "toolbox"
        / "ai"
        / "AiAgentRuntimeClient.java"
    ).read_text(encoding="utf-8")
    start = source.index("private Map<String, Object> strictParameters(")
    end = source.index("private Map<String, Object> strictMsfParameters(")
    body = source[start:end]
    keys_match = re.search(r"Set<String> allowed =\s*switch \(toolCode\) \{(.*?)\};", body, re.S)
    assert keys_match, "cannot locate allowed-keys switch in strictParameters"
    keys = set(re.findall(r'"([a-z_]+)"', keys_match.group(1)))
    values_start = body.index("switch (toolCode) {", body.index("Map<String, Object> result"))
    values_body = body[values_start:]
    values = set(re.findall(r'"([a-z_]+)"', values_body))
    return keys, values


def test_java_strict_parameters_covers_every_code() -> None:
    """The Java value-parsing switch must handle every tool the catalog offers.

    This is the exact drift that shipped site_crawl: whitelisted in the keys switch, missing
    from the value switch, so any plan proposing site_crawl died as "unknown tool".
    """
    keys, values = java_strict_parameters_switches()
    codes = set(java_runtime_codes())
    assert codes <= keys, f"missing from Java allowed-keys switch: {sorted(codes - keys)}"
    assert codes <= values, f"missing from Java value-parsing switch: {sorted(codes - values)}"
