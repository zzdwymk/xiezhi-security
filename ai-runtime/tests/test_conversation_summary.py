"""Conversation summary: structured要点, rendering, and merge on a second compaction.

The point of these tests is that compaction loses nothing the next turn still needs, and that
summarizing twice merges instead of discarding the earlier digest.
"""

from __future__ import annotations

from app.model import render_conversation_summary
from app.schemas import ConversationSummary


def test_summary_contract_rejects_extra_fields_and_enforces_bounds():
    # Unbounded lists would let a digest grow back into the problem it solves.
    field = ConversationSummary.model_fields["completedChecks"]
    assert field.metadata[0].max_length == 8
    assert ConversationSummary.model_config.get("extra") == "forbid"


def test_blank_entries_are_dropped():
    summary = ConversationSummary.model_validate(
        {
            "userIntents": ["  扫描端口  ", "", "   "],
            "completedChecks": ["nmap 完成"],
        }
    )
    assert summary.userIntents == ["扫描端口"]
    assert summary.completedChecks == ["nmap 完成"]


def test_render_skips_empty_sections():
    rendered = render_conversation_summary(
        {"userIntents": ["扫描端口"], "completedChecks": [], "openFindings": []}
    )
    assert "用户已明确的需求" in rendered
    assert "扫描端口" in rendered
    assert "已完成的检测及结果" not in rendered
    assert "尚未解决的发现" not in rendered


def test_render_of_an_empty_summary_is_empty():
    assert render_conversation_summary({}) == ""
    assert (
        render_conversation_summary(
            {"userIntents": [], "completedChecks": [], "openFindings": [],
             "pendingApprovals": [], "userConstraints": [], "targetScope": None}
        )
        == ""
    )


def test_render_includes_target_scope_when_present():
    rendered = render_conversation_summary(
        {"userIntents": ["扫描"], "targetScope": "192.168.1.10 端口 80,443"}
    )
    assert "授权目标范围：192.168.1.10 端口 80,443" in rendered


def test_render_carries_every_section():
    rendered = render_conversation_summary(
        {
            "userIntents": ["扫描端口"],
            "completedChecks": ["TCP 端口探测：开放 80,443"],
            "openFindings": ["/admin 可访问"],
            "pendingApprovals": ["sqlmap 方案待审批"],
            "userConstraints": ["只测内网"],
        }
    )
    for marker in (
        "用户已明确的需求",
        "已完成的检测及结果",
        "尚未解决的发现",
        "待审批或未派发的方案",
        "用户提出的约束",
        "TCP 端口探测：开放 80,443",
        "sqlmap 方案待审批",
        "只测内网",
    ):
        assert marker in rendered


def _merge(
    previous: dict[str, Any], fresh: dict[str, Any], *,
    max_intents: int = 8, max_checks: int = 8, max_findings: int = 8,
    max_approvals: int = 4, max_constraints: int = 6,
) -> dict[str, Any]:
    """Merge a fresh digest into an existing one, newest last, bounded."""
    from app.model import merge_conversation_summary

    return merge_conversation_summary(
        previous,
        fresh,
        max_intents=max_intents,
        max_checks=max_checks,
        max_findings=max_findings,
        max_approvals=max_approvals,
        max_constraints=max_constraints,
    )


def test_merge_keeps_old_entries_and_appends_new_ones():
    merged = _merge(
        {"userIntents": ["第一轮需求"], "completedChecks": ["端口探测完成"]},
        {"userIntents": ["第二轮需求"], "completedChecks": ["服务识别完成"]},
    )
    assert merged["userIntents"] == ["第一轮需求", "第二轮需求"]
    assert merged["completedChecks"] == ["端口探测完成", "服务识别完成"]


def test_merge_deduplicates_identical_entries():
    merged = _merge(
        {"userIntents": ["扫描端口"], "completedChecks": ["端口探测完成"]},
        {"userIntents": ["扫描端口"], "completedChecks": ["端口探测完成"]},
    )
    assert merged["userIntents"] == ["扫描端口"]
    assert merged["completedChecks"] == ["端口探测完成"]


def test_merge_drops_the_oldest_when_over_the_cap():
    previous = {"userIntents": [f"需求{i}" for i in range(8)]}
    merged = _merge(previous, {"userIntents": ["新需求"]})
    # The newest survives; the oldest is the one that falls off.
    assert merged["userIntents"][-1] == "新需求"
    assert merged["userIntents"][0] == "需求1"
    assert len(merged["userIntents"]) == 8


def test_merge_prefers_the_fresher_target_scope():
    merged = _merge(
        {"targetScope": "旧范围"},
        {"targetScope": "新范围"},
    )
    assert merged["targetScope"] == "新范围"


def test_merge_keeps_the_old_scope_when_the_fresh_one_is_absent():
    merged = _merge({"targetScope": "旧范围"}, {})
    assert merged["targetScope"] == "旧范围"
