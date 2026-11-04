"""留出集（held-out）：写 prompt 时未参考过的新句式，用来诚实检验 v2 是否泛化。

包含三类：
- 更多 ACTION_PLAN 口语（换说法）
- 更多 GENERAL_QA（必须不能误判成行动）
- 更多 CLARIFY（确实没方向）
- 关键负例：能力询问 / 假设 / 看结果 / 纯寒暄 —— 必须 NOT ACTION_PLAN
"""
from __future__ import annotations

from eval_route.harness import _load_prompt, call_route, ACCEPTABLE
import time

HELDOUT: list[dict[str, str]] = [
    # ACTION_PLAN（新说法）
    {"text": "这玩意儿稳不稳", "expect": "ACTION_PLAN"},
    {"text": "给我盘它", "expect": "ACTION_PLAN"},
    {"text": "先来一轮再说，别真扫", "expect": "ACTION_PLAN"},
    {"text": "你这能帮我把关口把一下吗", "expect": "ACTION_PLAN"},
    {"text": "看看还有啥没发现的", "expect": "ACTION_PLAN"},
    {"text": "帮我出个检查清单", "expect": "ACTION_PLAN"},
    # GENERAL_QA（概念，不能变行动）
    {"text": "越权是啥意思", "expect": "GENERAL_QA"},
    {"text": "为什么要把cookie设httponly", "expect": "GENERAL_QA"},
    {"text": "指纹识别靠什么原理", "expect": "GENERAL_QA"},
    {"text": "一个IP能有几个端口", "expect": "GENERAL_QA"},
    # CLARIFY（真的没方向）
    {"text": "弄一下", "expect": "CLARIFY"},
    {"text": "随便看看", "expect": "CLARIFY"},
    # 负例：这些不该是 ACTION_PLAN（能力询问/寒暄）
    {"text": "你能扫描端口吗", "expect": "GENERAL_QA"},          # 能力询问，只回答
    {"text": "你好", "expect": "GENERAL_QA"},                    # 寒暄
    {"text": "支不支持目录扫描", "expect": "GENERAL_QA"},        # 能力询问
    {"text": "能不能做漏洞扫描", "expect": "GENERAL_QA"},        # 能力询问
    # 查已有结果：应检索项目上下文回答（PROJECT_QA），不应凭空 GENERAL 回答
    {"text": "上次扫描结果怎么样", "expect": "PROJECT_QA"},
    {"text": "看看这轮发现了什么漏洞", "expect": "PROJECT_QA"},
]


ACCEPTABLE_OVERRIDE: dict[str, set[str]] = {
    # 边界句：既可视为"发动新探测"（ACTION_PLAN），也可视为"盘点已有发现"（PROJECT_QA）。
    # 两者都会检索并以有用回答收尾，不存在错误执行，故双接受。
    "看看还有啥没发现的": {"ACTION_PLAN", "PROJECT_QA"},
}


def _accepted(case: dict[str, str], got: str) -> bool:
    override = ACCEPTABLE_OVERRIDE.get(case["text"])
    if override:
        return got in override
    if case["expect"] == "PROJECT_QA":
        return got == "PROJECT_QA"
    return got in ACCEPTABLE.get(case["expect"], {case["expect"]})


def run(variant: str, json_out: str | None = None) -> None:
    system_prompt = _load_prompt(variant)
    correct = 0
    bad: list[str] = []
    rows = []
    for case in HELDOUT:
        res = call_route(case["text"], system_prompt)
        got = (res["parsed"] or {}).get("intent", "PARSE_FAIL")
        ok = _accepted(case, got)
        correct += int(ok)
        rows.append({"text": case["text"], "expect": case["expect"], "got": got, "ok": ok})
        if not ok:
            bad.append(f"  [BAD] expect={case['expect']:<11} got={got:<12} | {case['text']}")
        print(f"[{'OK ' if ok else 'BAD'}] expect={case['expect']:<11} got={got:<12} | {case['text']}")
    print(f"\n{variant}: {correct}/{len(HELDOUT)} = {correct/len(HELDOUT):.1%}")
    if bad:
        print("失败项：")
        print("\n".join(bad))
    if json_out:
        import json
        from pathlib import Path
        Path(json_out).write_text(
            json.dumps({"variant": variant, "summary": {"correct": correct, "total": len(HELDOUT)},
                        "rows": rows}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"结果已写入 {json_out}")


if __name__ == "__main__":
    import sys
    run(sys.argv[1] if len(sys.argv) > 1 else "v2",
        sys.argv[2] if len(sys.argv) > 2 else None)
