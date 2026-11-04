"""语义路由准确率回归。

背景：AUTO 意图路由曾把"这个项目怎么打/从哪开始"等真实口语判成 GENERAL_QA/CLARIFY，
把用户引到"不能生成检测动作"的死胡同（生产事故级体验）。根因是路由 prompt 规则堆叠
无优先级 + 零口语样例，且"路由准确率"从未被度量（旧测试只用关键词 mock 验管道）。

本文件两层防线：
1. 离线回放（默认，CI 可跑、零网络）：校验 eval_route/results/ 下的真实模型录制结果
   全部命中期望并达到阈值——防止有人改动评测集/放宽判定后悄悄丢失准确率。
2. 在线实测（设置 AI_EVAL_LIVE=1 才运行）：用生产 AUTO_INTENT_SYSTEM_PROMPT 直连
   本地 OpenAI 兼容代理重新评测，断言召回与防误判阈值；供改 prompt/换模型时手动跑。

录制再生方式（在 ai-runtime/ 下）：
    python eval_route/harness.py --prompt-variant v3 --json-out eval_route/results/v3_main.json
    python -m eval_route.heldout v3 eval_route/results/v3_heldout.json
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = RUNTIME_ROOT / "eval_route" / "results"

# 准确率阈值：主集曾从 68.2% 修复到 100%，留出+负例集从 83.3% 修复到 100%。
# 阈值留出回归余量，低于阈值即认为路由智能退化。
MAIN_MIN_ACCURACY = 0.95
HELDOUT_MIN_ACCURACY = 0.90


def _load(name: str) -> dict:
    path = RESULTS_DIR / name
    if not path.exists():
        pytest.fail(
            f"缺少语义路由录制结果 {path}；请按本文件 docstring 的命令重新录制，"
            "不允许让路由准确率脱离度量。"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def test_recorded_main_set_meets_accuracy_threshold() -> None:
    data = _load("v3_main.json")
    rows = data["rows"]
    assert rows, "主集录制结果为空"
    assert data.get("variant", data.get("prompt_version")) == "v3"
    failed = [r for r in rows if not r["ok"]]
    accuracy = data["summary"]["correct"] / data["summary"]["total"]
    assert not failed, f"录制的主集存在未命中用例：{[(r['text'], r['expect'], r['got']) for r in failed]}"
    assert accuracy >= MAIN_MIN_ACCURACY


def test_recorded_heldout_and_negatives_meet_threshold() -> None:
    data = _load("v3_heldout.json")
    rows = data["rows"]
    assert rows, "留出集录制结果为空"
    # 负例（能力探询/寒暄）绝不允许误判成 ACTION_PLAN：宁可少答，不可乱动。
    capability_probes = [r for r in rows if r["text"] in {"你能扫描端口吗", "支不支持目录扫描", "能不能做漏洞扫描"}]
    assert capability_probes, "负例集缺失能力探询用例"
    misfired = [r for r in capability_probes if r["got"] == "ACTION_PLAN"]
    assert not misfired, f"能力探询被误判为行动：{[r['text'] for r in misfired]}"
    accuracy = data["summary"]["correct"] / data["summary"]["total"]
    assert accuracy >= HELDOUT_MIN_ACCURACY, f"留出+负例集准确率 {accuracy:.1%} 低于阈值"


def test_production_prompt_keeps_priority_chain_anchors() -> None:
    """防止未来改动悄悄拆掉裁决链的关键锚点。"""
    from app.model import AUTO_INTENT_SYSTEM_PROMPT

    required_anchors = (
        "【裁决链】",                      # 优先级裁决链本体
        "第1步 能力探询",                  # 能力探询先于行动咨询（防 v2 式误判回归）
        "第4步 行动咨询",                  # "怎么打/从哪开始"归行动咨询的核心修复
        "宁可先给一份待审批方案",          # 行动默认倾向
        '"你好" / "在吗" -> GENERAL_QA',   # 寒暄 few-shot
        "加上目录扫描",                    # 既有契约短语（测试/协议依赖）
        "不能复用旧方案的审批",
        "只改方案、先不执行时必须用PLAN_ONLY",
        "executionDecision",               # mock 服务端识别 AUTO 模式的标记
    )
    missing = [a for a in required_anchors if a not in AUTO_INTENT_SYSTEM_PROMPT]
    assert not missing, f"AUTO 路由 prompt 缺少裁决链锚点：{missing}"


@pytest.mark.skipif(
    os.getenv("AI_EVAL_LIVE") != "1",
    reason="在线实测需要本地模型代理；设置 AI_EVAL_LIVE=1 并确保代理可用后运行",
)
def test_live_route_accuracy_meets_thresholds() -> None:
    import sys

    sys.path.insert(0, str(RUNTIME_ROOT))
    from eval_route.harness import CASES, ACCEPTABLE, call_route, _load_prompt
    from eval_route.heldout import HELDOUT, _accepted

    system_prompt = _load_prompt("current")  # current = 生产 AUTO prompt（含裁决链）
    correct, total = 0, 0
    for case in CASES:
        got = (call_route(case["text"], system_prompt)["parsed"] or {}).get("intent", "PARSE_FAIL")
        ok = got in ACCEPTABLE.get(case["expect"], {case["expect"]})
        assert ok, f"主集未命中：{case['text']} 期望 {case['expect']} 实得 {got}"
        correct += int(ok)
        total += 1
    main_accuracy = correct / total
    assert main_accuracy >= MAIN_MIN_ACCURACY

    correct, total = 0, 0
    for case in HELDOUT:
        got = (call_route(case["text"], system_prompt)["parsed"] or {}).get("intent", "PARSE_FAIL")
        assert _accepted(case, got), f"留出集未命中：{case['text']} 期望 {case['expect']} 实得 {got}"
        correct += 1
        total += 1
    assert correct / total >= HELDOUT_MIN_ACCURACY
