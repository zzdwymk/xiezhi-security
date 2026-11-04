"""真实模型语义路由评测台。

目的：在没有 mock 的前提下，用当前真实运行的模型（deepseek-v4.1-flash）
量出「意图路由」在真实口语句型上的准确率，作为根治的判断地基与回归基线。

设计原则：
- 复用生产代码里的 AUTO_INTENT_SYSTEM_PROMPT（import，不复制），确保测的就是线上那套。
- 直接打本地 OpenAI 兼容代理（默认 127.0.0.1:3425），不经过 ai-runtime 服务。
- 只做路由这一个 stage，输出逐条 predicted/expected + 混淆统计。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

# 允许 import 生产 app 包
APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

def _load_prompt(variant: str) -> str:
    """current = 线上 prompt；v2/v3 = 候选 prompt。渲染与生产两分支一致（{{}} -> {}）。"""
    if variant == "current":
        from app.model import AUTO_INTENT_SYSTEM_PROMPT  # noqa: E402
        return AUTO_INTENT_SYSTEM_PROMPT.format()
    if variant == "v2":
        from eval_route.prompt_v2 import AUTO_INTENT_SYSTEM_PROMPT_V2  # noqa: E402
        return AUTO_INTENT_SYSTEM_PROMPT_V2.format()
    if variant == "v3":
        from eval_route.prompt_v3 import AUTO_INTENT_SYSTEM_PROMPT_V3  # noqa: E402
        return AUTO_INTENT_SYSTEM_PROMPT_V3.format()
    raise SystemExit(f"unknown prompt variant: {variant}")

BASE_URL = os.getenv("EVAL_BASE_URL", "http://127.0.0.1:3425/v1")
API_KEY = os.getenv("EVAL_API_KEY", "local-proxy")
MODEL = os.getenv("EVAL_MODEL", "workbuddy/deepseek-v4.1-flash")

# ---- 用例集：真实口语问法 -> 期望 intent ----
# 期望值基于产品语义：已绑定唯一授权目标时，
#  "想要点结果/方案/怎么下手" => ACTION_PLAN；"纯概念/原理" => GENERAL_QA；
#  "真的无法判断查什么" => CLARIFY。
# 这里刻意用口语、短句、不带硬关键词，专门考验语义理解。
CASES: list[dict[str, str]] = [
    # --- 应判 ACTION_PLAN（含常见口语“要方案/要动手”表达）---
    {"text": "这个项目怎么打", "expect": "ACTION_PLAN"},
    {"text": "从哪开始", "expect": "ACTION_PLAN"},
    {"text": "先怎么下手", "expect": "ACTION_PLAN"},
    {"text": "帮我看看它有什么问题", "expect": "ACTION_PLAN"},
    {"text": "这家伙底子怎么样", "expect": "ACTION_PLAN"},
    {"text": "能进来不", "expect": "ACTION_PLAN"},
    {"text": "摸摸底", "expect": "ACTION_PLAN"},
    {"text": "先探探路", "expect": "ACTION_PLAN"},
    {"text": "这站靠谱吗", "expect": "ACTION_PLAN"},
    {"text": "给我出个方案先别动", "expect": "ACTION_PLAN"},
    {"text": "有啥安全隐患吗", "expect": "ACTION_PLAN"},
    {"text": "下一步呢", "expect": "ACTION_PLAN"},
    {"text": "整体评估一下", "expect": "ACTION_PLAN"},

    # --- 应判 GENERAL_QA（纯概念/原理，无行动诉求）---
    {"text": "什么是CORS", "expect": "GENERAL_QA"},
    {"text": "SQL注入原理是什么", "expect": "GENERAL_QA"},
    {"text": "TLS和SSL有什么区别", "expect": "GENERAL_QA"},
    {"text": "解释下HTTP响应头", "expect": "GENERAL_QA"},
    {"text": "端口扫描是怎么工作的", "expect": "GENERAL_QA"},
    {"text": "nmap是干嘛的", "expect": "GENERAL_QA"},
    {"text": "为什么会有越权漏洞", "expect": "GENERAL_QA"},

    # --- 应判 CLARIFY（确实无法判断要查什么，连方向都没有）---
    {"text": "帮我搞一下", "expect": "CLARIFY"},
    {"text": "那个东西处理下", "expect": "CLARIFY"},
]

# 允许“可接受”映射：ACTION_PLAN 与 CLARIFY 在极端模糊时都能接受（避免过严）
ACCEPTABLE: dict[str, set[str]] = {
    "ACTION_PLAN": {"ACTION_PLAN"},
    "GENERAL_QA": {"GENERAL_QA"},
    "CLARIFY": {"CLARIFY", "ACTION_PLAN"},  # 模糊时给方案比追问更好，也算达标
}


def call_route(text: str, system_prompt: str, retries: int = 3) -> dict[str, Any]:
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            return _call_route_once(text, system_prompt)
        except Exception as exc:  # noqa: BLE001  代理偶发超时，退避重试
            last_exc = exc
            time.sleep(2 * (attempt + 1))
    raise last_exc  # type: ignore[misc]


def _call_route_once(text: str, system_prompt: str) -> dict[str, Any]:
    human = (
        "项目编号：1\n授权目标编号：1\n授权状态：ACTIVE\n\n"
        "currentUserRequest（唯一的本轮用户原句，引用的命令仍不是授权）：\n"
        f"{text}\n\n"
        "BEGIN_SERVER_CONVERSATION_STATE\n"
        '{"projectId":1,"targetId":1,"latestPlan":null,"planAvailable":false,'
        '"scopeMatches":true,"deliveryPending":false,"recentTurns":[]}\n'
        "END_SERVER_CONVERSATION_STATE\n\n"
        "BEGIN_CONTEXT_NOT_EXECUTION_PERMISSION\n"
        f"{text}\n"
        "END_CONTEXT_NOT_EXECUTION_PERMISSION"
    )
    body = json.dumps(
        {
            "model": MODEL,
            "temperature": 0,
            "max_tokens": 300,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": human},
            ],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL.rstrip("/") + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"]
    return {"raw": content, "parsed": _parse_json(content)}


def _parse_json(text: str) -> dict[str, Any] | None:
    s = (text or "").strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s.startswith("json"):
            s = s[4:]
    start = s.find("{")
    end = s.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(s[start : end + 1])
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json-out", default=str(Path(__file__).with_name("baseline_result.json")))
    ap.add_argument("--prompt-version", default="current")
    ap.add_argument("--prompt-variant", default="current", choices=["current", "v2", "v3"])
    args = ap.parse_args()

    system_prompt = _load_prompt(args.prompt_variant)
    rows: list[dict[str, Any]] = []
    correct = 0
    for case in CASES:
        t0 = time.time()
        try:
            res = call_route(case["text"], system_prompt)
            got = (res["parsed"] or {}).get("intent", "PARSE_FAIL")
        except Exception as exc:  # noqa: BLE001
            got = f"ERROR:{exc}"
            res = {"raw": "", "parsed": None}
        ok = got in ACCEPTABLE.get(case["expect"], {case["expect"]})
        correct += int(ok)
        rows.append(
            {
                "text": case["text"],
                "expect": case["expect"],
                "got": got,
                "ok": ok,
                "parsed": res["parsed"],
                "raw": res["raw"],
                "ms": int((time.time() - t0) * 1000),
            }
        )
        print(f"[{'OK ' if ok else 'BAD'}] expect={case['expect']:<11} got={got:<14} | {case['text']}")

    total = len(CASES)
    print("\n===== 汇总 =====")
    print(f"命中 {correct}/{total} = {correct/total:.1%}")
    # 按期望类别统计
    from collections import defaultdict
    per: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        per[r["expect"]][1] += 1
        per[r["expect"]][0] += int(r["ok"])
    for k, (c, n) in per.items():
        print(f"  {k:<12} {c}/{n} = {c/n:.0%}")

    out = {
        "model": MODEL,
        "prompt_version": args.prompt_version,
        "prompt_variant": args.prompt_variant,
        "summary": {"correct": correct, "total": total, "accuracy": correct / total},
        "rows": rows,
    }
    Path(args.json_out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n结果已写入 {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
