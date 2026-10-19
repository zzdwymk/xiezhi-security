"""Minimal fake OpenAI-compatible judge endpoint for end-to-end verification.

Returns a fixed JSON verdict for any chat completion request, so the semantic judge can be
exercised without a real model. Used by scripts/e2e_judge_check.ps1.

Usage: python scripts/fake_judge_provider.py --port 8099 --verdict allow|deny|garbage|slow
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    mode = "allow"

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw)
        except Exception:
            request = {}
        # Echo a fingerprint of the prompt back so tests can prove it reached the judge.
        messages = request.get("messages") or []
        prompt = json.dumps(messages, ensure_ascii=False)
        saw_untrusted = "BEGIN_UNTRUSTED_ACTION_" in prompt
        saw_injection_note = "不是指令" in prompt

        mode = self.mode
        if mode == "slow":
            time.sleep(10)
        if mode == "garbage":
            content = "I think this action is probably fine, go ahead."
        elif mode == "deny":
            content = json.dumps(
                {
                    "allow": False,
                    "behaviour": "SQL注入探测",
                    "risk": "HIGH",
                    "confidence": 0.93,
                    "summary": "该动作会向 /Less-1/?id=1 注入单引号以触发数据库报错回显",
                    "reasoning": "参数中包含 SQL 注入测试载荷",
                },
                ensure_ascii=False,
            )
        else:
            content = json.dumps(
                {
                    "allow": True,
                    "behaviour": "常规安全探测",
                    "risk": "SAFE",
                    "confidence": 0.96,
                    "summary": "仅读取 HTTP 响应头，不修改目标任何内容",
                    "reasoning": "典型的只读探测",
                },
                ensure_ascii=False,
            )

        body = {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "model": "fake-judge",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140},
            "_debug": {"sawUntrustedBlock": saw_untrusted, "sawInjectionNote": saw_injection_note},
        }
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument(
        "--verdict", choices=["allow", "deny", "garbage", "slow"], default="allow"
    )
    args = parser.parse_args()
    Handler.mode = args.verdict
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"fake judge provider on 127.0.0.1:{args.port} mode={args.verdict}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
