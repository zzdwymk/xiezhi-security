from __future__ import annotations

import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


PLAN = {
    "summary": "Mock LLM generated an authorized service scan plan",
    "answer": "The authorized port and service scan plan is ready.",
    "intent": "plan",
    "actions": [
        {
            "tool": "nmap_service_scan",
            "parameters": {"ports": "80,443", "mode": "service"},
            "risk": "CAUTION",
            "requiresApproval": False,
            "group": 0,
        }
    ],
}

MALICIOUS_MIXED_PLAN = {
    "summary": "A mixed plan that must be rejected as a whole",
    "answer": "This response must never reach task creation.",
    "intent": "plan",
    "actions": [
        {
            "tool": "nmap_service_scan",
            "parameters": {"ports": "80,443", "mode": "service"},
            "risk": "CAUTION",
            "requiresApproval": False,
            "group": 0,
        },
        {
            "tool": "shell_exec",
            "parameters": {"command": "whoami"},
            "risk": "SAFE",
            "requiresApproval": False,
            "group": 0,
        },
    ],
}


_EVIDENCE_BLOCK = re.compile(
    r"BEGIN_UNTRUSTED_EVIDENCE\s*\r?\n(?P<payload>.*?)\r?\nEND_UNTRUSTED_EVIDENCE",
    re.DOTALL,
)
_WORKFLOW_BLOCK = re.compile(
    r"BEGIN_SERVER_WORKFLOW_CAPABILITIES\s*\r?\n(?P<payload>.*?)\r?\nEND_SERVER_WORKFLOW_CAPABILITIES",
    re.DOTALL,
)
_REWRITE_ONCE_MARKERS = (
    "MOCK_REWRITE_ONCE",
    "MOCK_EVIDENCE_REWRITE",
    "REWRITE_QUERY_ONCE",
)
_TWO_ROUND_CLARIFY_MARKERS = (
    "MOCK_TWO_ROUND_CLARIFY",
    "MOCK_CLARIFY_AFTER_REWRITE",
)


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                value = block.get("text")
                if isinstance(value, str):
                    parts.append(value)
                elif isinstance(value, dict) and isinstance(value.get("value"), str):
                    parts.append(value["value"])
        return "\n".join(parts)
    return str(content)


def _message_text(messages: list[dict[str, Any]]) -> str:
    return "\n".join(_content_text(message.get("content", "")) for message in messages)


def _prompt_kind(messages: list[dict[str, Any]]) -> str:
    system_text = "\n".join(
        _content_text(message.get("content", ""))
        for message in messages
        if message.get("role") == "system"
    )
    lowered = system_text.lower()
    if "grounded planner" in lowered:
        return "grounded"
    if "证据充分性检查器" in system_text:
        return "evidence"
    if "意图路由器" in system_text:
        return "intent"
    return "legacy"


def _extract_evidence_bundle(text: str) -> dict[str, Any]:
    bundle: dict[str, Any] = {}
    for match in _EVIDENCE_BLOCK.finditer(text):
        try:
            candidate = json.loads(match.group("payload"))
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and isinstance(candidate.get("items"), list):
            bundle = candidate
    return bundle


def _trusted_prompt_text(text: str) -> str:
    blocks = list(_EVIDENCE_BLOCK.finditer(text))
    if not blocks:
        return text
    prefix = text[: blocks[-1].start()]
    return _EVIDENCE_BLOCK.sub("[UNTRUSTED_EVIDENCE_REMOVED]", prefix)


def _evidence_refs(bundle: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in bundle.get("items", []):
        if not isinstance(item, dict):
            continue
        evidence_id = item.get("evidenceId")
        if isinstance(evidence_id, str) and evidence_id and evidence_id not in refs:
            refs.append(evidence_id)
    return refs[:10]


def _contains_marker(text: str, markers: tuple[str, ...]) -> bool:
    upper = text.upper()
    return any(marker in upper for marker in markers)


def _current_request(text: str) -> str:
    marker = "请路由下列对话："
    request = text.rsplit(marker, 1)[-1].strip() if marker in text else text.strip()
    return request[:2000] or "用户请求"


def _intent_response(text: str) -> dict[str, Any]:
    request = _current_request(text)
    upper = request.upper()
    action_words = ("扫描", "探测", "检测", "审计", "执行", "SCAN")
    question_words = ("什么", "为何", "为什么", "如何", "哪些", "多少", "吗", "?")

    if "MOCK_INTENT_CLARIFY" in upper or "CLARIFY_REQUEST" in upper:
        return {
            "intent": "CLARIFY",
            "needsRetrieval": False,
            "publicReasonCode": "AMBIGUOUS_REQUEST",
        }
    if "MOCK_PROJECT_QA" in upper or "PROJECT_QA" in upper or (
        "项目" in request
        and any(word in request for word in question_words)
        and not any(word in request for word in action_words)
    ):
        return {
            "intent": "PROJECT_QA",
            "needsRetrieval": True,
            "retrievalQuery": request,
            "publicReasonCode": "PROJECT_CONTEXT_REQUIRED",
        }
    if "MOCK_GENERAL_QA" in upper or "GENERAL_QA" in upper or (
        any(word in request for word in question_words)
        and "项目" not in request
        and not any(word in request for word in action_words)
    ):
        return {
            "intent": "GENERAL_QA",
            "needsRetrieval": False,
            "publicReasonCode": "GENERAL_KNOWLEDGE",
        }
    return {
        "intent": "ACTION_PLAN",
        "needsRetrieval": True,
        "retrievalQuery": request,
        "publicReasonCode": "AUTHORIZED_ACTION_REQUEST",
    }


def _retrieval_round(text: str, bundle: dict[str, Any]) -> int:
    value = bundle.get("round")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    match = re.search(r"检索轮次：\s*(\d+)", _trusted_prompt_text(text))
    return int(match.group(1)) if match else 0


def _evidence_response(text: str, bundle: dict[str, Any]) -> dict[str, Any]:
    trusted = _trusted_prompt_text(text)
    refs = _evidence_refs(bundle)
    round_number = _retrieval_round(text, bundle)

    if "MOCK_EVIDENCE_CLARIFY" in trusted.upper():
        return {
            "decision": "CLARIFY",
            "reasonCodes": ["NO_RELEVANT_EVIDENCE"],
            "evidenceRefs": [],
        }
    if _contains_marker(trusted, _TWO_ROUND_CLARIFY_MARKERS):
        if round_number == 0:
            return {
                "decision": "REWRITE_QUERY",
                "reasonCodes": ["PARTIAL_SUPPORT"],
                "evidenceRefs": [],
                "rewrittenQuery": "改写查询",
            }
        return {
            "decision": "CLARIFY",
            "reasonCodes": ["NO_RELEVANT_EVIDENCE"],
            "evidenceRefs": [],
        }
    if _contains_marker(trusted, _REWRITE_ONCE_MARKERS) and round_number == 0:
        return {
            "decision": "REWRITE_QUERY",
            "reasonCodes": ["PARTIAL_SUPPORT"],
            "evidenceRefs": [],
            "rewrittenQuery": "改写查询",
        }
    if refs:
        return {
            "decision": "FINALIZE",
            "reasonCodes": ["DIRECT_SUPPORT"],
            "evidenceRefs": refs,
        }
    return {
        "decision": "CLARIFY",
        "reasonCodes": ["NO_RELEVANT_EVIDENCE"],
        "evidenceRefs": [],
    }


def _route_intent(text: str) -> str:
    trusted = _trusted_prompt_text(text)
    match = re.search(r"路由决定：\s*(\{[^\r\n]*\})", trusted)
    if match:
        try:
            decision = json.loads(match.group(1))
        except json.JSONDecodeError:
            decision = {}
        intent = decision.get("intent") if isinstance(decision, dict) else None
        if isinstance(intent, str):
            return intent
    return "ACTION_PLAN"


def _workflow_node_id(text: str) -> str:
    match = _WORKFLOW_BLOCK.search(text)
    if match:
        try:
            manifest = json.loads(match.group("payload"))
        except json.JSONDecodeError:
            manifest = {}
        nodes = manifest.get("nodes") if isinstance(manifest, dict) else None
        if isinstance(nodes, list):
            for node in nodes:
                if (
                    isinstance(node, dict)
                    and node.get("tool") == "nmap_service_scan"
                    and isinstance(node.get("nodeId"), str)
                ):
                    return node["nodeId"]
    return "service-scan-01"


def _grounded_response(text: str, bundle: dict[str, Any]) -> dict[str, Any]:
    trusted = _trusted_prompt_text(text)
    refs = _evidence_refs(bundle)
    intent = _route_intent(text)

    if intent == "GENERAL_QA":
        return {
            "summary": "通用问题回答",
            "answer": "这是不依赖项目资料的通用回答。",
            "intent": "answer",
            "knowledgeMode": "GENERAL",
            "evidenceRefs": [],
            "actions": [],
        }
    if "MALICIOUS_MIXED_PLAN" in trusted.upper():
        return MALICIOUS_MIXED_PLAN
    if not refs or intent == "CLARIFY":
        return {
            "summary": "需要补充证据",
            "answer": "当前证据不足，请补充项目资料后重试。",
            "intent": "clarify",
            "knowledgeMode": "INSUFFICIENT_EVIDENCE",
            "evidenceRefs": [],
            "actions": [],
        }
    if intent == "PROJECT_QA":
        return {
            "summary": "已根据项目证据回答",
            "answer": "回答仅依据当前检索到的项目证据。",
            "intent": "answer",
            "knowledgeMode": "PROJECT_EVIDENCE",
            "evidenceRefs": refs,
            "actions": [],
        }
    return {
        "summary": "已根据项目证据生成授权服务扫描计划",
        "answer": "授权端口和服务扫描计划已准备。",
        "intent": "plan",
        "knowledgeMode": "PROJECT_EVIDENCE",
        "evidenceRefs": refs,
        "actions": [
            {
                "workflowNodeId": _workflow_node_id(text),
                "parameters": {"ports": "80,443", "mode": "service"},
                "evidenceRefs": refs,
            }
        ],
    }


def _select_response(messages: list[dict[str, Any]]) -> dict[str, Any]:
    kind = _prompt_kind(messages)
    text = _message_text(messages)
    user_text = "\n".join(
        _content_text(message.get("content", ""))
        for message in messages
        if message.get("role") != "system"
    )
    if kind == "intent":
        return _intent_response(_trusted_prompt_text(user_text))
    bundle = _extract_evidence_bundle(text)
    if kind == "evidence":
        return _evidence_response(text, bundle)
    if kind == "grounded":
        return _grounded_response(text, bundle)
    trusted = _trusted_prompt_text(text)
    return MALICIOUS_MIXED_PLAN if "MALICIOUS_MIXED_PLAN" in trusted else PLAN


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"status": "UP"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._json(404, {"error": "not found"})
            return
        expected_auth = f"Bearer {self.server.api_key}"
        if self.headers.get("Authorization") != expected_auth:
            self._json(401, {"error": "invalid authorization header"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            self._json(413, {"error": "request too large"})
            return
        try:
            request = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "invalid JSON body"})
            return
        messages = request.get("messages")
        if request.get("model") != self.server.model:
            self._json(400, {"error": "unexpected model"})
            return
        if not isinstance(messages, list) or not messages:
            self._json(400, {"error": "messages are required"})
            return
        if not all(
            isinstance(message, dict)
            and message.get("role") in {"system", "user", "assistant", "tool"}
            and "content" in message
            for message in messages
        ):
            self._json(400, {"error": "invalid messages"})
            return
        response_payload = _select_response(messages)
        self._json(
            200,
            {
                "id": "chatcmpl-harness-e2e",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": self.server.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                response_payload,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            ),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            },
        )

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--api-key", default="mock-key")
    parser.add_argument("--model", default="mock-harness-model")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.api_key = args.api_key
    server.model = args.model
    server.serve_forever()


if __name__ == "__main__":
    main()
