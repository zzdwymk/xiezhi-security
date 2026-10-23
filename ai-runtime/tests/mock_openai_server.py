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
_SERVER_OUTPUT_CONTRACT_BLOCK = re.compile(
    r"BEGIN_SERVER_OUTPUT_CONTRACT\s*\r?\n.*?\r?\nEND_SERVER_OUTPUT_CONTRACT",
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
    # Identify the declared role, not downstream stages mentioned in its policy.
    # The evidence assessor also discusses the grounded planner in its prompt.
    role = system_text.strip().splitlines()[0] if system_text.strip() else ""
    if role.startswith("你是授权安全测试平台的会话摘要器。"):
        return "summary"
    if role.startswith("你是授权安全测试平台的 grounded planner。"):
        return "grounded"
    if role.startswith("你是证据充分性检查器。"):
        return "evidence"
    if role.startswith("你是授权安全测试平台的意图路由器。"):
        # An AUTO turn extends the same router prompt with executionDecision / planRelation.
        # The two contracts differ, so they must not share one canned answer.
        return "auto_intent" if "executionDecision" in system_text else "intent"
    return "legacy"


def _summary_response(text: str) -> dict[str, Any]:
    """Recognisable, deterministic digest so a UI test can assert compaction actually happened."""
    return {
        "userIntents": ["早前轮次要求对授权目标做端口与服务发现"],
        "completedChecks": ["TCP 端口探测：已发现开放端口"],
        "openFindings": ["待确认开放端口对应的服务指纹"],
        "pendingApprovals": [],
        "userConstraints": ["只测试当前授权目标"],
        "targetScope": "已授权目标的允许端口范围",
    }


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


def _without_server_output_contract(text: str) -> str:
    """Drop the server-owned output contract from classification input.

    The contract is trusted server text that legitimately enumerates every legal
    value of the stage it constrains. For the intent stage that list contains all
    four intent names, so matching them as though they were the user's request
    would route every single turn to PROJECT_QA and produce an empty plan.
    Only the markers are removed here; the surrounding request text is untouched.
    """
    return _SERVER_OUTPUT_CONTRACT_BLOCK.sub("[SERVER_OUTPUT_CONTRACT_REMOVED]", text)


def _current_request(text: str) -> str:
    cleaned = _without_server_output_contract(text)
    marker = "请路由下列对话："
    request = cleaned.rsplit(marker, 1)[-1].strip() if marker in cleaned else cleaned.strip()
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


def _auto_intent_response(text: str) -> dict[str, Any]:
    """AUTO turns extend the router contract with executionDecision and planRelation.

    The desktop app always runs AUTO, so a mock that only answers the legacy router shape makes
    every desktop turn fail at the route stage — which looks exactly like "the model is down".
    """
    decision = dict(_intent_response(text))
    intent = decision.get("intent")
    if intent == "ACTION_PLAN":
        decision["executionDecision"] = "EXECUTE"
        decision["planRelation"] = "NEW"
    else:
        decision["executionDecision"] = "CLARIFY" if intent == "CLARIFY" else "PLAN_ONLY"
        decision["planRelation"] = "NONE"
    return decision


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
            # A workflow may legitimately carry more than one Nmap node: a fast port-discovery
            # pass and a later service-identification pass. The mock answers with a service plan,
            # so it must target the node that actually performs service identification — pick a
            # nmap node that is not the quick/discovery pass, preferring the last such node.
            candidates = [
                node
                for node in nodes
                if isinstance(node, dict)
                and node.get("tool") == "nmap_service_scan"
                and isinstance(node.get("nodeId"), str)
            ]
            for node in reversed(candidates):
                params = node.get("parameters") if isinstance(node.get("parameters"), dict) else {}
                mode = str(params.get("mode") or "").strip().lower()
                if mode not in {"quick", "ping", "quick_trace"}:
                    return node["nodeId"]
            if candidates:
                return candidates[-1]["nodeId"]
    return "service-scan-01"


def _find_workflow_node(text: str, tool_name: str) -> str | None:
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
                    and node.get("tool") == tool_name
                    and isinstance(node.get("nodeId"), str)
                ):
                    return node["nodeId"]
    return None


def _requests_web_path_enumeration(text: str) -> bool:
    """True only when the operator asked for directory/path enumeration.

    The planner prompt is not just the operator's sentence: it also carries the
    authorization summary ("授权工具：...dir_scan, site_crawl..."), which names
    every permitted tool. Matching the raw prompt therefore let an enumeration
    tool answer "请扫描端口和服务" purely because the tool list mentioned it,
    which is exactly the prompt-fidelity failure a real model must not make.
    Only the current request line is classified.
    """
    match = re.search(r"currentUserRequest（本轮原句）：\s*\r?\n(?P<request>.*?)(?:\r?\n|$)", text)
    request = match.group("request") if match else text
    lowered = request.lower()
    return any(word in request for word in ("目录", "路径")) or "dir" in lowered


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
    dir_node = _find_workflow_node(text, "dir_scan")
    if dir_node and _requests_web_path_enumeration(trusted):
        return {
            "summary": "已根据项目证据生成授权目录枚举与路径扫描方案",
            "answer": "授权目录与路径扫描方案已准备就绪，使用内置 dirb-small 字典和 20 并发探测。",
            "intent": "plan",
            "knowledgeMode": "PROJECT_EVIDENCE",
            "evidenceRefs": refs,
            "actions": [
                {
                    "workflowNodeId": dir_node,
                    "parameters": {"concurrency": 20, "dictionary": "dirb-small"},
                    "evidenceRefs": refs,
                }
            ],
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
    if kind == "summary":
        return _summary_response(text)
    if kind == "auto_intent":
        return _auto_intent_response(_trusted_prompt_text(user_text))
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
