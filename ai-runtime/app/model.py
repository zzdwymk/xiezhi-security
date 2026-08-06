from __future__ import annotations

import json
import re
from typing import Any

from .config import settings

try:
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI

    LANGCHAIN_AVAILABLE = True
except Exception:  # pragma: no cover - dependency diagnostic is exposed by /health
    ChatPromptTemplate = None  # type: ignore[assignment]
    ChatOpenAI = None  # type: ignore[assignment]
    LANGCHAIN_AVAILABLE = False


SAFE_TOOLS = {
    "retrieve_project_context",
    "nmap_service_scan",
    "tcp_ports",
    "http_headers",
    "http_security_check",
    "tls_config",
    "nuclei_scan",
}
HIGH_RISK_TOOLS = {
    "password_audit",
    "post_exploitation",
    "privilege_escalation",
    "lateral_movement",
    "persistence_validation",
    "exploit_validation",
}


def _last_user_message(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return str(message.get("content", ""))
    return str(messages[-1].get("content", "")) if messages else ""


def _json_from_text(text: str) -> dict[str, Any] | None:
    text = text.strip()
    candidates = [text]
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.I | re.S)
    if fenced:
        candidates.insert(0, fenced.group(1))
    object_match = re.search(r"\{.*\}", text, flags=re.S)
    if object_match:
        candidates.append(object_match.group(0))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            continue
    return None


def _message_text(content: Any) -> str:
    """Normalize LangChain 1.x string or content-block model responses."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
            elif isinstance(text, dict) and isinstance(text.get("value"), str):
                parts.append(text["value"])
        return "\n".join(parts)
    return str(content)


class AgentPlanner:
    """LLM-first intent planner."""

    def __init__(self, index_store: Any) -> None:
        self.index_store = index_store
        self._model = None
        self._planner_chain = None
        if settings.llm_enabled and settings.api_key and LANGCHAIN_AVAILABLE:
            try:
                self._model = ChatOpenAI(
                    model=settings.model,
                    api_key=settings.api_key,
                    base_url=settings.base_url,
                    timeout=settings.llm_timeout_seconds,
                    max_retries=1,
                    temperature=0,
                )
                prompt = ChatPromptTemplate.from_messages(
                    [
                        ("system", SYSTEM_PROMPT),
                        ("human", HUMAN_PROMPT),
                    ]
                )
                self._planner_chain = prompt | self._model
            except Exception:
                self._model = None
                self._planner_chain = None

    @property
    def status(self) -> dict[str, Any]:
        return {
            "langchainAvailable": LANGCHAIN_AVAILABLE,
            "llmConfigured": self._planner_chain is not None,
            "model": (
                settings.model
                if self._planner_chain is not None
                else "local-rule-redteam-orchestrator"
            ),
            "intentMode": (
                "llm" if self._planner_chain is not None else "heuristic-fallback"
            ),
        }

    async def plan(self, request: dict[str, Any]) -> dict[str, Any]:
        messages = request.get("messages", [])
        user_message = _last_user_message(messages)
        current_request = _current_request(user_message)
        workflow = request.get("workflow") or []
        auth = (
            request.get("authorization")
            if isinstance(request.get("authorization"), dict)
            else {}
        )
        allowed_tools = ",".join(str(t) for t in auth.get("allowedTools", []) if t) or (
            "retrieve_project_context,nmap_service_scan,tcp_ports,http_headers,http_security_check,tls_config,nuclei_scan"
        )
        conversation = _format_conversation_for_model(messages, user_message)

        if self._planner_chain is not None:
            try:
                response = await self._planner_chain.ainvoke(
                    {
                        "project_id": request.get("projectId"),
                        "target_id": request.get("targetId") or "",
                        "allowed_tools": allowed_tools,
                        "allowed_ports": auth.get("allowedPorts") or "",
                        "auth_status": auth.get("status") or "",
                        "message": conversation[:20_000],
                    }
                )
                parsed = _json_from_text(
                    _message_text(getattr(response, "content", response))
                )
                if parsed is not None:
                    return self._finalize_model_plan(parsed, user_message, workflow)
            except Exception:
                fallback = self._heuristic_plan(
                    request, current_request, user_message, workflow
                )
                fallback["modelWarning"] = "模型服务不可用，已切换本地规则规划"
                return fallback
            fallback = self._heuristic_plan(
                request, current_request, user_message, workflow
            )
            fallback["modelWarning"] = "模型输出无法解析，已切换本地规则规划"
            return fallback

        return self._heuristic_plan(request, current_request, user_message, workflow)

    def _finalize_model_plan(
        self, parsed: dict[str, Any], user_message: str, workflow: list[dict[str, Any]]
    ) -> dict[str, Any]:
        normalized = self._normalize(parsed, user_message)
        normalized["source"] = "langchain"
        if normalized.get("actions"):
            normalized["intent"] = "plan"
            if workflow:
                refined = self._workflow_plan(workflow, user_message)
                refined["source"] = "langchain+workflow"
                refined["answer"] = normalized.get("answer") or refined.get("answer")
                refined["summary"] = normalized.get("summary") or refined.get("summary")
                return refined
            return normalized
        intent = str(
            parsed.get("intent") or normalized.get("intent") or "answer"
        ).lower()
        normalized["actions"] = []
        normalized["intent"] = intent if intent in {"answer", "clarify"} else "answer"
        if not str(normalized.get("answer") or "").strip():
            normalized["answer"] = "我已理解你的请求。"
        return normalized

    def _heuristic_plan(
        self,
        request: dict[str, Any],
        current_request: str,
        user_message: str,
        workflow: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not _wants_execution(current_request, user_message):
            return self._local_answer(request, current_request)
        if workflow:
            return self._workflow_plan(workflow, user_message)
        return self._local_plan(current_request)

    def _local_answer(self, request: dict[str, Any], message: str) -> dict[str, Any]:
        lowered = message.lower()
        if any(
            token in lowered
            for token in (
                "介绍一下项目",
                "介绍项目",
                "当前项目",
                "项目概况",
                "项目情况",
            )
        ):
            references = self.index_store.query(
                int(request.get("projectId", 0) or 0), "项目授权目标任务漏洞", 5
            )
            details = ""
            if references:
                details = "\n\n已读取项目资料：\n" + "\n".join(
                    f"- {item.get('title', '项目资料')}：{str(item.get('text', ''))[:600]}"
                    for item in references[:5]
                )
            answer = (
                "这是獬豸授权安全测试平台中的安全评估项目。项目用于集中管理授权范围、目标、检测任务、漏洞与复测记录、审批审计以及项目总结报告。"
                + details
            )
        elif any(
            token in lowered
            for token in ("有哪些功能", "能做什么", "程序功能", "怎么使用", "如何使用")
        ):
            answer = "獬豸支持项目管理、信息收集、探测服务、工作流、主动检测、任务控制、结果复核、报告、流量与审计。直接说要扫描/检查什么即可。"
        elif any(
            token in lowered
            for token in ("怎么扫描", "如何扫描", "怎么检测", "如何检测", "可以扫描吗")
        ):
            answer = "直接说要做什么即可，例如“扫端口”“漏扫一下”“检查 HTTP 头”。我会理解意图并在授权范围内生成受控任务。"
        elif any(token in lowered for token in ("你好", "您好", "hello", "hi", "嗨")):
            answer = "你好！我是安全助手。可以直接问功能，或直接说要扫描/检查的内容。"
        elif any(token in lowered for token in ("项目报告", "pdf报告", "报告怎么导出")):
            answer = "请进入“评估项目”→项目详情→“项目报告”生成 PDF。"
        elif any(
            token in lowered for token in ("新建项目", "创建项目", "评估项目在哪里")
        ):
            answer = "请打开左侧“评估项目”，点击“新建评估项目”。"
        else:
            answer = "我先按咨询理解了你的问题。若要实际检测，直接说动作即可（例如“对当前目标漏扫”“扫端口”）。"
        return {
            "summary": answer[:1000],
            "answer": answer[:20_000],
            "actions": [],
            "source": "local-answer",
            "intent": "answer",
        }

    def _normalize(self, candidate: dict[str, Any], message: str) -> dict[str, Any]:
        raw_actions = candidate.get("actions", [])
        actions: list[dict[str, Any]] = []
        if isinstance(raw_actions, list):
            for raw in raw_actions[:8]:
                if not isinstance(raw, dict):
                    continue
                tool = str(raw.get("tool", "")).strip()
                if tool not in SAFE_TOOLS | HIGH_RISK_TOOLS:
                    continue
                parameters = (
                    raw.get("parameters")
                    if isinstance(raw.get("parameters"), dict)
                    else {}
                )
                risk = str(raw.get("risk", "SAFE")).upper()
                if risk not in {"SAFE", "CAUTION", "HIGH"}:
                    risk = "CAUTION"
                actions.append(
                    {
                        "tool": tool,
                        "parameters": {
                            str(k)[:80]: str(v)[:500] for k, v in parameters.items()
                        },
                        "risk": risk,
                        "requiresApproval": bool(
                            raw.get(
                                "requires_approval", raw.get("requiresApproval", False)
                            )
                        )
                        or tool in HIGH_RISK_TOOLS,
                    }
                )
        intent = str(candidate.get("intent", "")).strip().lower()
        if actions:
            intent = "plan"
        elif intent not in {"answer", "clarify", "plan"}:
            intent = "answer"
        answer = str(candidate.get("answer") or candidate.get("summary") or "").strip()
        if not answer:
            answer = (
                "已根据当前对话完成意图理解。"
                if not actions
                else "已根据你的意图生成受控检测计划。"
            )
        return {
            "summary": str(candidate.get("summary") or answer)[:1000],
            "answer": answer[:20_000],
            "actions": actions,
            "intent": intent,
            "source": "langchain",
        }

    def _workflow_plan(
        self, workflow: list[dict[str, Any]], message: str
    ) -> dict[str, Any]:
        allowed = SAFE_TOOLS | HIGH_RISK_TOOLS
        actions: list[dict[str, Any]] = []
        for step in workflow[:16]:
            if not isinstance(step, dict):
                continue
            tool = str(step.get("tool", "")).strip()
            if tool not in allowed:
                continue
            parameters = (
                step.get("parameters")
                if isinstance(step.get("parameters"), dict)
                else {}
            )
            risk = str(step.get("risk", "SAFE")).upper()
            if risk not in {"SAFE", "CAUTION", "HIGH"}:
                risk = "CAUTION"
            actions.append(
                {
                    "tool": tool,
                    "parameters": {
                        str(k)[:80]: str(v)[:500] for k, v in parameters.items()
                    },
                    "risk": risk,
                    "requiresApproval": bool(
                        step.get(
                            "requiresApproval", step.get("requires_approval", False)
                        )
                    )
                    or tool in HIGH_RISK_TOOLS,
                    "group": int(step.get("group", 0) or 0),
                }
            )
        if not actions:
            return self._local_plan(message)
        return {
            "summary": "已按你的执行意图激活当前红队工作流",
            "answer": "已理解你要执行检测。将按工作流在授权范围内推进，具体命令仍由受控执行边界二次校验。",
            "actions": actions[:8],
            "source": "workflow",
            "intent": "plan",
        }

    def _local_plan(self, message: str) -> dict[str, Any]:
        lowered = message.lower()
        actions: list[dict[str, Any]] = []
        broad = any(marker in lowered for marker in _BROAD_SCAN) or any(
            marker in lowered
            for marker in ("扫描啊", "扫吧", "开始扫描", "全面", "综合", "都扫")
        )
        wants_vuln = any(
            k in lowered
            for k in ("漏洞扫描", "漏扫", "nuclei", "漏洞检测", "扫漏洞", "通用漏洞")
        )
        wants_port = any(
            k in lowered for k in ("端口", "服务", "存活", "nmap", "扫端口", "资产")
        )
        wants_http = any(
            k in lowered for k in ("http", "请求头", "指纹", "header", "cors", "cookie")
        )
        wants_tls = any(k in lowered for k in ("tls", "证书", "加密", "https"))
        wants_context = any(k in lowered for k in ("总结", "资料", "项目情况", "报告"))
        if wants_context and not (
            wants_vuln or wants_port or wants_http or wants_tls or broad
        ):
            actions.append(
                {
                    "tool": "retrieve_project_context",
                    "parameters": {"query": message[:1000]},
                    "risk": "SAFE",
                    "requiresApproval": False,
                }
            )
        if wants_port or broad:
            actions.append(
                {
                    "tool": "nmap_service_scan",
                    "parameters": {},
                    "risk": "SAFE",
                    "requiresApproval": False,
                }
            )
        if wants_http or broad:
            actions.append(
                {
                    "tool": "http_headers",
                    "parameters": {},
                    "risk": "SAFE",
                    "requiresApproval": False,
                }
            )
            actions.append(
                {
                    "tool": "http_security_check",
                    "parameters": {"check": "disclosure"},
                    "risk": "SAFE",
                    "requiresApproval": False,
                }
            )
        if wants_tls or broad:
            actions.append(
                {
                    "tool": "tls_config",
                    "parameters": {},
                    "risk": "SAFE",
                    "requiresApproval": False,
                }
            )
        if wants_vuln or broad:
            actions.append(
                {
                    "tool": "nuclei_scan",
                    "parameters": {"templates": "approved-safe"},
                    "risk": "CAUTION",
                    "requiresApproval": False,
                }
            )
        if any(
            k in lowered
            for k in (
                "爆破",
                "密码破解",
                "提权",
                "后渗透",
                "横向",
                "持久化",
                "利用漏洞",
                "反弹 shell",
                "hash",
            )
        ):
            actions.append(
                {
                    "tool": "exploit_validation",
                    "parameters": {"intent": "人工审批后验证"},
                    "risk": "HIGH",
                    "requiresApproval": True,
                }
            )
        if not actions:
            actions = [
                {
                    "tool": "nmap_service_scan",
                    "parameters": {},
                    "risk": "SAFE",
                    "requiresApproval": False,
                },
                {
                    "tool": "http_headers",
                    "parameters": {},
                    "risk": "SAFE",
                    "requiresApproval": False,
                },
            ]
        deduped: list[dict[str, Any]] = []
        seen: set[str] = set()
        for action in actions:
            tool = str(action.get("tool", ""))
            if tool in seen:
                continue
            seen.add(tool)
            deduped.append(action)
        return {
            "summary": "已根据你的扫描意图生成受控检测计划",
            "answer": "已识别到执行意图。将在当前授权目标范围内派发低风险检测步骤；具体命令由授权执行器二次校验后创建任务。",
            "actions": deduped[:8],
            "source": "local-rules",
            "intent": "plan",
        }


SYSTEM_PROMPT = (
    "你是授权安全测试平台的智能安全助手与红队行动编排器。只输出 JSON，不要输出隐藏思维链。\n\n"
    "核心原则：理解用户自然语言意图，不要做关键词表匹配。\n"
    "1. 结合完整对话（历史 + 当前请求 + 短确认）判断用户现在要什么。\n"
    "2. 执行意图（扫描/漏扫/探测/检查/审计，含口语）→ intent=plan，生成 actions，answer 一句话确认目标。\n"
    "3. 问答/解释/找页面/看结果/闲聊 → intent=answer 或 clarify，actions 必须为 []。\n"
    "4. 意图含糊时先用上下文推断；仍不够再 clarify。不要把明确执行请求误判成咨询。\n"
    "5. “能扫的都扫”→ 按白名单组合低风险工具。\n\n"
    "安全边界：只能使用白名单工具；高风险仅 requires_approval=true；禁止 shell/利用/爆破命令。\n"
    "白名单：retrieve_project_context, nmap_service_scan, tcp_ports, http_headers, http_security_check, tls_config, nuclei_scan\n\n"
    'JSON：{"summary":string,"answer":string,"intent":"answer|plan|clarify","actions":[{"tool":string,"parameters":object,"risk":"SAFE|CAUTION|HIGH","requires_approval":boolean}]}'
)

HUMAN_PROMPT = (
    "项目编号：{project_id}\n授权目标编号：{target_id}\n授权状态：{auth_status}\n"
    "授权允许工具：{allowed_tools}\n授权端口：{allowed_ports}\n\n"
    "请理解下列对话，并决定本轮是回答还是执行：\n{message}"
)


def _format_conversation_for_model(
    messages: list[dict[str, Any]], fallback_user_message: str
) -> str:
    if (
        "当前请求：" in fallback_user_message
        or "服务端授权上下文：" in fallback_user_message
    ):
        return fallback_user_message[:20_000]
    lines: list[str] = []
    for message in messages[-12:]:
        role = str(message.get("role", "")).lower()
        content = str(message.get("content", "")).strip()
        if not content:
            continue
        if role == "system":
            lines.append(f"[系统/授权上下文]\n{content[:4000]}")
        elif role == "assistant":
            lines.append(f"助手：{content[:4000]}")
        else:
            lines.append(f"用户：{content[:4000]}")
    if not lines:
        return f"当前请求：{_current_request(fallback_user_message)}"
    current = _current_request(fallback_user_message)
    if current and (not lines or f"用户：{current}" not in lines[-1]):
        lines.append(f"当前请求：{current}")
    return "\n\n".join(lines)[:20_000]


def _current_request(message: str) -> str:
    value = str(message or "").strip()
    marker = "当前请求："
    if marker in value:
        value = value.rsplit(marker, 1)[1].strip()
    for marker in ("\n\n服务端授权上下文：", "\n以下是服务端重新查询", "\n[功能引用："):
        if marker in value:
            value = value.split(marker, 1)[0].strip()
    return value


def _conversation_history(message: str) -> str:
    value = str(message or "")
    marker = "当前请求："
    if marker in value:
        return value.rsplit(marker, 1)[0]
    return ""


_QUESTION_MARKERS = (
    "什么是",
    "是什么意思",
    "为什么",
    "介绍",
    "解释",
    "区别",
    "原理",
    "算漏洞吗",
    "是否算",
    "怎么使用",
    "如何使用",
    "怎么扫描",
    "如何扫描",
    "怎么检测",
    "如何检测",
    "怎么检查",
    "如何检查",
    "可以扫描吗",
    "可以检测吗",
    "在哪里",
    "怎么用",
)

_EXECUTION_PHRASES = (
    "请扫描",
    "帮我扫描",
    "开始扫描",
    "执行扫描",
    "立即扫描",
    "重新扫描",
    "扫描一下",
    "扫一下",
    "进行扫描",
    "进行漏扫",
    "漏扫一下",
    "做个扫描",
    "做下扫描",
    "发起扫描",
    "启动扫描",
    "请检测",
    "帮我检测",
    "开始检测",
    "执行检测",
    "重新检测",
    "检测一下",
    "测一下",
    "请检查",
    "帮我检查",
    "开始检查",
    "执行检查",
    "检查一下",
    "查一下",
    "请探测",
    "帮我探测",
    "开始探测",
    "执行探测",
    "探测一下",
    "运行工具",
    "执行工具",
    "运行扫描",
    "执行任务",
    "扫描端口",
    "端口扫描",
    "漏洞扫描",
    "漏扫",
    "服务扫描",
    "全端口",
    "探测端口",
    "探测服务",
    "识别服务",
    "服务版本",
    "端口和服务",
    "进行后渗透",
    "提权验证",
    "扫端口",
    "扫服务",
    "扫漏洞",
    "nmap",
    "nuclei",
    "scan ",
    "run scan",
    "start scan",
    "execute scan",
)

_ACTION_VERBS = (
    "扫描",
    "漏扫",
    "探测",
    "检测",
    "检查",
    "审计",
    "扫一扫",
    "scan",
    "probe",
    "audit",
)

_AFFIRMATIONS = (
    "授权了",
    "已授权",
    "确认执行",
    "确认",
    "开始吧",
    "开始",
    "执行吧",
    "执行",
    "扫吧",
    "扫描啊",
    "扫啊",
    "好的",
    "可以",
    "行",
    "ok",
    "okay",
    "yes",
    "继续",
    "就扫",
    "快扫",
)

_BROAD_SCAN = (
    "有什么功能就扫描",
    "有什么就扫",
    "能扫的都扫",
    "全部扫描",
    "全面扫描",
    "都扫一遍",
    "该扫的都扫",
    "随便扫",
    "尽量扫",
    "全做一遍",
    "综合扫描",
    "全面检查",
    "全面检测",
)


def _is_pure_question(message: str) -> bool:
    lowered = str(message or "").lower().strip()
    if not lowered:
        return False
    # Strong imperatives always win over a question-shaped sentence.
    strong = (
        "请扫描",
        "帮我扫描",
        "开始扫描",
        "执行扫描",
        "立即扫描",
        "扫描一下",
        "扫一下",
        "请检测",
        "帮我检测",
        "开始检测",
        "执行检测",
        "请检查",
        "帮我检查",
        "请探测",
        "开始探测",
        "漏扫一下",
        "进行漏扫",
        "授权了",
        "确认执行",
    )
    if any(marker in lowered for marker in strong) or any(
        marker in lowered for marker in _BROAD_SCAN
    ):
        return False
    if any(marker in lowered for marker in _QUESTION_MARKERS):
        return True
    if any(
        marker in lowered
        for marker in ("有哪些功能", "能做什么", "程序功能", "怎么使用", "如何使用")
    ):
        return True
    return False


def _history_implies_execution(history: str) -> bool:
    text = str(history or "").lower()
    if not text:
        return False
    return any(
        marker in text for marker in _EXECUTION_PHRASES + _ACTION_VERBS + _BROAD_SCAN
    )


def _explicit_execution_request(message: str, full_message: str | None = None) -> bool:
    return _wants_execution(message, full_message)


def _wants_execution(message: str, full_message: str | None = None) -> bool:
    current = _current_request(message).strip()
    lowered = current.lower()
    if not lowered:
        return False
    if _is_pure_question(lowered):
        return False
    if any(marker in lowered for marker in _EXECUTION_PHRASES):
        return True
    if any(marker in lowered for marker in _BROAD_SCAN):
        return True
    if any(verb in lowered for verb in _ACTION_VERBS):
        return True
    compact = "".join(lowered.split())
    affirmation_hit = compact in {
        "".join(item.split()) for item in _AFFIRMATIONS
    } or any(
        token in compact
        for token in (
            "授权了",
            "已授权",
            "确认执行",
            "开始吧",
            "执行吧",
            "扫吧",
            "扫描啊",
        )
    )
    if affirmation_hit:
        history = _conversation_history(full_message or message)
        if _history_implies_execution(history):
            return True
        if any(
            token in compact for token in ("授权", "确认执行", "开始执行", "执行吧")
        ):
            return True
    return False


def _clearly_informational(message: str) -> bool:
    lowered = str(message or "").lower()
    if _wants_execution(lowered):
        return False
    if any(
        marker in lowered for marker in ("你好", "您好", "hello", "hi", "嗨", "谢谢")
    ):
        return True
    return _is_pure_question(lowered)
