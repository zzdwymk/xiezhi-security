from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Annotated, Any, ClassVar, Literal, Union
from urllib.parse import unquote_plus, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationInfo,
    field_validator,
    model_validator,
)


class ProjectDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=300)
    text: str = Field(min_length=1, max_length=1_000_000)
    source: str = Field(default="project", min_length=1, max_length=200)
    metadata: dict[str, str] = Field(default_factory=dict)
    id: str | None = Field(default=None, max_length=128)


class IndexProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    projectId: int = Field(gt=0)
    documents: list[ProjectDocument] = Field(min_length=1, max_length=2000)
    replace: bool = True


class AppendDocumentsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    documents: list[ProjectDocument] = Field(min_length=1, max_length=200)


class QueryProjectEvidenceRequest(BaseModel):
    """A workflow read selects one target; project identity comes from the signed path."""

    model_config = ConfigDict(extra="forbid", strict=True)
    targetId: StrictInt = Field(gt=0)
    query: StrictStr = Field(min_length=1, max_length=2000)
    topK: StrictInt = Field(default=5, ge=1, le=10)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
            raise ValueError("query must not contain control characters")
        value = value.strip()
        if not value:
            raise ValueError("query must not be blank")
        return value


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["user", "assistant", "system"]
    content: str = Field(min_length=1, max_length=100_000)


class Quota(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maxActions: int = Field(default=10, ge=0, le=1000)
    usedActions: int = Field(default=0, ge=0, le=1000)


class AuthorizationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(default="UNKNOWN", max_length=40)
    targetIds: list[int] = Field(default_factory=list, max_length=1000)
    allowedTools: list[str] = Field(default_factory=list, max_length=100)
    allowedPorts: str | list[int] | None = None
    approved: bool = False
    validFrom: datetime | None = None
    expiresAt: datetime | None = None
    quota: Quota = Field(default_factory=Quota)
    policyRevision: str = Field(default="java-authoritative-v1", min_length=1, max_length=80)


class EmptyToolParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PocSelectionParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    pocCodes: list[
        Annotated[
            StrictStr,
            Field(pattern=r"^[A-Z]{2}-[A-F0-9]{24}$"),
        ]
    ] | None = Field(default=None, min_length=1, max_length=50)
    allPocs: StrictBool | None = None

    @model_validator(mode="after")
    def require_one_selection_mode(self) -> "PocSelectionParameters":
        if (self.pocCodes is None) == (self.allPocs is None):
            raise ValueError("select concrete PoCs or all PoCs")
        if self.allPocs is not None and not self.allPocs:
            raise ValueError("allPocs must be true when provided")
        if self.pocCodes is not None and len(self.pocCodes) != len(set(self.pocCodes)):
            raise ValueError("PoC codes must be unique")
        return self


class NucleiParameters(PocSelectionParameters):
    """An empty legacy selection uses server defaults; explicit choices stay bounded."""

    @model_validator(mode="after")
    def require_one_selection_mode(self) -> "NucleiParameters":
        if self.pocCodes is None and self.allPocs is None:
            return self
        super().require_one_selection_mode()
        return self


class RetrievalParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: StrictStr = Field(min_length=1, max_length=2000)


class PortScanParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ports: StrictStr | None = Field(default=None, min_length=1, max_length=200)


class NmapParameters(PortScanParameters):
    mode: Literal["quick", "service"] = "quick"


class FscanParameters(PortScanParameters):
    vulnMode: Literal["SAFE", "FINGERPRINT", "FULL"] | None = None


class ZapParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    spider: StrictBool | None = None
    strength: Literal["LOW", "MEDIUM", "HIGH", "INSANE"] | None = None


class DirScanParameters(BaseModel):
    """Directory/path enumeration.

    ``concurrency`` and ``maxRequests`` are deliberately bounded here as well as in the Java
    guard: the runtime must never emit a value the server would reject, and the server must never
    accept a value the runtime would not emit (the two sides use the same 1..50 / depth 0..3
    bounds, mirroring ToolParameterSpec on the Java side).
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    dictionary: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    concurrency: StrictInt | None = Field(default=None, ge=1, le=50)
    depth: StrictInt | None = Field(default=None, ge=0, le=3)
    maxRequests: StrictInt | None = Field(default=None, ge=1, le=200000)
    extensions: list[
        Annotated[StrictStr, Field(min_length=1, max_length=10, pattern=r"^[A-Za-z0-9]+$")]
    ] | None = Field(default=None, max_length=10)


class WorkflowZapFuzzParameters(BaseModel):
    """A saved node may defer fields; a final action must describe one concrete request."""

    model_config = ConfigDict(extra="forbid", strict=True)
    fuzzRequestUrl: StrictStr | None = Field(default=None, min_length=1, max_length=2000)
    method: Literal["GET", "POST"] | None = None
    fuzzPostBody: StrictStr | None = Field(default=None, max_length=4000)
    fuzzPayload: StrictStr | None = Field(default=None, min_length=1, max_length=1000)
    fuzzTargetField: StrictStr | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("fuzzRequestUrl", "fuzzPostBody", "fuzzPayload", "fuzzTargetField")
    @classmethod
    def no_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
            raise ValueError("ZAP request fields must not contain control characters")
        return value

    @field_validator("fuzzRequestUrl")
    @classmethod
    def absolute_http_url(cls, value: str | None) -> str | None:
        if value is not None:
            parsed = urlsplit(value)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or "#" in value
                    or any(c.isspace() for c in value) or parsed.port == 0):
                raise ValueError("ZAP fuzzRequestUrl must be an absolute HTTP URL without credentials or fragment")
        return value

    @field_validator("fuzzTargetField")
    @classmethod
    def nonblank_field(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("ZAP fuzzTargetField cannot be blank")
        return value

    @model_validator(mode="after")
    def get_has_no_body(self) -> "WorkflowZapFuzzParameters":
        if self.method == "GET" and self.fuzzPostBody:
            raise ValueError("ZAP GET request cannot carry a form body")
        return self


class ZapFuzzParameters(WorkflowZapFuzzParameters):
    fuzzRequestUrl: StrictStr = Field(min_length=1, max_length=2000)
    method: Literal["GET", "POST"] = "POST"
    fuzzPayload: StrictStr = Field(min_length=1, max_length=1000)
    fuzzTargetField: StrictStr = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def existing_unique_field(self) -> "ZapFuzzParameters":
        form = urlsplit(self.fuzzRequestUrl).query if self.method == "GET" else self.fuzzPostBody
        if not form or re.search(r"%(?![0-9A-Fa-f]{2})", form):
            raise ValueError("ZAP needs an existing query or URL-encoded form")
        names = [unquote_plus(field.split("=", 1)[0]) for field in form.split("&")]
        if names.count(self.fuzzTargetField) != 1:
            raise ValueError("ZAP fuzzTargetField must occur exactly once in the original request")
        return self


class WorkflowSqlmapParameters(BaseModel):
    """Saved workflow defaults; action patches must still pass the tighter AI contract."""

    model_config = ConfigDict(extra="forbid", strict=True)
    path: StrictStr | None = Field(default=None, min_length=1, max_length=2000)
    level: StrictInt | None = Field(default=None, ge=1, le=5)
    risk: StrictInt | None = Field(default=None, ge=1, le=3)
    technique: StrictStr | None = Field(default=None, pattern=r"^[BEUSTQ]{1,6}$")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        if value is not None:
            if value != value.strip() or any(char.isspace() or ord(char) == 127 for char in value):
                raise ValueError("SQLMap path contains forbidden whitespace")
            try:
                parsed = urlsplit(value)
                if (value.startswith("//") or parsed.username is not None or parsed.fragment
                        or parsed.scheme not in {"", "http", "https"}):
                    raise ValueError("SQLMap path must be an HTTP path without credentials or fragment")
            except ValueError as error:
                raise ValueError("SQLMap path is invalid") from error
        return value

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, value: str | None) -> str | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("SQLMap technique must not contain duplicates")
        return value


class SqlmapParameterPatch(WorkflowSqlmapParameters):
    risk: StrictInt | None = Field(default=None, ge=1, le=1)
    technique: StrictStr | None = Field(default=None, pattern=r"^[BEUT]{1,4}$")


class SqlmapParameters(SqlmapParameterPatch):
    level: StrictInt = Field(default=1, ge=1, le=5)
    risk: StrictInt = Field(default=1, ge=1, le=1)
    technique: StrictStr = Field(default="BEUT", pattern=r"^[BEUT]{1,4}$")


MsfModule = Annotated[
    StrictStr,
    Field(max_length=256, pattern=r"^(auxiliary|exploit)/[a-z0-9_]+(?:/[a-z0-9_]+)*$"),
]


class WorkflowMsfParameters(BaseModel):
    """A workflow may defer its module choice; the final action must provide it."""

    model_config = ConfigDict(extra="forbid", strict=True)
    module: MsfModule | None = None
    modules: list[MsfModule] | None = Field(default=None, min_length=1, max_length=16)
    options: dict[
        Annotated[StrictStr, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")],
        Annotated[StrictStr, Field(min_length=1, max_length=500)],
    ] | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def validate_selection_and_options(self) -> "WorkflowMsfParameters":
        if self.module is not None and self.modules is not None:
            raise ValueError("select one module or a module list")
        if self.modules is not None and len(self.modules) != len(set(self.modules)):
            raise ValueError("MSF modules must be unique")
        forbidden = {
            "RHOST", "RHOSTS", "RPORT", "LHOST", "LPORT", "PAYLOAD", "CMD",
            "COMMAND", "SHELL", "CHOST", "CPORT",
        }
        for key, value in (self.options or {}).items():
            if key in forbidden or any(ord(char) < 32 or ord(char) == 127 or char == ";" for char in value):
                raise ValueError("MSF option is not allowed")
        return self


class MsfParameters(WorkflowMsfParameters):
    @model_validator(mode="after")
    def require_selection(self) -> "MsfParameters":
        if self.module is None and self.modules is None:
            raise ValueError("MSF action must select a module")
        return self


class HttpSecurityParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check: Literal["cookies", "cors", "methods", "disclosure"]


class WorkflowRetrievalParameters(BaseModel):
    """A saved workflow may leave the runtime-only retrieval query unset."""

    model_config = ConfigDict(extra="forbid", strict=True)
    query: StrictStr | None = Field(default=None, min_length=1, max_length=2000)


class WorkflowHttpSecurityParameters(BaseModel):
    """The editor may defer the concrete check to an action parameter patch."""

    model_config = ConfigDict(extra="forbid", strict=True)
    check: Literal["cookies", "cors", "methods", "disclosure"] | None = None


WorkflowToolParameters = Union[
    EmptyToolParameters,
    NucleiParameters,
    WorkflowRetrievalParameters,
    PortScanParameters,
    NmapParameters,
    WorkflowHttpSecurityParameters,
    DirScanParameters,
    PocSelectionParameters,
    FscanParameters,
    ZapParameters,
    WorkflowZapFuzzParameters,
    WorkflowSqlmapParameters,
    WorkflowMsfParameters,
]

GroundedParameterPatch = Union[
    EmptyToolParameters,
    PortScanParameters,
    NmapParameters,
    WorkflowHttpSecurityParameters,
    DirScanParameters,
    PocSelectionParameters,
    FscanParameters,
    ZapParameters,
    WorkflowZapFuzzParameters,
    SqlmapParameterPatch,
    WorkflowMsfParameters,
]


class _PlanAction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    risk: Literal["SAFE", "CAUTION"]
    requiresApproval: StrictBool
    group: StrictInt = Field(default=0, ge=0, le=32)


class RetrieveProjectContextAction(_PlanAction):
    tool: Literal["retrieve_project_context"]
    parameters: RetrievalParameters


class NmapServiceScanAction(_PlanAction):
    tool: Literal["nmap_service_scan"]
    parameters: NmapParameters


class TcpPortsAction(_PlanAction):
    tool: Literal["tcp_ports"]
    parameters: PortScanParameters


class HttpHeadersAction(_PlanAction):
    tool: Literal["http_headers"]
    parameters: EmptyToolParameters


class HttpSecurityCheckAction(_PlanAction):
    tool: Literal["http_security_check"]
    parameters: HttpSecurityParameters


class TlsConfigAction(_PlanAction):
    tool: Literal["tls_config"]
    parameters: EmptyToolParameters


class SiteCrawlAction(_PlanAction):
    tool: Literal["site_crawl"]
    parameters: EmptyToolParameters


class DirScanAction(_PlanAction):
    tool: Literal["dir_scan"]
    parameters: DirScanParameters


class NucleiScanAction(_PlanAction):
    tool: Literal["nuclei_scan"]
    parameters: NucleiParameters


class AfrogScanAction(_PlanAction):
    tool: Literal["afrog_scan"]
    parameters: PocSelectionParameters


class XrayScanAction(_PlanAction):
    tool: Literal["xray_scan"]
    parameters: PocSelectionParameters


class ZapScanAction(_PlanAction):
    tool: Literal["zap_scan"]
    parameters: ZapParameters


class FscanScanAction(_PlanAction):
    tool: Literal["fscan_scan"]
    parameters: FscanParameters


class MsfScanAction(_PlanAction):
    tool: Literal["msf_scan"]
    parameters: MsfParameters


class SqlmapScanAction(_PlanAction):
    tool: Literal["sqlmap_scan"]
    parameters: SqlmapParameters
    requiresApproval: Literal[True]


class ZapFuzzAction(_PlanAction):
    tool: Literal["zap_fuzz"]
    parameters: ZapFuzzParameters
    requiresApproval: Literal[True]


PlanAction = Annotated[
    Union[
        RetrieveProjectContextAction,
        NmapServiceScanAction,
        TcpPortsAction,
        HttpHeadersAction,
        HttpSecurityCheckAction,
        TlsConfigAction,
        SiteCrawlAction,
        DirScanAction,
        NucleiScanAction,
        AfrogScanAction,
        XrayScanAction,
        ZapScanAction,
        FscanScanAction,
        MsfScanAction,
        SqlmapScanAction,
        ZapFuzzAction,
    ],
    Field(discriminator="tool"),
]


class PlannerOutput(BaseModel):
    """The only model output accepted by the LangGraph planner boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)
    summary: StrictStr = Field(min_length=1, max_length=1000)
    answer: StrictStr = Field(min_length=1, max_length=20_000)
    intent: Literal["answer", "plan", "clarify"]
    actions: list[PlanAction] = Field(max_length=8)

    @field_validator("actions")
    @classmethod
    def validate_action_uniqueness(cls, value: list[PlanAction]) -> list[PlanAction]:
        keys: set[tuple[str, str]] = set()
        for action in value:
            parameters = action.parameters.model_dump(mode="json")
            discriminator = str(parameters.get("check", ""))
            key = (action.tool, discriminator)
            if key in keys:
                raise ValueError("计划不能包含重复工具动作")
            keys.add(key)
        return value


EvidenceRef = Annotated[
    StrictStr,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"),
]


class IntentDecision(BaseModel):
    """Small routing decision. It intentionally contains no reasoning or chain of thought."""

    model_config = ConfigDict(extra="forbid", strict=True)
    intent: Literal["GENERAL_QA", "PROJECT_QA", "ACTION_PLAN", "CLARIFY"]
    needsRetrieval: StrictBool
    retrievalQuery: StrictStr | None = Field(default=None, min_length=1, max_length=2000)
    publicReasonCode: Literal[
        "GENERAL_KNOWLEDGE",
        "PROJECT_CONTEXT_REQUIRED",
        "AUTHORIZED_ACTION_REQUEST",
        "AMBIGUOUS_REQUEST",
    ]
    executionDecision: Literal["EXECUTE", "PLAN_ONLY", "CLARIFY"] | None = None
    planRelation: Literal["NEW", "CONTINUE", "REVISE", "NONE"] | None = None

    @model_validator(mode="after")
    def validate_retrieval_contract(self) -> "IntentDecision":
        expected = {
            "GENERAL_QA": (False, "GENERAL_KNOWLEDGE"),
            "PROJECT_QA": (True, "PROJECT_CONTEXT_REQUIRED"),
            "ACTION_PLAN": (True, "AUTHORIZED_ACTION_REQUEST"),
            "CLARIFY": (False, "AMBIGUOUS_REQUEST"),
        }
        expected_retrieval, expected_reason = expected[self.intent]
        if self.needsRetrieval is not expected_retrieval:
            raise ValueError("intent and needsRetrieval are inconsistent")
        if self.publicReasonCode != expected_reason:
            raise ValueError("intent and publicReasonCode are inconsistent")
        if self.needsRetrieval and self.retrievalQuery is None:
            raise ValueError("retrieval intent requires retrievalQuery")
        if not self.needsRetrieval and self.retrievalQuery is not None:
            raise ValueError("non-retrieval intent cannot include retrievalQuery")
        if self.executionDecision == "EXECUTE" and self.intent != "ACTION_PLAN":
            raise ValueError("only ACTION_PLAN may request execution")
        if self.executionDecision == "CLARIFY" and self.intent != "CLARIFY":
            raise ValueError("CLARIFY execution decision requires CLARIFY intent")
        if self.intent == "CLARIFY" and self.executionDecision not in {None, "CLARIFY"}:
            raise ValueError("CLARIFY intent cannot authorize execution or a plan")
        if self.intent != "ACTION_PLAN" and self.planRelation not in {None, "NONE"}:
            raise ValueError("only ACTION_PLAN may relate to an executable plan")
        return self


class AutoIntentDecision(IntentDecision):
    """AUTO requires an explicit, finite decision from the model route boundary."""
    executionDecision: Literal["EXECUTE", "PLAN_ONLY", "CLARIFY"]
    planRelation: Literal["NEW", "CONTINUE", "REVISE", "NONE"] = "NONE"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    evidenceId: EvidenceRef
    documentId: StrictStr = Field(min_length=1, max_length=128)
    title: StrictStr = Field(min_length=1, max_length=300)
    source: StrictStr = Field(min_length=1, max_length=200)
    snippet: StrictStr = Field(min_length=1, max_length=2000)
    score: float = Field(strict=True, ge=0)
    targetId: StrictInt | None
    contentDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    projectId: StrictInt = Field(gt=0)
    targetId: StrictInt | None
    conversationId: StrictStr | None = Field(max_length=200)
    query: StrictStr = Field(min_length=1, max_length=2000)
    round: StrictInt = Field(ge=0, le=1)
    retrievalMethod: Literal["bm25", "real_embedding"]
    indexRevision: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    items: list[EvidenceItem] = Field(default_factory=list, max_length=10)

    @field_validator("items")
    @classmethod
    def validate_items(cls, value: list[EvidenceItem]) -> list[EvidenceItem]:
        identifiers = [item.evidenceId for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidenceId values must be unique")
        if sum(len(item.snippet) for item in value) > 12_000:
            raise ValueError("evidence bundle is too large")
        return value


class EvidenceDecision(BaseModel):
    """Evidence disposition without free-form reasoning."""

    model_config = ConfigDict(extra="forbid", strict=True)
    decision: Literal["FINALIZE", "REWRITE_QUERY", "CLARIFY"]
    reasonCodes: list[
        Literal[
            "DIRECT_SUPPORT",
            "PARTIAL_SUPPORT",
            "NO_RELEVANT_EVIDENCE",
            "CONFLICTING_EVIDENCE",
            "SCOPE_MISMATCH",
            "QUERY_TOO_BROAD",
        ]
    ] = Field(min_length=1, max_length=4)
    evidenceRefs: list[EvidenceRef] = Field(default_factory=list, max_length=10)
    rewrittenQuery: StrictStr | None = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def validate_decision_contract(self) -> "EvidenceDecision":
        if len(self.evidenceRefs) != len(set(self.evidenceRefs)):
            raise ValueError("evidenceRefs values must be unique")
        if len(self.reasonCodes) != len(set(self.reasonCodes)):
            raise ValueError("reasonCodes values must be unique")
        allowed_reasons = {
            "FINALIZE": {"DIRECT_SUPPORT", "PARTIAL_SUPPORT"},
            "REWRITE_QUERY": {
                "PARTIAL_SUPPORT",
                "NO_RELEVANT_EVIDENCE",
                "QUERY_TOO_BROAD",
            },
            "CLARIFY": {
                "NO_RELEVANT_EVIDENCE",
                "CONFLICTING_EVIDENCE",
                "SCOPE_MISMATCH",
            },
        }
        if not set(self.reasonCodes).issubset(allowed_reasons[self.decision]):
            raise ValueError("decision and reasonCodes are inconsistent")
        if self.decision == "FINALIZE":
            if not self.evidenceRefs or self.rewrittenQuery is not None:
                raise ValueError("FINALIZE requires refs and no rewrittenQuery")
        elif self.decision == "REWRITE_QUERY":
            if self.rewrittenQuery is None or self.evidenceRefs:
                raise ValueError("REWRITE_QUERY requires only rewrittenQuery")
        elif self.evidenceRefs or self.rewrittenQuery is not None:
            raise ValueError("CLARIFY cannot include refs or rewrittenQuery")
        return self


class GroundedWorkflowAction(BaseModel):
    """A model proposal names a node; executable metadata comes from its snapshot."""

    model_config = ConfigDict(extra="forbid", strict=True)
    workflowNodeId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    parameters: GroundedParameterPatch
    evidenceRefs: list[EvidenceRef] = Field(default_factory=list, max_length=16)

    @field_validator("evidenceRefs")
    @classmethod
    def validate_evidence_refs(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("action evidenceRefs values must be unique")
        return value


GroundedPlanAction = GroundedWorkflowAction


class GroundedPlannerOutput(BaseModel):
    """Planner output whose claims and actions are bound to retrieved evidence."""

    model_config = ConfigDict(extra="forbid", strict=True)
    summary: StrictStr = Field(min_length=1, max_length=1000)
    answer: StrictStr = Field(min_length=1, max_length=20_000)
    intent: Literal["answer", "plan", "clarify"]
    knowledgeMode: Literal["GENERAL", "PROJECT_EVIDENCE", "INSUFFICIENT_EVIDENCE"]
    evidenceRefs: list[EvidenceRef] = Field(default_factory=list, max_length=10)
    actions: list[GroundedPlanAction] = Field(max_length=8)

    @model_validator(mode="after")
    def validate_grounding_contract(self, info: ValidationInfo) -> "GroundedPlannerOutput":
        # Only the model-input parser may defer duplicated top-level declarations.
        # Every returned/runtime output is revalidated without this context after
        # checking each selected reference against the current evidence bundle.
        aggregate_selected_refs = (
            isinstance(info.context, dict)
            and info.context.get("aggregate_model_selected_references") is True
            and self.intent == "plan"
            and self.knowledgeMode == "PROJECT_EVIDENCE"
        )
        if len(self.evidenceRefs) != len(set(self.evidenceRefs)):
            raise ValueError("evidenceRefs values must be unique")
        if self.intent == "plan" and not self.actions:
            raise ValueError("plan intent requires at least one action")
        if self.intent != "plan" and self.actions:
            raise ValueError("only plan intent can include actions")
        if self.knowledgeMode == "GENERAL":
            if self.evidenceRefs or any(action.evidenceRefs for action in self.actions):
                raise ValueError("GENERAL knowledge mode cannot cite evidence")
        elif self.knowledgeMode == "INSUFFICIENT_EVIDENCE":
            if self.intent != "clarify" or self.actions or self.evidenceRefs:
                raise ValueError("INSUFFICIENT_EVIDENCE must produce only clarification")
        elif (
            self.knowledgeMode == "PROJECT_EVIDENCE"
            and not self.evidenceRefs
            and not aggregate_selected_refs
            and self.intent != "plan"
        ):
            # A grounded *claim* still needs a citation. A grounded-mode *proposal*
            # may stand on the request alone: the plan is what the human reviews, and
            # the server re-checks authorization and parameters regardless.
            raise ValueError("PROJECT_EVIDENCE requires evidenceRefs")
        known_refs = set(self.evidenceRefs)
        action_nodes: set[str] = set()
        for action in self.actions:
            # An action may only cite references the output actually declared. It is
            # not forced to cite one: a proposal that needs no project evidence (a
            # first-time service scan of an authorized target) is still a proposal the
            # human reviews before anything runs. Fabricated or smuggled references
            # stay rejected, which is the property that matters for grounding.
            if not aggregate_selected_refs and not set(action.evidenceRefs).issubset(known_refs):
                raise ValueError("action evidenceRefs must be declared by the output")
            if action.workflowNodeId in action_nodes:
                raise ValueError("plan cannot contain duplicate workflow nodes")
            action_nodes.add(action.workflowNodeId)
        return self


class ClarificationPlannerOutput(GroundedPlannerOutput):
    """A CLARIFY route cannot propose actions or claim a grounded/general answer."""

    intent: Literal["clarify"]
    knowledgeMode: Literal["INSUFFICIENT_EVIDENCE"]
    evidenceRefs: list[EvidenceRef] = Field(default_factory=list, max_length=0)
    actions: list[GroundedPlanAction] = Field(max_length=0)


class GeneralQaPlannerOutput(GroundedPlannerOutput):
    intent: Literal["answer", "clarify"]
    knowledgeMode: Literal["GENERAL"]
    evidenceRefs: list[EvidenceRef] = Field(default_factory=list, max_length=0)
    actions: list[GroundedPlanAction] = Field(max_length=0)


class EvidenceOrClarificationPlannerOutput(GroundedPlannerOutput):
    knowledgeMode: Literal["PROJECT_EVIDENCE", "INSUFFICIENT_EVIDENCE"]

    @model_validator(mode="after")
    def validate_clarification_mode(self) -> "EvidenceOrClarificationPlannerOutput":
        if self.intent == "clarify" and self.knowledgeMode != "INSUFFICIENT_EVIDENCE":
            raise ValueError("retrieval route clarification requires INSUFFICIENT_EVIDENCE")
        return self


class ProjectQaPlannerOutput(EvidenceOrClarificationPlannerOutput):
    intent: Literal["answer", "clarify"]
    actions: list[GroundedPlanAction] = Field(max_length=0)


class ActionPlanPlannerOutput(EvidenceOrClarificationPlannerOutput):
    """An action route always proposes a reviewable plan, with or without evidence.

    A proposal is not an execution permit: every action still passes the server's
    authorization, parameter, dependency-closure and human-approval checks before
    anything runs. Requiring retrieved project evidence *before the model may even
    propose a scan* turned ordinary requests into a fixed "insufficient evidence"
    template, so the contract lets the model think and propose, and reserves
    ``clarify`` for a request that is genuinely under-specified.
    """

    intent: Literal["plan", "clarify"]

    @model_validator(mode="after")
    def validate_action_route_evidence(self) -> "ActionPlanPlannerOutput":
        if self.knowledgeMode == "INSUFFICIENT_EVIDENCE" and self.intent != "clarify":
            raise ValueError("action route lacks evidence; propose a plan or clarify")
        if self.intent == "plan" and not self.actions:
            raise ValueError("plan intent requires at least one action")
        return self


class WorkflowStep(BaseModel):
    """One user-composed tool step from the visual workflow editor."""

    model_config = ConfigDict(extra="forbid", strict=True)
    nodeId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    tool: Literal[
        "retrieve_project_context",
        "nmap_service_scan",
        "tcp_ports",
        "http_headers",
        "http_security_check",
        "tls_config",
        "site_crawl",
        "dir_scan",
        "nuclei_scan",
        "afrog_scan",
        "xray_scan",
        "zap_scan",
        "fscan_scan",
        "msf_scan",
        "sqlmap_scan",
        "zap_fuzz",
    ]
    parameters: WorkflowToolParameters
    risk: Literal["SAFE", "CAUTION"] = "SAFE"
    requiresApproval: StrictBool = False
    group: StrictInt = Field(default=0, ge=0, le=32)
    dependsOnNodeIds: list[
        Annotated[
            StrictStr,
            Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"),
        ]
    ] = Field(default_factory=list, max_length=16)
    summary: StrictStr | None = Field(default=None, min_length=1, max_length=300)

    _PARAMETER_MODELS: ClassVar[dict[str, type[BaseModel]]] = {
        "retrieve_project_context": WorkflowRetrievalParameters,
        "nmap_service_scan": NmapParameters,
        "tcp_ports": PortScanParameters,
        "http_headers": EmptyToolParameters,
        "http_security_check": WorkflowHttpSecurityParameters,
        "tls_config": EmptyToolParameters,
        "site_crawl": EmptyToolParameters,
        "dir_scan": DirScanParameters,
        "nuclei_scan": NucleiParameters,
        "afrog_scan": PocSelectionParameters,
        "xray_scan": PocSelectionParameters,
        "zap_scan": ZapParameters,
        "fscan_scan": FscanParameters,
        "msf_scan": WorkflowMsfParameters,
        "sqlmap_scan": WorkflowSqlmapParameters,
        "zap_fuzz": WorkflowZapFuzzParameters,
    }

    @model_validator(mode="before")
    @classmethod
    def validate_parameters_for_tool(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        tool = value.get("tool")
        parameter_model = cls._PARAMETER_MODELS.get(tool)
        if parameter_model is None:
            return value
        normalized = dict(value)
        normalized["parameters"] = parameter_model.model_validate(
            value.get("parameters", {})
        )
        return normalized

    @model_validator(mode="after")
    def validate_dependencies(self) -> "WorkflowStep":
        if self.nodeId in self.dependsOnNodeIds:
            raise ValueError("workflow node cannot depend on itself")
        if len(self.dependsOnNodeIds) != len(set(self.dependsOnNodeIds)):
            raise ValueError("workflow dependencies must be unique")
        return self


class LedgerAgentBudget(BaseModel):
    """Finite defensive budgets supplied with one LedgerAgent node run."""

    model_config = ConfigDict(extra="forbid", strict=True)
    maxRetrievalRounds: StrictInt = Field(default=2, ge=1, le=2)
    maxLlmCalls: StrictInt = Field(default=4, ge=1, le=8)
    timeoutSeconds: StrictInt = Field(default=30, ge=5, le=120)


class LedgerAgentContext(BaseModel):
    """The only public input contract accepted by the LedgerAgent runtime."""

    model_config = ConfigDict(extra="forbid")
    projectId: int = Field(gt=0)
    conversationId: str | None = Field(default=None, max_length=200)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    authorization: AuthorizationContext = Field(default_factory=AuthorizationContext)
    targetId: int | None = Field(default=None, gt=0)
    mode: str = Field(default="plan", max_length=40)
    executionIntent: Literal["AUTO"] | None = None
    currentUserRequest: StrictStr | None = Field(default=None, min_length=1, max_length=4000)
    conversationState: dict[str, Any] | None = None
    maxRetries: int | None = Field(default=None, ge=0, le=3)
    workflow: list[WorkflowStep] = Field(default_factory=list, max_length=16)
    runId: str | None = Field(default=None, min_length=8, max_length=80, pattern=r"^[A-Za-z0-9_-]{8,80}$")
    workflowId: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    workflowRevision: StrictInt | None = Field(default=None, ge=1)
    workflowDigest: StrictStr | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    outerNodeId: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    nodeRunId: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    budget: LedgerAgentBudget = Field(default_factory=LedgerAgentBudget)

    @field_validator("messages")
    @classmethod
    def validate_messages(cls, value: list[ChatMessage]) -> list[ChatMessage]:
        if sum(len(message.content) for message in value) > 500_000:
            raise ValueError("对话内容总长度超过限制")
        return value

    @model_validator(mode="after")
    def validate_workflow_snapshot(self) -> "LedgerAgentContext":
        if self.executionIntent == "AUTO" and (
            self.currentUserRequest is None or not self.currentUserRequest.strip()
        ):
            raise ValueError("AUTO requires a separate currentUserRequest")
        if self.conversationState is not None:
            if len(json.dumps(self.conversationState, ensure_ascii=False)) > 40_000:
                raise ValueError("conversation state exceeds its context budget")
            for key, expected in (("projectId", self.projectId), ("targetId", self.targetId)):
                actual = self.conversationState.get(key)
                if actual != expected or (expected is not None and type(actual) is not int):
                    raise ValueError("conversation state must match the request scope")
        metadata = (
            self.workflowId,
            self.workflowRevision,
            self.workflowDigest,
            self.outerNodeId,
            self.nodeRunId,
        )
        if any(item is not None for item in metadata) and not all(
            item is not None for item in metadata
        ):
            raise ValueError("workflow snapshot metadata must be complete")

        node_ids = [step.nodeId for step in self.workflow]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("workflow nodeId values must be unique")
        known = set(node_ids)
        for step in self.workflow:
            if not set(step.dependsOnNodeIds).issubset(known):
                raise ValueError("workflow dependency references an unknown node")

        visiting: set[str] = set()
        visited: set[str] = set()
        dependencies = {step.nodeId: step.dependsOnNodeIds for step in self.workflow}

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError("workflow dependencies contain a cycle")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dependency in dependencies[node_id]:
                visit(dependency)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in node_ids:
            visit(node_id)
        return self


# Source compatibility for existing callers while the public contract is named explicitly.
AgentRequest = LedgerAgentContext


class AgentRecoveryIdentity(BaseModel):
    """Exact public identity shared by checkpoint and callback requests."""

    model_config = ConfigDict(extra="forbid", strict=True)
    projectId: StrictInt = Field(gt=0)
    targetId: StrictInt = Field(gt=0)
    conversationId: StrictStr | None = Field(default=None, max_length=200)
    runId: StrictStr = Field(
        min_length=8, max_length=80, pattern=r"^[A-Za-z0-9_-]+$"
    )
    nodeRunId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    workflowId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    workflowRevision: StrictInt = Field(ge=1)
    workflowDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    outerNodeId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    policyRevision: StrictStr = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    requestDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    stateVersion: StrictInt = Field(ge=1)
    ledgerDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class AgentCheckpointRequest(AgentRecoveryIdentity):
    """Finite callback checkpoint; task IDs are references, never result bodies."""

    pendingTaskIds: list[StrictInt] = Field(min_length=1, max_length=64)

    @field_validator("pendingTaskIds")
    @classmethod
    def validate_pending_task_ids(cls, value: list[int]) -> list[int]:
        if any(task_id <= 0 for task_id in value):
            raise ValueError("pending task IDs must be positive")
        if len(value) != len(set(value)):
            raise ValueError("pending task IDs must be unique")
        return value


class AgentResumeRequest(AgentRecoveryIdentity):
    """One idempotent terminal task callback for a persisted checkpoint."""

    callbackId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    taskId: StrictInt = Field(gt=0)
    taskStatus: Literal[
        "SUCCESS", "FAILED", "TIMEOUT", "CANCELLED", "REJECTED", "SKIPPED"
    ]
    resultDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class LedgerAgentProposedAction(BaseModel):
    """A proposal only; executable policy metadata is deliberately absent."""

    model_config = ConfigDict(extra="forbid", strict=True)
    workflowNodeId: StrictStr = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    parameters: GroundedParameterPatch
    evidenceRefs: list[EvidenceRef] = Field(default_factory=list, max_length=16)


class LedgerAgentResult(BaseModel):
    """Finite LedgerAgent output without authorization conclusions or private reasoning."""

    model_config = ConfigDict(extra="forbid", strict=True)
    status: Literal["COMPLETED", "CLARIFY", "DENIED", "APPROVAL_REQUIRED", "FAILED"]
    answer: StrictStr = Field(max_length=20_000)
    evidenceIds: list[EvidenceRef] = Field(default_factory=list, max_length=20)
    proposedActions: list[LedgerAgentProposedAction] = Field(default_factory=list, max_length=8)
    terminationReason: StrictStr | None = Field(default=None, min_length=1, max_length=64)
    planRelation: Literal["NEW", "CONTINUE", "REVISE", "NONE"] | None = None
    ledgerDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
