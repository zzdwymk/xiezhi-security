from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, ClassVar, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
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


class RetrievalParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: StrictStr = Field(min_length=1, max_length=2000)


class PortScanParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ports: StrictStr | None = Field(default=None, min_length=1, max_length=200)


class NmapParameters(PortScanParameters):
    mode: Literal["quick", "service"] = "quick"


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
    WorkflowRetrievalParameters,
    PortScanParameters,
    NmapParameters,
    WorkflowHttpSecurityParameters,
]

GroundedParameterPatch = Union[
    EmptyToolParameters,
    PortScanParameters,
    NmapParameters,
    WorkflowHttpSecurityParameters,
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


class NucleiScanAction(_PlanAction):
    tool: Literal["nuclei_scan"]
    parameters: EmptyToolParameters


PlanAction = Annotated[
    Union[
        RetrieveProjectContextAction,
        NmapServiceScanAction,
        TcpPortsAction,
        HttpHeadersAction,
        HttpSecurityCheckAction,
        TlsConfigAction,
        NucleiScanAction,
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
        return self


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
    def validate_grounding_contract(self) -> "GroundedPlannerOutput":
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
        elif not self.evidenceRefs:
            raise ValueError("PROJECT_EVIDENCE requires evidenceRefs")
        known_refs = set(self.evidenceRefs)
        action_nodes: set[str] = set()
        for action in self.actions:
            if self.knowledgeMode == "PROJECT_EVIDENCE" and not action.evidenceRefs:
                raise ValueError("grounded actions require evidenceRefs")
            if not set(action.evidenceRefs).issubset(known_refs):
                raise ValueError("action evidenceRefs must be declared by the output")
            if action.workflowNodeId in action_nodes:
                raise ValueError("plan cannot contain duplicate workflow nodes")
            action_nodes.add(action.workflowNodeId)
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
        "nuclei_scan",
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
        "nuclei_scan": EmptyToolParameters,
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
    maxRetries: int | None = Field(default=None, ge=0, le=3)
    workflow: list[WorkflowStep] = Field(default_factory=list, max_length=16)
    runId: str | None = Field(default=None, pattern=r"[A-Za-z0-9_-]{8,80}")
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
    ledgerDigest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
