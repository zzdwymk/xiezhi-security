from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class WorkflowStep(BaseModel):
    """One user-composed tool step from the visual workflow editor."""

    model_config = ConfigDict(extra="ignore")
    tool: str = Field(min_length=1, max_length=64)
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk: str = Field(default="SAFE", max_length=16)
    requiresApproval: bool = False
    group: int = Field(default=0, ge=0, le=32)


class AgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    projectId: int = Field(gt=0)
    conversationId: str | None = Field(default=None, max_length=200)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    authorization: AuthorizationContext = Field(default_factory=AuthorizationContext)
    targetId: int | None = Field(default=None, gt=0)
    mode: str = Field(default="plan", max_length=40)
    maxRetries: int | None = Field(default=None, ge=0, le=3)
    workflow: list[WorkflowStep] = Field(default_factory=list, max_length=16)

    @field_validator("messages")
    @classmethod
    def validate_messages(cls, value: list[ChatMessage]) -> list[ChatMessage]:
        if sum(len(message.content) for message in value) > 500_000:
            raise ValueError("对话内容总长度超过限制")
        return value
