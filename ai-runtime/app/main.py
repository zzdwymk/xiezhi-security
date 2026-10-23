from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError
from .progress import with_public_progress
from contextlib import aclosing

from .config import settings
from .graph import (
    RUNTIME_LEDGER_GENESIS_DIGEST,
    LedgerAgentRuntime,
    encode_sse,
    envelope_runtime_event,
)
from .indexing import IndexValidationError, ProjectIndexStore
from .recovery import (
    AgentTombstoneStore,
    RecoveryConflict,
    RecoveryNotFound,
)
from .schemas import (
    AgentCheckpointRequest,
    AgentRequest,
    AgentResumeRequest,
    AppendDocumentsRequest,
    EvidenceBundle,
    IndexProjectRequest,
    QueryProjectEvidenceRequest,
    SummarizeRequest,
)
from .security import require_project_authorization, require_runtime_token
from .semantic_judge import BEHAVIOUR_LABELS, RISK_LEVELS, evaluate_action
from .tools import LANGCHAIN_TOOLS_AVAILABLE

logger = logging.getLogger(__name__)

VERSION = "0.1.0"
index_store = ProjectIndexStore()
agent_runtime = LedgerAgentRuntime(index_store)
recovery_store = AgentTombstoneStore(
    settings.data_dir / "recovery",
    ttl_minutes=settings.recovery_ttl_minutes,
    max_records_per_project=settings.recovery_max_records_per_project,
    max_callbacks_per_record=settings.recovery_max_callbacks_per_record,
)

app = FastAPI(
    title="Xiezhi Local AI Runtime",
    version=VERSION,
    docs_url="/docs",
    redoc_url=None,
)


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    _request: Request, _exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": "请求参数格式不正确"},
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "AI Runtime 请求处理发生未预期异常",
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "本地智能服务处理失败，请稍后重试"},
    )


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_request_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "请求体超过本地智能服务限制"},
                )
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "请求长度标头格式无效"},
            )
    # Content-Length is optional (and can understate the payload). Bound bytes
    # as they arrive, then retain the body for Starlette's downstream request.
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > settings.max_request_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": "请求体超过本地智能服务限制"},
            )
        chunks.append(chunk)
    request._body = b"".join(chunks)
    return await call_next(request)


@app.get("/health")
async def health() -> dict:
    index_stats = await asyncio.to_thread(index_store.stats)
    recovery_stats = await asyncio.to_thread(recovery_store.stats)
    planner_status = agent_runtime.planner.status
    components = {
        "runtimeAuth": bool(settings.token),
        "langchain": agent_runtime.planner.status.get("langchainAvailable", False),
        "langgraph": agent_runtime.health.get("langGraphAvailable", False),
        "retrieval": index_stats.get("retrievalReady", False),
        "embedding": index_stats.get("realEmbeddingAvailable", False),
        # Legacy desktop readiness key: it now means that the selected
        # retrieval backend (BM25 or real embedding) is ready.
        "llamaIndex": index_stats.get("retrievalReady", False),
        "langchainTools": LANGCHAIN_TOOLS_AVAILABLE,
    }
    ready = all(
        components[name]
        for name in (
            "runtimeAuth",
            "langchain",
            "langgraph",
            "retrieval",
            "langchainTools",
        )
    )
    return {
        "status": "UP" if ready else "DEGRADED",
        "runtimeReady": ready,
        "modelConfigured": planner_status.get("llmConfigured", False),
        "modelVerified": planner_status.get("llmVerified", False),
        "modelStatus": planner_status.get("modelStatus", "NOT_CONFIGURED"),
        "version": VERSION,
        "time": datetime.now(timezone.utc).isoformat(),
        "bind": f"{settings.host}:{settings.port}",
        "tokenRequired": bool(settings.token),
        "components": components,
        "agent": agent_runtime.health,
        "index": index_stats,
        "recovery": recovery_stats,
    }


@app.get("/agent/graph")
async def agent_graph() -> dict:
    """Public outer graph. LedgerAgent internals are intentionally opaque."""
    return agent_runtime.graph_structure()


@app.get("/agent/judge/vocabulary")
async def judge_vocabulary() -> dict:
    """Closed label sets the judge can emit, so the UI never hard-codes them."""
    return {"behaviours": list(BEHAVIOUR_LABELS), "riskLevels": list(RISK_LEVELS)}


@app.post("/agent/judge/evaluate", dependencies=[Depends(require_runtime_token)])
async def agent_judge_evaluate(payload: dict) -> dict:
    """Judge one proposed action.

    Deliberately returns HTTP 200 for every outcome, including judge failures: the verdict body
    carries ``allow=false`` plus a ``degraded`` reason, and turning that into an error status would
    make callers treat "cannot judge" as "transport problem to retry" rather than "block it".
    """
    action = payload.get("action") if isinstance(payload.get("action"), dict) else payload
    verdict = await evaluate_action(action or {})
    return verdict.to_dict()


@app.get("/agent/graph/debug", dependencies=[Depends(require_runtime_token)])
async def agent_graph_debug() -> dict:
    """Protected internal topology for explicitly enabled local diagnostics."""
    if not settings.internal_graph_debug:
        raise HTTPException(status_code=404, detail="内部图调试接口未启用")
    return agent_runtime.internal_graph_structure()


@app.post("/agent/summarize", dependencies=[Depends(require_runtime_token)])
async def agent_summarize(payload: SummarizeRequest, raw_request: Request) -> dict:
    """Compact a conversation on demand.

    Compaction normally fires by itself once a conversation outgrows its budget. This endpoint
    exposes the same work explicitly, so a user can reclaim context in a long session — and so the
    behaviour is observable without having to talk past a size threshold first. The digest is
    descriptive only: it never authorizes anything.
    """
    require_project_authorization(raw_request, payload.projectId, "agent")
    summary = await agent_runtime.planner.summarize_conversation(
        payload.conversation, payload.targetId
    )
    return {"summary": summary or {}}


@app.post("/agent/checkpoint", dependencies=[Depends(require_runtime_token)])
async def agent_checkpoint(
    request: AgentCheckpointRequest, raw_request: Request
) -> dict:
    """Persist finite callback metadata; prompts and evidence bodies are never stored."""
    require_project_authorization(raw_request, request.projectId, "agent-resume")
    try:
        return await asyncio.to_thread(
            recovery_store.checkpoint, request.model_dump(mode="json")
        )
    except RecoveryConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


@app.post("/agent/resume", dependencies=[Depends(require_runtime_token)])
async def agent_resume(request: AgentResumeRequest, raw_request: Request) -> dict:
    """Accept one idempotent terminal-task callback for a verified checkpoint."""
    require_project_authorization(raw_request, request.projectId, "agent-resume")
    try:
        return await asyncio.to_thread(
            recovery_store.resume, request.model_dump(mode="json")
        )
    except RecoveryNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except RecoveryConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


@app.post("/index/project", dependencies=[Depends(require_runtime_token)])
async def index_project(request: IndexProjectRequest, raw_request: Request) -> dict:
    require_project_authorization(raw_request, request.projectId, "index-write")
    try:
        result = await asyncio.to_thread(
            index_store.index_project,
            request.projectId,
            request.documents,
            request.replace,
        )
        return {**result, "status": "INDEXED"}
    except IndexValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        logger.error("项目索引写入失败", exc_info=(type(exc), exc, exc.__traceback__))
        raise HTTPException(status_code=503, detail="项目索引暂时不可写") from exc


@app.post("/agent/stream", dependencies=[Depends(require_runtime_token)])
async def agent_stream(
    request: AgentRequest, raw_request: Request
) -> StreamingResponse:
    require_project_authorization(raw_request, request.projectId, "agent")
    effective_request = request.model_copy(
        update={"runId": request.runId or str(uuid.uuid4())}
    )

    async def generate() -> AsyncIterator[str]:
        last_state_version = 0
        last_ledger_digest = RUNTIME_LEDGER_GENESIS_DIGEST
        try:
            async with aclosing(with_public_progress(agent_runtime.stream(effective_request))) as stream:
                async for kind, event in stream:
                    if await raw_request.is_disconnected():
                        break
                    if kind == "progress":
                        # SSE comments never enter the versioned ledger contract.
                        yield ": toolbox-progress " + json.dumps(event, separators=(",", ":")) + "\n\n"
                        continue
                    last_state_version = int(event.get("stateVersion", last_state_version + 1))
                    last_ledger_digest = str(
                        event.get("ledgerEntryDigest", last_ledger_digest)
                    )
                    yield encode_sse(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("AI Runtime 处理流式请求失败")
            event_id = str(uuid.uuid4())
            error = envelope_runtime_event(
                {
                    "eventId": event_id,
                    "type": "error",
                    "node": "runtime",
                    "message": "本地智能服务处理失败，未执行未授权动作",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "status": "FAILED",
                        "errorCode": "RUNTIME_PROCESSING_FAILED",
                    },
                },
                effective_request.model_dump(mode="json"),
                str(effective_request.runId),
                last_state_version + 1,
                last_ledger_digest,
            )
            yield encode_sse(error)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/index/project/{project_id}", dependencies=[Depends(require_runtime_token)])
async def project_index_status(project_id: int, request: Request) -> dict:
    if project_id <= 0:
        raise HTTPException(status_code=400, detail="项目编号必须为正整数")
    require_project_authorization(request, project_id, "index-read")
    match = await asyncio.to_thread(index_store.project_stats, project_id)
    if match is None:
        raise HTTPException(status_code=404, detail="项目尚未建立 AI 索引")
    return match


@app.post(
    "/index/project/{project_id}/query",
    dependencies=[Depends(require_runtime_token)],
    response_model=EvidenceBundle,
)
async def query_project_evidence(
    project_id: int, request: QueryProjectEvidenceRequest, raw_request: Request
) -> EvidenceBundle:
    if project_id <= 0:
        raise HTTPException(status_code=400, detail="项目编号必须为正整数")
    require_project_authorization(raw_request, project_id, "index-read")
    if not settings.rag_enabled:
        raise HTTPException(status_code=503, detail="项目资料检索尚未启用")
    try:
        # Conversation context is deliberately unavailable to workflow reads.
        # Query/ranking and target filtering happen in the existing bounded store.
        raw_bundle = await asyncio.wait_for(
            asyncio.to_thread(
                index_store.evidence_bundle,
                project_id,
                request.query,
                0,
                None,
                request.targetId,
                top_k=request.topK,
                max_chars=min(settings.max_evidence_chars, 12_000),
            ),
            timeout=settings.retrieval_timeout_seconds,
        )
        bundle = EvidenceBundle.model_validate(raw_bundle)
        if (bundle.projectId != project_id or bundle.targetId != request.targetId
                or bundle.conversationId is not None or bundle.round != 0
                or bundle.query != request.query or len(bundle.items) > request.topK):
            raise IndexValidationError("检索结果范围不一致")
        for item in bundle.items:
            if item.source.strip().lower() == "conversation" or (
                item.targetId != request.targetId
                and not (item.targetId is None and item.source == "project")
            ):
                raise IndexValidationError("检索结果来源或目标不一致")
        return bundle
    except (IndexValidationError, ValidationError, OSError, TimeoutError) as exc:
        logger.warning("项目资料检索未完成或结果校验失败", exc_info=(type(exc), exc, exc.__traceback__))
        raise HTTPException(status_code=503, detail="项目资料检索未完成，请稍后重试") from exc


@app.post(
    "/index/project/{project_id}/documents",
    dependencies=[Depends(require_runtime_token)],
)
async def append_documents(
    project_id: int, request: AppendDocumentsRequest, raw_request: Request
) -> dict:
    if project_id <= 0:
        raise HTTPException(status_code=400, detail="项目编号必须为正整数")
    require_project_authorization(raw_request, project_id, "index-write")
    try:
        result = await asyncio.to_thread(
            index_store.index_project, project_id, request.documents, False
        )
        return {**result, "status": "APPENDED"}
    except IndexValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        logger.error("项目索引写入失败", exc_info=(type(exc), exc, exc.__traceback__))
        raise HTTPException(status_code=503, detail="项目索引暂时不可写") from exc


@app.get(
    "/index/project/{project_id}/documents",
    dependencies=[Depends(require_runtime_token)],
)
async def list_project_documents(
    project_id: int, request: Request, source: str | None = None
) -> dict:
    if project_id <= 0:
        raise HTTPException(status_code=400, detail="项目编号必须为正整数")
    require_project_authorization(request, project_id, "index-read")
    return {
        "projectId": project_id,
        "documents": await asyncio.to_thread(
            index_store.list_documents, project_id, source
        ),
    }


@app.delete(
    "/index/project/{project_id}/documents/{doc_id}",
    dependencies=[Depends(require_runtime_token)],
)
async def delete_project_document(
    project_id: int, doc_id: str, request: Request, source: str
) -> dict:
    if project_id <= 0:
        raise HTTPException(status_code=400, detail="项目编号必须为正整数")
    require_project_authorization(request, project_id, "index-write")
    try:
        result = await asyncio.to_thread(
            index_store.delete_document, project_id, doc_id, source
        )
        return {"projectId": project_id, "source": source.strip(), **result}
    except IndexValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete(
    "/index/project/{project_id}/documents",
    dependencies=[Depends(require_runtime_token)],
)
async def clear_project_documents(
    project_id: int,
    request: Request,
    source: str | None = None,
    conversationId: str | None = None,
) -> dict:
    """Clear project documents. When source is set, only that source is removed."""
    if project_id <= 0:
        raise HTTPException(status_code=400, detail="项目编号必须为正整数")
    require_project_authorization(request, project_id, "index-write")
    if not source or not source.strip():
        raise HTTPException(
            status_code=400, detail="清空时必须指定资料来源，例如 conversation"
        )
    try:
        result = await asyncio.to_thread(
            index_store.clear_documents_by_source,
            project_id,
            source.strip(),
            conversationId,
        )
        return {"projectId": project_id, "source": source.strip(), **result}
    except IndexValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
