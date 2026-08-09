from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, minimum), maximum)


def _bounded_float(
    name: str, default: float, minimum: float, maximum: float
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return min(max(value, minimum), maximum)


def _choice(name: str, default: str, allowed: set[str]) -> str:
    value = os.getenv(name, default).strip().lower()
    return value if value in allowed else default


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("AI_RUNTIME_HOST", "127.0.0.1")
    port: int = int(os.getenv("AI_RUNTIME_PORT", "8090"))
    token: str = os.getenv("AI_RUNTIME_TOKEN", "")
    project_signing_secret: str = os.getenv("AI_RUNTIME_PROJECT_SIGNING_SECRET", "")
    data_dir: Path = Path(os.getenv("AI_RUNTIME_DATA_DIR", "./data/ai-runtime"))
    llm_enabled: bool = _bool("AI_RUNTIME_LLM_ENABLED", False)
    api_key: str = os.getenv("AI_RUNTIME_API_KEY", "")
    base_url: str = os.getenv("AI_RUNTIME_BASE_URL", "https://api.openai.com/v1")
    model: str = os.getenv("AI_RUNTIME_MODEL", "gpt-4.1-mini")
    rag_prompt_version: str = os.getenv(
        "AI_RUNTIME_RAG_PROMPT_VERSION", "agentic-rag-v1"
    )[:64]
    experiment_date: str = os.getenv(
        "AI_RUNTIME_EXPERIMENT_DATE", "2026-08-07"
    )[:32]
    llm_timeout_seconds: float = _bounded_float(
        "AI_RUNTIME_LLM_TIMEOUT_SECONDS", 45.0, 0.1, 120.0
    )
    max_retries: int = min(max(int(os.getenv("AI_RUNTIME_MAX_RETRIES", "2")), 0), 3)
    max_request_bytes: int = min(
        max(
            int(os.getenv("AI_RUNTIME_MAX_REQUEST_BYTES", str(2 * 1024 * 1024))),
            64 * 1024,
        ),
        8 * 1024 * 1024,
    )
    max_documents: int = min(
        max(int(os.getenv("AI_RUNTIME_MAX_DOCUMENTS", "500")), 1), 2000
    )
    max_document_chars: int = min(
        max(int(os.getenv("AI_RUNTIME_MAX_DOCUMENT_CHARS", "200000")), 1000), 1_000_000
    )
    document_cache_chars: int = min(
        max(int(os.getenv("AI_RUNTIME_DOCUMENT_CACHE_CHARS", str(8 * 1024 * 1024))), 0),
        256 * 1024 * 1024,
    )
    document_cache_projects: int = min(
        max(int(os.getenv("AI_RUNTIME_DOCUMENT_CACHE_PROJECTS", "32")), 0), 256
    )
    index_cache_projects: int = min(
        max(int(os.getenv("AI_RUNTIME_INDEX_CACHE_PROJECTS", "8")), 0), 64
    )
    conversation_memory_ttl_minutes: int = min(
        max(int(os.getenv("AI_AGENT_SESSION_TTL_MINUTES", "120")), 5), 24 * 60
    )
    conversation_memory_documents: int = min(
        max(int(os.getenv("AI_RUNTIME_CONVERSATION_MEMORY_DOCUMENTS", "50")), 1),
        200,
    )
    rag_enabled: bool = _bool("AI_RUNTIME_RAG_ENABLED", True)
    retrieval_backend: str = _choice(
        "AI_RUNTIME_RETRIEVAL_BACKEND", "bm25", {"bm25", "real_embedding"}
    )
    max_retrieval_rounds: int = _bounded_int(
        "AI_RUNTIME_MAX_RETRIEVAL_ROUNDS", 2, 1, 2
    )
    max_evidence_items: int = _bounded_int(
        "AI_RUNTIME_MAX_EVIDENCE_ITEMS", 5, 1, 10
    )
    max_evidence_chars: int = _bounded_int(
        "AI_RUNTIME_MAX_EVIDENCE_CHARS", 10_000, 1_000, 12_000
    )
    retrieval_timeout_seconds: float = _bounded_float(
        "AI_RUNTIME_RETRIEVAL_TIMEOUT_SECONDS", 5.0, 0.1, 30.0
    )
    max_rag_llm_calls: int = _bounded_int(
        "AI_RUNTIME_MAX_RAG_LLM_CALLS", 5, 1, 8
    )
    agent_turn_timeout_seconds: float = _bounded_float(
        "AI_RUNTIME_AGENT_TURN_TIMEOUT_SECONDS", 60.0, 5.0, 300.0
    )
    graph_recursion_limit: int = _bounded_int(
        "AI_RUNTIME_GRAPH_RECURSION_LIMIT", 32, 8, 64
    )
    internal_graph_debug: bool = _bool("AI_RUNTIME_INTERNAL_GRAPH_DEBUG", False)

    def prepare(self) -> "Settings":
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self


settings = Settings().prepare()
