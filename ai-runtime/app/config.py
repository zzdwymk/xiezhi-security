from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("AI_RUNTIME_HOST", "127.0.0.1")
    port: int = int(os.getenv("AI_RUNTIME_PORT", "8090"))
    token: str = os.getenv("AI_RUNTIME_TOKEN", "")
    data_dir: Path = Path(os.getenv("AI_RUNTIME_DATA_DIR", "./data/ai-runtime"))
    llm_enabled: bool = _bool("AI_RUNTIME_LLM_ENABLED", False)
    api_key: str = os.getenv("AI_RUNTIME_API_KEY", "")
    base_url: str = os.getenv("AI_RUNTIME_BASE_URL", "https://api.openai.com/v1")
    model: str = os.getenv("AI_RUNTIME_MODEL", "gpt-4.1-mini")
    llm_timeout_seconds: float = float(
        os.getenv("AI_RUNTIME_LLM_TIMEOUT_SECONDS", "45")
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

    def prepare(self) -> "Settings":
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self


settings = Settings().prepare()
