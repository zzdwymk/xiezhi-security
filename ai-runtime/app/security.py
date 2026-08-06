from __future__ import annotations

import hmac
from fastapi import HTTPException, Request

from .config import settings


def require_runtime_token(request: Request) -> None:
    """Protect non-health endpoints while keeping the desktop service loopback-only."""
    if not settings.token:
        return
    supplied = request.headers.get("X-AI-Runtime-Token", "")
    if not supplied or not hmac.compare_digest(supplied, settings.token):
        raise HTTPException(status_code=401, detail="本地智能服务令牌无效")


def safe_project_file(project_id: int) -> str:
    if project_id <= 0:
        raise ValueError("项目编号必须为正整数")
    return f"project-{project_id}.json"
