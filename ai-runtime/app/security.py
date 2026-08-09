from __future__ import annotations

import hmac
import hashlib
import time
from fastapi import HTTPException, Request

from .config import settings


def require_runtime_token(request: Request) -> None:
    """Protect non-health endpoints while keeping the desktop service loopback-only."""
    if not settings.token:
        raise HTTPException(status_code=503, detail="本地智能服务未配置访问令牌")
    supplied = request.headers.get("X-AI-Runtime-Token", "")
    if not supplied or not hmac.compare_digest(supplied, settings.token):
        raise HTTPException(status_code=401, detail="本地智能服务令牌无效")


def project_authorization_value(project_id: int, scope: str, expires_at: int) -> str:
    """Create the short-lived credential Java uses for one project operation."""
    if not settings.project_signing_secret:
        raise ValueError("project signing secret is not configured")
    message = f"v1:{project_id}:{scope}:{expires_at}"
    signature = hmac.new(
        settings.project_signing_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{message}:{signature}"


def require_project_authorization(
    request: Request, project_id: int, scope: str
) -> None:
    if not settings.project_signing_secret:
        raise HTTPException(status_code=503, detail="项目级智能服务签名密钥未配置")
    supplied = request.headers.get("X-AI-Project-Authorization", "")
    parts = supplied.split(":")
    if len(parts) != 5:
        raise HTTPException(status_code=403, detail="缺少项目级智能服务授权")
    version, raw_project, raw_scope, raw_expires, signature = parts
    try:
        credential_project = int(raw_project)
        expires_at = int(raw_expires)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="项目级智能服务授权格式无效") from exc
    now = int(time.time())
    if (
        version != "v1"
        or credential_project != project_id
        or raw_scope != scope
        or expires_at < now
        or expires_at > now + 300
    ):
        raise HTTPException(status_code=403, detail="项目级智能服务授权无效或已过期")
    expected = project_authorization_value(project_id, scope, expires_at).rsplit(":", 1)[1]
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=403, detail="项目级智能服务授权签名无效")


def safe_project_file(project_id: int) -> str:
    if project_id <= 0:
        raise ValueError("项目编号必须为正整数")
    return f"project-{project_id}.json"
