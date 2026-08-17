from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class RecoveryStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RecoveryNotFound(RecoveryStoreError):
    pass


class RecoveryConflict(RecoveryStoreError):
    pass


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class AgentTombstoneStore:
    """Atomic, finite recovery metadata store.

    Tombstones intentionally contain no prompt, messages, evidence body, model output,
    authorization secret, or reasoning. They can prove that a task callback belongs to
    a completed Agent checkpoint, but cannot deserialize arbitrary Python/LangGraph state.
    """

    _IDENTITY_FIELDS = (
        "projectId",
        "targetId",
        "conversationId",
        "runId",
        "nodeRunId",
        "workflowId",
        "workflowRevision",
        "workflowDigest",
        "outerNodeId",
        "policyRevision",
    )

    def __init__(
        self,
        root: Path,
        *,
        ttl_minutes: int = 30,
        max_records_per_project: int = 256,
        max_callbacks_per_record: int = 128,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(minutes=max(5, min(ttl_minutes, 24 * 60)))
        self.max_records_per_project = max(16, min(max_records_per_project, 2048))
        self.max_callbacks_per_record = max(16, min(max_callbacks_per_record, 512))
        self._lock = threading.RLock()

    def checkpoint(self, request: dict[str, Any]) -> dict[str, Any]:
        identity = self._identity(request)
        now = _utc_now()
        with self._lock:
            path = self._path(identity)
            existing = self._read(path)
            if existing is not None:
                mismatch = self._mismatch(existing, request)
                if mismatch is not None:
                    raise RecoveryConflict(
                        self._mismatch_code(mismatch),
                        f"Agent checkpoint 字段不匹配：{mismatch}",
                    )
                return self._response(existing, reason="CHECKPOINT_EXISTS")

            pending_ids = sorted({int(value) for value in request["pendingTaskIds"]})
            record = {
                "schemaVersion": 1,
                **identity,
                "requestDigest": request["requestDigest"],
                "stateVersion": int(request["stateVersion"]),
                "ledgerDigest": request["ledgerDigest"],
                "pendingTaskIds": pending_ids,
                "taskResults": {},
                "callbackReceipts": {},
                "status": "WAITING_TASKS",
                "createdAt": _format_time(now),
                "updatedAt": _format_time(now),
                "expiresAt": _format_time(now + self.ttl),
            }
            removable = self._prune_project(identity["projectId"], keep=path)
            self._write(path, record)
            for old_path in removable:
                try:
                    old_path.unlink(missing_ok=True)
                except OSError:
                    # The new checkpoint is already durable; a later capacity pass can
                    # retry removing this stale record without losing the new one.
                    pass
            return self._response(record, reason="CHECKPOINT_CREATED")

    def resume(self, request: dict[str, Any]) -> dict[str, Any]:
        identity = self._identity(request)
        with self._lock:
            path = self._path(identity)
            record = self._read(path)
            if record is None:
                raise RecoveryNotFound("CHECKPOINT_NOT_FOUND", "Agent checkpoint 不存在")

            mismatch = self._mismatch(record, request)
            if mismatch is not None:
                return self._response(
                    record,
                    status="STALE",
                    reason=self._mismatch_code(mismatch),
                )
            if self._is_expired(record):
                return self._response(
                    record, status="STALE", reason="RECOVERY_WINDOW_EXPIRED"
                )

            callback_id = str(request["callbackId"])
            callback_digest = canonical_digest(
                {
                    **identity,
                    "requestDigest": request["requestDigest"],
                    "stateVersion": request["stateVersion"],
                    "ledgerDigest": request["ledgerDigest"],
                    "callbackId": callback_id,
                    "taskId": request["taskId"],
                    "taskStatus": request["taskStatus"],
                    "resultDigest": request["resultDigest"],
                }
            )
            receipts = record["callbackReceipts"]
            receipt = receipts.get(callback_id)
            if receipt is not None:
                if receipt["bodyDigest"] != callback_digest:
                    raise RecoveryConflict(
                        "CALLBACK_CONFLICT", "相同 callbackId 对应了不同回调内容"
                    )
                return dict(receipt["response"])
            if len(receipts) >= self.max_callbacks_per_record:
                raise RecoveryConflict(
                    "CALLBACK_LIMIT_REACHED", "Agent checkpoint 回调数量超过限制"
                )

            task_id = int(request["taskId"])
            if task_id not in record["pendingTaskIds"]:
                raise RecoveryConflict(
                    "TASK_NOT_PENDING", "任务不属于该 Agent checkpoint"
                )
            result = {
                "taskStatus": request["taskStatus"],
                "resultDigest": request["resultDigest"],
            }
            task_key = str(task_id)
            existing_result = record["taskResults"].get(task_key)
            if existing_result is not None and existing_result != result:
                raise RecoveryConflict(
                    "TASK_RESULT_CONFLICT", "同一任务提交了不同的终态摘要"
                )
            record["taskResults"][task_key] = result
            completed_ids = {int(value) for value in record["taskResults"]}
            record["status"] = (
                "CONTINUATION_READY"
                if completed_ids == set(record["pendingTaskIds"])
                else "WAITING_TASKS"
            )
            record["updatedAt"] = _format_time(_utc_now())
            response = self._response(record, reason="CALLBACK_ACCEPTED")
            receipts[callback_id] = {
                "bodyDigest": callback_digest,
                "response": response,
            }
            self._write(path, record)
            return response

    def stats(self) -> dict[str, Any]:
        with self._lock:
            records = 0
            waiting = 0
            ready = 0
            stale = 0
            for path in self.root.glob("project-*/*.json"):
                record = self._read(path)
                if record is None:
                    continue
                records += 1
                if self._is_expired(record):
                    stale += 1
                elif record.get("status") == "WAITING_TASKS":
                    waiting += 1
                elif record.get("status") == "CONTINUATION_READY":
                    ready += 1
            return {
                "records": records,
                "waitingTasks": waiting,
                "continuationReady": ready,
                "stale": stale,
                "ttlMinutes": int(self.ttl.total_seconds() // 60),
            }

    def _identity(self, request: dict[str, Any]) -> dict[str, Any]:
        return {field: request.get(field) for field in self._IDENTITY_FIELDS}

    def _mismatch(self, record: dict[str, Any], request: dict[str, Any]) -> str | None:
        for field in (
            *self._IDENTITY_FIELDS,
            "requestDigest",
            "stateVersion",
            "ledgerDigest",
        ):
            if record.get(field) != request.get(field):
                return field
        pending_ids = request.get("pendingTaskIds")
        if pending_ids is not None and record.get("pendingTaskIds") != sorted(
            {int(value) for value in pending_ids}
        ):
            return "pendingTaskIds"
        return None

    def _mismatch_code(self, field: str) -> str:
        if field in {"workflowId", "workflowRevision", "workflowDigest", "outerNodeId"}:
            return "STALE_WORKFLOW"
        if field == "policyRevision":
            return "STALE_POLICY"
        if field in {"stateVersion", "ledgerDigest"}:
            return "STALE_LEDGER_ANCHOR"
        if field == "requestDigest":
            return "STALE_REQUEST"
        if field == "pendingTaskIds":
            return "CHECKPOINT_CONFLICT"
        return "SCOPE_MISMATCH"

    def _response(
        self,
        record: dict[str, Any],
        *,
        status: str | None = None,
        reason: str,
    ) -> dict[str, Any]:
        completed_ids = sorted(int(value) for value in record["taskResults"])
        pending_ids = list(record["pendingTaskIds"])
        return {
            "status": status or record["status"],
            "reason": reason,
            "projectId": record["projectId"],
            "targetId": record["targetId"],
            "runId": record["runId"],
            "nodeRunId": record["nodeRunId"],
            "stateVersion": record["stateVersion"],
            "ledgerDigest": record["ledgerDigest"],
            "pendingTaskIds": pending_ids,
            "completedTaskIds": completed_ids,
            "remainingTaskIds": sorted(set(pending_ids) - set(completed_ids)),
        }

    def _path(self, identity: dict[str, Any]) -> Path:
        project_dir = self.root / f"project-{int(identity['projectId'])}"
        key = hashlib.sha256(
            f"{identity['runId']}\n{identity['nodeRunId']}".encode("utf-8")
        ).hexdigest()
        return project_dir / f"{key}.json"

    def _read(self, path: Path) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryConflict("CHECKPOINT_CORRUPT", "Agent checkpoint 已损坏") from exc
        if not isinstance(value, dict) or value.get("schemaVersion") != 1:
            raise RecoveryConflict("CHECKPOINT_CORRUPT", "Agent checkpoint 格式无效")
        required = {
            *self._IDENTITY_FIELDS,
            "requestDigest",
            "stateVersion",
            "ledgerDigest",
            "pendingTaskIds",
            "taskResults",
            "callbackReceipts",
            "status",
            "expiresAt",
        }
        if not required.issubset(value):
            raise RecoveryConflict("CHECKPOINT_CORRUPT", "Agent checkpoint 字段不完整")
        return value

    def _write(self, path: Path, record: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            temporary.write_text(
                json.dumps(
                    record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _is_expired(self, record: dict[str, Any]) -> bool:
        try:
            return _parse_time(record.get("expiresAt")) < _utc_now()
        except (TypeError, ValueError) as exc:
            raise RecoveryConflict(
                "CHECKPOINT_CORRUPT", "Agent checkpoint 恢复时间格式无效"
            ) from exc

    def _prune_project(self, project_id: int, *, keep: Path) -> list[Path]:
        project_dir = self.root / f"project-{project_id}"
        paths = [path for path in project_dir.glob("*.json") if path != keep]
        if len(paths) < self.max_records_per_project:
            return []
        removable: list[tuple[int, datetime, Path]] = []
        for path in paths:
            record = self._read(path)
            expired = record is None or self._is_expired(record)
            try:
                updated = _parse_time(record.get("updatedAt") if record else None)
            except (TypeError, ValueError):
                updated = datetime.min.replace(tzinfo=timezone.utc)
            if expired or (
                record is not None
                and record.get("status") in {"CONTINUATION_READY", "STALE"}
            ):
                # Expired records are always safe to remove first. Among records
                # with the same lifecycle class, oldest activity is removed first.
                removable.append((0 if expired else 1, updated, path))
        count = len(paths) - self.max_records_per_project + 1
        if len(removable) < count:
            raise RecoveryConflict(
                "RECOVERY_CAPACITY",
                "项目活跃 Agent checkpoint 已达到容量上限",
            )
        return [path for _, _, path in sorted(removable)[:count]]
