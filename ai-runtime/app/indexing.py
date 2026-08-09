from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple

from rank_bm25 import BM25Plus

from .config import settings
from .schemas import ProjectDocument
from .security import safe_project_file

logger = logging.getLogger(__name__)


class IndexValidationError(ValueError):
    """可安全返回给调用方的项目索引参数错误。"""


def _module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (AttributeError, ImportError, ModuleNotFoundError):
        return False


# Kept as compatibility probes for callers/tests that still inspect the old optional
# backend. MockEmbedding is intentionally not a valid retrieval backend.
LLAMA_INDEX_AVAILABLE = False
_llama_api = None
_llama_load_attempted = True


def _load_llama_api() -> None:
    return None


def llama_index_available() -> bool:
    return False


_TOKEN_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,}"
    r"|(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
    r"|(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![\w.-])"
    r"|(?<!\w)\d{1,5}/(?:tcp|udp)(?!\w)"
    r"|(?<!\w)tls(?:v)?\d(?:\.\d+)?(?!\w)"
    r"|[a-z][a-z0-9]*(?:[._+#-][a-z0-9]+)*"
    r"|\d+"
    r"|[\u3400-\u4dbf\u4e00-\u9fff]+",
    re.IGNORECASE,
)


def tokenize_for_bm25(value: str) -> list[str]:
    """Stable offline tokenizer with intact security identifiers and CJK n-grams."""
    normalized = unicodedata.normalize("NFKC", value or "").casefold()
    tokens: list[str] = []
    for match in _TOKEN_PATTERN.finditer(normalized):
        token = match.group(0)
        if re.fullmatch(r"[\u3400-\u4dbf\u4e00-\u9fff]+", token):
            tokens.extend(token)
            tokens.extend(token[index : index + 2] for index in range(len(token) - 1))
        else:
            tokens.append(token)
    return tokens


class _Bm25Corpus(NamedTuple):
    revision: str
    entries: tuple[tuple[dict[str, Any], tuple[str, ...]], ...]


def _canonical_documents(documents: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        documents, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _clean_document(document: ProjectDocument) -> dict[str, Any]:
    metadata = {
        str(key)[:80]: str(value)[:500]
        for key, value in document.metadata.items()
        if str(key).strip()
    }
    title = document.title.strip()
    text = document.text
    doc_id = (document.id or "").strip() or hashlib.sha256(
        f"{document.source}|{title}|{text}".encode("utf-8")
    ).hexdigest()[:16]
    return {
        "id": doc_id,
        "title": title,
        "text": text,
        "source": document.source.strip(),
        "metadata": metadata,
    }


def _merge_by_id(
    existing: list[dict[str, Any]], incoming: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in existing + incoming:
        merged[str(item.get("id"))] = item
    return list(merged.values())


class ProjectIndexStore:
    """Project-scoped, offline-first BM25 evidence store.

    Canonical documents remain the source of truth. Token caches are derived,
    bounded per project, and invalidated after every document mutation.
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        *,
        document_cache_chars: int | None = None,
        document_cache_projects: int | None = None,
        index_cache_projects: int | None = None,
    ) -> None:
        self.root = (data_dir or settings.data_dir) / "indexes"
        self.root.mkdir(parents=True, exist_ok=True)
        self._indexes: OrderedDict[int, Any] = OrderedDict()
        self._documents: OrderedDict[int, list[dict[str, Any]]] = OrderedDict()
        self._document_cache_sizes: dict[int, int] = {}
        self._cached_document_chars = 0
        self._document_cache_chars = max(
            0,
            settings.document_cache_chars
            if document_cache_chars is None
            else int(document_cache_chars),
        )
        self._document_cache_projects = max(
            0,
            settings.document_cache_projects
            if document_cache_projects is None
            else int(document_cache_projects),
        )
        self._index_cache_projects = max(
            0,
            settings.index_cache_projects
            if index_cache_projects is None
            else int(index_cache_projects),
        )
        self._cache_lock = threading.RLock()
        self._project_locks = tuple(threading.RLock() for _ in range(64))
        self._stats_lock = threading.RLock()
        self._project_stats: dict[int, dict[str, Any]] = {}
        self._stats_loaded = False

    def _project_lock(self, project_id: int) -> threading.RLock:
        return self._project_locks[project_id % len(self._project_locks)]

    def _document_path(self, project_id: int) -> Path:
        return self.root / safe_project_file(project_id)

    def _index_path(self, project_id: int) -> Path:
        return self.root / f"project-{project_id}" / "llama-index"

    @staticmethod
    def _documents_chars(documents: list[dict[str, Any]]) -> int:
        return sum(
            len(str(item.get("title", "")))
            + len(str(item.get("text", "")))
            + len(str(item.get("source", "")))
            + sum(
                len(str(key)) + len(str(value))
                for key, value in item.get("metadata", {}).items()
            )
            for item in documents
        )

    def _get_cached_documents(
        self, project_id: int
    ) -> list[dict[str, Any]] | None:
        with self._cache_lock:
            if project_id not in self._documents:
                return None
            documents = self._documents.pop(project_id)
            self._documents[project_id] = documents
            return documents

    def _cache_documents(
        self, project_id: int, documents: list[dict[str, Any]]
    ) -> None:
        size = self._documents_chars(documents)
        with self._cache_lock:
            self._documents.pop(project_id, None)
            self._cached_document_chars -= self._document_cache_sizes.pop(
                project_id, 0
            )
            if (
                self._document_cache_chars <= 0
                or self._document_cache_projects <= 0
                or size > self._document_cache_chars
            ):
                return
            self._documents[project_id] = documents
            self._document_cache_sizes[project_id] = size
            self._cached_document_chars += size
            while self._documents and (
                self._cached_document_chars > self._document_cache_chars
                or len(self._documents) > self._document_cache_projects
            ):
                evicted_id, _ = self._documents.popitem(last=False)
                self._cached_document_chars -= self._document_cache_sizes.pop(
                    evicted_id, 0
                )

    def _get_cached_index(self, project_id: int) -> Any:
        with self._cache_lock:
            if project_id not in self._indexes:
                return None
            index = self._indexes.pop(project_id)
            self._indexes[project_id] = index
            return index

    def _cache_index(self, project_id: int, index: Any) -> None:
        with self._cache_lock:
            self._indexes.pop(project_id, None)
            if self._index_cache_projects <= 0:
                return
            self._indexes[project_id] = index
            while len(self._indexes) > self._index_cache_projects:
                self._indexes.popitem(last=False)

    def _drop_cached_index(self, project_id: int) -> None:
        with self._cache_lock:
            self._indexes.pop(project_id, None)

    @staticmethod
    def _revision(documents: list[dict[str, Any]]) -> str:
        return "sha256:" + hashlib.sha256(_canonical_documents(documents)).hexdigest()

    @staticmethod
    def _content_digest(document: dict[str, Any]) -> str:
        canonical = json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _get_bm25_corpus(
        self,
        project_id: int,
        documents: list[dict[str, Any]],
        deadline: float,
    ) -> _Bm25Corpus:
        cached = self._get_cached_index(project_id)
        if isinstance(cached, _Bm25Corpus):
            return cached
        revision = self._revision(documents)
        entries: list[tuple[dict[str, Any], tuple[str, ...]]] = []
        for item in documents:
            if time.monotonic() > deadline:
                raise IndexValidationError("项目资料检索超时")
            tokens = (
                tokenize_for_bm25(str(item.get("title", ""))) * 2
                + tokenize_for_bm25(str(item.get("source", "")))
                + tokenize_for_bm25(str(item.get("text", "")))
            )
            entries.append((item, tuple(tokens)))
        corpus = _Bm25Corpus(revision, tuple(entries))
        self._cache_index(project_id, corpus)
        return corpus

    def _read_documents(self, project_id: int) -> list[dict[str, Any]]:
        cached = self._get_cached_documents(project_id)
        if cached is not None:
            return cached
        path = self._document_path(project_id)
        if not path.exists():
            self._cache_documents(project_id, [])
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            documents = data.get("documents", []) if isinstance(data, dict) else []
            if not isinstance(documents, list):
                documents = []
            with self._stats_lock:
                self._project_stats[project_id] = {
                    "projectId": project_id,
                    "documentCount": len(documents),
                    "sha256": data.get("sha256") if isinstance(data, dict) else None,
                }
        except (OSError, ValueError):
            documents = []
        self._cache_documents(project_id, documents)
        return documents

    def _persist_documents(
        self, project_id: int, documents: list[dict[str, Any]]
    ) -> str:
        payload = _canonical_documents(documents)
        digest = hashlib.sha256(payload).hexdigest()
        record = {
            "projectId": project_id,
            "updatedAt": __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .isoformat(),
            "sha256": digest,
            "documents": documents,
        }
        path = self._document_path(project_id)
        temporary = path.with_suffix(f".tmp-{__import__('os').getpid()}")
        temporary.write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporary.replace(path)
        with self._stats_lock:
            self._project_stats[project_id] = {
                "projectId": project_id,
                "documentCount": len(documents),
                "sha256": digest,
            }
        return digest

    def index_project(
        self, project_id: int, incoming: list[ProjectDocument], replace: bool = True
    ) -> dict[str, Any]:
        with self._project_lock(project_id):
            return self._index_project_locked(project_id, incoming, replace)

    def _index_project_locked(
        self, project_id: int, incoming: list[ProjectDocument], replace: bool
    ) -> dict[str, Any]:
        if not 0 < len(incoming) <= settings.max_documents:
            raise IndexValidationError(
                f"资料数量必须在 1 到 {settings.max_documents} 条之间"
            )
        cleaned = [_clean_document(document) for document in incoming]
        for document in cleaned:
            if document.get("source") == "conversation" and not self._valid_conversation_document(
                document
            ):
                raise IndexValidationError("会话记忆必须绑定 conversationId、targetId 和 createdAt")
        if any(
            len(document["text"]) > settings.max_document_chars for document in cleaned
        ):
            raise IndexValidationError(
                f"单份项目资料不能超过 {settings.max_document_chars} 个字符"
            )
        if replace:
            # Replacing project materials must NOT wipe conversation memory: keep
            # any existing source=='conversation' documents and merge the rest.
            existing = self._read_documents(project_id)
            preserved = [d for d in existing if d.get("source") == "conversation"]
            documents = _merge_by_id(preserved, cleaned)
        else:
            documents = _merge_by_id(self._read_documents(project_id), cleaned)
        documents = self._bounded_conversation_documents(documents)
        if len(documents) > settings.max_documents:
            raise IndexValidationError(
                f"项目资料总数不能超过 {settings.max_documents} 条"
            )
        digest = self._persist_documents(project_id, documents)
        self._cache_documents(project_id, documents)
        self._drop_cached_index(project_id)
        legacy_vector_failure = False
        if LLAMA_INDEX_AVAILABLE:
            try:
                legacy_vector_failure = _load_llama_api() is None
            except Exception:
                legacy_vector_failure = True
        return {
            "projectId": project_id,
            "documentCount": len(documents),
            "sha256": digest,
            "engine": "lexical-fallback" if legacy_vector_failure else "bm25",
            "retrievalMethod": "bm25",
            "indexRevision": f"sha256:{digest}",
            "configuredBackend": settings.retrieval_backend,
            "status": "DEGRADED" if legacy_vector_failure else "READY",
        }

    def query(
        self,
        project_id: int,
        query: str,
        top_k: int = 5,
        conversation_id: str | None = None,
        target_id: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._project_lock(project_id):
            return self._query_locked(
                project_id, query, top_k, conversation_id, target_id
            )

    def _query_locked(
        self,
        project_id: int,
        query: str,
        top_k: int,
        conversation_id: str | None,
        target_id: int | None,
    ) -> list[dict[str, Any]]:
        query = query.strip()
        if not settings.rag_enabled or not query:
            return []
        top_k = min(max(top_k, 1), 10)
        deadline = time.monotonic() + settings.retrieval_timeout_seconds
        return self._bm25_query(
            project_id, query, top_k, conversation_id, target_id, deadline
        )

    def _bm25_query(
        self,
        project_id: int,
        query: str,
        top_k: int,
        conversation_id: str | None = None,
        target_id: int | None = None,
        deadline: float | None = None,
    ) -> list[dict[str, Any]]:
        deadline = deadline or time.monotonic() + settings.retrieval_timeout_seconds
        query_tokens = tokenize_for_bm25(query)
        if not query_tokens:
            return []
        corpus = self._get_bm25_corpus(
            project_id, self._read_documents(project_id), deadline
        )
        visible = [
            (item, tokens)
            for item, tokens in corpus.entries
            if self._visible_to_conversation(
                str(item.get("source") or "project"),
                item.get("metadata", {}),
                conversation_id,
                target_id,
            )
        ]
        if not visible:
            return []

        if time.monotonic() > deadline:
            raise IndexValidationError("项目资料检索超时")
        ranker = BM25Plus([list(tokens) for _, tokens in visible])
        scores = ranker.get_scores(query_tokens)
        query_token_set = set(query_tokens)
        scored: list[tuple[float, str, dict[str, Any]]] = []
        for (item, tokens), raw_score in zip(visible, scores, strict=True):
            if time.monotonic() > deadline:
                raise IndexValidationError("项目资料检索超时")
            if query_token_set.isdisjoint(tokens):
                continue
            score = float(raw_score)
            document_id = str(item.get("id") or "")
            content_digest = self._content_digest(item)
            evidence_seed = json.dumps(
                {
                    "projectId": project_id,
                    "targetId": target_id,
                    "conversationId": conversation_id,
                    "documentId": document_id,
                    "contentDigest": content_digest,
                    "indexRevision": corpus.revision,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            stored_target = self._metadata_target_id(item.get("metadata", {}))
            result = {
                "evidenceId": "ev-" + hashlib.sha256(evidence_seed).hexdigest()[:24],
                "documentId": document_id,
                "title": str(item.get("title") or "项目资料"),
                "source": str(item.get("source") or "project"),
                "text": str(item.get("text") or "")[:4000],
                "score": round(float(score), 12),
                "targetId": stored_target if stored_target is not None else target_id,
                "contentDigest": content_digest,
                "indexRevision": corpus.revision,
                "retrievalMethod": "bm25",
            }
            scored.append((score, document_id, result))
        scored.sort(key=lambda match: (-match[0], match[1]))
        return [result for _, _, result in scored[:top_k]]

    def _lexical_query(
        self,
        project_id: int,
        query: str,
        top_k: int,
        conversation_id: str | None = None,
        target_id: int | None = None,
    ) -> list[dict[str, Any]]:
        return self._bm25_query(
            project_id, query, top_k, conversation_id, target_id
        )

    def build_evidence_bundle(
        self,
        project_id: int,
        query: str,
        round: int,
        conversation_id: str | None,
        target_id: int | None,
        top_k: int | None = None,
    ) -> dict[str, Any]:
        return self.evidence_bundle(
            project_id,
            query,
            round,
            conversation_id,
            target_id,
            top_k=top_k,
        )

    def evidence_bundle(
        self,
        project_id: int,
        query: str,
        round: int,
        conversation_id: str | None,
        target_id: int | None,
        top_k: int | None = None,
        max_chars: int | None = None,
    ) -> dict[str, Any]:
        with self._project_lock(project_id):
            if round < 0 or round >= settings.max_retrieval_rounds:
                raise IndexValidationError("检索轮次超过运行时限制")
            item_limit = min(
                max(top_k or settings.max_evidence_items, 1),
                settings.max_evidence_items,
                10,
            )
            char_limit = min(
                max(
                    settings.max_evidence_chars
                    if max_chars is None
                    else int(max_chars),
                    0,
                ),
                settings.max_evidence_chars,
            )
            documents = self._read_documents(project_id)
            revision = self._revision(documents)
            matches = self._query_locked(
                project_id,
                query,
                item_limit,
                conversation_id,
                target_id,
            )
            items: list[dict[str, Any]] = []
            used_chars = 0
            for match in matches:
                remaining = char_limit - used_chars
                if remaining <= 0:
                    break
                snippet = str(match.get("text") or "")[: min(remaining, 2000)]
                if not snippet:
                    continue
                used_chars += len(snippet)
                items.append(
                    {
                        "evidenceId": match["evidenceId"],
                        "documentId": match["documentId"],
                        "source": match["source"],
                        "title": match["title"],
                        "snippet": snippet,
                        "score": match["score"],
                        "targetId": match["targetId"],
                        "contentDigest": match["contentDigest"],
                    }
                )
            return {
                "projectId": project_id,
                "targetId": target_id,
                "conversationId": conversation_id,
                "query": query.strip(),
                "round": round,
                "retrievalMethod": "bm25",
                "indexRevision": revision,
                "items": items,
            }

    @staticmethod
    def _metadata_target_id(metadata: dict[str, Any]) -> int | None:
        value = str(metadata.get("targetId") or "").strip()
        if not value.isdigit():
            return None
        parsed = int(value)
        return parsed if parsed > 0 else None

    def _visible_to_conversation(
        self,
        source: str,
        metadata: dict[str, Any],
        conversation_id: str | None,
        target_id: int | None,
    ) -> bool:
        stored_target_id = self._metadata_target_id(metadata)
        if source != "conversation":
            raw_target_id = str(metadata.get("targetId") or "").strip()
            if raw_target_id and stored_target_id is None:
                return False
            return not raw_target_id or (
                target_id is not None and stored_target_id == target_id
            )
        created_at = self._conversation_created_at(metadata)
        if created_at is None or created_at < datetime.now(timezone.utc) - timedelta(
            minutes=settings.conversation_memory_ttl_minutes
        ):
            return False
        stored_id = str(metadata.get("conversationId") or "")
        return (
            bool(conversation_id)
            and stored_id == conversation_id
            and (target_id is None or stored_target_id == target_id)
        )

    def _valid_conversation_document(self, document: dict[str, Any]) -> bool:
        metadata = document.get("metadata", {})
        created_at = self._conversation_created_at(metadata)
        return (
            bool(str(metadata.get("conversationId") or "").strip())
            and str(metadata.get("targetId") or "").isdigit()
            and created_at is not None
            and created_at <= datetime.now(timezone.utc) + timedelta(minutes=5)
        )

    def _conversation_created_at(
        self, metadata: dict[str, Any]
    ) -> datetime | None:
        value = str(metadata.get("createdAt") or "").strip()
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _bounded_conversation_documents(
        self, documents: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        threshold = datetime.now(timezone.utc) - timedelta(
            minutes=settings.conversation_memory_ttl_minutes
        )
        regular = [item for item in documents if item.get("source") != "conversation"]
        grouped: dict[tuple[str, str], list[tuple[datetime, dict[str, Any]]]] = {}
        for item in documents:
            if item.get("source") != "conversation":
                continue
            metadata = item.get("metadata", {})
            created_at = self._conversation_created_at(metadata)
            if (
                created_at is None
                or created_at < threshold
                or created_at > datetime.now(timezone.utc) + timedelta(minutes=5)
            ):
                continue
            key = (
                str(metadata.get("conversationId") or ""),
                str(metadata.get("targetId") or ""),
            )
            grouped.setdefault(key, []).append((created_at, item))
        memories: list[dict[str, Any]] = []
        for items in grouped.values():
            items.sort(key=lambda pair: pair[0], reverse=True)
            memories.extend(
                item for _, item in items[: settings.conversation_memory_documents]
            )
        return regular + memories

    def list_documents(
        self, project_id: int, source: str | None = None
    ) -> list[dict[str, Any]]:
        with self._project_lock(project_id):
            return [
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "source": item.get("source"),
                    "chars": len(item.get("text", "")),
                    "conversationId": item.get("metadata", {}).get(
                        "conversationId"
                    ),
                    "createdAt": item.get("metadata", {}).get("createdAt"),
                }
                for item in self._read_documents(project_id)
                if source is None or item.get("source") == source
            ]

    def delete_document(
        self, project_id: int, doc_id: str, expected_source: str
    ) -> dict[str, Any]:
        with self._project_lock(project_id):
            return self._delete_document_locked(project_id, doc_id, expected_source)

    def _delete_document_locked(
        self, project_id: int, doc_id: str, expected_source: str
    ) -> dict[str, Any]:
        source = (expected_source or "").strip()
        if not source:
            raise IndexValidationError("删除资料时必须指定资料来源")
        documents = self._read_documents(project_id)
        remaining = [
            item
            for item in documents
            if str(item.get("id")) != str(doc_id)
            or str(item.get("source") or "") != source
        ]
        if len(remaining) == len(documents):
            return {"deleted": False, "documentCount": len(documents)}
        self._persist_documents(project_id, remaining)
        self._cache_documents(project_id, remaining)
        self._drop_cached_index(project_id)
        return {"deleted": True, "documentCount": len(remaining)}

    def clear_documents_by_source(
        self, project_id: int, source: str, conversation_id: str | None = None
    ) -> dict[str, Any]:
        """Remove every document whose source matches, then rebuild the index."""
        with self._project_lock(project_id):
            return self._clear_documents_by_source_locked(
                project_id, source, conversation_id
            )

    def _clear_documents_by_source_locked(
        self, project_id: int, source: str, conversation_id: str | None
    ) -> dict[str, Any]:
        source = (source or "").strip()
        if not source:
            raise IndexValidationError("资料来源不能为空")
        documents = self._read_documents(project_id)
        remaining = [
            item
            for item in documents
            if item.get("source") != source
            or (
                conversation_id is not None
                and str(item.get("metadata", {}).get("conversationId") or "")
                != conversation_id
            )
        ]
        removed = len(documents) - len(remaining)
        if removed <= 0:
            return {"deleted": 0, "documentCount": len(documents)}
        self._persist_documents(project_id, remaining)
        self._cache_documents(project_id, remaining)
        self._drop_cached_index(project_id)
        return {"deleted": removed, "documentCount": len(remaining)}

    def stats(self) -> dict[str, Any]:
        with self._stats_lock:
            if not self._stats_loaded:
                for path in self.root.glob("project-*.json"):
                    try:
                        data = json.loads(path.read_text(encoding="utf-8"))
                        project_id = int(data.get("projectId"))
                        self._project_stats[project_id] = {
                            "projectId": project_id,
                            "documentCount": len(data.get("documents", [])),
                            "sha256": data.get("sha256"),
                        }
                    except (OSError, TypeError, ValueError):
                        continue
                self._stats_loaded = True
            return {
                "engineAvailable": True,
                "retrievalReady": True,
                "ragEnabled": settings.rag_enabled,
                "retrievalMethod": "bm25",
                "configuredBackend": settings.retrieval_backend,
                "realEmbeddingAvailable": False,
                "mockEmbedding": "DISABLED",
                "projects": sorted(
                    (dict(value) for value in self._project_stats.values()),
                    key=lambda value: int(value["projectId"]),
                ),
            }

    def project_stats(self, project_id: int) -> dict[str, Any] | None:
        with self._project_lock(project_id):
            with self._stats_lock:
                value = self._project_stats.get(project_id)
                if value is not None:
                    return dict(value)
            path = self._document_path(project_id)
            if not path.exists():
                return None
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                value = {
                    "projectId": int(data.get("projectId")),
                    "documentCount": len(data.get("documents", [])),
                    "sha256": data.get("sha256"),
                }
            except (OSError, TypeError, ValueError):
                return None
            with self._stats_lock:
                self._project_stats[project_id] = value
            return dict(value)
