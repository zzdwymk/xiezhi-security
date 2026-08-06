from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .config import settings
from .schemas import ProjectDocument
from .security import safe_project_file

logger = logging.getLogger(__name__)


class IndexValidationError(ValueError):
    """可安全返回给调用方的项目索引参数错误。"""


try:  # LlamaIndex is optional at import time so health can explain a bad install.
    from llama_index.core import (
        Document,
        Settings as LlamaSettings,
        StorageContext,
        VectorStoreIndex,
        load_index_from_storage,
    )
    from llama_index.core.embeddings import MockEmbedding

    LLAMA_INDEX_AVAILABLE = True
except Exception:  # pragma: no cover - exercised when optional dependencies are absent
    Document = Any  # type: ignore[misc,assignment]
    LlamaSettings = Any  # type: ignore[misc,assignment]
    StorageContext = Any  # type: ignore[misc,assignment]
    VectorStoreIndex = Any  # type: ignore[misc,assignment]
    load_index_from_storage = None  # type: ignore[assignment]
    MockEmbedding = Any  # type: ignore[misc,assignment]
    LLAMA_INDEX_AVAILABLE = False


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
    """Project-scoped, offline-first RAG store.

    The canonical document file is deliberately separate from the LlamaIndex
    persistence directory. This makes rebuilding deterministic and allows the
    Java service to re-index after a project report or audit changes.
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        self.root = (data_dir or settings.data_dir) / "indexes"
        self.root.mkdir(parents=True, exist_ok=True)
        self._indexes: dict[int, Any] = {}
        self._documents: dict[int, list[dict[str, Any]]] = {}

    def _document_path(self, project_id: int) -> Path:
        return self.root / safe_project_file(project_id)

    def _index_path(self, project_id: int) -> Path:
        return self.root / f"project-{project_id}" / "llama-index"

    def _read_documents(self, project_id: int) -> list[dict[str, Any]]:
        if project_id in self._documents:
            return self._documents[project_id]
        path = self._document_path(project_id)
        if not path.exists():
            self._documents[project_id] = []
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            documents = data.get("documents", []) if isinstance(data, dict) else []
            if not isinstance(documents, list):
                documents = []
        except (OSError, ValueError):
            documents = []
        self._documents[project_id] = documents
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
        return digest

    def index_project(
        self, project_id: int, incoming: list[ProjectDocument], replace: bool = True
    ) -> dict[str, Any]:
        if not 0 < len(incoming) <= settings.max_documents:
            raise IndexValidationError(
                f"资料数量必须在 1 到 {settings.max_documents} 条之间"
            )
        cleaned = [_clean_document(document) for document in incoming]
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
        if len(documents) > settings.max_documents:
            raise IndexValidationError(
                f"项目资料总数不能超过 {settings.max_documents} 条"
            )
        digest = self._persist_documents(project_id, documents)
        self._documents[project_id] = documents
        self._indexes.pop(project_id, None)
        llama_status = "UNAVAILABLE"
        if LLAMA_INDEX_AVAILABLE:
            try:
                self._build_llama_index(project_id, documents)
                llama_status = "READY"
            except Exception:  # keep lexical fallback usable
                logger.exception("LlamaIndex 项目索引构建失败，已切换到词法检索")
                llama_status = "DEGRADED"
        return {
            "projectId": project_id,
            "documentCount": len(documents),
            "sha256": digest,
            "engine": "llama-index" if llama_status == "READY" else "lexical-fallback",
            "status": llama_status,
        }

    def _build_llama_index(
        self, project_id: int, documents: list[dict[str, Any]]
    ) -> Any:
        if not LLAMA_INDEX_AVAILABLE:
            return None
        index_path = self._index_path(project_id)
        if index_path.exists():
            shutil.rmtree(index_path, ignore_errors=True)
        index_path.mkdir(parents=True, exist_ok=True)
        # MockEmbedding keeps the desktop runtime offline and deterministic. It
        # is still a real LlamaIndex vector index and can later be replaced by a
        # locally installed embedding model without changing the API.
        LlamaSettings.embed_model = MockEmbedding(embed_dim=256)
        llama_documents = [
            Document(
                text=f"标题：{item['title']}\n来源：{item['source']}\n{item['text']}",
                metadata={
                    **item.get("metadata", {}),
                    "title": item["title"],
                    "source": item["source"],
                },
            )
            for item in documents
        ]
        index = VectorStoreIndex.from_documents(llama_documents, show_progress=False)
        index.storage_context.persist(persist_dir=str(index_path))
        self._indexes[project_id] = index
        return index

    def _get_llama_index(self, project_id: int) -> Any:
        if not LLAMA_INDEX_AVAILABLE:
            return None
        if project_id in self._indexes:
            return self._indexes[project_id]
        documents = self._read_documents(project_id)
        if not documents:
            return None
        index_path = self._index_path(project_id)
        if index_path.exists() and any(index_path.iterdir()):
            try:
                LlamaSettings.embed_model = MockEmbedding(embed_dim=256)
                storage = StorageContext.from_defaults(persist_dir=str(index_path))
                index = load_index_from_storage(storage)
                self._indexes[project_id] = index
                return index
            except Exception:
                pass
        return self._build_llama_index(project_id, documents)

    def query(
        self, project_id: int, query: str, top_k: int = 5
    ) -> list[dict[str, Any]]:
        query = query.strip()
        if not query:
            return []
        top_k = min(max(top_k, 1), 10)
        index = self._get_llama_index(project_id)
        if index is not None:
            try:
                # A retriever performs vector search without invoking a default
                # LLM, keeping project RAG fully local when no model is enabled.
                source_nodes = index.as_retriever(similarity_top_k=top_k).retrieve(
                    query
                )
                results: list[dict[str, Any]] = []
                for node_with_score in source_nodes[:top_k]:
                    node = getattr(node_with_score, "node", node_with_score)
                    metadata = node.metadata if getattr(node, "metadata", None) else {}
                    results.append(
                        {
                            "title": metadata.get("title", "项目资料"),
                            "source": metadata.get("source", "project"),
                            "text": str(getattr(node, "text", ""))[:4000],
                            "score": float(
                                getattr(node_with_score, "score", 0.0) or 0.0
                            ),
                        }
                    )
                if results:
                    return results
            except Exception:
                pass
        return self._lexical_query(project_id, query, top_k)

    def _lexical_query(
        self, project_id: int, query: str, top_k: int
    ) -> list[dict[str, Any]]:
        terms = {
            term.lower() for term in re.findall(r"[\w.-]+", query) if len(term) > 1
        }
        scored: list[tuple[int, dict[str, Any]]] = []
        for item in self._read_documents(project_id):
            haystack = f"{item['title']} {item['source']} {item['text']}".lower()
            score = sum(haystack.count(term) for term in terms)
            if score:
                scored.append((score, item))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [
            {
                "title": item["title"],
                "source": item["source"],
                "text": item["text"][:4000],
                "score": float(score),
            }
            for score, item in scored[:top_k]
        ]

    def list_documents(
        self, project_id: int, source: str | None = None
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "source": item.get("source"),
                "chars": len(item.get("text", "")),
                "conversationId": item.get("metadata", {}).get("conversationId"),
                "createdAt": item.get("metadata", {}).get("createdAt"),
            }
            for item in self._read_documents(project_id)
            if source is None or item.get("source") == source
        ]

    def delete_document(self, project_id: int, doc_id: str) -> dict[str, Any]:
        documents = self._read_documents(project_id)
        remaining = [item for item in documents if str(item.get("id")) != str(doc_id)]
        if len(remaining) == len(documents):
            return {"deleted": False, "documentCount": len(documents)}
        self._persist_documents(project_id, remaining)
        self._documents[project_id] = remaining
        self._indexes.pop(project_id, None)
        if LLAMA_INDEX_AVAILABLE and remaining:
            try:
                self._build_llama_index(project_id, remaining)
            except Exception:
                pass
        return {"deleted": True, "documentCount": len(remaining)}

    def clear_documents_by_source(self, project_id: int, source: str) -> dict[str, Any]:
        """Remove every document whose source matches, then rebuild the index."""
        source = (source or "").strip()
        if not source:
            raise IndexValidationError("资料来源不能为空")
        documents = self._read_documents(project_id)
        remaining = [item for item in documents if item.get("source") != source]
        removed = len(documents) - len(remaining)
        if removed <= 0:
            return {"deleted": 0, "documentCount": len(documents)}
        self._persist_documents(project_id, remaining)
        self._documents[project_id] = remaining
        self._indexes.pop(project_id, None)
        if LLAMA_INDEX_AVAILABLE and remaining:
            try:
                self._build_llama_index(project_id, remaining)
            except Exception:
                pass
        return {"deleted": removed, "documentCount": len(remaining)}

    def stats(self) -> dict[str, Any]:
        projects = []
        for path in self.root.glob("project-*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                projects.append(
                    {
                        "projectId": data.get("projectId"),
                        "documentCount": len(data.get("documents", [])),
                        "sha256": data.get("sha256"),
                    }
                )
            except (OSError, ValueError):
                continue
        return {"engineAvailable": LLAMA_INDEX_AVAILABLE, "projects": projects}
