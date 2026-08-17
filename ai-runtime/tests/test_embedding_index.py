from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.embedding import EmbeddingProviderRequestError
from app.indexing import IndexValidationError, ProjectIndexStore
from app.schemas import ProjectDocument


class FakeEmbeddingProvider:
    model = "fake-security-embedding-v1"
    dimension = 2
    max_batch_size = 8

    def __init__(self) -> None:
        self.document_batches: list[list[str]] = []
        self.query_inputs: list[str] = []
        self.fail_documents = False
        self.fail_query = False

    @staticmethod
    def _vector(text: str) -> list[float]:
        if "closest" in text:
            return [1.0, 0.0]
        if "related" in text:
            return [0.8, 0.6]
        if "opposite" in text:
            return [-1.0, 0.0]
        if "query-vector" in text:
            return [1.0, 0.0]
        return [0.0, 1.0]

    def embed_documents(self, texts) -> list[list[float]]:
        values = list(texts)
        self.document_batches.append(values)
        if self.fail_documents:
            raise EmbeddingProviderRequestError("fake document failure")
        return [self._vector(value) for value in values]

    def embed_query(self, text: str) -> list[float]:
        self.query_inputs.append(text)
        if self.fail_query:
            raise EmbeddingProviderRequestError("fake query failure")
        return self._vector(text)


def _document(
    doc_id: str,
    text: str,
    *,
    title: str = "Evidence",
    source: str = "project",
    metadata: dict[str, str] | None = None,
) -> ProjectDocument:
    return ProjectDocument(
        id=doc_id,
        title=title,
        text=text,
        source=source,
        metadata=metadata or {},
    )


def _store(tmp_path, provider: FakeEmbeddingProvider) -> ProjectIndexStore:
    return ProjectIndexStore(
        tmp_path,
        retrieval_backend="real_embedding",
        embedding_provider=provider,
    )


def test_real_embedding_orders_by_cosine_and_marks_retrieval_method(tmp_path):
    provider = FakeEmbeddingProvider()
    store = _store(tmp_path, provider)
    indexed = store.index_project(
        1,
        [
            _document("related", "related evidence"),
            _document("closest", "closest evidence"),
            _document("opposite", "opposite evidence"),
        ],
    )

    matches = store.query(1, "query-vector", 10)
    bundle = store.evidence_bundle(1, "query-vector", 0, None, None)

    assert indexed["engine"] == "openai-compatible-embedding"
    assert indexed["retrievalMethod"] == "real_embedding"
    assert [item["documentId"] for item in matches] == ["closest", "related"]
    assert all(item["retrievalMethod"] == "real_embedding" for item in matches)
    assert matches[0]["score"] > matches[1]["score"]
    assert bundle["retrievalMethod"] == "real_embedding"


def test_persisted_vectors_are_reused_after_store_restart(tmp_path):
    first_provider = FakeEmbeddingProvider()
    first = _store(tmp_path, first_provider)
    first.index_project(
        2,
        [
            _document("doc-a", "closest persisted evidence"),
            _document("doc-b", "related persisted evidence"),
        ],
    )
    assert sum(map(len, first_provider.document_batches)) == 2

    second_provider = FakeEmbeddingProvider()
    restarted = _store(tmp_path, second_provider)
    matches = restarted.query(2, "query-vector", 2)

    assert second_provider.document_batches == []
    assert second_provider.query_inputs == ["query-vector"]
    assert [item["documentId"] for item in matches] == ["doc-a", "doc-b"]


def test_content_update_only_reembeds_the_changed_document(tmp_path):
    provider = FakeEmbeddingProvider()
    store = _store(tmp_path, provider)
    store.index_project(
        3,
        [
            _document("stable", "closest unchanged evidence"),
            _document("mutable", "related old evidence"),
        ],
    )
    provider.document_batches.clear()

    store.index_project(
        3,
        [
            _document("stable", "closest unchanged evidence"),
            _document("mutable", "opposite updated evidence"),
        ],
    )

    assert len(provider.document_batches) == 1
    assert len(provider.document_batches[0]) == 1
    assert "opposite updated evidence" in provider.document_batches[0][0]
    assert "closest unchanged evidence" not in provider.document_batches[0][0]
    assert [item["documentId"] for item in store.query(3, "query-vector", 5)] == [
        "stable"
    ]


def test_scope_and_ttl_filter_before_query_embedding_or_ranking(tmp_path):
    provider = FakeEmbeddingProvider()
    store = _store(tmp_path, provider)
    now = datetime.now(timezone.utc)
    store.index_project(
        7,
        [
            _document(
                "other-target",
                "closest hidden target evidence",
                metadata={"targetId": "71"},
            ),
            _document(
                "other-conversation",
                "closest hidden conversation evidence",
                source="conversation",
                metadata={
                    "conversationId": "conversation-b",
                    "targetId": "70",
                    "createdAt": now.isoformat(),
                },
            ),
            _document(
                "expired-conversation",
                "closest expired conversation evidence",
                source="conversation",
                metadata={
                    "conversationId": "conversation-a",
                    "targetId": "70",
                    "createdAt": (now - timedelta(days=2)).isoformat(),
                },
            ),
        ],
    )
    store.index_project(8, [_document("other-project", "closest project evidence")])

    # Expired conversation memory is removed before indexing; target/project and
    # conversation visibility then leave no candidates before query embedding.
    embedded_text = "\n".join(
        text for batch in provider.document_batches for text in batch
    )
    assert "expired conversation evidence" not in embedded_text
    provider.query_inputs.clear()

    matches = store.query(
        7,
        "query-vector",
        10,
        conversation_id="conversation-a",
        target_id=70,
    )

    assert matches == []
    assert provider.query_inputs == []
    assert "other-project" not in {item["documentId"] for item in matches}


def test_provider_failure_is_fail_closed_without_bm25_fallback(tmp_path):
    provider = FakeEmbeddingProvider()
    store = _store(tmp_path, provider)
    store.index_project(9, [_document("doc", "closest lexical keyword")])
    provider.fail_query = True

    with pytest.raises(IndexValidationError, match="Embedding 服务调用失败"):
        store.query(9, "query-vector lexical keyword", 1)

    assert provider.query_inputs == ["query-vector lexical keyword"]

    failed_provider = FakeEmbeddingProvider()
    failed_provider.fail_documents = True
    failed_store = _store(tmp_path / "failed", failed_provider)
    with pytest.raises(IndexValidationError, match="Embedding 服务调用失败"):
        failed_store.index_project(10, [_document("doc", "closest evidence")])
    assert failed_store.project_stats(10) is None


def test_stats_and_health_expose_real_embedding_state(tmp_path, monkeypatch):
    provider = FakeEmbeddingProvider()
    store = _store(tmp_path, provider)
    store.index_project(11, [_document("doc", "closest health evidence")])

    stats = store.stats()
    assert stats["engineAvailable"] is True
    assert stats["retrievalReady"] is True
    assert stats["retrievalMethod"] == "real_embedding"
    assert stats["configuredBackend"] == "real_embedding"
    assert stats["realEmbeddingAvailable"] is True
    assert stats["embeddingModel"] == provider.model
    assert stats["embeddingDimension"] == provider.dimension
    assert stats["embeddingProviderError"] is None

    from app import main as main_module

    monkeypatch.setattr(main_module, "index_store", store)
    health = asyncio.run(main_module.health())

    assert health["components"]["retrieval"] is True
    assert health["components"]["embedding"] is True
    assert health["components"]["llamaIndex"] is True
    assert health["index"]["retrievalMethod"] == "real_embedding"
    assert health["index"]["realEmbeddingAvailable"] is True
