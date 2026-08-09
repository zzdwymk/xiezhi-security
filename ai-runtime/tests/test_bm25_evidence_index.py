from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import settings
from app.indexing import ProjectIndexStore, tokenize_for_bm25
from app.schemas import ProjectDocument


def _document(
    doc_id: str,
    title: str,
    text: str,
    *,
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


def test_security_tokenizer_preserves_identifiers_and_adds_chinese_ngrams():
    tokens = tokenize_for_bm25(
        "检查 CVE-2025-1234、192.168.1.10、example.com、443/tcp、TLS1.2 高危漏洞"
    )

    assert {
        "cve-2025-1234",
        "192.168.1.10",
        "example.com",
        "443/tcp",
        "tls1.2",
        "高危",
        "漏洞",
    }.issubset(tokens)
    assert tokens == tokenize_for_bm25(
        "检查 CVE-2025-1234、192.168.1.10、example.com、443/tcp、TLS1.2 高危漏洞"
    )


def test_rag_runtime_limits_and_bm25_health_defaults():
    assert settings.rag_enabled is True
    assert settings.retrieval_backend == "bm25"
    assert settings.max_retrieval_rounds == 2
    assert settings.max_evidence_items == 5
    assert settings.max_evidence_chars == 10_000
    assert settings.retrieval_timeout_seconds == 5
    assert settings.max_rag_llm_calls == 5
    assert settings.agent_turn_timeout_seconds == 60
    assert settings.graph_recursion_limit == 32


def test_chinese_bm25_relevance_and_evidence_metadata_are_stable(tmp_path):
    store = ProjectIndexStore(tmp_path)
    indexed = store.index_project(
        1,
        [
            _document(
                "finding-critical",
                "example.com 高危 TLS 漏洞",
                "目标 192.168.1.10 的 443/tcp 暴露 TLS1.2，命中 CVE-2025-1234。",
                metadata={"targetId": "10"},
            ),
            _document(
                "inventory",
                "资产清单",
                "内部系统的负责人和普通维护窗口。",
                metadata={"targetId": "10"},
            ),
            _document(
                "finding-low",
                "低风险信息",
                "example.com 提供普通 HTTP 服务。",
                metadata={"targetId": "10"},
            ),
        ],
    )
    stats = store.stats()

    first = store.query(
        1,
        "example.com 的 CVE-2025-1234 TLS1.2 高危漏洞",
        3,
        target_id=10,
    )
    second = store.query(
        1,
        "example.com 的 CVE-2025-1234 TLS1.2 高危漏洞",
        3,
        target_id=10,
    )

    assert first == second
    assert indexed["engine"] == "bm25"
    assert indexed["status"] == "READY"
    assert stats["retrievalReady"] is True
    assert stats["retrievalMethod"] == "bm25"
    assert stats["realEmbeddingAvailable"] is False
    assert stats["mockEmbedding"] == "DISABLED"
    assert first[0]["documentId"] == "finding-critical"
    assert first[0]["targetId"] == 10
    assert first[0]["retrievalMethod"] == "bm25"
    assert first[0]["indexRevision"] == indexed["indexRevision"]
    assert first[0]["contentDigest"].startswith("sha256:")
    assert first[0]["evidenceId"].startswith("ev-")


def test_scope_and_ttl_are_applied_before_bm25_ranking(tmp_path):
    store = ProjectIndexStore(tmp_path)
    now = datetime.now(timezone.utc)
    store.index_project(
        7,
        [
            _document("global", "项目基线", "needle visible baseline"),
            _document(
                "target-visible",
                "目标 70 资料",
                "needle visible target",
                metadata={"targetId": "70"},
            ),
            _document(
                "target-hidden",
                "其他目标资料",
                "needle " * 100,
                metadata={"targetId": "71"},
            ),
            _document(
                "conversation-visible",
                "当前会话",
                "needle visible conversation",
                source="conversation",
                metadata={
                    "conversationId": "conversation-a",
                    "targetId": "70",
                    "createdAt": now.isoformat(),
                },
            ),
            _document(
                "conversation-hidden",
                "其他会话",
                "needle " * 100,
                source="conversation",
                metadata={
                    "conversationId": "conversation-b",
                    "targetId": "70",
                    "createdAt": now.isoformat(),
                },
            ),
            _document(
                "conversation-expired",
                "过期会话",
                "needle " * 100,
                source="conversation",
                metadata={
                    "conversationId": "conversation-a",
                    "targetId": "70",
                    "createdAt": (now - timedelta(days=2)).isoformat(),
                },
            ),
        ],
    )
    store.index_project(
        8,
        [_document("other-project", "其他项目", "needle " * 100)],
    )

    matches = store.query(
        7,
        "needle",
        10,
        conversation_id="conversation-a",
        target_id=70,
    )
    document_ids = {match["documentId"] for match in matches}

    assert document_ids == {"global", "target-visible", "conversation-visible"}
    assert "other-project" not in document_ids


def test_equal_scores_use_document_id_as_deterministic_tie_breaker(tmp_path):
    store = ProjectIndexStore(tmp_path)
    store.index_project(
        12,
        [
            _document("doc-b", "相同标题", "deterministic needle"),
            _document("doc-a", "相同标题", "deterministic needle"),
        ],
    )

    assert [item["documentId"] for item in store.query(12, "needle", 10)] == [
        "doc-a",
        "doc-b",
    ]


def test_index_update_invalidates_bm25_cache_and_revision(tmp_path):
    store = ProjectIndexStore(tmp_path)
    first_index = store.index_project(
        20,
        [_document("mutable", "缓存资料", "alpha-only evidence")],
    )
    first_match = store.query(20, "alpha-only", 1)[0]
    assert 20 in store._indexes

    second_index = store.index_project(
        20,
        [_document("mutable", "缓存资料", "beta-only evidence")],
    )

    assert 20 not in store._indexes
    assert store.query(20, "alpha-only", 1) == []
    second_match = store.query(20, "beta-only", 1)[0]
    assert second_index["indexRevision"] != first_index["indexRevision"]
    assert second_match["indexRevision"] == second_index["indexRevision"]
    assert second_match["contentDigest"] != first_match["contentDigest"]


def test_evidence_bundle_enforces_item_and_character_budgets(tmp_path):
    store = ProjectIndexStore(tmp_path)
    store.index_project(
        30,
        [
            _document("evidence-a", "证据 A", "needle " + "甲" * 100),
            _document("evidence-b", "证据 B", "needle " + "乙" * 100),
        ],
    )

    bundle = store.evidence_bundle(
        30,
        "needle",
        0,
        None,
        300,
        top_k=10,
        max_chars=25,
    )

    assert bundle.keys() == {
        "projectId",
        "targetId",
        "conversationId",
        "query",
        "round",
        "retrievalMethod",
        "indexRevision",
        "items",
    }
    assert bundle["retrievalMethod"] == "bm25"
    assert bundle["indexRevision"].startswith("sha256:")
    assert len(bundle["items"]) <= 2
    assert sum(len(item["snippet"]) for item in bundle["items"]) <= 25
    assert all(
        {
            "evidenceId",
            "documentId",
            "source",
            "title",
            "snippet",
            "score",
            "targetId",
            "contentDigest",
        }
        == item.keys()
        for item in bundle["items"]
    )


def test_empty_project_returns_empty_evidence_bundle(tmp_path):
    bundle = ProjectIndexStore(tmp_path).evidence_bundle(
        404, "不存在的项目", 0, "conversation-x", 9
    )

    assert bundle["items"] == []
    assert bundle["retrievalMethod"] == "bm25"
    assert bundle["indexRevision"].startswith("sha256:")


def test_graph_builder_alias_returns_the_same_bounded_contract(tmp_path):
    store = ProjectIndexStore(tmp_path)
    store.index_project(
        405,
        [_document("builder-evidence", "构建器证据", "needle " + "证" * 3000)],
    )

    bundle = store.build_evidence_bundle(405, "needle", 0, None, 99, 10)

    assert bundle["projectId"] == 405
    assert bundle["targetId"] == 99
    assert len(bundle["items"]) <= settings.max_evidence_items
    assert sum(len(item["snippet"]) for item in bundle["items"]) <= 12_000
