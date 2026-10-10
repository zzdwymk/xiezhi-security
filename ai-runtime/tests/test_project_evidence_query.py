from __future__ import annotations

import copy
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import indexing as indexing_module
from app import main as main_module
from app import security as security_module
from app.indexing import IndexValidationError, ProjectIndexStore
from app.schemas import EvidenceBundle, ProjectDocument


PROJECT = 71
TARGET = 710
TOKEN = "project-query-test-runtime-token"
URL = f"/index/project/{PROJECT}/query"


def _headers(project=PROJECT, scope="index-read", *, expires=None):
    return {
        "X-AI-Runtime-Token": TOKEN,
        "X-AI-Project-Authorization": security_module.project_authorization_value(
            project, scope, int(time.time()) + 60 if expires is None else expires),
    }


def _document(identifier, text, target=TARGET, source="project", **metadata):
    values = {} if target is None else {"targetId": str(target)}
    return ProjectDocument(id=identifier, title=identifier, text=text, source=source,
                           metadata={**values, **metadata})


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(security_module, "settings", replace(
        security_module.settings, token=TOKEN, project_signing_secret="project-query-test-signing-secret"))
    limits = dict(rag_enabled=True, retrieval_backend="bm25", max_evidence_items=10,
                  max_evidence_chars=12_000, max_retrieval_rounds=2, retrieval_timeout_seconds=2.0)
    monkeypatch.setattr(main_module, "settings", replace(main_module.settings, **limits))
    monkeypatch.setattr(indexing_module, "settings", replace(indexing_module.settings, **limits))
    store = ProjectIndexStore(tmp_path)
    store.index_project(PROJECT, [
        _document("target-visible", "alpha service baseline"),
        _document("project-visible", "alpha project policy", target=None),
        _document("target-private", "alpha " * 100 + "PRIVATE_OTHER_TARGET", target=711),
        _document("conversation-private", "alpha PRIVATE_CONVERSATION", source="conversation",
                  conversationId="chat-private", createdAt=datetime.now(timezone.utc).isoformat()),
    ], True)
    store.index_project(72, [_document("project-private", "alpha PRIVATE_OTHER_PROJECT")], True)
    monkeypatch.setattr(main_module, "index_store", store)
    with TestClient(main_module.app, raise_server_exceptions=False) as client:
        yield client, store


def test_real_query_returns_current_target_and_project_evidence_without_chat_memory(fixture):
    client, store = fixture
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "  alpha  "})
    assert response.status_code == 200
    bundle = EvidenceBundle.model_validate(response.json())
    assert bundle.projectId == PROJECT and bundle.targetId == TARGET
    assert bundle.query == "alpha" and bundle.round == 0 and bundle.conversationId is None
    assert bundle.retrievalMethod == "bm25"
    assert {item.documentId for item in bundle.items} == {"target-visible", "project-visible"}
    assert all(item.targetId == TARGET for item in bundle.items)
    assert "PRIVATE_" not in response.text
    assert response.json() == store.evidence_bundle(PROJECT, "alpha", 0, None, TARGET, top_k=5, max_chars=12_000)


def test_unicode_space_around_query_is_normalized_without_changing_internal_text(fixture):
    client, _ = fixture
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "\u00a0\u2007alpha service\u202f"})
    assert response.status_code == 200
    assert response.json()["query"] == "alpha service"


def test_query_uses_actual_query_and_empty_match_is_a_completed_read(fixture):
    client, _ = fixture
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "no_matching_needle_923"})
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["query"] == "no_matching_needle_923"
    assert response.json()["indexRevision"].startswith("sha256:")


@pytest.mark.parametrize("top_k", [1, 5, 10])
def test_query_caps_results_and_snippets_even_for_large_matching_corpus(fixture, top_k):
    client, store = fixture
    store.index_project(PROJECT, [_document(f"doc-{i}", "alpha " * 500) for i in range(15)], True)
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "alpha", "topK": top_k})
    assert response.status_code == 200
    bundle = EvidenceBundle.model_validate(response.json())
    assert 0 < len(bundle.items) <= top_k
    assert sum(len(item.snippet) for item in bundle.items) <= 12_000
    assert all(len(item.snippet) <= 2000 for item in bundle.items)


@pytest.mark.parametrize("patch", [
    {"targetId": None}, {"targetId": 0}, {"targetId": -1}, {"targetId": True}, {"targetId": "710"},
    {"query": ""}, {"query": "   "}, {"query": "alpha\n"}, {"query": "alpha\t"}, {"query": "a\x85b"},
    {"query": "x" * 2001}, {"query": 1}, {"query": ["alpha"]},
    {"topK": 0}, {"topK": 11}, {"topK": True}, {"topK": "5"},
    {"projectId": 72}, {"conversationId": "chat-private"}, {"metadata": {"targetId": "711"}},
])
def test_invalid_or_scope_widening_input_is_rejected_before_storage(fixture, monkeypatch, patch):
    client, store = fixture
    def unexpected(*args, **kwargs):
        pytest.fail("invalid request must not reach index storage")
    monkeypatch.setattr(store, "evidence_bundle", unexpected)
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "alpha", **patch})
    assert response.status_code == 422
    assert response.json() == {"detail": "请求参数格式不正确"}


@pytest.mark.parametrize("headers_kind,status_code", [
    ("missing-token", 401), ("wrong-token", 401), ("missing-project", 403),
    ("other-project", 403), ("write-scope", 403), ("expired", 403),
])
def test_query_requires_runtime_token_and_current_project_read_signature(
    fixture, monkeypatch, headers_kind, status_code,
):
    client, store = fixture
    headers = _headers()
    if headers_kind == "missing-token":
        headers.pop("X-AI-Runtime-Token")
    elif headers_kind == "wrong-token":
        headers["X-AI-Runtime-Token"] = "invalid"
    elif headers_kind == "missing-project":
        headers.pop("X-AI-Project-Authorization")
    elif headers_kind == "other-project":
        headers = _headers(project=72)
    elif headers_kind == "write-scope":
        headers = _headers(scope="index-write")
    else:
        headers = _headers(expires=int(time.time()) - 10)
    def unexpected(*args, **kwargs):
        pytest.fail("unauthorized request must not reach index storage")
    monkeypatch.setattr(store, "evidence_bundle", unexpected)
    response = client.post(URL, headers=headers, json={"targetId": TARGET, "query": "alpha"})
    assert response.status_code == status_code
    assert "items" not in response.json()


@pytest.mark.parametrize("corruption", [
    "project", "target", "conversation", "query", "round", "item-target", "item-conversation",
    "unbound-task", "duplicate-id", "oversized-snippet", "too-many", "too-many-chars",
])
def test_store_response_must_pass_schema_and_scope_before_any_evidence_is_returned(
    fixture, monkeypatch, corruption,
):
    client, store = fixture
    bundle = copy.deepcopy(store.evidence_bundle(PROJECT, "alpha", 0, None, TARGET))
    if corruption in {"project", "target", "conversation", "query", "round"}:
        field, value = {"project": ("projectId", 72), "target": ("targetId", 711),
                        "conversation": ("conversationId", "private-chat"), "query": ("query", "different"),
                        "round": ("round", 1)}[corruption]
        bundle[field] = value
    elif corruption == "item-target":
        bundle["items"][0]["targetId"] = 711
    elif corruption == "item-conversation":
        bundle["items"][0]["source"] = "conversation"
    elif corruption == "unbound-task":
        bundle["items"][0].update(source="task", targetId=None)
    elif corruption == "duplicate-id":
        bundle["items"].append(copy.deepcopy(bundle["items"][0]))
    elif corruption == "oversized-snippet":
        bundle["items"][0]["snippet"] = "x" * 2001
    else:
        count = 11 if corruption == "too-many" else 7
        bundle["items"] = [{**bundle["items"][0], "evidenceId": f"ev-{i}", "snippet": "x" * 2000}
                           for i in range(count)]
    monkeypatch.setattr(store, "evidence_bundle", lambda *args, **kwargs: bundle)
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "alpha", "topK": 10})
    assert response.status_code == 503
    assert response.json() == {"detail": "项目资料检索未完成，请稍后重试"}


@pytest.mark.parametrize("failure", [IndexValidationError("PRIVATE failure"), OSError("PRIVATE file"), TimeoutError("PRIVATE timeout")])
def test_storage_or_retrieval_failure_is_not_reported_as_empty_success(fixture, monkeypatch, failure):
    client, store = fixture
    def unavailable(*args, **kwargs):
        raise failure
    monkeypatch.setattr(store, "evidence_bundle", unavailable)
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "alpha"})
    assert response.status_code == 503
    assert "PRIVATE" not in response.text and "items" not in response.json()


def test_disabled_retrieval_does_not_return_empty_success(fixture, monkeypatch):
    client, store = fixture
    monkeypatch.setattr(main_module, "settings", replace(main_module.settings, rag_enabled=False))
    def unexpected(*args, **kwargs):
        pytest.fail("disabled retrieval must not reach storage")
    monkeypatch.setattr(store, "evidence_bundle", unexpected)
    response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "alpha"})
    assert response.status_code == 503 and "items" not in response.json()


def test_outer_deadline_bounds_a_stalled_store_without_returning_partial_evidence(fixture, monkeypatch):
    client, store = fixture
    release = threading.Event()
    started = threading.Event()
    monkeypatch.setattr(main_module, "settings", replace(main_module.settings, retrieval_timeout_seconds=0.05))
    def stalled(*args, **kwargs):
        started.set()
        release.wait(2)
        return {}
    monkeypatch.setattr(store, "evidence_bundle", stalled)
    try:
        response = client.post(URL, headers=_headers(), json={"targetId": TARGET, "query": "alpha"})
        assert started.is_set()
        assert not release.is_set()
        assert response.status_code == 503
        assert response.json() == {"detail": "项目资料检索未完成，请稍后重试"}
    finally:
        release.set()
