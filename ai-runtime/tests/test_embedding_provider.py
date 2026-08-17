from __future__ import annotations

import httpx
import pytest

from app.embedding import (
    EmbeddingProvider,
    EmbeddingProviderConfigurationError,
    EmbeddingProviderResponseError,
    EmbeddingProviderTimeoutError,
    cosine_similarity,
    validate_vector,
)


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_provider_posts_openai_compatible_payload_and_validates_response():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers.get("authorization")
        seen["payload"] = request.read()
        return httpx.Response(
            200,
            json={
                "object": "list",
                "data": [
                    {"object": "embedding", "index": 0, "embedding": [1, 0]},
                    {"object": "embedding", "index": 1, "embedding": [0, 1]},
                ],
                "model": "test-model",
            },
        )

    with EmbeddingProvider(
        "https://example.test/v1/",
        "secret-key",
        "test-model",
        dimension=2,
        client=_client(handler),
    ) as provider:
        vectors = provider.embed_documents(["first", "second"])

    import json

    assert seen["url"] == "https://example.test/v1/embeddings"
    assert seen["authorization"] == "Bearer secret-key"
    assert json.loads(seen["payload"]) == {
        "model": "test-model",
        "input": ["first", "second"],
    }
    assert vectors == [[1.0, 0.0], [0.0, 1.0]]


def test_provider_infers_dimension_when_not_configured():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"embedding": [0.25, 0.75]}]})

    with EmbeddingProvider(
        "http://localhost:1234/v1", "key", "model", client=_client(handler)
    ) as provider:
        assert provider.embed_query("query") == [0.25, 0.75]
        assert provider.dimension == 2


@pytest.mark.parametrize(
    "texts",
    ["single string", [""], ["   "], [1], ["one", "two", "three"]],
)
def test_provider_rejects_invalid_inputs_and_batch_limit(texts):
    kwargs = {"max_batch_size": 2} if isinstance(texts, list) and len(texts) == 3 else {}
    with pytest.raises(EmbeddingProviderConfigurationError):
        EmbeddingProvider("http://localhost/v1", "key", "model", **kwargs).embed_documents(texts)


def test_provider_rejects_malformed_response_and_dimension_mismatch():
    def malformed(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"embedding": [1, 2, 3]}]})

    with EmbeddingProvider(
        "http://localhost/v1", "key", "model", dimension=2, client=_client(malformed)
    ) as provider:
        with pytest.raises(EmbeddingProviderResponseError):
            provider.embed_query("query")


def test_provider_rejects_non_finite_and_zero_vectors():
    def non_finite(_request: httpx.Request) -> httpx.Response:
        # Python's JSON decoder accepts this non-standard token; the provider
        # must still reject it as a non-finite model component.
        return httpx.Response(
            200,
            content=b'{"data":[{"embedding":[NaN,1]}]}',
            headers={"content-type": "application/json"},
        )

    with EmbeddingProvider(
        "http://localhost/v1", "key", "model", client=_client(non_finite)
    ) as provider:
        with pytest.raises(EmbeddingProviderResponseError):
            provider.embed_query("query")

    with pytest.raises(ValueError):
        validate_vector([0, 0])


def test_provider_translates_timeout_without_exposing_api_key():
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    with EmbeddingProvider(
        "http://localhost/v1", "top-secret", "model", client=_client(handler)
    ) as provider:
        with pytest.raises(EmbeddingProviderTimeoutError) as error:
            provider.embed_query("query")
    assert "top-secret" not in str(error.value)


def test_provider_allows_blank_api_key_without_authorization_header():
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": [{"embedding": [1, 0]}]})

    with EmbeddingProvider(
        "http://localhost/v1", "", "model", client=_client(handler)
    ) as provider:
        assert provider.embed_query("query") == [1.0, 0.0]
    assert seen["authorization"] is None


def test_cosine_similarity_is_pure_python_and_validates_dimensions():
    assert cosine_similarity([1, 0], [1, 0]) == pytest.approx(1.0)
    assert cosine_similarity([1, 0], [0, 1]) == pytest.approx(0.0)
    assert cosine_similarity([1, 0], [-1, 0]) == pytest.approx(-1.0)
    with pytest.raises(ValueError):
        cosine_similarity([1, 0], [1])
