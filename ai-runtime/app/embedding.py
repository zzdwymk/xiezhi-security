"""Synchronous OpenAI-compatible embedding client and vector helpers.

This module deliberately has no dependency on the index implementation.  The
provider validates both request inputs and the wire response so callers never
have to rank malformed, non-finite, or differently-sized vectors.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from numbers import Real
from typing import Any
from urllib.parse import urlparse

import httpx


class EmbeddingProviderError(RuntimeError):
    """Base class for provider configuration, transport, and response errors."""


class EmbeddingProviderConfigurationError(EmbeddingProviderError, ValueError):
    """The provider was constructed with an unsafe or unusable setting."""


class EmbeddingProviderRequestError(EmbeddingProviderError):
    """The remote endpoint rejected a request or could not be reached."""


class EmbeddingProviderTimeoutError(EmbeddingProviderRequestError, TimeoutError):
    """The embedding request exceeded its configured timeout."""


class EmbeddingProviderResponseError(EmbeddingProviderError, ValueError):
    """The endpoint returned a malformed or incompatible embedding payload."""


def validate_vector(
    vector: Sequence[Real],
    *,
    expected_dimension: int | None = None,
    name: str = "vector",
) -> list[float]:
    """Validate and normalize one finite, non-zero embedding vector.

    The function is intentionally pure Python.  It returns a new list of
    ``float`` values and rejects booleans, nested values, NaN/infinity, empty
    vectors, and an explicitly mismatched dimension.
    """

    if isinstance(vector, (str, bytes, bytearray)) or not isinstance(vector, Sequence):
        raise ValueError(f"{name} must be a sequence of numbers")
    if not vector:
        raise ValueError(f"{name} must not be empty")
    if expected_dimension is not None:
        if (
            isinstance(expected_dimension, bool)
            or not isinstance(expected_dimension, int)
            or expected_dimension <= 0
        ):
            raise ValueError("expected_dimension must be a positive integer")
        if len(vector) != expected_dimension:
            raise ValueError(
                f"{name} dimension {len(vector)} does not match "
                f"expected {expected_dimension}"
            )

    normalized: list[float] = []
    for index, value in enumerate(vector):
        # bool is a Real in Python, but it is never a valid model component.
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"{name}[{index}] must be a real number")
        converted = float(value)
        if not math.isfinite(converted):
            raise ValueError(f"{name}[{index}] must be finite")
        normalized.append(converted)
    if not any(component != 0.0 for component in normalized):
        raise ValueError(f"{name} must not be the zero vector")
    return normalized


# Descriptive alias for callers that do not use the shorter helper name.
validate_embedding_vector = validate_vector


def cosine_similarity(
    left: Sequence[Real], right: Sequence[Real]
) -> float:
    """Return cosine similarity for two finite, non-zero vectors.

    Both vectors must have the same positive dimension.  The result is
    clamped to ``[-1, 1]`` to absorb tiny floating-point rounding errors.
    """

    first = validate_vector(left, name="left")
    second = validate_vector(right, name="right")
    if len(first) != len(second):
        raise ValueError(
            f"vector dimensions differ: {len(first)} != {len(second)}"
        )
    dot = sum(a * b for a, b in zip(first, second))
    first_norm = math.sqrt(sum(value * value for value in first))
    second_norm = math.sqrt(sum(value * value for value in second))
    result = dot / (first_norm * second_norm)
    return max(-1.0, min(1.0, result))


class EmbeddingProvider:
    """Small synchronous client for an OpenAI-compatible ``/embeddings`` API.

    ``client`` is optional and primarily useful for tests or applications that
    own an ``httpx.Client``.  An injected client is never closed by this class.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        timeout_seconds: float = 10.0,
        max_batch_size: int = 64,
        dimension: int | None = None,
        expected_dimension: int | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = self._validate_base_url(base_url)
        self.api_key = self._validate_api_key(api_key)
        self.model = self._validate_text_setting(model, "model")
        self.timeout_seconds = self._validate_timeout(timeout_seconds)
        self.max_batch_size = self._validate_positive_int(
            max_batch_size, "max_batch_size"
        )
        if dimension is not None and expected_dimension is not None and dimension != expected_dimension:
            raise EmbeddingProviderConfigurationError(
                "dimension and expected_dimension must match"
            )
        configured_dimension = (
            dimension if dimension is not None else expected_dimension
        )
        if configured_dimension is not None:
            try:
                configured_dimension = self._validate_positive_int(
                    configured_dimension, "dimension"
                )
            except EmbeddingProviderConfigurationError:
                raise
        self.dimension: int | None = configured_dimension
        default_headers = {"Content-Type": "application/json"}
        if self.api_key:
            default_headers["Authorization"] = f"Bearer {self.api_key}"
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds), headers=default_headers
        )
        self._owns_client = client is None

    @staticmethod
    def _validate_base_url(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise EmbeddingProviderConfigurationError("base_url is required")
        normalized = value.strip().rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise EmbeddingProviderConfigurationError(
                "base_url must be an http or https URL"
            )
        return normalized

    @staticmethod
    def _validate_api_key(value: str) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise EmbeddingProviderConfigurationError("api_key must be a string")
        return value.strip()

    @staticmethod
    def _validate_text_setting(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise EmbeddingProviderConfigurationError(f"{name} is required")
        return value.strip()

    @staticmethod
    def _validate_timeout(value: float) -> float:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise EmbeddingProviderConfigurationError(
                "timeout_seconds must be a positive finite number"
            )
        normalized = float(value)
        if not math.isfinite(normalized) or normalized <= 0:
            raise EmbeddingProviderConfigurationError(
                "timeout_seconds must be a positive finite number"
            )
        return normalized

    @staticmethod
    def _validate_positive_int(value: int, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise EmbeddingProviderConfigurationError(
                f"{name} must be a positive integer"
            )
        return value

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/embeddings"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "EmbeddingProvider":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def embed_query(self, text: str) -> list[float]:
        """Embed one query string."""

        return self.embed_documents([text])[0]

    def embed_documents(self, texts: Iterable[str]) -> list[list[float]]:
        """Embed a bounded batch of strings and return normalized vectors."""

        values = self._validate_inputs(texts)
        if not values:
            return []
        payload = {"model": self.model, "input": values}
        try:
            response = self._client.post(
                self.endpoint,
                json=payload,
                headers={
                    **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
                    "Content-Type": "application/json",
                },
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise EmbeddingProviderTimeoutError(
                f"embedding request timed out after {self.timeout_seconds:g}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise EmbeddingProviderRequestError(
                "embedding request failed"
            ) from exc
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EmbeddingProviderRequestError(
                f"embedding endpoint returned HTTP {response.status_code}"
            ) from exc
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise EmbeddingProviderResponseError(
                "embedding endpoint returned invalid JSON"
            ) from exc
        return self._parse_response(body, len(values))

    def _validate_inputs(self, texts: Iterable[str]) -> list[str]:
        if isinstance(texts, (str, bytes, bytearray)):
            raise EmbeddingProviderConfigurationError(
                "texts must be an iterable of strings, not a single string"
            )
        try:
            values = list(texts)
        except TypeError as exc:
            raise EmbeddingProviderConfigurationError(
                "texts must be an iterable of strings"
            ) from exc
        if len(values) > self.max_batch_size:
            raise EmbeddingProviderConfigurationError(
                f"embedding batch cannot exceed {self.max_batch_size} items"
            )
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value.strip():
                raise EmbeddingProviderConfigurationError(
                    f"texts[{index}] must be a non-empty string"
                )
        return values

    def _parse_response(self, body: Any, expected_count: int) -> list[list[float]]:
        if not isinstance(body, dict):
            raise EmbeddingProviderResponseError("embedding response must be an object")
        data = body.get("data")
        if not isinstance(data, list) or len(data) != expected_count:
            raise EmbeddingProviderResponseError(
                "embedding response data count does not match the request"
            )
        vectors: list[list[float]] = []
        indexes: list[int] = []
        for position, item in enumerate(data):
            if not isinstance(item, dict) or "embedding" not in item:
                raise EmbeddingProviderResponseError(
                    f"embedding response data[{position}] is missing embedding"
                )
            index = item.get("index")
            if index is not None:
                if isinstance(index, bool) or not isinstance(index, int):
                    raise EmbeddingProviderResponseError(
                        f"embedding response data[{position}] has invalid index"
                    )
                indexes.append(index)
            try:
                vector = validate_vector(
                    item["embedding"],
                    expected_dimension=self.dimension,
                    name=f"data[{position}].embedding",
                )
            except ValueError as exc:
                raise EmbeddingProviderResponseError(str(exc)) from exc
            vectors.append(vector)
        if indexes and indexes != list(range(expected_count)):
            raise EmbeddingProviderResponseError("embedding response indexes are invalid")
        inferred_dimension = len(vectors[0])
        if any(len(vector) != inferred_dimension for vector in vectors):
            raise EmbeddingProviderResponseError(
                "embedding response vectors have inconsistent dimensions"
            )
        if self.dimension is None:
            self.dimension = inferred_dimension
        return vectors
