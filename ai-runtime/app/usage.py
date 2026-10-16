"""Per-run model usage telemetry: tokens, cache hit rate and context window pressure.

Only provider-reported counters and server-owned estimates cross this module.
Raw prompts, model output and evidence bodies are never retained here: the
snapshot contains integers, bounded identifiers and fixed enumerations so it can
safely enter the public event stream and the runtime ledger digest chain.

All rates are integers (per mille, 0..1000) on purpose. A float would be
re-serialized by the Java counterpart when it recomputes the ledger digest and
could produce a different textual form than Python's ``json.dumps``.
"""
from __future__ import annotations

import math
import threading
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterator

from .config import settings

ESTIMATOR_VERSION = "heuristic-v1"
DEFAULT_CONTEXT_WINDOW_TOKENS = 128_000
MAX_CONTEXT_WINDOW_TOKENS = 4_000_000
MAX_TOKENS_PER_CALL = 64_000_000

# Longest/most specific model prefixes win; matching is case-insensitive on the
# configured or provider-reported model name.
_CONTEXT_WINDOWS: tuple[tuple[str, int], ...] = (
    ("gpt-4.1-mini", 1_047_576),
    ("gpt-4.1-nano", 1_047_576),
    ("gpt-4.1", 1_047_576),
    ("gpt-4o-mini", 128_000),
    ("gpt-4o", 128_000),
    ("gpt-4-turbo", 128_000),
    ("gpt-4", 8_192),
    ("gpt-3.5", 16_385),
    ("o4-mini", 200_000),
    ("o3-mini", 200_000),
    ("o3", 200_000),
    ("o1", 200_000),
    ("deepseek-reasoner", 128_000),
    ("deepseek-chat", 128_000),
    ("deepseek", 65_536),
    ("claude-opus-4", 200_000),
    ("claude-sonnet-4", 200_000),
    ("claude-3-7-sonnet", 200_000),
    ("claude-3-5-sonnet", 200_000),
    ("claude-3-5-haiku", 200_000),
    ("claude-3", 200_000),
    ("qwen", 131_072),
    ("glm-4", 128_000),
    ("moonshot", 128_000),
    ("kimi", 128_000),
    ("gemini-1.5-pro", 1_048_576),
    ("gemini-2.0-flash", 1_048_576),
    ("gemini", 1_048_576),
    ("grok", 131_072),
)


def context_window_for_model(model: str | None) -> tuple[int, str]:
    """Return (limit tokens, source) for the configured/provider model name."""
    configured = int(getattr(settings, "context_window_tokens", 0) or 0)
    if configured > 0:
        return min(configured, MAX_CONTEXT_WINDOW_TOKENS), "CONFIGURED"
    name = (model or "").strip().casefold()
    candidates = [name]
    configured_model = str(getattr(settings, "model", "") or "").strip().casefold()
    if configured_model and configured_model not in candidates:
        candidates.append(configured_model)
    for candidate in candidates:
        if not candidate:
            continue
        for prefix, window in _CONTEXT_WINDOWS:
            if prefix in candidate:
                return window, "MODEL"
    return DEFAULT_CONTEXT_WINDOW_TOKENS, "DEFAULT"


def estimate_tokens(text: str) -> int:
    """Provider-independent estimate; ASCII ≈ 4 chars/token, wide chars ≈ 1 token."""
    if not text:
        return 0
    ascii_chars = 0
    wide_chars = 0
    for character in text:
        if ord(character) < 128:
            ascii_chars += 1
        else:
            wide_chars += 1
    return int(math.ceil(ascii_chars / 4.0)) + wide_chars


def estimate_messages_tokens(texts: list[str]) -> int:
    """Estimate a prompt: 4 tokens of message framing plus the text estimate."""
    if not texts:
        return 0
    return 4 + sum(estimate_tokens(text) for text in texts)


@dataclass
class ModelCallUsage:
    """Usage of exactly one provider invocation."""

    model: str = ""
    inputTokens: int | None = None
    outputTokens: int | None = None
    totalTokens: int | None = None
    cachedInputTokens: int | None = None
    cacheWriteTokens: int | None = None
    reasoningTokens: int | None = None
    providerReported: bool = False
    cacheReported: bool = False
    estimatedInputTokens: int = 0


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= MAX_TOKENS_PER_CALL else None
    if isinstance(value, float):
        if value.is_integer() and 0 <= value <= MAX_TOKENS_PER_CALL:
            return int(value)
        return None
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return None
        return parsed if 0 <= parsed <= MAX_TOKENS_PER_CALL else None
    return None


def _lookup(mapping: Any, *keys: str) -> int | None:
    if not isinstance(mapping, Mapping):
        return None
    for key in keys:
        if key in mapping:
            return _as_int(mapping.get(key))
    return None


def _nested(mapping: Any, outer: str) -> Any:
    if not isinstance(mapping, Mapping):
        return None
    value = mapping.get(outer)
    return value if isinstance(value, Mapping) else None


def _usage_mapping(response: Any) -> tuple[dict[str, Any], bool]:
    """Find the provider usage mapping on a LangChain message or plain mapping."""
    if isinstance(response, Mapping):
        for candidate in (response, response.get("usage"), response.get("token_usage")):
            if isinstance(candidate, Mapping) and any(
                key in candidate
                for key in (
                    "prompt_tokens",
                    "input_tokens",
                    "completion_tokens",
                    "output_tokens",
                )
            ):
                return candidate, True
        return {}, False
    usage_metadata = getattr(response, "usage_metadata", None)
    if isinstance(usage_metadata, Mapping) and usage_metadata:
        return usage_metadata, True
    response_metadata = getattr(response, "response_metadata", None)
    for candidate in (
        _nested(response_metadata, "token_usage"),
        _nested(response_metadata, "usage"),
        response_metadata if isinstance(response_metadata, Mapping) else None,
    ):
        if isinstance(candidate, Mapping) and any(
            key in candidate
            for key in ("prompt_tokens", "input_tokens", "completion_tokens", "output_tokens")
        ):
            return candidate, True
    return {}, False


def reported_model(response: Any, fallback: str = "") -> str:
    """Provider-reported model id wins over the configured name when present."""
    if isinstance(response, Mapping):
        metadata = response.get("response_metadata")
    else:
        metadata = getattr(response, "response_metadata", None)
    if isinstance(metadata, Mapping):
        for key in ("model_name", "model", "model_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:120]
    return str(fallback or "")[:120]


def _has_invalid_count(mapping: Any) -> bool:
    """Return True if any present token-related count is malformed or negative."""
    if not isinstance(mapping, Mapping):
        return False
    for key, value in mapping.items():
        if isinstance(value, Mapping):
            if _has_invalid_count(value):
                return True
        elif value is not None and any(
            token_word in key
            for token_word in ("token", "cached", "reasoning")
        ):
            if _as_int(value) is None:
                return True
    return False


def usage_from_response(response: Any, *, model: str = "", estimated_input_tokens: int = 0) -> ModelCallUsage:
    """Extract provider-reported usage; fall back to the local estimate only."""
    usage, reported = _usage_mapping(response)
    call = ModelCallUsage(
        model=reported_model(response, model),
        estimatedInputTokens=max(0, int(estimated_input_tokens)),
    )
    if not reported or _has_invalid_count(usage):
        return call
    input_tokens = _lookup(usage, "input_tokens", "prompt_tokens")
    output_tokens = _lookup(usage, "output_tokens", "completion_tokens")
    total_tokens = _lookup(usage, "total_tokens")
    cache_read = _lookup(
        _nested(usage, "input_token_details"),
        "cache_read",
        "cached_tokens",
    )
    cache_reported = cache_read is not None
    if cache_read is None:
        cache_read = _lookup(usage, "cache_read_input_tokens", "cached_input_tokens")
        cache_reported = cache_read is not None
    if cache_read is None:
        cache_read = _lookup(_nested(usage, "prompt_tokens_details"), "cached_tokens")
        cache_reported = cache_read is not None
    if cache_read is None:
        cache_read = _lookup(_nested(usage, "input_tokens_details"), "cached_tokens")
        cache_reported = cache_read is not None
    if cache_read is None:
        # DeepSeek (and several OpenAI-compatible gateways) report cache hits as
        # a flat counter instead of a nested ``*_details`` object. Without this
        # branch the hit rate would silently read as "unreported" for every
        # DeepSeek call, so the UI would show 0% or hide the row entirely.
        # ``prompt_cache_miss_tokens`` is intentionally ignored: a miss is not a
        # cache *write*, and accepting a new snapshot field would require a
        # matching schema change on the Java ledger side.
        cache_read = _lookup(usage, "prompt_cache_hit_tokens")
        cache_reported = cache_read is not None
    cache_write = _lookup(
        _nested(usage, "input_token_details"),
        "cache_creation",
        "cache_write",
    )
    if cache_write is None:
        cache_write = _lookup(usage, "cache_creation_input_tokens", "cache_write_tokens")
    reasoning = _lookup(
        _nested(usage, "output_token_details"), "reasoning", "reasoning_tokens"
    )
    if reasoning is None:
        reasoning = _lookup(
            _nested(usage, "completion_tokens_details"), "reasoning_tokens"
        )
    call.inputTokens = input_tokens
    call.outputTokens = output_tokens
    call.totalTokens = total_tokens
    call.cachedInputTokens = cache_read
    call.cacheWriteTokens = cache_write
    call.reasoningTokens = reasoning
    call.cacheReported = cache_reported
    call.providerReported = input_tokens is not None or output_tokens is not None
    return call


@dataclass
class _Totals:
    runs: int = 0
    modelCalls: int = 0
    providerReportedCalls: int = 0
    estimatedCalls: int = 0
    cacheReportedCalls: int = 0
    inputTokens: int = 0
    outputTokens: int = 0
    totalTokens: int = 0
    cachedInputTokens: int = 0
    cacheWriteTokens: int = 0
    reasoningTokens: int = 0
    estimatedInputTokens: int = 0
    peakInputTokens: int = 0
    lastInputTokens: int = 0
    model: str = ""
    contextWindowTokens: int = 0
    contextWindowSource: str = "DEFAULT"
    failureCount: int = 0


class UsageAccumulator:
    """Mutable per-run accumulator; snapshots are plain, digest-safe values."""

    def __init__(self, model: str = "") -> None:
        self._totals = _Totals(model=str(model or "")[:120])
        self.reset()

    def reset(self) -> None:
        self._totals = _Totals(model=self._totals.model)

    @property
    def model_calls(self) -> int:
        return self._totals.modelCalls

    def record(self, call: ModelCallUsage) -> None:
        totals = self._totals
        totals.modelCalls += 1
        if call.model:
            totals.model = call.model[:120]
        input_tokens = call.inputTokens
        call_input = input_tokens if input_tokens is not None else 0
        if call.providerReported:
            totals.providerReportedCalls += 1
            if input_tokens is None:
                # A provider may return output-only usage. Preserve its authoritative
                # output count, but use the prompt estimate for input/context totals.
                call_input = max(0, call.estimatedInputTokens)
                totals.estimatedInputTokens += call_input
        else:
            totals.estimatedCalls += 1
            totals.estimatedInputTokens += max(0, call.estimatedInputTokens)
            call_input = max(0, call.estimatedInputTokens)
        if call.cacheReported:
            totals.cacheReportedCalls += 1
        totals.inputTokens += call_input
        totals.outputTokens += max(0, call.outputTokens or 0)
        reported_total = call.totalTokens
        if reported_total is None:
            # If input usage is missing, report the estimate as a component. If the
            # provider supplied its own total, that total remains authoritative.
            total_input = call_input if input_tokens is None else input_tokens
            reported_total = total_input + (call.outputTokens or 0)
        elif input_tokens is None and call.estimatedInputTokens > 0:
            reported_total += max(0, call.estimatedInputTokens)
        totals.totalTokens += max(0, reported_total)
        totals.cachedInputTokens += max(0, call.cachedInputTokens or 0)
        totals.cacheWriteTokens += max(0, call.cacheWriteTokens or 0)
        totals.reasoningTokens += max(0, call.reasoningTokens or 0)
        totals.peakInputTokens = max(totals.peakInputTokens, call_input)
        totals.lastInputTokens = call_input

    def snapshot(self) -> dict[str, Any]:
        totals = self._totals
        window, window_source = context_window_for_model(totals.model)
        used = min(totals.peakInputTokens, MAX_CONTEXT_WINDOW_TOKENS)
        if totals.modelCalls and totals.cacheReportedCalls:
            cache_rate: int | None = round(
                1000 * totals.cachedInputTokens / max(1, totals.inputTokens)
            )
            cache_rate = max(0, min(cache_rate, 1000))
        else:
            cache_rate = None
        if not totals.modelCalls:
            source = "UNAVAILABLE"
        elif totals.providerReportedCalls and totals.estimatedCalls:
            source = "MIXED"
        elif totals.providerReportedCalls:
            source = "PROVIDER"
        else:
            source = "ESTIMATED"
        return {
            "available": totals.modelCalls > 0,
            "source": source,
            "model": totals.model,
            "modelCalls": totals.modelCalls,
            "providerReportedCalls": totals.providerReportedCalls,
            "estimatedCalls": totals.estimatedCalls,
            "cacheReportedCalls": totals.cacheReportedCalls,
            "inputTokens": totals.inputTokens,
            "outputTokens": totals.outputTokens,
            "totalTokens": totals.totalTokens,
            "cachedInputTokens": totals.cachedInputTokens,
            "cacheWriteTokens": totals.cacheWriteTokens,
            "reasoningTokens": totals.reasoningTokens,
            "estimatedInputTokens": totals.estimatedInputTokens,
            "cacheHitRatePermille": cache_rate,
            "contextWindowTokens": window,
            "contextWindowSource": window_source,
            "contextWindowUsedTokens": used,
            "contextWindowUsagePermille": max(
                0, min(round(1000 * used / max(1, window)), 1000)
            ),
            "peakInputTokens": totals.peakInputTokens,
            "lastInputTokens": totals.lastInputTokens,
            "estimator": ESTIMATOR_VERSION,
        }


_usage: ContextVar[UsageAccumulator | None] = ContextVar("model_usage_scope", default=None)


@contextmanager
def usage_scope(model: str = "") -> Iterator[UsageAccumulator]:
    """Open a run-scoped accumulator; nested scopes inherit the outer one."""
    existing = _usage.get()
    if existing is not None:
        yield existing
        return
    accumulator = UsageAccumulator(model)
    token = _usage.set(accumulator)
    try:
        yield accumulator
    finally:
        _usage.reset(token)


def current_usage() -> UsageAccumulator | None:
    return _usage.get()


def usage_snapshot() -> dict[str, Any]:
    """Snapshot of the active run; an empty, honest snapshot when nothing ran."""
    accumulator = _usage.get()
    if accumulator is None:
        empty = UsageAccumulator()
        return empty.snapshot()
    return accumulator.snapshot()


def record_model_call(call: ModelCallUsage) -> dict[str, Any]:
    """Record one provider invocation in the run scope and the process totals."""
    accumulator = _usage.get()
    if accumulator is not None:
        accumulator.record(call)
        snapshot = accumulator.snapshot()
    else:
        snapshot = {}
    _PROCESS.record(call)
    return snapshot


class _ProcessUsage:
    """Process-wide totals for the health/diagnostics surface (bounded memory)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._accumulator = UsageAccumulator()
        self._runs = 0

    def start_run(self) -> None:
        with self._lock:
            self._runs += 1

    def record(self, call: ModelCallUsage) -> None:
        with self._lock:
            self._accumulator.record(call)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            snapshot = self._accumulator.snapshot()
        snapshot["runs"] = self._runs
        return snapshot


_PROCESS = _ProcessUsage()


def process_usage() -> dict[str, Any]:
    return _PROCESS.snapshot()


def start_usage_run() -> None:
    _PROCESS.start_run()


def model_name() -> str:
    return str(getattr(settings, "model", "") or "")[:120]
