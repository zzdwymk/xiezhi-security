from types import SimpleNamespace

import pytest

from app.usage import (
    ModelCallUsage,
    UsageAccumulator,
    estimate_messages_tokens,
    estimate_tokens,
    usage_from_response,
)


def test_token_estimator_handles_ascii_and_cjk():
    assert estimate_tokens("1234abcd") == 2
    assert estimate_tokens("中文") == 2
    assert estimate_messages_tokens(["hello", "世界"]) == 8


def test_extracts_openai_usage_and_cache_details():
    response = SimpleNamespace(
        response_metadata={
            "token_usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
                "prompt_tokens_details": {"cached_tokens": 25},
                "completion_tokens_details": {"reasoning_tokens": 5},
            },
            "model_name": "gpt-4o-mini-2024-07-18",
        }
    )
    usage = usage_from_response(response, model="configured-model")
    assert usage.model == "gpt-4o-mini-2024-07-18"
    assert usage.providerReported
    assert usage.inputTokens == 100
    assert usage.outputTokens == 20
    assert usage.totalTokens == 120
    assert usage.cachedInputTokens == 25
    assert usage.reasoningTokens == 5
    assert usage.cacheReported


def test_extracts_langchain_metadata_and_rejects_invalid_counts():
    response = SimpleNamespace(
        usage_metadata={"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
        response_metadata={},
    )
    usage = usage_from_response(response, estimated_input_tokens=30)
    assert usage.providerReported
    assert usage.inputTokens == 11
    assert usage.outputTokens == 7
    assert not usage.cacheReported
    invalid = usage_from_response({"usage": {"prompt_tokens": -2, "completion_tokens": 3}})
    assert not invalid.providerReported


def test_snapshot_does_not_invent_cache_rate_and_labels_estimates():
    accumulator = UsageAccumulator("gpt-4o-mini")
    accumulator.record(
        ModelCallUsage(model="gpt-4o-mini", outputTokens=5, estimatedInputTokens=40)
    )
    snapshot = accumulator.snapshot()
    assert snapshot["source"] == "ESTIMATED"
    assert snapshot["inputTokens"] == 40
    assert snapshot["outputTokens"] == 5
    assert snapshot["totalTokens"] == 45
    assert snapshot["cacheHitRatePermille"] is None
    assert snapshot["contextWindowTokens"] == 128000
    assert snapshot["estimatedCalls"] == 1


def test_provider_output_with_estimated_input_has_consistent_totals():
    accumulator = UsageAccumulator("gpt-4o-mini")
    accumulator.record(
        ModelCallUsage(
            model="gpt-4o-mini",
            outputTokens=7,
            totalTokens=7,
            providerReported=True,
            estimatedInputTokens=40,
        )
    )
    snapshot = accumulator.snapshot()
    assert snapshot["inputTokens"] == 40
    assert snapshot["outputTokens"] == 7
    assert snapshot["totalTokens"] == 47
    assert snapshot["estimatedInputTokens"] == 40
    assert snapshot["contextWindowUsedTokens"] == 40
    assert snapshot["source"] == "PROVIDER"
    assert snapshot["estimatedCalls"] == 0



def test_cache_hit_rate_is_reported_only_when_provider_reports_cache():
    accumulator = UsageAccumulator("gpt-4o-mini")
    accumulator.record(
        ModelCallUsage(
            model="gpt-4o-mini",
            inputTokens=100,
            outputTokens=20,
            totalTokens=120,
            cachedInputTokens=25,
            providerReported=True,
            cacheReported=True,
        )
    )
    snapshot = accumulator.snapshot()
    assert snapshot["cacheHitRatePermille"] == 250
    assert snapshot["contextWindowUsagePermille"] == 1


def test_multi_call_accumulation_and_cache_hit_rate():
    accumulator = UsageAccumulator("gpt-4o-mini")
    # Call 1: 50 input, 10 output, 10 cached
    accumulator.record(
        ModelCallUsage(
            model="gpt-4o-mini",
            inputTokens=50,
            outputTokens=10,
            totalTokens=60,
            cachedInputTokens=10,
            providerReported=True,
            cacheReported=True,
        )
    )
    # Call 2: 80 input, 20 output, 30 cached
    accumulator.record(
        ModelCallUsage(
            model="gpt-4o-mini",
            inputTokens=80,
            outputTokens=20,
            totalTokens=100,
            cachedInputTokens=30,
            providerReported=True,
            cacheReported=True,
        )
    )
    snapshot = accumulator.snapshot()
    assert snapshot["modelCalls"] == 2
    assert snapshot["inputTokens"] == 130
    assert snapshot["outputTokens"] == 30
    assert snapshot["totalTokens"] == 160
    assert snapshot["cachedInputTokens"] == 40
    # 40 / 130 = 0.30769... -> 308 permille (30.8%)
    assert snapshot["cacheHitRatePermille"] == 308
    # Context window used is peak single-call input: max(50, 80) = 80
    assert snapshot["contextWindowUsedTokens"] == 80
    assert snapshot["peakInputTokens"] == 80
    assert snapshot["lastInputTokens"] == 80


def test_zero_cache_hit_rate_distinguished_from_unreported():
    accumulator = UsageAccumulator("gpt-4o-mini")
    accumulator.record(
        ModelCallUsage(
            model="gpt-4o-mini",
            inputTokens=100,
            outputTokens=20,
            totalTokens=120,
            cachedInputTokens=0,
            providerReported=True,
            cacheReported=True,
        )
    )
    snapshot = accumulator.snapshot()
    # Explicit 0 cached tokens reported -> 0 permille
    assert snapshot["cacheHitRatePermille"] == 0

    unreported = UsageAccumulator("gpt-4o-mini")
    unreported.record(
        ModelCallUsage(
            model="gpt-4o-mini",
            inputTokens=100,
            outputTokens=20,
            totalTokens=120,
            providerReported=True,
            cacheReported=False,
        )
    )
    # Cache not reported -> None
    assert unreported.snapshot()["cacheHitRatePermille"] is None


def test_extracts_deepseek_flat_cache_counters():
    # DeepSeek reports cache hits as a flat counter next to prompt_tokens.
    usage = usage_from_response({
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 20,
            "total_tokens": 1020,
            "prompt_cache_hit_tokens": 640,
            "prompt_cache_miss_tokens": 360,
        }
    })
    assert usage.providerReported
    assert usage.inputTokens == 1000
    assert usage.outputTokens == 20
    assert usage.cacheReported
    assert usage.cachedInputTokens == 640

    accumulator = UsageAccumulator("deepseek-chat")
    accumulator.record(usage)
    snapshot = accumulator.snapshot()
    assert snapshot["cacheHitRatePermille"] == 640
    assert snapshot["source"] == "PROVIDER"
    assert snapshot["contextWindowTokens"] == 128000


def test_deepseek_missing_hit_counter_is_not_invented():
    # No prompt_cache_hit_tokens in the response: the rate must stay unreported
    # rather than silently collapsing to 0%.
    accumulator = UsageAccumulator("deepseek-chat")
    accumulator.record(
        usage_from_response({"usage": {"prompt_tokens": 100, "completion_tokens": 20}})
    )
    snapshot = accumulator.snapshot()
    assert snapshot["cacheHitRatePermille"] is None
    assert snapshot["cacheReportedCalls"] == 0


def test_deepseek_invalid_hit_counter_rejects_the_whole_snapshot():
    bad = usage_from_response({
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_cache_hit_tokens": -1,
        }
    })
    assert not bad.providerReported
    assert not bad.cacheReported


def test_corrupted_usage_details_rejected():
    # Negative cached tokens in nested details
    bad_cached = usage_from_response({
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "prompt_tokens_details": {"cached_tokens": -5},
        }
    })
    assert not bad_cached.providerReported

    # Boolean count in completion tokens
    bad_type = usage_from_response({
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": True,
        }
    })
    assert not bad_type.providerReported
