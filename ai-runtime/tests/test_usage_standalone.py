"""Dependency-free checks for usage accounting; run with python -m unittest."""
from types import SimpleNamespace
import unittest

from app.usage import ModelCallUsage, UsageAccumulator, estimate_messages_tokens, usage_from_response


class UsageAccountingTest(unittest.TestCase):
    def test_known_provider_counts_and_cache_rate(self):
        usage = UsageAccumulator("gpt-4o-mini")
        usage.record(ModelCallUsage(model="gpt-4o-mini", inputTokens=100, outputTokens=20,
                                   totalTokens=120, cachedInputTokens=25, providerReported=True,
                                   cacheReported=True))
        snapshot = usage.snapshot()
        self.assertEqual(snapshot["inputTokens"], 100)
        self.assertEqual(snapshot["outputTokens"], 20)
        self.assertEqual(snapshot["totalTokens"], 120)
        self.assertEqual(snapshot["cacheHitRatePermille"], 250)
        self.assertEqual(snapshot["contextWindowUsedTokens"], 100)
        self.assertEqual(snapshot["contextWindowUsagePermille"], 1)

    def test_output_only_provider_uses_prompt_estimate_for_context(self):
        usage = UsageAccumulator("gpt-4o-mini")
        usage.record(ModelCallUsage(model="gpt-4o-mini", outputTokens=7, totalTokens=7,
                                   providerReported=True, estimatedInputTokens=40))
        snapshot = usage.snapshot()
        self.assertEqual(snapshot["source"], "PROVIDER")
        self.assertEqual(snapshot["inputTokens"], 40)
        self.assertEqual(snapshot["outputTokens"], 7)
        self.assertEqual(snapshot["totalTokens"], 47)
        self.assertEqual(snapshot["estimatedInputTokens"], 40)
        self.assertEqual(snapshot["contextWindowUsedTokens"], 40)
        self.assertIsNone(snapshot["cacheHitRatePermille"])

    def test_provider_payload_extraction_and_estimated_fallback(self):
        response = SimpleNamespace(response_metadata={"token_usage": {
            "prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
            "prompt_tokens_details": {"cached_tokens": 25}}})
        call = usage_from_response(response, estimated_input_tokens=80)
        self.assertTrue(call.providerReported)
        self.assertTrue(call.cacheReported)
        self.assertEqual(call.cachedInputTokens, 25)
        self.assertEqual(estimate_messages_tokens(["hello", "世界"]), 8)

    def test_multi_call_accumulation_and_cache_hit_rate(self):
        usage = UsageAccumulator("gpt-4o-mini")
        usage.record(ModelCallUsage(model="gpt-4o-mini", inputTokens=50, outputTokens=10,
                                   totalTokens=60, cachedInputTokens=10, providerReported=True,
                                   cacheReported=True))
        usage.record(ModelCallUsage(model="gpt-4o-mini", inputTokens=80, outputTokens=20,
                                   totalTokens=100, cachedInputTokens=30, providerReported=True,
                                   cacheReported=True))
        snapshot = usage.snapshot()
        self.assertEqual(snapshot["modelCalls"], 2)
        self.assertEqual(snapshot["inputTokens"], 130)
        self.assertEqual(snapshot["outputTokens"], 30)
        self.assertEqual(snapshot["totalTokens"], 160)
        self.assertEqual(snapshot["cachedInputTokens"], 40)
        self.assertEqual(snapshot["cacheHitRatePermille"], 308)
        self.assertEqual(snapshot["contextWindowUsedTokens"], 80)

    def test_corrupted_usage_details_rejected(self):
        bad_cached = usage_from_response({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "prompt_tokens_details": {"cached_tokens": -5},
            }
        })
        self.assertFalse(bad_cached.providerReported)

        bad_prompt = usage_from_response({"usage": {"prompt_tokens": -2, "completion_tokens": 3}})
        self.assertFalse(bad_prompt.providerReported)


if __name__ == "__main__":
    unittest.main()
