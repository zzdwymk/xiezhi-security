package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AiConversationUsageTest {
  @Test
  void aggregatesCountsAndPreservesUnknownCacheRate() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 200, 120);
    AiConversationMemoryService.SessionHandle session = memory.open("usage_test", 1L, 2L);
    Map<String, Object> first = snapshot(2, 100, 20, 25);
    memory.addModelUsage(session.id(), first);
    memory.addModelUsage(session.id(), snapshot(1, 40, 10, null));

    Map<String, Object> result = memory.usage(session.id());
    assertEquals(3L, ((Number) result.get("modelCalls")).longValue());
    assertEquals(140L, ((Number) result.get("inputTokens")).longValue());
    assertEquals(30L, ((Number) result.get("outputTokens")).longValue());
    assertNull(result.get("cacheHitRatePermille"));
  }

  @Test
  void aggregatesMultiTurnAccurateCacheRateAndSource() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 200, 120);
    AiConversationMemoryService.SessionHandle session = memory.open("usage_multiturn", 1L, 2L);

    // Turn 1: 100 input, 20 output, 20 cached (20% cache rate)
    Map<String, Object> turn1 = snapshot(1, 100, 20, 200);
    memory.addModelUsage(session.id(), turn1);

    // Turn 2: 100 input, 20 output, 40 cached (40% cache rate)
    Map<String, Object> turn2 = snapshot(1, 100, 20, 400);
    memory.addModelUsage(session.id(), turn2);

    Map<String, Object> result = memory.usage(session.id());
    assertEquals(2L, ((Number) result.get("modelCalls")).longValue());
    assertEquals(200L, ((Number) result.get("inputTokens")).longValue());
    assertEquals(40L, ((Number) result.get("outputTokens")).longValue());
    assertEquals(240L, ((Number) result.get("totalTokens")).longValue());
    assertEquals(60L, ((Number) result.get("cachedInputTokens")).longValue());
    // 60 / 200 = 300 permille (30.0%)
    assertEquals(300, ((Number) result.get("cacheHitRatePermille")).intValue());
    assertEquals("PROVIDER", result.get("source"));
  }

  @Test
  void computesSessionContextWindowUsageFromPeakUsage() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 200, 120);
    AiConversationMemoryService.SessionHandle session = memory.open("usage_window", 1L, 2L);

    // Turn 1: peak input 64,000 out of 128,000 window (50% = 500 permille)
    Map<String, Object> turn1 = snapshot(1, 64_000, 500, null);
    memory.addModelUsage(session.id(), turn1);

    // Turn 2: small input 1,280 out of 128,000 window (1% = 10 permille)
    Map<String, Object> turn2 = snapshot(1, 1_280, 200, null);
    memory.addModelUsage(session.id(), turn2);

    Map<String, Object> result = memory.usage(session.id());
    assertEquals(64_000L, ((Number) result.get("peakInputTokens")).longValue());
    assertEquals(64_000L, ((Number) result.get("contextWindowUsedTokens")).longValue());
    assertEquals(1_280L, ((Number) result.get("lastInputTokens")).longValue());
    // Usage permille should remain at peak (500), not overwritten by 10
    assertEquals(500, ((Number) result.get("contextWindowUsagePermille")).intValue());
  }

  @Test
  void ignoresMalformedUsageWithoutMutatingSession() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 200, 120);
    AiConversationMemoryService.SessionHandle session = memory.open("usage_invalid", 1L, 2L);
    Map<String, Object> malformed = snapshot(1, 40, 10, null);
    malformed.put("model", "private\nvalue");

    memory.addModelUsage(session.id(), malformed);

    assertEquals(Map.of(), memory.usage(session.id()));
  }

  private Map<String, Object> snapshot(int calls, int input, int output, Integer cacheRate) {
    Map<String, Object> usage = new LinkedHashMap<>();
    usage.put("modelCalls", calls);
    usage.put("providerReportedCalls", calls);
    usage.put("estimatedCalls", 0);
    usage.put("cacheReportedCalls", cacheRate == null ? 0 : calls);
    usage.put("inputTokens", input);
    usage.put("outputTokens", output);
    usage.put("totalTokens", input + output);
    usage.put("cachedInputTokens", cacheRate == null ? 0 : input * cacheRate / 1000);
    usage.put("cacheWriteTokens", 0);
    usage.put("reasoningTokens", 0);
    usage.put("estimatedInputTokens", 0);
    usage.put("available", true);
    usage.put("source", "PROVIDER");
    usage.put("model", "test-model");
    usage.put("contextWindowTokens", 128_000);
    usage.put("contextWindowSource", "DEFAULT");
    usage.put("contextWindowUsedTokens", input);
    usage.put("contextWindowUsagePermille", input * 1000 / 128_000);
    usage.put("peakInputTokens", input);
    usage.put("lastInputTokens", input);
    usage.put("cacheHitRatePermille", cacheRate);
    usage.put("estimator", "heuristic-v1");
    return usage;
  }
}
