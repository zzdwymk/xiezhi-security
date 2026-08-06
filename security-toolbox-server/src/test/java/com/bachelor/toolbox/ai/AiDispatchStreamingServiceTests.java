package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class AiDispatchStreamingServiceTests {
  private final AiPlanningService planningService = mock(AiPlanningService.class);
  private final AiTaskDispatchService dispatchService = mock(AiTaskDispatchService.class);
  private final AiDispatchStreamingService service =
      new AiDispatchStreamingService(planningService, dispatchService);

  @Test
  void streamsSafeProgressThenPlanTasksAndDoneWithoutRedispatching() throws Exception {
    AiPlanRequest request = new AiPlanRequest(7L, "检查响应头");
    AiPlanResponse generated =
        new AiPlanResponse(
            "ccs",
            "test",
            "计划",
            true,
            List.of(new AiPlanResponse.PlanStep("http_headers", "响应头", "安全基线", Map.of())));
    AiPlanResponse executable = new AiPlanResponse("ccs", "test", "计划", false, generated.steps());
    AiDispatchResponse response = new AiDispatchResponse(7L, executable, 1, List.of(42L));
    when(planningService.planStreaming(any(), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Consumer<AiModelClient.AiModelStreamEvent> listener = invocation.getArgument(1);
              listener.accept(new AiModelClient.AiModelStreamEvent("activity", "AI 已开始分析"));
              listener.accept(new AiModelClient.AiModelStreamEvent("reasoning_summary", "先确认授权边界"));
              listener.accept(
                  new AiModelClient.AiModelStreamEvent("output_delta", "secret-plan-json"));
              return generated;
            });
    when(dispatchService.dispatchPlanned(request, generated)).thenReturn(response);
    List<Map<String, Object>> events = new ArrayList<>();

    service.stream(request, events::add);

    assertThat(events)
        .extracting(event -> event.get("type"))
        .containsSequence(
            "progress", "progress", "progress", "progress", "progress", "plan", "tasks", "done");
    assertThat(events)
        .anyMatch(
            event ->
                "reasoning".equals(event.get("stage")) && "先确认授权边界".equals(event.get("summary")));
    assertThat(events).noneMatch(event -> "secret-plan-json".equals(event.get("summary")));
    Map<String, Object> done = events.get(events.size() - 1);
    assertThat(done)
        .containsEntry("targetId", 7L)
        .containsEntry("taskCount", 1)
        .containsEntry("taskIds", List.of(42L));
    verify(dispatchService).dispatchPlanned(request, generated);
  }

  @Test
  void emitsErrorEventWhenAuthorizationValidationRejectsPlan() throws Exception {
    AiPlanRequest request = new AiPlanRequest(7L, "扫描未授权端口");
    AiPlanResponse generated =
        new AiPlanResponse(
            "ccs",
            "test",
            "计划",
            true,
            List.of(new AiPlanResponse.PlanStep("tcp_ports", "端口", "请求", Map.of("ports", "22"))));
    when(planningService.planStreaming(any(), any())).thenReturn(generated);
    when(dispatchService.dispatchPlanned(request, generated))
        .thenThrow(new ApiException("AI 请求的端口超出目标授权范围"));
    List<Map<String, Object>> events = new ArrayList<>();

    service.stream(request, events::add);

    assertThat(events.get(events.size() - 1))
        .containsEntry("type", "error")
        .containsEntry("message", "AI 请求的端口超出目标授权范围");
    assertThat(events).noneMatch(event -> "tasks".equals(event.get("type")));
  }
}
