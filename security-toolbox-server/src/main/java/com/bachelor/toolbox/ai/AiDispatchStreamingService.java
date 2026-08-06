package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;

@Service
public class AiDispatchStreamingService {
  private final AiPlanningService planningService;
  private final AiTaskDispatchService dispatchService;

  public AiDispatchStreamingService(
      AiPlanningService planningService, AiTaskDispatchService dispatchService) {
    this.planningService = planningService;
    this.dispatchService = dispatchService;
  }

  public void stream(AiPlanRequest request, Consumer<Map<String, Object>> sink) {
    AtomicLong outputCharacters = new AtomicLong();
    try {
      emitProgress(sink, "status", "正在核对授权目标与请求范围");
      AiPlanResponse generatedPlan =
          planningService.planStreaming(
              request,
              event -> {
                String text = sanitize(event.text());
                switch (event.type()) {
                  case "reasoning_summary" -> {
                    if (!text.isBlank()) {
                      emitProgress(sink, "reasoning", text);
                    }
                  }
                  case "output_delta" -> {
                    long count =
                        outputCharacters.addAndGet(
                            event.text() == null ? 0 : event.text().length());
                    Map<String, Object> progress = progress("output", "AI 正在生成可执行检测计划");
                    progress.put("receivedCharacters", count);
                    sink.accept(progress);
                  }
                  default -> emitProgress(sink, "status", text.isBlank() ? "AI 正在处理请求" : text);
                }
              });

      emitProgress(sink, "validation", "正在验证工具、参数与授权边界");
      // Validation and task creation remain centralized in AiTaskDispatchService. Passing the
      // already generated plan prevents a second model call and duplicate task creation.
      AiDispatchResponse response = dispatchService.dispatchPlanned(request, generatedPlan);
      sink.accept(planEvent(response));
      sink.accept(responseEvent("tasks", response));
      sink.accept(responseEvent("done", response));
    } catch (Exception ex) {
      Map<String, Object> error = new LinkedHashMap<>();
      error.put("type", "error");
      error.put("message", safeError(ex));
      sink.accept(error);
    }
  }

  private void emitProgress(Consumer<Map<String, Object>> sink, String stage, String message) {
    sink.accept(progress(stage, message));
  }

  private Map<String, Object> progress(String stage, String message) {
    Map<String, Object> event = new LinkedHashMap<>();
    event.put("type", "progress");
    event.put("stage", stage);
    event.put("summary", message);
    event.put("message", message);
    return event;
  }

  private Map<String, Object> planEvent(AiDispatchResponse response) {
    Map<String, Object> event = responseEvent("plan", response);
    event.put("plan", response.plan());
    return event;
  }

  private Map<String, Object> responseEvent(String type, AiDispatchResponse response) {
    Map<String, Object> event = new LinkedHashMap<>();
    event.put("type", type);
    event.put("targetId", response.targetId());
    event.put("plan", response.plan());
    event.put("taskCount", response.taskCount());
    event.put("taskIds", response.taskIds());
    return event;
  }

  private String sanitize(String text) {
    if (text == null) {
      return "";
    }
    String cleaned = text.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "");
    return cleaned.length() <= 1000 ? cleaned : cleaned.substring(0, 1000);
  }

  private String safeError(Exception ex) {
    if (ex instanceof ApiException && ex.getMessage() != null && !ex.getMessage().isBlank()) {
      return ex.getMessage();
    }
    // 计划生成失败会自动回退本地关键字规则；能走到这里通常是任务派发校验失败。
    return "AI 任务派发失败：请确认目标已授权、项目处于 ACTIVE 且授权未过期后重试。";
  }
}
