package com.bachelor.toolbox.ai;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * One project-scoped turn of the security agent.
 *
 * <p>{@code execute=false} is the safe default and only produces a reviewed plan. Setting {@code
 * execute=true} is the caller's explicit confirmation for the existing low-risk task dispatcher. It
 * never enables tools outside that dispatcher's hard-coded allow-list.
 */
public record AiAgentRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @Pattern(regexp = "[A-Za-z0-9_-]{1,64}", message = "会话 ID 只能包含字母、数字、下划线和连字符，长度为 1-64 个字符")
        String sessionId,
    @NotBlank(message = "提示内容不能为空") @Size(max = 4000, message = "提示内容长度不得超过 4000 个字符")
        String prompt,
    Boolean execute,
    AiPlanRequest.ContextRefs contextRefs,
    @Size(max = 40, message = "上下文引用数量不得超过 40 个") List<AiPlanRequest.ContextRef> refs,
    @Size(max = 30, message = "模式长度不得超过 30 个字符") String mode) {
  public boolean executionRequested() {
    return Boolean.TRUE.equals(execute);
  }
}
