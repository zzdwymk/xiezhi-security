package com.bachelor.toolbox.ai;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * One project-scoped turn of the security agent.
 *
 * <p>Legacy {@code execute=false} only produces a reviewed plan and {@code execute=true} carries
 * explicit confirmation. AUTO uses a separate current user sentence and a validated model decision;
 * the orchestrator resolves execution only after the server policy agrees. Neither path enables
 * tools outside the dispatcher's hard-coded allow-list.
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
    @Size(max = 30, message = "模式长度不得超过 30 个字符") String mode,
    @NotBlank(message = "Turn ID 不能为空")
        @Pattern(regexp = "[A-Za-z0-9_-]{1,80}", message = "Turn ID 格式不合法")
        String turnId,
    @Pattern(regexp = "[A-Za-z0-9_-]{1,64}", message = "工作流 ID 格式不合法") String workflowId,
    @Positive(message = "工作流版本必须大于 0") Long workflowRevision,
    @Pattern(regexp = "sha256:[0-9a-f]{64}", message = "工作流摘要格式不合法")
        String workflowDigest,
    @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", message = "外层节点 ID 格式不合法")
        String outerNodeId,
    @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", message = "节点运行 ID 格式不合法")
        String nodeRunId,
    ExecutionIntent executionIntent,
    @Size(max = 4000, message = "本轮用户原句不得超过 4000 个字符") String userPrompt) {
  public enum ExecutionIntent { AUTO }

  public AiAgentRequest {
    if (executionIntent == ExecutionIntent.AUTO
        && (userPrompt == null || userPrompt.isBlank() || userPrompt.length() > 4000)) {
      throw new IllegalArgumentException("AUTO 请求必须携带独立的本轮用户原句 userPrompt");
    }
  }

  /** Compatibility with the existing fully bound request constructor. */
  public AiAgentRequest(Long projectId, Long targetId, String sessionId, String prompt,
      Boolean execute, AiPlanRequest.ContextRefs contextRefs, List<AiPlanRequest.ContextRef> refs,
      String mode, String turnId, String workflowId, Long workflowRevision, String workflowDigest,
      String outerNodeId, String nodeRunId) {
    this(projectId, targetId, sessionId, prompt, execute, contextRefs, refs, mode, turnId,
        workflowId, workflowRevision, workflowDigest, outerNodeId, nodeRunId, null, null);
  }
  /** Source-compatible constructor for callers that select the latest project workflow. */
  public AiAgentRequest(
      Long projectId,
      Long targetId,
      String sessionId,
      String prompt,
      Boolean execute,
      AiPlanRequest.ContextRefs contextRefs,
      List<AiPlanRequest.ContextRef> refs,
      String mode,
      String turnId) {
    this(
        projectId,
        targetId,
        sessionId,
        prompt,
        execute,
        contextRefs,
        refs,
        mode,
        turnId,
        null,
        null,
        null,
        null,
        null);
  }

  /** Compatibility constructor for callers that already selected a workflow revision. */
  public AiAgentRequest(
      Long projectId,
      Long targetId,
      String sessionId,
      String prompt,
      Boolean execute,
      AiPlanRequest.ContextRefs contextRefs,
      List<AiPlanRequest.ContextRef> refs,
      String mode,
      String turnId,
      String workflowId,
      Long workflowRevision,
      String workflowDigest) {
    this(
        projectId,
        targetId,
        sessionId,
        prompt,
        execute,
        contextRefs,
        refs,
        mode,
        turnId,
        workflowId,
        workflowRevision,
        workflowDigest,
        null,
        null);
  }

  public boolean executionRequested() {
    return !automaticExecutionIntent() && Boolean.TRUE.equals(execute);
  }

  public boolean automaticExecutionIntent() {
    return executionIntent == ExecutionIntent.AUTO;
  }

  /** Called only after the trusted runtime decision and server intent policy agree. */
  public AiAgentRequest withResolvedExecution(boolean resolved) {
    return new AiAgentRequest(projectId, targetId, sessionId, prompt, resolved, contextRefs,
        refs, mode, turnId, workflowId, workflowRevision, workflowDigest, outerNodeId,
        nodeRunId, null, userPrompt);
  }

  public AiAgentRequest withWorkflowSnapshot(AgentWorkflowSpecService.WorkflowSnapshot snapshot) {
    return new AiAgentRequest(
        projectId,
        targetId,
        sessionId,
        prompt,
        execute,
        contextRefs,
        refs,
        mode,
        turnId,
        snapshot.workflowId(),
        snapshot.revision(),
        snapshot.specDigest(),
        "ledger-agent",
        stableNodeRunId(projectId, turnId, snapshot.specDigest()),
        executionIntent,
        userPrompt);
  }

  private static String stableNodeRunId(Long projectId, String turnId, String workflowDigest) {
    try {
      String input = projectId + "\n" + turnId + "\n" + workflowDigest + "\nledger-agent";
      String digest =
          HexFormat.of()
              .formatHex(
                  MessageDigest.getInstance("SHA-256")
                      .digest(input.getBytes(StandardCharsets.UTF_8)));
      return "node-" + digest;
    } catch (Exception ex) {
      throw new IllegalStateException("无法生成节点运行 ID", ex);
    }
  }
}
