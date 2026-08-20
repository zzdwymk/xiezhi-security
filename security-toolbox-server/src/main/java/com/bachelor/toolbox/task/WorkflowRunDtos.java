package com.bachelor.toolbox.task;

import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public final class WorkflowRunDtos {
  private WorkflowRunDtos() {}

  public record SnapshotRequest(
      @NotNull(message = "项目 ID 不能为空") Long projectId,
      @NotNull(message = "目标 ID 不能为空") Long targetId,
      String workflowId,
      Long workflowRevision,
      String workflowDigest) {}

  public record StartRequest(
      @NotNull(message = "项目 ID 不能为空") Long projectId,
      @NotNull(message = "目标 ID 不能为空") Long targetId,
      String workflowId,
      Long workflowRevision,
      String workflowDigest,
      List<String> approvedNodeIds,
      List<String> skippedNodeIds) {}

  public record NodeIssue(String nodeId, String toolCode, String label, String reason) {}

  public record PreflightResponse(
      String workflowId,
      Long workflowRevision,
      String workflowDigest,
      List<NodeIssue> issues) {}

  public record Summary(
      Long id,
      Long projectId,
      Long targetId,
      String workflowId,
      Long workflowRevision,
      String workflowDigest,
      String status,
      int progress,
      String message,
      int taskCount,
      Instant createdAt,
      Instant startedAt,
      Instant finishedAt) {}

  public record Detail(Summary run, Map<String, Object> spec, List<SecurityTask> tasks) {}
}
