package com.bachelor.toolbox.task;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;

/** A start request may not skip nodes that are available in the current analysis. */
public final class WorkflowPreflightChangedException extends ApiException {
  private final WorkflowRunDtos.PreflightResponse currentPreflight;
  private final List<String> rejectedSkippedNodeIds;

  public WorkflowPreflightChangedException(
      WorkflowRunDtos.PreflightResponse currentPreflight, List<String> rejectedSkippedNodeIds) {
    super("请求跳过的节点不在当前预检的不可用列表中，已拒绝创建工作流；请重新预检并确认后重试");
    this.currentPreflight = currentPreflight;
    this.rejectedSkippedNodeIds = List.copyOf(rejectedSkippedNodeIds);
  }

  public WorkflowRunDtos.PreflightResponse currentPreflight() {
    return currentPreflight;
  }

  public List<String> rejectedSkippedNodeIds() {
    return rejectedSkippedNodeIds;
  }
}
