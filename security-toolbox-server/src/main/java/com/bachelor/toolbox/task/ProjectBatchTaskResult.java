package com.bachelor.toolbox.task;

import java.util.List;

/**
 * 项目级批量执行结果：逐目标报告是否成功创建任务或失败原因，便于前端展示部分成功。
 *
 * <p>{@code total}/{@code succeeded}/{@code failed} 汇总整体执行情况；{@code items} 保持请求的顺序（全部目标时为项目内登记顺序）。
 */
public record ProjectBatchTaskResult(
    Long projectId,
    String toolCode,
    int total,
    int succeeded,
    int failed,
    List<Item> items) {

  public record Item(
      Long targetId,
      String targetName,
      Long taskId,
      String status,
      String message) {

    public static Item success(Long targetId, String targetName, Long taskId) {
      return new Item(targetId, targetName, taskId, "CREATED", "任务已创建并进入执行队列");
    }

    public static Item failure(Long targetId, String targetName, String message) {
      return new Item(targetId, targetName, null, "FAILED", message);
    }
  }
}
