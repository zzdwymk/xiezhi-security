package com.bachelor.toolbox.task;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;

/**
 * 项目级批量执行请求：直接按授权项目（而非单个授权目标）对整个项目内的目标批量下发同一工具。
 *
 * <p>{@code targetIds} 为空表示对项目内全部授权目标执行；非空表示只对指定的目标子集执行（子集必须都属于该项目）。
 * 每个目标仍独立接受项目授权时间窗、目标授权状态和任务配额校验，因此可能出现部分成功。
 */
public record ProjectBatchTaskRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotBlank(message = "工具代码不能为空") String toolCode,
    Map<String, Object> parameters,
    List<Long> targetIds) {

  /** 目标范围为空即代表项目内全部目标。 */
  public boolean allTargets() {
    return targetIds == null || targetIds.isEmpty();
  }
}
