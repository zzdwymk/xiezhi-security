package com.bachelor.toolbox.operation;

import jakarta.validation.constraints.AssertFalse;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public final class SecurityActionDtos {
  private SecurityActionDtos() {}

  public record Create(
      @NotNull(message = "必须指定授权目标") Long targetId,
      Long findingId,
      @NotBlank(message = "安全动作类型不能为空")
          @Pattern(
              regexp =
                  "VULNERABILITY_VALIDATION|CONTROLLED_EXPLOITATION|PRIVILEGE_VALIDATION|"
                      + "INTERNAL_ASSESSMENT|PERSISTENCE_VALIDATION",
              message = "不支持的安全动作类型")
          String category,
      @NotBlank(message = "动作标题不能为空") @Size(max = 200, message = "动作标题长度不得超过 200 个字符") String title,
      @NotBlank(message = "验证目的不能为空") @Size(max = 4000, message = "验证目的长度不得超过 4000 个字符")
          String purpose,
      @Pattern(regexp = "(?i)LOW|MEDIUM|HIGH|CRITICAL", message = "风险等级无效") String riskLevel,
      @NotNull(message = "必须明确非破坏性属性") @AssertTrue(message = "当前系统仅允许非破坏性验证")
          Boolean nonDestructive,
      @AssertFalse(message = "禁止未授权横向移动") Boolean lateralMovement,
      @NotBlank(message = "执行计划不能为空") @Size(max = 4000, message = "执行计划长度不得超过 4000 个字符")
          String executionPlan,
      @NotBlank(message = "回滚计划不能为空") @Size(max = 4000, message = "回滚计划长度不得超过 4000 个字符")
          String rollbackPlan,
      @NotNull(message = "必须指定执行开始时间") Instant windowStart,
      @NotNull(message = "必须指定执行结束时间") Instant windowEnd) {}

  public record Decision(
      @NotBlank(message = "审批结果不能为空") @Pattern(regexp = "(?i)APPROVED|REJECTED", message = "审批结果无效")
          String decision,
      @Size(max = 4000, message = "审批备注长度不得超过 4000 个字符") String comment) {}

  public record Complete(
      @NotBlank(message = "执行证据不能为空") @Size(max = 8000, message = "执行证据长度不得超过 8000 个字符")
          String evidence,
      @Size(max = 4000, message = "终止原因长度不得超过 4000 个字符") String terminationReason) {}

  public record Rollback(
      @NotBlank(message = "回滚证据不能为空") @Size(max = 8000, message = "回滚证据长度不得超过 8000 个字符")
          String evidence,
      @NotBlank(message = "回滚原因不能为空") @Size(max = 4000, message = "回滚原因长度不得超过 4000 个字符")
          String reason) {}
}
