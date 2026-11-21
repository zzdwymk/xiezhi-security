package com.bachelor.toolbox.target;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;

/**
 * 目标登记请求。
 *
 * <p>这里的 {@code @Size} 上限必须与 {@link AuthorizedTarget} 的列长度保持一致。
 * 否则超长输入会通过 Bean Validation，直接落到数据库约束上，
 * 抛出未处理的约束异常并返回 HTTP 500（而不是可读的 400 参数错误）。
 */
public record TargetRequest(
    @NotBlank(message = "目标名称不能为空")
        @Size(max = 100, message = "目标名称不能超过 100 个字符")
        String name,
    @NotBlank(message = "目标地址不能为空")
        @Size(max = 500, message = "目标地址不能超过 500 个字符")
        String targetValue,
    @NotBlank(message = "目标类型不能为空")
        @Size(max = 20, message = "目标类型不能超过 20 个字符")
        String targetType,
    @NotBlank(message = "授权记录不能为空")
        @Size(max = 2000, message = "授权记录不能超过 2000 个字符")
        String authorizationNote,
    @Size(max = 200, message = "授权端口不能超过 200 个字符") String allowedPorts,
    Boolean enabled,
    Instant authorizationValidFrom,
    Instant authorizationExpiresAt,
    Long projectId,
    /**
     * Round 286：显式清空授权时间窗。{@code null} 的时间窗字段在更新时表示「保持不变」，
     * 因此清空必须是显式动作，不能靠省略字段达成（省略即放宽是必须避免的）。
     */
    Boolean clearAuthorizationWindow) {
  public TargetRequest(
      String name,
      String targetValue,
      String targetType,
      String authorizationNote,
      String allowedPorts,
      Boolean enabled) {
    this(name, targetValue, targetType, authorizationNote, allowedPorts, enabled, null, null, null, null);
  }

  /** 兼容既有 9 参调用（不含清空标志）。 */
  public TargetRequest(
      String name,
      String targetValue,
      String targetType,
      String authorizationNote,
      String allowedPorts,
      Boolean enabled,
      Instant authorizationValidFrom,
      Instant authorizationExpiresAt,
      Long projectId) {
    this(
        name,
        targetValue,
        targetType,
        authorizationNote,
        allowedPorts,
        enabled,
        authorizationValidFrom,
        authorizationExpiresAt,
        projectId,
        null);
  }
}
