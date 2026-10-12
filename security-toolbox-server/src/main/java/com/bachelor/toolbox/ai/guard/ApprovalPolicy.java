package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 确认策略（设计文档 §6.6）：按"<strong>影响面 × 可逆性</strong>"分级，而不是按 HTTP 方法。
 *
 * <p>{@link ApprovalLevel#REQUIRED} 只覆盖文档明确列出的五类：
 *
 * <ol>
 *   <li>对授权目标发起实际执行（扫描/探测/利用）——由"触及目标 + 非只读"判定；
 *   <li>删除类操作（{@code DELETE}）；
 *   <li>影响授权范围的操作（增删授权目标）；
 *   <li>修改安全配置；
 *   <li>{@code bash_probe} 且动作分级为 INTRUSIVE。
 * </ol>
 *
 * <p>其余归 {@link ApprovalLevel#BATCH} 或 {@link ApprovalLevel#NONE}。这样用户每次确认都有实际意义，避免"习惯性批准"。
 *
 * <p><strong>保守优先</strong>：所有不确定的输入都往更严格的方向取（§10："宁高勿低"）。黑名单能力返回 {@link
 * ApprovalLevel#FORBIDDEN}，由护栏 L-B 拒绝——本类只负责"分级"，不负责"拒绝"。
 */
@Component
public class ApprovalPolicy {

  /** 对目标发起实际执行的能力码前缀/后缀特征（用于兜底识别手工能力）。 */
  private static final Set<String> EXECUTION_MARKERS =
      Set.of("scan", "probe", "exploit", "fuzz", "bruteforce", "inject");

  /** 删除类动作标记。 */
  private static final Set<String> DELETE_MARKERS = Set.of("delete", "remove", "purge", "drop");

  /** 影响授权范围的动作标记。 */
  private static final Set<String> AUTHORIZATION_MARKERS =
      Set.of("target", "authorization", "approval", "project");

  /** 修改安全配置的动作标记。 */
  private static final Set<String> SECURITY_CONFIG_MARKERS =
      Set.of("settings", "config", "security", "permission", "role", "user");

  /** bash 能力码。 */
  public static final String BASH_PROBE_CODE = "bash_probe";

  /** bash 动作分级为 INTRUSIVE 时参数键。 */
  private static final Set<String> BASH_ACTION_KEYS = Set.of("action", "mode", "actionClass", "action_class");

  private final boolean requireApprovalForExecution;
  private final boolean requireApprovalForDestructive;

  public ApprovalPolicy(
      @Value("${toolbox.agent.guard.approval.execution-required:true}")
          boolean requireApprovalForExecution,
      @Value("${toolbox.agent.guard.approval.destructive-required:true}")
          boolean requireApprovalForDestructive) {
    this.requireApprovalForExecution = requireApprovalForExecution;
    this.requireApprovalForDestructive = requireApprovalForDestructive;
  }

  /** 测试与手工装配用的默认实例（两项开关均为 true，最严格）。 */
  public ApprovalPolicy() {
    this(true, true);
  }

  /**
   * 判定一次调用的确认等级。
   *
   * @param capability 能力
   * @param params 实际参数（用于识别 DELETE 语义与 bash 动作分级）；允许为 {@code null}
   * @param targetBindings 本次调用触及的目标绑定；允许为 {@code null}
   */
  public ApprovalLevel levelFor(
      AgentCapability capability, Map<String, Object> params, Set<String> targetBindings) {
    if (capability == null) {
      // 判不出能力就按最严处理；真正的拒绝发生在 L-D 的未知能力分支。
      return ApprovalLevel.REQUIRED;
    }
    if (capability.requiresApproval()) {
      // 能力自己声明要确认，这是最直接的信号，优先采信。
      return ApprovalLevel.REQUIRED;
    }
    if (isDestructive(capability)) {
      return ApprovalLevel.REQUIRED;
    }
    if (isBashIntrusive(capability, params)) {
      return ApprovalLevel.REQUIRED;
    }
    if (isAuthorizationBoundaryChange(capability, params)) {
      return ApprovalLevel.REQUIRED;
    }
    if (isSecurityConfigChange(capability, params)) {
      return ApprovalLevel.REQUIRED;
    }
    if (isActualExecution(capability, params, targetBindings)) {
      return ApprovalLevel.REQUIRED;
    }
    if (capability.kind() == CapabilityKind.READ && capability.risk() == RiskLevel.SAFE) {
      return ApprovalLevel.NONE;
    }
    return ApprovalLevel.BATCH;
  }

  /** 不可逆操作：{@link RiskLevel#DESTRUCTIVE}，或 DELETE 语义。 */
  private boolean isDestructive(AgentCapability capability) {
    return requireApprovalForDestructive && capability.risk() == RiskLevel.DESTRUCTIVE;
  }

  /** 对授权目标发起实际执行：触及目标 + 非只读，或能力码带执行特征。 */
  private boolean isActualExecution(
      AgentCapability capability, Map<String, Object> params, Set<String> targetBindings) {
    if (!requireApprovalForExecution) {
      return false;
    }
    boolean touchesTarget = targetBindings != null && !targetBindings.isEmpty();
    if (touchesTarget && capability.kind() != CapabilityKind.READ) {
      return true;
    }
    return hasMarker(capability.code(), EXECUTION_MARKERS) || hasMarker(httpMethod(params), EXECUTION_MARKERS);
  }

  /** 删除类操作：HTTP DELETE，或能力码带删除特征。 */
  private boolean isDeleteLike(AgentCapability capability, Map<String, Object> params) {
    String method = httpMethod(params);
    if ("DELETE".equalsIgnoreCase(method)) {
      return true;
    }
    return hasMarker(capability.code(), DELETE_MARKERS);
  }

  /** 影响授权范围：增删授权目标 / 审批 / 项目授权声明。 */
  private boolean isAuthorizationBoundaryChange(
      AgentCapability capability, Map<String, Object> params) {
    if (isDeleteLike(capability, params)) {
      // DELETE 已经在文档里单列，但"删除授权目标"同样属于影响授权范围，两者都指向 REQUIRED。
      return true;
    }
    if (capability.kind() == CapabilityKind.READ) {
      return false;
    }
    String code = capability.code() == null ? "" : capability.code().toLowerCase(Locale.ROOT);
    boolean mentionsAuthorization =
        code.contains("target") || code.contains("authoriz") || code.contains("approval");
    return mentionsAuthorization && hasMarker(code, AUTHORIZATION_MARKERS);
  }

  /** 修改安全配置：settings / config / security / 权限相关写操作。 */
  private boolean isSecurityConfigChange(AgentCapability capability, Map<String, Object> params) {
    if (capability.kind() == CapabilityKind.READ) {
      return false;
    }
    if (isDeleteLike(capability, params)) {
      return true;
    }
    String code = capability.code() == null ? "" : capability.code().toLowerCase(Locale.ROOT);
    return code.contains("settings")
        || code.contains("config")
        || code.contains("security")
        || code.contains("permission")
        || code.contains("role");
  }

  /** bash_probe 且动作分级为 INTRUSIVE。 */
  private boolean isBashIntrusive(AgentCapability capability, Map<String, Object> params) {
    if (!BASH_PROBE_CODE.equalsIgnoreCase(capability.code())) {
      return false;
    }
    if (params == null) {
      // 拿不到动作分级时按 INTRUSIVE 处理（保守优先）。
      return true;
    }
    for (Map.Entry<String, Object> entry : params.entrySet()) {
      if (entry.getKey() != null && BASH_ACTION_KEYS.contains(entry.getKey().trim())) {
        String action = String.valueOf(entry.getValue()).trim().toUpperCase(Locale.ROOT);
        if ("INTRUSIVE".equals(action) || "DESTRUCTIVE".equals(action)) {
          return true;
        }
        if ("SAFE".equals(action) || "READ_ONLY".equals(action) || "RECON".equals(action)) {
          return false;
        }
      }
    }
    // 参数里没写动作分级 → 保守按 INTRUSIVE。
    return true;
  }

  /** 从参数中取 HTTP 方法（端点能力的常见写法）。 */
  private static String httpMethod(Map<String, Object> params) {
    if (params == null) {
      return null;
    }
    for (String key : new String[] {"method", "httpMethod", "http_method"}) {
      Object value = params.get(key);
      if (value instanceof String text && !text.isBlank()) {
        return text.trim().toUpperCase(Locale.ROOT);
      }
    }
    return null;
  }

  private static boolean hasMarker(String text, Set<String> markers) {
    if (text == null || text.isBlank()) {
      return false;
    }
    String lower = text.toLowerCase(Locale.ROOT);
    for (String marker : markers) {
      if (lower.contains(marker)) {
        return true;
      }
    }
    return false;
  }
}
