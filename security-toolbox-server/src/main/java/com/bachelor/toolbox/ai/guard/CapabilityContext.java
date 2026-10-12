package com.bachelor.toolbox.ai.guard;

import java.util.Map;

/**
 * 一次能力调用的上下文（设计文档 §6.3 的 {@code AgentContext}）。
 *
 * <p>只承载护栏判定真正需要的少量事实：谁在调用、在哪个项目/会话里调用、是否已获得人工批准、以及审批时记录的目标绑定快照
 * （§6.7 防 TOCTOU）。
 *
 * <p>刻意用 record + 静态工厂而不是一堆构造器重载，避免调用点出现"参数顺序写反导致安全参数静默丢失"。
 *
 * @param operator 调用主体（用户名或 {@code ai-agent}）；允许为 {@code null}，此时审计记为 {@code SYSTEM}
 * @param projectId 所属评估项目 ID；允许为 {@code null}
 * @param sessionId 会话 ID，用于 {@link ApprovalLevel#BATCH} 的会话级合并确认；允许为 {@code null}
 * @param humanApproved 是否已由人工显式批准（{@link ApprovalLevel#REQUIRED} 的唯一放行依据）
 * @param approvalId 对应的人工审批单 ID；允许为 {@code null}
 * @param approvedTargetBindings 审批时记录的目标绑定快照（形如 {@code "12=..."}）；允许为 {@code null}
 * @param metadata 其余透传信息（不参与判定，仅供审计）
 */
public record CapabilityContext(
    String operator,
    Long projectId,
    String sessionId,
    boolean humanApproved,
    Long approvalId,
    Map<String, String> approvedTargetBindings,
    Map<String, Object> metadata) {

  /** 归一化：把 {@code null} 集合字段换成空集合，避免调用点到处判空。 */
  public CapabilityContext {
    approvedTargetBindings =
        approvedTargetBindings == null ? Map.of() : Map.copyOf(approvedTargetBindings);
    metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
  }

  /** 无主体、无项目的最小上下文，用于测试与系统内部调用。 */
  public static CapabilityContext anonymous() {
    return new CapabilityContext(null, null, null, false, null, Map.of(), Map.of());
  }

  /** 指定调用主体。 */
  public static CapabilityContext of(String operator) {
    return new CapabilityContext(operator, null, null, false, null, Map.of(), Map.of());
  }

  /** 指定调用主体与项目。 */
  public static CapabilityContext of(String operator, Long projectId) {
    return new CapabilityContext(operator, projectId, null, false, null, Map.of(), Map.of());
  }

  /** 标记为已人工批准（{@link ApprovalLevel#REQUIRED} 的放行条件）。 */
  public CapabilityContext approved(Long approvalId) {
    return new CapabilityContext(
        operator, projectId, sessionId, true, approvalId, approvedTargetBindings, metadata);
  }

  /** 携带审批时的目标绑定快照，供 §6.7 的 TOCTOU 比对使用。 */
  public CapabilityContext withApprovedTargetBindings(Map<String, String> bindings) {
    return new CapabilityContext(
        operator, projectId, sessionId, humanApproved, approvalId, bindings, metadata);
  }
}
