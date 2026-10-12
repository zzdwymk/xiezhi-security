package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.audit.AuditService;
import java.util.Map;

/**
 * 护栏审计出口（设计文档 §6.1 末段"审计入账（全量）"）。
 *
 * <p>存在的理由：{@link CapabilityGate} 必须在<strong>没有 Spring 上下文</strong>时也可构造（越权用例集是纯单元测试，不能每个用例
 * 都起容器）。因此审计依赖被抽象成这个单方法接口，生产环境由 {@link AgentCapabilityGuardConfiguration} 接上真实的 {@link
 * AuditService}，测试可注入内存实现来断言"被拒绝的调用也被记录了"。
 *
 * <p>约定：实现<strong>不得</strong>抛出异常。审计失败不能把一次合法的放行变成拒绝（可用性），更不能把一次拒绝变成放行（安全）。
 */
@FunctionalInterface
public interface CapabilityAuditSink {

  /**
   * 记录一次能力调用尝试。
   *
   * @param action 动作名，形如 {@code AGENT_CAPABILITY_INVOKE}
   * @param capabilityCode 能力码
   * @param detail 结构化详情（能力类别、风险等级、确认等级、目标绑定、拒绝层与原因等）
   * @param result 结果：{@code SUCCESS} / {@code DENIED} / {@code FAILED}
   */
  void record(String action, String capabilityCode, Map<String, Object> detail, String result);

  /** 丢弃全部审计的实现，仅供不需要审计断言的场景使用。 */
  CapabilityAuditSink NOOP = (action, capabilityCode, detail, result) -> {};

  /** 接到平台既有审计服务上；序列化或落库失败时静默降级，绝不影响护栏判定。 */
  static CapabilityAuditSink of(AuditService auditService) {
    if (auditService == null) {
      return NOOP;
    }
    return (action, capabilityCode, detail, result) -> {
      try {
        auditService.recordStructured(action, "AGENT_CAPABILITY", capabilityCode, detail, result);
      } catch (RuntimeException ignored) {
        // 审计通道故障不得改变护栏结论：放行仍是放行，拒绝仍是拒绝。
      }
    };
  }
}
