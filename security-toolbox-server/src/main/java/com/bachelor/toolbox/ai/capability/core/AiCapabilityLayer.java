package com.bachelor.toolbox.ai.capability.core;

/**
 * 能力分层标注（设计文档 §5 分层暴露策略）。
 *
 * <h2>三层各自解决什么问题</h2>
 *
 * <table border="1">
 *   <caption>分层与暴露方式</caption>
 *   <tr><th>层</th><th>内容</th><th>暴露方式</th></tr>
 *   <tr><td>{@link #L1}</td><td>工作流、任务、发现、流量、资产、报告、审计等核心域</td>
 *       <td>直接进 prompt，完整 schema</td></tr>
 *   <tr><td>{@link #L2}</td><td>字典、指纹、计划、审计、设置、通知等扩展域</td>
 *       <td>经 {@code search_capabilities} 发现 → {@code unlock_capability} 解锁</td></tr>
 *   <tr><td>{@link #L3}</td><td>其余端点</td><td>经 {@code invoke_endpoint} 触达</td></tr>
 * </table>
 *
 * <h2>为什么"分层"本身不是安全机制</h2>
 *
 * <p>分层只解决<strong>上下文膨胀</strong>（§10 局限 1）：180 个端点的完整 schema 塞不进 prompt。它<strong>不是</strong>
 * 权限边界——L2 能力解锁后与 L1 能力走<strong>同一个</strong> {@code CapabilityGate}，受完全相同的 L-B/L-C/L-A/L-D 约束。
 *
 * <p>这一点必须显式记录，否则很容易把"没暴露给模型"误当成"模型做不到"：那正是设计文档 §6.9 批评的"削减式"方案。本方案的立场是
 * Agent <strong>能做到</strong>，但<strong>执行前被拒绝</strong>。
 *
 * <h2>与 {@code kind()}/{@code risk()} 的关系</h2>
 *
 * <p>分层标注<strong>只影响提示词构建</strong>，与 {@code CapabilityKind}/{@code RiskLevel} 正交：
 *
 * <ul>
 *   <li>L1 里既有 {@code READ}/{@code SAFE}（{@code query_audit}），也有 {@code WRITE}/{@code SENSITIVE}
 *       （{@code run_workflow}）；
 *   <li>L2 里同样可能包含高危能力（如指纹规则的写操作）。
 * </ul>
 *
 * <p>因此<strong>不得</strong>用层号推导风险等级，也不得用层号替代 {@code targetBindings} 声明。层号不是授权依据。
 */
public enum AiCapabilityLayer {

  /** L1 核心层：直接进 prompt，语义清晰、优先选用。 */
  L1(1),

  /** L2 扩展层：按需解锁（{@code search_capabilities} → {@code unlock_capability}）。 */
  L2(2),

  /** L3 通用层：经 {@code invoke_endpoint} 触达的其余端点。 */
  L3(3);

  private final int depth;

  AiCapabilityLayer(int depth) {
    this.depth = depth;
  }

  /** 层号（1/2/3），供提示词与审计排序使用。 */
  public int depth() {
    return depth;
  }

  /** 是否需要在进 prompt 前显式解锁。 */
  public boolean requiresUnlock() {
    return this != L1;
  }

  /** 是否为"直接可用"层。 */
  public boolean isDirectlyExposed() {
    return this == L1;
  }
}
