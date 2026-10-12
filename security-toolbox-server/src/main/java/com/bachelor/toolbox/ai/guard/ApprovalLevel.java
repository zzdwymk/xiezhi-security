package com.bachelor.toolbox.ai.guard;

/**
 * 能力调用的确认等级（设计文档 §6.6）。
 *
 * <p>分级依据是"<strong>影响面 × 可逆性</strong>"，而不是 HTTP 方法。自动派生的约 180 个端点中大量是 {@code POST}，若按方法
 * 判定就会全部弹确认，用户习惯性批准后护栏失效（确认疲劳）。因此这里只把真正高危的少数操作列为 {@link #REQUIRED}。
 *
 * <table border="1">
 *   <caption>等级语义</caption>
 *   <tr><th>等级</th><th>判定</th><th>处理</th></tr>
 *   <tr><td>{@link #NONE}</td><td>只读查询、无副作用</td><td>自动放行</td></tr>
 *   <tr><td>{@link #SINGLE}</td><td>按需授权的<strong>默认粒度</strong>：仅本次有效</td><td>逐次确认，凭据一次性</td></tr>
 *   <tr><td>{@link #BATCH}</td><td>有副作用但可逆、且属常规流程</td><td>批量确认（一次会话内同类操作合并确认）</td></tr>
 *   <tr><td>{@link #REQUIRED}</td><td>不可逆、影响授权边界、或触及目标执行</td><td>逐次确认</td></tr>
 *   <tr><td>{@link #FORBIDDEN}</td><td>黑名单</td><td>直接拒绝</td></tr>
 * </table>
 *
 * <h2>{@link #SINGLE} 与 {@link #REQUIRED} 的区别</h2>
 *
 * <p>两者都要求人工确认，差别在<strong>凭据时效</strong>：
 *
 * <ul>
 *   <li>{@link #REQUIRED}：确认后本次放行，<strong>不签发可复用凭据</strong>
 *   <li>{@link #SINGLE}：按需授权场景下签发<strong>一次性凭据</strong>（绑定能力+目标+参数摘要），
 *       供 Agent 持凭据重试
 * </ul>
 *
 * <p>数值刻意与 {@link #REQUIRED} 相同（2）：二者严格程度等价，合并判定时不应互相压制。
 * {@link #stricterOf} 在同severity 时保留自身，因此不会意外降级。
 */
public enum ApprovalLevel {

  /** 只读、无副作用，自动放行。 */
  NONE(0),

  /** 有副作用但可逆，合并为一次会话级确认。 */
  BATCH(1),

  /** 会话级授权：本次会话内，对"同一能力+目标+参数摘要"的重复调用有效。 */
  SESSION(1),

  /** 按需授权的一次性凭据：需人工确认，确认后凭据仅对"同一能力+目标+参数"有效一次。 */
  SINGLE(2),

  /** 不可逆、影响授权边界、或对目标实际执行，逐次确认。 */
  REQUIRED(2),

  /** 黑名单能力，任何情况下都不允许由 Agent 调用。 */
  FORBIDDEN(3);

  private final int severity;

  ApprovalLevel(int severity) {
    this.severity = severity;
  }

  /** 数值越大越严格，用于"取更严格者"的合并判定。 */
  public int severity() {
    return severity;
  }

  /** 返回两个等级中更严格的一个（fail-closed：不确定时取更严）。 */
  public ApprovalLevel stricterOf(ApprovalLevel other) {
    if (other == null) {
      return this;
    }
    return other.severity > this.severity ? other : this;
  }

  /** 是否需要人工介入（{@link #BATCH} 及以上）。 */
  public boolean requiresHumanDecision() {
    return this == BATCH || this == REQUIRED || this == SINGLE;
  }
}
