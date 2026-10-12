package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import java.util.Map;
import java.util.Set;

/**
 * 护栏放行结果（设计文档 §6.3 的 {@code CapabilityResult}）。
 *
 * <p>只有通过四层校验的调用才会得到本对象——拿到它就意味着"授权范围已核验、能力已准入、参数已校验"。调用方据此执行能力。
 *
 * <p>刻意<strong>不</strong>携带"执行函数"：护栏不做派发（§6.3 伪码末行的 {@code dispatch} 属于能力层的职责），否则护栏会同时
 * 承担"判定"与"执行"，一旦执行路径出问题就难以判断是护栏失效还是执行层失效。
 *
 * <h2>三种出口（"先看见，要用时申请"）</h2>
 *
 * <p>护栏原先只有两个出口（放行 / 拒绝），本记录新增第三个：
 *
 * <table border="1">
 *   <caption>护栏的三个出口</caption>
 *   <tr><th>出口</th><th>返回值</th><th>Agent 应做什么</th></tr>
 *   <tr><td>已授权</td><td>{@code CapabilityOutcome}（{@link #isApprovalRequired()} 为 false）</td><td>直接执行</td></tr>
 *   <tr><td><strong>未授权</strong></td><td>{@code CapabilityOutcome.approvalRequired(...)}</td><td><strong>向用户申请</strong></td></tr>
 *   <tr><td>越权/非法</td><td>抛 {@link CapabilityDeniedException}</td><td>放弃（不可申请）</td></tr>
 * </table>
 *
 * <p><strong>为什么"未授权"必须是返回值而不是异常</strong>：若抛异常，Agent 只看到"失败"，
 * <strong>不知道可以申请</strong>，于是放弃或尝试绕过。返回 {@link CapabilityApprovalRequest}
 * 才能让它知道"这条路可以走，只要用户同意"。
 *
 * @param capability 通过校验的能力
 * @param approvalLevel 本次调用的确认等级（{@link ApprovalLevel#REQUIRED} 时调用方必须确认已有 {@code humanApproved}）
 * @param targetBindings 本次调用触及的授权目标 ID（真空集表示确实不触及目标）
 * @param auditDetail 已写入审计的结构化详情（便于调用方在后续阶段补充）
 * @param approvalRequest 需要用户授权的申请；为 {@code null} 表示已授权、可直接执行
 */
public record CapabilityOutcome(
    AgentCapability capability,
    ApprovalLevel approvalLevel,
    Set<String> targetBindings,
    Map<String, Object> auditDetail,
    CapabilityApprovalRequest approvalRequest) {

  public CapabilityOutcome {
    targetBindings = targetBindings == null ? Set.of() : Set.copyOf(targetBindings);
    auditDetail = auditDetail == null ? Map.of() : Map.copyOf(auditDetail);
  }

  /** 兼容构造：已授权、可直接执行（无待批申请）。 */
  public CapabilityOutcome(
      AgentCapability capability,
      ApprovalLevel approvalLevel,
      Set<String> targetBindings,
      Map<String, Object> auditDetail) {
    this(capability, approvalLevel, targetBindings, auditDetail, null);
  }

  /**
   * 构造"需要用户授权"的结果。
   *
   * <p>这是护栏的<strong>第三个出口</strong>：能力本身合法、参数也合法，只是目标尚未授权。
   * Agent 收到后应向用户呈现申请，而不是放弃。
   */
  public static CapabilityOutcome approvalRequired(
      AgentCapability capability, CapabilityApprovalRequest request) {
    return new CapabilityOutcome(
        capability, ApprovalLevel.REQUIRED, Set.of(), Map.of("approvalRequested", true), request);
  }

  /** 本次调用是否需要用户授权（尚未授权）。 */
  public boolean isApprovalRequired() {
    return approvalRequest != null;
  }

  /** 能力码。 */
  public String code() {
    return capability == null ? null : capability.code();
  }

  /** 是否触及授权目标。 */
  public boolean touchesTargets() {
    return !targetBindings.isEmpty();
  }

  /**
   * 本次调用解析出的唯一目标 ID。
   *
   * <p>供 {@code SecurityTool} 适配器使用：现有工具的签名是 {@code execute(AuthorizedTarget, params)}，目标由框架注入。这里返回
   * 的正是护栏刚刚校验过的那个目标，从而保证"被校验的目标"与"被执行的目标"是同一个，杜绝校验与执行之间的目标错位。
   *
   * @throws CapabilityDeniedException 绑定数量不是 1 时（多目标或零目标的能力不能走单目标执行路径）
   */
  public long singleTargetId() {
    if (targetBindings.size() != 1) {
      throw new CapabilityDeniedException(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_AMBIGUOUS",
          code(),
          "该执行路径要求恰好一个授权目标，实际为 " + targetBindings.size() + " 个");
    }
    return Long.parseLong(targetBindings.iterator().next());
  }
}
