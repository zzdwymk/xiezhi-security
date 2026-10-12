package com.bachelor.toolbox.ai.guard;

/**
 * 按需授权凭据的签发与校验（"先看见，要用时申请"的落地）。
 *
 * <h2>为什么需要它</h2>
 *
 * <p>护栏原先只有两个出口：已授权 → 放行，未授权 → 拒绝。缺少"未授权 → <strong>申请授权</strong>"。
 * 后果是 Agent 能<em>看见</em>全部 206 个能力，但 168 个端点能力一个都用不了；遇到未授权时
 * 只得到一句"拒绝"，<strong>不知道可以申请</strong>。
 *
 * <p>本接口补上第三个出口。护栏在"目标未授权"时返回 {@link CapabilityOutcome#approvalRequired}，
 * 平台把 {@link CapabilityApprovalRequest} 渲染成确认卡片；用户批准后经 {@link #grant} 签发凭据，
 * Agent 持凭据重试时 {@link #hasValidApproval} 返回 true → 放行。
 *
 * <h2>凭据必须绑定四要素</h2>
 *
 * <p>{@code capabilityCode} + {@code targetId} + {@code parameterDigest} + 有效期。
 * 前三个由参数决定，有效期由 {@link ApprovalLevel} 决定：
 *
 * <table border="1">
 *   <caption>批准粒度与时效</caption>
 *   <tr><th>粒度</th><th>有效期</th><th>适用</th></tr>
 *   <tr><td>{@link ApprovalLevel#SINGLE}</td><td>仅本次（一次性）</td><td>默认；高危操作</td></tr>
 *   <tr><td>{@link ApprovalLevel#SESSION}</td><td>本会话内，且参数摘要相同</td><td>反复的同类只读/低危操作</td></tr>
 *   <tr><td>{@link ApprovalLevel#BATCH}</td><td>批量范围（需显式列出）</td><td>批量任务</td></tr>
 *   <tr><td>{@link ApprovalLevel#FORBIDDEN}</td><td>不签发</td><td>禁止的能力</td></tr>
 * </table>
 *
 * <p><strong>⚠️ 绝不提供"全部允许"</strong>——那是 ARTEX 的 {@code fail_action: allow}（模型故障时放行）。
 *
 * <h2>安全性质疑：Agent 会不会绕过申请直接调？</h2>
 *
 * <p>不会。申请是<strong>护栏内部的强制环节</strong>，不是 Agent 的自觉行为：
 * Agent 调用能力 → 护栏检查授权 → 未授权则<strong>返回申请而非放行</strong>。
 * Agent 拿不到"已授权"的状态，也就无法跳过。
 *
 * <h2>默认实现</h2>
 *
 * <p>{@link #denyAll()} 是默认（不签发任何凭据）——即"按需授权"未装配时，
 * 行为退回修复前的"未授权即拒绝"，<strong>不会因为缺少实现而 fail-open</strong>。
 */
public interface CapabilityApprovalGrantResolver {

  /**
   * 校验是否存在覆盖本次调用的有效凭据。
   *
   * @param capabilityCode 能力码
   * @param targetId 目标 ID
   * @param parameterDigest 参数摘要（见 {@link CapabilityApprovalRequest#digestOf}）
   * @return 有有效凭据则 true（护栏放行）
   */
  boolean hasValidApproval(String capabilityCode, String targetId, String parameterDigest);

  /**
   * 用户批准后签发凭据。
   *
   * <p>由平台在用户点击"同意"后调用；<strong>Agent 不得调用</strong>（否则等于自己批准自己）。
   *
   * @param request 申请（含四要素）
   * @param level 批准粒度
   * @return 签发的凭据（便于回显与审计）
   */
  CapabilityApprovalGrant grant(CapabilityApprovalRequest request, ApprovalLevel level);

  /**
   * 默认实现：不签发任何凭据（按需授权未装配）。
   *
   * <p>刻意选择"全部拒绝"而非"全部允许"——缺实现时退回 fail-closed，
   * 与护栏的整体取向一致。
   */
  static CapabilityApprovalGrantResolver denyAll() {
    return new CapabilityApprovalGrantResolver() {
      @Override
      public boolean hasValidApproval(
          String capabilityCode, String targetId, String parameterDigest) {
        return false;
      }

      @Override
      public CapabilityApprovalGrant grant(CapabilityApprovalRequest request, ApprovalLevel level) {
        throw new UnsupportedOperationException("按需授权未装配，无法签发凭据");
      }
    };
  }
}
