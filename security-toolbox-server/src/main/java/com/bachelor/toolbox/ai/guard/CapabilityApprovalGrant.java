package com.bachelor.toolbox.ai.guard;

import java.time.Instant;

/**
 * 已签发的按需授权凭据。
 *
 * <p>绑定四要素（能力 + 目标 + 参数摘要 + 时效），见
 * {@link CapabilityApprovalGrantResolver} 的说明。
 *
 * @param capabilityCode 被批准的能力码
 * @param targetId 被批准的目标 ID
 * @param parameterDigest 被批准的参数摘要
 * @param level 批准粒度
 * @param grantedBy 批准人（用户标识）
 * @param grantedAt 签发时刻
 * @param expiresAt 失效时刻；{@code null} 表示不过期（仅 {@link ApprovalLevel#BATCH} 且显式指定范围时）
 */
public record CapabilityApprovalGrant(
    String capabilityCode,
    String targetId,
    String parameterDigest,
    ApprovalLevel level,
    String grantedBy,
    Instant grantedAt,
    Instant expiresAt) {

  /** 凭据在给定时刻是否有效（比对四要素 + 时效）。 */
  public boolean isValidAt(
      String requestedCapability, String requestedTarget, String requestedDigest, Instant now) {
    if (expiresAt != null && !now.isBefore(expiresAt)) {
      return false;
    }
    // 四要素逐一比对：任一不符即失效（防"批准 A 执行 B"）。
    return equalsText(capabilityCode, requestedCapability)
        && equalsText(targetId, requestedTarget)
        && equalsText(parameterDigest, requestedDigest);
  }

  private static boolean equalsText(String left, String right) {
    return left == null ? right == null : left.equals(right);
  }
}
