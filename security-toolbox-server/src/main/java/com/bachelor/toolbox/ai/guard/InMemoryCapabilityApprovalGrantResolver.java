package com.bachelor.toolbox.ai.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 按需授权凭据的<strong>内存实现</strong>（可用的默认实现）。
 *
 * <h2>用途</h2>
 *
 * <p>提供"用户批准 → 签发凭据 → Agent 持凭据重试"的完整闭环，供 UI 层直接使用：
 *
 * <pre>
 * // 1. Agent 调用能力 → 护栏返回申请
 * CapabilityOutcome outcome = gate.invoke(code, params, ctx);
 * if (outcome.isApprovalRequired()) {
 *   // 2. 平台把申请渲染成确认卡片（摘要由平台生成，非 Agent 措辞）
 *   showApprovalCard(outcome.approvalRequest());
 *   // 3. 用户点击"同意" → 签发凭据
 *   resolver.grant(outcome.approvalRequest(), ApprovalLevel.SINGLE);
 *   // 4. Agent 持凭据重试 → 放行
 *   gate.invoke(code, params, ctx);
 * }
 * </pre>
 *
 * <h2>时效策略</h2>
 *
 * <table border="1">
 *   <caption>批准粒度 → 有效期</caption>
 *   <tr><th>粒度</th><th>有效期</th><th>说明</th></tr>
 *   <tr><td>{@link ApprovalLevel#SINGLE}</td><td><strong>一次性</strong>（用后即焚）</td><td>默认；最安全</td></tr>
 *   <tr><td>{@link ApprovalLevel#SESSION}</td><td>本会话内（默认 30 分钟）</td><td>反复的同类低危操作</td></tr>
 *   <tr><td>{@link ApprovalLevel#BATCH}</td><td>默认 10 分钟</td><td>批量任务</td></tr>
 *   <tr><td>{@link ApprovalLevel#FORBIDDEN}</td><td><strong>不签发</strong></td><td>禁止的能力</td></tr>
 * </table>
 *
 * <h2>⚠️ 安全边界（如实记录）</h2>
 *
 * <ol>
 *   <li><strong>单机内存</strong>：多实例部署时凭据不共享——Agent 在实例 A 获批，重试落到实例 B 会再次申请。
 *       这是"可用性下降"而非"安全下降"（fail-closed），但生产多实例应改为共享存储。
 *   <li><strong>不持久化</strong>：重启后凭据失效（同上，方向安全）。
 *   <li><strong>无清理线程</strong>：过期条目在查询时惰性判定失效，但不会主动移除——长期运行需定期清理。
 * </ol>
 */
public class InMemoryCapabilityApprovalGrantResolver implements CapabilityApprovalGrantResolver {

  private static final Logger log =
      LoggerFactory.getLogger(InMemoryCapabilityApprovalGrantResolver.class);

  /** {@link ApprovalLevel#SESSION} 的默认有效期。 */
  public static final Duration SESSION_TTL = Duration.ofMinutes(30);

  /** {@link ApprovalLevel#BATCH} 的默认有效期。 */
  public static final Duration BATCH_TTL = Duration.ofMinutes(10);

  private final Map<String, CapabilityApprovalGrant> grants = new ConcurrentHashMap<>();
  private final AtomicLong grantCounter = new AtomicLong();

  @Override
  public boolean hasValidApproval(
      String capabilityCode, String targetId, String parameterDigest) {
    String key = key(capabilityCode, targetId, parameterDigest);
    CapabilityApprovalGrant grant = grants.get(key);
    if (grant == null) {
      return false;
    }
    Instant now = Instant.now();
    if (!grant.isValidAt(capabilityCode, targetId, parameterDigest, now)) {
      // 过期 → 惰性移除，并拒绝。
      grants.remove(key);
      log.debug("按需授权凭据已过期并移除: capability={} target={}", capabilityCode, targetId);
      return false;
    }
    if (grant.level() == ApprovalLevel.SINGLE) {
      // 一次性凭据：校验通过后立即消费，防止重放。
      grants.remove(key);
      log.debug("一次性凭据已消费: capability={} target={}", capabilityCode, targetId);
    }
    return true;
  }

  @Override
  public CapabilityApprovalGrant grant(CapabilityApprovalRequest request, ApprovalLevel level) {
    Objects.requireNonNull(request, "授权申请不能为空");
    ApprovalLevel effective = level == null ? ApprovalLevel.SINGLE : level;
    if (effective == ApprovalLevel.FORBIDDEN) {
      // 禁止的能力不签发凭据——申请也不该走到这里（护栏在 L-B 已拒）。
      throw new IllegalArgumentException("禁止的能力不能签发授权凭据: " + request.capabilityCode());
    }
    Instant now = Instant.now();
    Instant expiresAt =
        switch (effective) {
          case SINGLE -> now.plusSeconds(1); // 语义上是一次性；给 1 秒窗口以完成"批准→重试"的往返
          case SESSION -> now.plus(SESSION_TTL);
          case BATCH -> now.plus(BATCH_TTL);
          default -> now.plus(SESSION_TTL);
        };
    CapabilityApprovalGrant grant =
        new CapabilityApprovalGrant(
            request.capabilityCode(),
            request.targetId(),
            request.parameterDigest(),
            effective,
            "user",
            now,
            expiresAt);
    grants.put(key(request.capabilityCode(), request.targetId(), request.parameterDigest()), grant);
    grantCounter.incrementAndGet();
    log.info(
        "按需授权凭据已签发: capability={} target={} level={} 有效期至 {}",
        request.capabilityCode(),
        request.targetId(),
        effective,
        expiresAt);
    return grant;
  }

  /** 已签发的凭据数量（未过期的近似值，供运维观测）。 */
  public int size() {
    return grants.size();
  }

  /** 累计签发次数（供运维观测）。 */
  public long issuedCount() {
    return grantCounter.get();
  }

  /** 主动撤销一条凭据（供"用户撤回授权"使用）。 */
  public boolean revoke(String capabilityCode, String targetId, String parameterDigest) {
    return grants.remove(key(capabilityCode, targetId, parameterDigest)) != null;
  }

  /** 清空全部凭据（供测试与运维使用）。 */
  public void clear() {
    grants.clear();
  }

  /** 查看当前凭据（只读，供 UI 展示"已授权的操作"）。 */
  public Optional<CapabilityApprovalGrant> peek(
      String capabilityCode, String targetId, String parameterDigest) {
    return Optional.ofNullable(grants.get(key(capabilityCode, targetId, parameterDigest)));
  }

  private static String key(String capabilityCode, String targetId, String parameterDigest) {
    return String.valueOf(capabilityCode)
        + "|"
        + String.valueOf(targetId)
        + "|"
        + String.valueOf(parameterDigest);
  }
}
