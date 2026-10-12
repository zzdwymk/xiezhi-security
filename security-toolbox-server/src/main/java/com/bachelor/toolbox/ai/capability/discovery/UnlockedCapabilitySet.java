package com.bachelor.toolbox.ai.capability.discovery;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * L2 能力解锁集合（设计文档 §5，借鉴 ARTEX 的 {@code DeferredTools}/{@code UnlockSet}）。
 *
 * <h2>它做什么</h2>
 *
 * <p>记录"本次会话已经解锁了哪些 L2 能力"。解锁是<strong>会话级</strong>的：解锁后该能力的完整 schema 才会进入后续
 * 轮次的 prompt。
 *
 * <h2>⚠️ 它<strong>不是</strong>安全机制——这一点必须写死在这里</h2>
 *
 * <p>解锁集合<strong>只影响提示词构建</strong>，<strong>不参与任何授权判定</strong>：
 *
 * <ul>
 *   <li>一个<strong>未解锁</strong>的能力，如果被直接调用，护栏仍然照常执行 L-B/L-C/L-A/L-D 全套校验——
 *       解锁与否不改变护栏结论；
 *   <li>一个<strong>已解锁</strong>的能力，不会因此获得任何额外权限。
 * </ul>
 *
 * <p>换句话说：把"解锁"实现成权限提升是<strong>架构性错误</strong>。§5 的分层解决的是上下文膨胀（§10 局限 1），
 * 不是访问控制。护栏是唯一的访问控制点，且它对所有能力一视同仁——这样"绕过解锁"就毫无收益，Agent 没有动机去绕。
 *
 * <p>反过来说，如果哪天有人把 {@code UnlockSet} 接进护栏做成"未解锁即拒绝"，就会立刻产生两个恶果：
 * ① 分层变成权限等级，与 §6.9 批评的"削减式方案"合流；② 解锁状态成为新的攻击面（谁能改解锁集合？）。
 * 因此本类的 Javadoc 同时也是对未来的约束。
 *
 * <h2>为什么按会话隔离</h2>
 *
 * <p>解锁状态跨会话共享会让"本次任务需要的能力"污染其它会话的上下文预算；更糟的是它让上下文占用变成不可预测的
 * 全局状态。因此键是会话 ID（{@code sessionId}）；无会话时用一个稳定的默认桶，保证同一轮内的解锁对后续轮次可见。
 */
@Component
public class UnlockedCapabilitySet {

  /** 无会话 ID 时使用的默认桶（保证解锁在同一次无会话调用链内可见）。 */
  public static final String DEFAULT_SESSION = "__default__";

  /** 单个会话可解锁的能力数上限，防止用解锁把 L2 全量拉进 prompt（等价于取消了分层）。 */
  public static final int MAX_UNLOCKED_PER_SESSION = 60;

  private final CapabilityRegistry registry;

  /** sessionId → 已解锁能力码（按解锁顺序）。 */
  private final ConcurrentHashMap<String, Set<String>> unlocked = new ConcurrentHashMap<>();

  public UnlockedCapabilitySet(CapabilityRegistry registry) {
    this.registry = Objects.requireNonNull(registry, "能力注册表不能为空");
  }

  /**
   * 解锁一个 L2 能力。
   *
   * @param sessionId 会话 ID；{@code null}/空白时落到 {@link #DEFAULT_SESSION}
   * @param code 能力码
   * @return 解锁结果
   */
  public UnlockResult unlock(String sessionId, String code) {
    String session = normalizeSession(sessionId);
    String normalized = code == null ? "" : code.trim();
    if (normalized.isEmpty()) {
      return new UnlockResult(false, "", "能力码不能为空");
    }
    AgentCapability capability = registry.find(normalized).orElse(null);
    if (capability == null) {
      // 未注册的能力不允许"预先解锁"：解锁集合不能成为比注册表更宽的清单。
      return new UnlockResult(false, normalized, "能力未在注册表中登记: " + normalized);
    }
    if (!CapabilityLayers.isUnlockable(capability)) {
      return new UnlockResult(
          true,
          normalized,
          "能力 " + normalized + " 属于 " + CapabilityLayers.layerOf(capability)
              + " 层，已直接可用，无需解锁");
    }
    Set<String> sessionUnlocks =
        unlocked.computeIfAbsent(session, ignored -> new LinkedHashSet<>());
    synchronized (sessionUnlocks) {
      if (sessionUnlocks.contains(normalized)) {
        return new UnlockResult(true, normalized, "能力已处于解锁状态: " + normalized);
      }
      if (sessionUnlocks.size() >= MAX_UNLOCKED_PER_SESSION) {
        return new UnlockResult(
            false,
            normalized,
            "本次会话解锁的能力数已达上限 " + MAX_UNLOCKED_PER_SESSION
                + "，请收敛任务范围（分层的目的正是控制上下文占用）");
      }
      sessionUnlocks.add(normalized);
    }
    return new UnlockResult(true, normalized, "已解锁能力: " + normalized);
  }

  /** 该能力在指定会话中是否已解锁。 */
  public boolean isUnlocked(String sessionId, String code) {
    if (code == null || code.isBlank()) {
      return false;
    }
    Set<String> session = unlocked.get(normalizeSession(sessionId));
    if (session == null) {
      return false;
    }
    synchronized (session) {
      return session.contains(code.trim());
    }
  }

  /** 指定会话已解锁的能力码（只读快照，按解锁顺序）。 */
  public Set<String> unlockedCodes(String sessionId) {
    Set<String> session = unlocked.get(normalizeSession(sessionId));
    if (session == null) {
      return Set.of();
    }
    synchronized (session) {
      return Set.copyOf(session);
    }
  }

  /** 指定会话已解锁的能力对象（跳过期间被移除的能力）。 */
  public java.util.List<AgentCapability> unlockedCapabilities(String sessionId) {
    java.util.List<AgentCapability> result = new java.util.ArrayList<>();
    for (String code : unlockedCodes(sessionId)) {
      registry.find(code).ifPresent(result::add);
    }
    return java.util.List.copyOf(result);
  }

  /** 清空指定会话的解锁状态。 */
  public void clear(String sessionId) {
    unlocked.remove(normalizeSession(sessionId));
  }

  /** 全部会话的解锁数量统计（供审计与调试）。 */
  public int sessionCount() {
    return unlocked.size();
  }

  private static String normalizeSession(String sessionId) {
    return sessionId == null || sessionId.isBlank() ? DEFAULT_SESSION : sessionId.trim();
  }

  /** 解锁结果。 */
  public record UnlockResult(boolean accepted, String code, String message) {}
}
