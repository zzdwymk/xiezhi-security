package com.bachelor.toolbox.ai.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 待批申请登记表——护栏提出的申请暂存在这里，等用户在 UI 上批准。
 *
 * <h2>为什么需要"待批"这个中间态</h2>
 *
 * <p>护栏返回 {@link CapabilityOutcome#approvalRequired} 时，申请是<strong>返回值</strong>，
 * 不是持久状态。但用户批准时，服务端必须能验证"这条申请确实由 Agent 提出过"——
 * 否则任何人都能凭空构造一个批准请求（<strong>凭空批准漏洞</strong>）。
 *
 * <p>本类就是这个验证依据：批准端点先用四要素在本表里查，
 * <strong>查不到就拒绝签发</strong>。
 *
 * <h2>安全与资源约束</h2>
 *
 * <ol>
 *   <li><strong>容量上限</strong>（{@value #MAX_PENDING}）：防止 Agent 反复提出申请把内存撑爆
 *       （拒绝服务）。超出时<strong>丢弃最旧的</strong>——新申请更可能被用户处理。
 *   <li><strong>过期清理</strong>：超过 {@value #PENDING_TTL_MINUTES} 分钟的申请自动失效
 *       （用户不会去批准一小时前的申请）。
 *   <li><strong>按四要素去重</strong>：同一申请重复提出只保留一条，避免刷屏。
 * </ol>
 */
public class PendingApprovalRegistry {

  private static final Logger log = LoggerFactory.getLogger(PendingApprovalRegistry.class);

  /** 待批申请容量上限。 */
  public static final int MAX_PENDING = 200;

  /** 待批申请有效期（分钟）。 */
  public static final long PENDING_TTL_MINUTES = 15;

  private static final Duration PENDING_TTL = Duration.ofMinutes(PENDING_TTL_MINUTES);

  private final Map<String, Entry> pending = new ConcurrentHashMap<>();

  /** 登记一条申请（护栏返回申请时调用）。 */
  public void register(CapabilityApprovalRequest request) {
    if (request == null) {
      return;
    }
    evictExpired();
    String key = key(request.capabilityCode(), request.targetId(), request.parameterDigest());
    // 去重：同一申请重复提出只更新时间戳。
    pending.put(key, new Entry(request, Instant.now()));
    if (pending.size() > MAX_PENDING) {
      evictOldest();
    }
  }

  /** 查找待批申请（批准端点用它验证"申请确实存在"）。 */
  public Optional<CapabilityApprovalRequest> find(
      String capabilityCode, String targetId, String parameterDigest) {
    Entry entry = pending.get(key(capabilityCode, targetId, parameterDigest));
    if (entry == null) {
      return Optional.empty();
    }
    if (isExpired(entry)) {
      pending.remove(key(capabilityCode, targetId, parameterDigest));
      return Optional.empty();
    }
    return Optional.of(entry.request());
  }

  /** 批准后移除（防止重复批准）。 */
  public void remove(String capabilityCode, String targetId, String parameterDigest) {
    pending.remove(key(capabilityCode, targetId, parameterDigest));
  }

  /** 当前待批申请列表（供 UI 渲染）。 */
  public List<CapabilityApprovalRequest> pending() {
    evictExpired();
    return pending.values().stream()
        .sorted(Comparator.comparing(Entry::createdAt))
        .map(Entry::request)
        .toList();
  }

  /** 当前待批数量。 */
  public int size() {
    evictExpired();
    return pending.size();
  }

  /** 清空（供测试与运维使用）。 */
  public void clear() {
    pending.clear();
  }

  // ------------------------------------------------------------------ 内部

  private void evictExpired() {
    pending.entrySet().removeIf(entry -> isExpired(entry.getValue()));
  }

  private void evictOldest() {
    pending.entrySet().stream()
        .min(Comparator.comparing(entry -> entry.getValue().createdAt()))
        .ifPresent(
            oldest -> {
              pending.remove(oldest.getKey());
              log.warn(
                  "待批申请超过容量上限 {}，已丢弃最旧的一条: {}",
                  MAX_PENDING,
                  oldest.getValue().request().capabilityCode());
            });
  }

  private static boolean isExpired(Entry entry) {
    return entry.createdAt().plus(PENDING_TTL).isBefore(Instant.now());
  }

  private static String key(String capabilityCode, String targetId, String parameterDigest) {
    return String.valueOf(capabilityCode)
        + "|"
        + String.valueOf(targetId)
        + "|"
        + String.valueOf(parameterDigest);
  }

  private record Entry(CapabilityApprovalRequest request, Instant createdAt) {}
}
