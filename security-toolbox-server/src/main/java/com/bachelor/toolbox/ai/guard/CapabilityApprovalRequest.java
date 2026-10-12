package com.bachelor.toolbox.ai.guard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * 一次能力调用的<strong>授权申请</strong>——由护栏生成，Agent 不可伪造。
 *
 * <h2>设计动机（"先看见，要用时申请"）</h2>
 *
 * <p>护栏原先只有两个出口：<strong>已授权 → 放行</strong>，<strong>未授权 → 拒绝</strong>。
 * 缺少第三个出口：<strong>未授权 → 申请授权</strong>。后果是：
 *
 * <ul>
 *   <li>Agent 能<em>看见</em>全部 206 个能力，但 168 个端点能力<strong>一个都用不了</strong>
 *   <li>遇到未授权时只得到一句"拒绝"，<strong>不知道可以申请</strong>，于是放弃或尝试绕过
 * </ul>
 *
 * <p>本对象补上第三个出口：护栏返回 {@link CapabilityOutcome#approvalRequired}，
 * 其中携带本申请 → 平台渲染成确认卡片给用户 → 用户批准后签发凭据 → Agent 持凭据重试。
 *
 * <h2>凭据绑定四要素（缺一即 fail-open）</h2>
 *
 * <table border="1">
 *   <caption>为什么必须绑定这四样</caption>
 *   <tr><th>要素</th><th>作用</th><th>缺了会怎样</th></tr>
 *   <tr><td>{@link #capabilityCode}</td><td>限定是哪个能力</td><td>批准 A 能力却执行 B</td></tr>
 *   <tr><td>{@link #targetId}</td><td>限定操作哪个目标</td><td>批准目标 1 却打目标 2（IDOR）</td></tr>
 *   <tr><td>{@link #parameterDigest}</td><td>限定具体参数</td><td>批准扫 80 端口却扫 3306</td></tr>
 *   <tr><td>{@link #requestedLevel}</td><td>限定批准粒度/时效</td><td>一次批准永久可用</td></tr>
 * </table>
 *
 * <h2>⚠️ 安全关键：申请卡片必须由平台渲染</h2>
 *
 * <p>{@link #humanReadableSummary} 由<strong>平台从能力元数据生成</strong>，
 * <strong>不是</strong> Agent 写的文案。若允许 Agent 自由描述申请内容，
 * 它可以"把 3306 端口说成 80"来说服用户批准——<strong>这是本机制最容易被忽视的风险</strong>。
 *
 * @param capabilityCode 申请的能力码
 * @param targetId 目标 ID；不触及目标的能力为 {@code null}
 * @param parameterDigest 参数摘要（见 {@link #digestOf}）
 * @param risk 风险等级（供用户判断）
 * @param requestedLevel 申请的批准粒度
 * @param humanReadableSummary 平台生成的人类可读摘要（<strong>非 Agent 生成</strong>）
 * @param parameters 参数原文（供用户核对；已做只读拷贝）
 */
public record CapabilityApprovalRequest(
    String capabilityCode,
    String targetId,
    String parameterDigest,
    String risk,
    ApprovalLevel requestedLevel,
    String humanReadableSummary,
    Map<String, Object> parameters) {

  public CapabilityApprovalRequest {
    Objects.requireNonNull(capabilityCode, "能力码不能为空");
    Objects.requireNonNull(parameterDigest, "参数摘要不能为空");
    requestedLevel = requestedLevel == null ? ApprovalLevel.SINGLE : requestedLevel;
    parameters = parameters == null ? Map.of() : Map.copyOf(parameters);
  }

  /**
   * 计算参数摘要——凭据绑定的核心。
   *
   * <h2>为什么需要它（防 TOCTOU）</h2>
   *
   * <p>用户批准时看到的是 {@code ports=80}，若执行时参数被改成 {@code ports=3306} 而护栏不比对，
   * 就等于"用户批准了 A，系统执行了 B"。摘要把批准与执行<strong>绑定到同一组参数</strong>。
   *
   * <h2>规范化：集合类参数先排序</h2>
   *
   * <p>{@code {"ports":"80,443"}} 与 {@code {"ports":"443,80"}} 在语义上是同一请求。
   * 若不排序，Agent 稍作调整就要重新申请——<strong>体验差会诱使用户无脑同意</strong>（批准疲劳）。
   *
   * <p>实现：递归展开 Map/Collection，键排序后拼接为规范字符串，再取 SHA-256。
   */
  public static String digestOf(String capabilityCode, String targetId, Map<String, Object> params) {
    StringBuilder canonical = new StringBuilder();
    canonical.append(capabilityCode == null ? "" : capabilityCode).append('\u0000');
    canonical.append(targetId == null ? "" : targetId).append('\u0000');
    canonical.append(canonicalize(params));
    return sha256(canonical.toString());
  }

  /** 递归规范化：Map 按键排序，Collection 元素排序，保证语义等价 → 摘要相同。 */
  private static String canonicalize(Object value) {
    if (value == null) {
      return "null";
    }
    if (value instanceof Map<?, ?> map) {
      // 键排序 → 与插入顺序无关。
      TreeMap<String, Object> sorted = new TreeMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        sorted.put(String.valueOf(entry.getKey()), entry.getValue());
      }
      StringBuilder builder = new StringBuilder("{");
      sorted.forEach(
          (key, item) -> builder.append(key).append('=').append(canonicalize(item)).append(';'));
      return builder.append('}').toString();
    }
    if (value instanceof Collection<?> collection) {
      // 元素排序 → "80,443" 与 "443,80" 摘要相同。
      List<String> items = collection.stream().map(CapabilityApprovalRequest::canonicalize).sorted().toList();
      return items.toString();
    }
    if (value instanceof Object[] array) {
      return canonicalize(java.util.Arrays.asList(array));
    }
    // 字符串形式的集合（如 "443,80"）也排序，使其与 "80,443" 等价。
    String text = String.valueOf(value);
    if (text.contains(",")) {
      List<String> parts =
          java.util.Arrays.stream(text.split(","))
              .map(String::trim)
              .filter(part -> !part.isEmpty())
              .sorted()
              .toList();
      return parts.toString();
    }
    return text;
  }

  private static String sha256(String input) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (NoSuchAlgorithmException unavailable) {
      // SHA-256 是 JDK 必须支持的算法，走到这里说明运行环境损坏。
      throw new IllegalStateException("SHA-256 不可用，无法生成参数摘要", unavailable);
    }
  }
}
