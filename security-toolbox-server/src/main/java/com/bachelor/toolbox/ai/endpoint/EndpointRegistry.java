package com.bachelor.toolbox.ai.endpoint;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * 端点注册表：把 (HTTP 方法, 路径) 映射到自动派生的能力（设计文档 §4.2 路线 B、§6.5 第二重约束）。
 *
 * <p>它是 {@code invoke_endpoint} 反向能力映射的<strong>唯一</strong>数据来源。{@code invoke_endpoint} 本身不是特权通道：
 * 它必须先用 {@link #contains} 证明端点已注册，再用 {@link #capabilityFor} 取回底层能力并套用后者的风险等级与确认要求。
 *
 * <h2>填充时机（重要）</h2>
 *
 * <p>本 Bean 是一个<strong>空容器</strong>：它在 {@code CapabilityRegistry} 之前构造完成，随后由
 * {@link EndpointCapabilityScanner} 在 {@code @PostConstruct} 中把端点写进来。
 *
 * <p>本类<strong>不</strong>实现 {@code List<AgentCapability>}，因为实测证明那条路无效：Spring 对
 * {@code List<T>} 的构造注入只汇总类型为 {@code T} 的独立 Bean，不会展开"返回类型为 {@code List<T>} 的集合 Bean"。
 * 端点能力改为由扫描器在扫描完成后调用 {@code CapabilityRegistry#register} 增量推入。详见
 * {@code EndpointCapabilityConfiguration} 的实测表格。
 *
 * <h2>匹配语义</h2>
 *
 * <p>请求路径先经 {@link PathNormalizer#normalize} 校验，然后与注册的路径模板匹配：
 *
 * <ul>
 *   <li>字面段必须完全相等（大小写敏感）
 *   <li>模板段 {@code {id}} 匹配任意单个合法路径段（该段内容必须通过 {@link PathNormalizer} 的字符集校验）
 * </ul>
 *
 * <p>匹配<strong>不做</strong>大小写折叠、不忽略结尾斜杠、不做前缀匹配——任何"宽松化"都会扩大可达面并制造绕过。
 * 需要宽松匹配的调用方应在能力层显式声明，而不是在这里悄悄放宽。
 *
 * <h2>为什么精确匹配的"字面优先"很重要</h2>
 *
 * <p>若同时存在 {@code /api/audits} 与 {@code /api/audits/{id}}，请求 {@code /api/audits} 必须命中前者。本实现先扫描字面
 * 段更多的模板（更具体者优先），因此不会出现"被模板抢走"的歧义。
 */
public final class EndpointRegistry {

  /** 键为 {@code METHOD /path/template}，保证同一方法+路径只登记一次。 */
  private final Map<String, EndpointCapability> byKey = new LinkedHashMap<>();

  /** 按路径模板分组的方法集合，供覆盖率统计与调试。 */
  private final Map<String, Set<String>> methodsByPath = new TreeMap<>();

  /** 缓存：具体请求路径 → 命中的端点能力。空值用 {@link Optional#empty()} 表示，避免重复匹配开销。 */
  private final Map<String, Optional<EndpointCapability>> matchCache = new LinkedHashMap<>();

  private int maxCacheSize = 4096;

  public EndpointRegistry() {}

  public EndpointRegistry(Collection<EndpointCapability> endpoints) {
    registerAll(endpoints);
  }

  /** 批量登记；重复的 (method, path) 会被忽略（同一端点不应产生两个能力）。 */
  public void registerAll(Collection<EndpointCapability> endpoints) {
    if (endpoints == null) return;
    for (EndpointCapability endpoint : endpoints) {
      register(endpoint);
    }
  }

  /**
   * 登记一个端点能力。
   *
   * <p>同一 (method, path) 重复登记是<strong>幂等</strong>的：保留先登记者并静默返回。这与 {@code CapabilityRegistry}
   * 对能力码重复的严格态度不同——端点是外部事实（Spring MVC 的映射表），重复登记只说明调用方重复喂数据，不构成安全风险；
   * 而能力码重复会掩盖"两个能力互相覆盖"的问题，因此那里必须抛错。
   *
   * @throws IllegalArgumentException 端点为空、方法为空或路径模板未以 {@code /} 开头时抛出
   */
  public void register(EndpointCapability endpoint) {
    if (endpoint == null) {
      throw new IllegalArgumentException("端点能力不能为空");
    }
    String method = endpoint.method();
    String path = endpoint.pathTemplate();
    if (method == null || method.isBlank()) {
      throw new IllegalArgumentException("端点方法不能为空: " + endpoint);
    }
    if (path == null || !path.startsWith("/")) {
      throw new IllegalArgumentException("端点路径模板必须以 / 开头: " + path);
    }
    String key = key(method, path);
    if (byKey.containsKey(key)) {
      return;
    }
    byKey.put(key, endpoint);
    methodsByPath.computeIfAbsent(path, ignored -> new LinkedHashSet<>()).add(method);
    matchCache.clear();
  }

  /**
   * 端点是否已注册（§6.5 第一重约束）。
   *
   * @param method HTTP 方法
   * @param path 请求路径（应已规范化；本方法会再做一次安全校验，非法路径直接判为未注册）
   * @return 已注册返回 {@code true}
   */
  public boolean contains(String method, String path) {
    return capabilityFor(method, path).isPresent();
  }

  /**
   * 反向能力映射（§6.5 第二重约束）：把端点还原为它的能力对象。
   *
   * <p>返回的能力携带该端点推断/校准后的风险等级与确认要求，{@code invoke_endpoint} 必须原样套用，不得放行。
   *
   * @param method HTTP 方法
   * @param path 请求路径
   * @return 命中的端点能力；未注册或路径非法时返回空
   */
  public Optional<EndpointCapability> capabilityFor(String method, String path) {
    if (method == null || path == null) {
      return Optional.empty();
    }
    String normalizedMethod = RiskInference.normalizeMethod(method);
    if (normalizedMethod.isEmpty()) {
      return Optional.empty();
    }
    String cacheKey = normalizedMethod + " " + path;
    Optional<EndpointCapability> cached = matchCache.get(cacheKey);
    if (cached != null) {
      return cached;
    }
    Optional<EndpointCapability> resolved = resolve(normalizedMethod, path);
    if (matchCache.size() >= maxCacheSize) {
      matchCache.clear();
    }
    matchCache.put(cacheKey, resolved);
    return resolved;
  }

  /** 按 (method, 模板) 精确查询，不做模板段匹配。供启动期自检使用。 */
  public Optional<EndpointCapability> exact(String method, String pathTemplate) {
    if (method == null || pathTemplate == null) return Optional.empty();
    return Optional.ofNullable(byKey.get(key(method, pathTemplate)));
  }

  /** 全部端点能力，按登记顺序。 */
  public Collection<EndpointCapability> all() {
    return List.copyOf(byKey.values());
  }

  /** 已登记的 (method, path) 数量。 */
  public int size() {
    return byKey.size();
  }

  /** 已登记的端点能力对象集合（供汇总进 {@code CapabilityRegistry}）。 */
  public List<AgentCapability> capabilities() {
    return new ArrayList<>(byKey.values());
  }

  /** 路径模板 → 该路径上注册的方法集合（只读快照）。 */
  public Map<String, Set<String>> methodsByPath() {
    Map<String, Set<String>> snapshot = new TreeMap<>();
    methodsByPath.forEach((path, methods) -> snapshot.put(path, Set.copyOf(methods)));
    return Map.copyOf(snapshot);
  }

  /** 按路径模板查询该模板上的全部端点能力。 */
  public List<EndpointCapability> byPath(String pathTemplate) {
    List<EndpointCapability> result = new ArrayList<>();
    for (EndpointCapability endpoint : byKey.values()) {
      if (endpoint.pathTemplate().equals(pathTemplate)) {
        result.add(endpoint);
      }
    }
    return List.copyOf(result);
  }

  /** 清空匹配缓存；人工校准风险等级后调用，避免命中旧结果。 */
  public void invalidateCache() {
    matchCache.clear();
  }

  /** 设置匹配缓存上限；小于 1 时按 1 处理。 */
  public void setMaxCacheSize(int maxCacheSize) {
    this.maxCacheSize = Math.max(1, maxCacheSize);
    matchCache.clear();
  }

  // ---------------------------------------------------------------- 内部实现

  private static String key(String method, String path) {
    return RiskInference.normalizeMethod(method) + " " + path;
  }

  private Optional<EndpointCapability> resolve(String method, String path) {
    if (!path.startsWith("/")) {
      return Optional.empty();
    }
    if (!PathNormalizer.isValid(path)) {
      // 非法路径（遍历、编码绕过、空段…）一律视为"未注册端点"，由调用方拒绝。
      return Optional.empty();
    }
    List<String> requestSegments = PathNormalizer.segments(path);
    EndpointCapability best = null;
    int bestLiteralCount = -1;
    for (EndpointCapability endpoint : byKey.values()) {
      if (!endpoint.method().equals(method)) {
        continue;
      }
      List<String> templateSegments = PathNormalizer.segments(endpoint.pathTemplate());
      if (templateSegments.size() != requestSegments.size()) {
        continue;
      }
      int literalCount = 0;
      boolean matched = true;
      for (int index = 0; index < templateSegments.size(); index++) {
        String templateSegment = templateSegments.get(index);
        String requestSegment = requestSegments.get(index);
        if (isTemplateSegment(templateSegment)) {
          if (requestSegment.isEmpty() || !isAcceptablePathValue(requestSegment)) {
            matched = false;
            break;
          }
          continue;
        }
        if (!templateSegment.equals(requestSegment)) {
          matched = false;
          break;
        }
        literalCount++;
      }
      if (matched && literalCount > bestLiteralCount) {
        best = endpoint;
        bestLiteralCount = literalCount;
      }
    }
    return Optional.ofNullable(best);
  }

  private static boolean isTemplateSegment(String segment) {
    return segment.length() > 2 && segment.startsWith("{") && segment.endsWith("}");
  }

  /** 路径参数取值：不允许含 {@code /}、{@code %}、{@code ..}、空白或非 ASCII。 */
  private static boolean isAcceptablePathValue(String value) {
    if (value.contains("%") || value.contains("\\") || value.contains("..")) {
      return false;
    }
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (current < 0x21 || current > 0x7e) {
        return false;
      }
    }
    return true;
  }

  /** 便捷工厂：把请求方法规范化后查询，供外部只读使用。 */
  public static String normalizeMethod(String method) {
    return RiskInference.normalizeMethod(method);
  }

  /** 调试用：返回注册表的可读摘要。 */
  public String describe() {
    StringBuilder builder = new StringBuilder();
    builder.append("端点注册表：").append(byKey.size()).append(" 个端点，覆盖 ")
        .append(methodsByPath.size()).append(" 条路径");
    byKey.values().forEach(endpoint -> builder.append(System.lineSeparator()).append("  ").append(endpoint));
    return builder.toString();
  }

  /** 仅供测试：暴露内部键集合。 */
  Set<String> keys() {
    return Set.copyOf(byKey.keySet());
  }

  /** 供 {@code Locale} 一致性检查使用，避免不同默认区域导致的意外行为。 */
  static Locale stableLocale() {
    return Locale.ROOT;
  }
}
