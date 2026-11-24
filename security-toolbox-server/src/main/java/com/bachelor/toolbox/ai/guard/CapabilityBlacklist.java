package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * 能力黑名单（设计文档 §6.4）。<strong>黑名单是绝对禁止</strong>：Agent 无论如何都不得调用，不接受任何确认或提升权限的旁路。
 *
 * <p>黑名单同时登记两类标识，因为它们描述的是同一件坏事的不同入口：
 *
 * <ul>
 *   <li><strong>能力码</strong>：直接以能力形态调用（{@code shutdown_system}）。
 *   <li><strong>端点</strong>：经通用端点原语 {@code invoke_endpoint("POST", "/api/system/shutdown")} 间接调用（§6.5 的
 *       "反向能力映射"约束）。只拦能力码会留下这个后门。
 * </ul>
 *
 * <p>构造时做前缀展开，把 {@code /api/auth/*} 这类模式展开成具体路径，避免运行期反复做前缀匹配（也就避免"某个调用点忘了匹配前缀"
 * 导致的 fail-open）。展开后的集合是只读快照。
 *
 * <p><strong>默认列表刻意"宁多勿少"</strong>（§10 失败模式：误判时应保守优先）。多拦一条会立刻在测试里暴露，少拦一条可能永远不被发现。
 */
public final class CapabilityBlacklist {

  /** §6.4 表中"绝对禁止 Agent 调用"的能力码。 */
  private static final Set<String> DEFAULT_CODES =
      Set.of(
          // 系统关机：拒绝服务
          "shutdown_system",
          "system_shutdown",
          // 认证操作：人类专属
          "auth_login",
          "auth_logout",
          "auth_refresh",
          "auth_me",
          "change_password",
          "auth_change_password",
          "reset_password",
          // 业务数据重置：不可逆破坏
          "reset_business_data",
          "business_data_reset",
          "clear_business_data",
          // 用户/权限管理：提权风险
          "manage_users",
          "manage_roles",
          "grant_role");

  /** §6.4 表中"绝对禁止"的端点路径模式；以 {@code /*} 结尾者按前缀展开。 */
  private static final Set<String> DEFAULT_PATH_PATTERNS =
      Set.of(
          // 系统关机：拒绝服务
          "/api/system/shutdown",
          // 认证操作：人类专属
          "/api/auth/*",
          // 业务数据重置：不可逆破坏
          "/api/settings/business-data",
          "/api/settings/business-data/*",
          "/api/settings/reset",
          "/api/settings/data-reset",
          // Round 386：实际存在的「清空全部业务数据」端点（SettingsController → BusinessDataResetService.clear）。
          // 此前只登记了 business-data*/reset/data-reset，漏掉本条，Agent 经 invoke_endpoint 调用时
          // 只落在"需管理员确认"而非"绝对禁止"，与黑名单对同类不可逆操作的立场不一致。
          "/api/settings/data");

  /**
   * 第387轮：<strong>方法 + 路径</strong>级绝对禁止条目（形如 {@code "DELETE /api/findings"}）。
   *
   * <p>存在原因：{@link #DEFAULT_PATH_PATTERNS} 只按路径匹配、不含 HTTP 方法，因此只能收录
   * "该路径上所有方法都是破坏性"的端点。{@code /api/findings}、{@code /api/vulnerabilities/catalog}
   * 这类**同时提供读接口**的资源无法整体拉黑（会把合法 GET 也禁掉），结果是它们的 DELETE
   * 只能靠"需管理员确认"防守——与黑名单对"不可逆批量删除"的立场不一致。
   *
   * <p>因此这里增加方法维度：只禁止破坏性的那个方法，读方法照常放行。
   */
  private static final Set<String> DEFAULT_METHOD_PATHS =
      Set.of(
          // 批量删除全部扫描发现（不可逆）
          "DELETE /api/findings",
          // 清空漏洞目录（不可逆）
          "DELETE /api/vulnerabilities/catalog",
          // Round 388：清空全部抓包会话/报文（TrafficProxyController → clearPackets）——
          // 抓包是取证与复核的原始证据，一次性清空不可恢复，与"清空发现/目录"同一风险等级。
          // 单条删除（DELETE /api/traffic/sessions/{packetId}）不在此列：那是正常的逐条清理。
          "DELETE /api/traffic/sessions");

  private final Set<String> blockedCodes;
  private final Set<String> blockedPaths;
  private final Set<String> blockedMethodPaths;

  private CapabilityBlacklist(Set<String> codes, Set<String> paths) {
    this(codes, paths, DEFAULT_METHOD_PATHS);
  }

  private CapabilityBlacklist(Set<String> codes, Set<String> paths, Set<String> methodPaths) {
    this.blockedCodes = Set.copyOf(codes);
    this.blockedPaths = Set.copyOf(paths);
    this.blockedMethodPaths = Set.copyOf(methodPaths);
  }

  /** §6.4 默认黑名单。 */
  public static CapabilityBlacklist defaults() {
    Set<String> paths = new LinkedHashSet<>();
    for (String pattern : DEFAULT_PATH_PATTERNS) {
      expand(pattern, paths);
    }
    return new CapabilityBlacklist(DEFAULT_CODES, paths);
  }

  /** 在默认黑名单之外追加能力码与路径模式（不接受移除，避免误配削弱护栏）。 */
  public CapabilityBlacklist withAdditional(Set<String> extraCodes, Set<String> extraPathPatterns) {
    Set<String> codes = new TreeSet<>(blockedCodes);
    if (extraCodes != null) {
      for (String code : extraCodes) {
        if (code != null && !code.isBlank()) {
          codes.add(code.trim());
        }
      }
    }
    Set<String> paths = new TreeSet<>(blockedPaths);
    if (extraPathPatterns != null) {
      for (String pattern : extraPathPatterns) {
        if (pattern != null && !pattern.isBlank()) {
          expand(pattern.trim(), paths);
        }
      }
    }
    return new CapabilityBlacklist(codes, paths, blockedMethodPaths);
  }

  /** 从逗号/分号/空白分隔的配置串构建追加黑名单。 */
  public CapabilityBlacklist withAdditionalCodes(String commaSeparated) {
    Set<String> codes = new TreeSet<>();
    if (commaSeparated != null) {
      for (String part : commaSeparated.split("[,;\\s]+")) {
        if (!part.isBlank()) {
          codes.add(part.trim());
        }
      }
    }
    return withAdditional(codes, Set.of());
  }

  /**
   * 能力码是否被禁止。
   *
   * <p>除精确匹配外，还对 {@code "*"} 通配码做前缀匹配，便于把"某前缀下的全部能力"整体拉黑。
   */
  public boolean blocksCode(String code) {
    if (code == null || code.isBlank()) {
      return false;
    }
    String normalized = code.trim();
    if (blockedCodes.contains(normalized)) {
      return true;
    }
    for (String blocked : blockedCodes) {
      if (blocked.endsWith("*") && normalized.startsWith(blocked.substring(0, blocked.length() - 1))) {
        return true;
      }
    }
    return false;
  }

  /** 能力是否被禁止（先看能力码，再看其声明的端点）。 */
  public boolean blocks(AgentCapability capability) {
    if (capability == null) {
      return false;
    }
    if (blocksCode(capability.code())) {
      return true;
    }
    String path = endpointPath(capability);
    return path != null && blocksPath(path);
  }

  /** 端点路径是否被禁止（§6.5 反向能力映射用）。 */
  public boolean blocksPath(String path) {
    if (path == null || path.isBlank()) {
      return false;
    }
    String normalized = normalizePath(path);
    if (blockedPaths.contains(normalized)) {
      return true;
    }
    for (String blocked : blockedPaths) {
      if (blocked.endsWith("/*")
          && normalized.startsWith(blocked.substring(0, blocked.length() - 1))) {
        return true;
      }
    }
    return false;
  }

  /** 能力码黑名单快照。 */
  public Set<String> blockedCodes() {
    return blockedCodes;
  }

  /**
   * 第387轮：按<strong>方法 + 路径</strong>判定是否被绝对禁止。
   *
   * <p>判定顺序（任何一步命中即禁止）：
   *
   * <ol>
   *   <li>先走 <strong>仅路径</strong> 规则（{@link #blocksPath(String)}）——这类端点上所有方法都属破坏性；
   *   <li>再看方法级规则（{@link #DEFAULT_METHOD_PATHS}）——只禁止破坏性方法，读方法放行。
   * </ol>
   *
   * <p>方法缺失/为空时**只**按路径规则判定：不给调用方"省略方法即逃逸"的机会，也不会因为读不到方法
   * 就把 DELETE 放行——真正的方法级拦截发生在 {@link CapabilityGate} 拿得到方法的那条路径上。
   */
  public boolean blocksMethodPath(String method, String path) {
    if (blocksPath(path)) {
      return true;
    }
    if (path == null || path.isBlank() || method == null || method.isBlank()) {
      return false;
    }
    String normalizedMethod = method.trim().toUpperCase(java.util.Locale.ROOT);
    String normalizedPath = normalizePath(path);
    if (blockedMethodPaths.contains(normalizedMethod + " " + normalizedPath)) {
      return true;
    }
    for (String blocked : blockedMethodPaths) {
      int split = blocked.indexOf(' ');
      if (split <= 0) {
        continue;
      }
      String blockedMethod = blocked.substring(0, split);
      String blockedPath = blocked.substring(split + 1);
      if (!blockedMethod.equals(normalizedMethod)) {
        continue;
      }
      if (blockedPath.endsWith("/*")
          && normalizedPath.startsWith(blockedPath.substring(0, blockedPath.length() - 1))) {
        return true;
      }
    }
    return false;
  }

  /** 方法级黑名单快照（形如 {@code "DELETE /api/findings"}）。 */
  public Set<String> blockedMethodPaths() {
    return blockedMethodPaths;
  }

  /** 端点黑名单快照（前缀模式已展开）。 */
  public Set<String> blockedPaths() {
    return blockedPaths;
  }

  /**
   * 尽力从能力对象上读取其声明的 HTTP 端点路径。
   *
   * <p>端点能力（§4.2 路线 B）通常会提供 {@code path()} / {@code endpointPath()} 之类的访问器；本类不依赖具体实现类型，只按方法名
   * 反射读取。读不到就返回 {@code null}——这不构成绕过，因为端点原语自身也会把 {@code path} 参数交给 {@link
   * #blocksPath(String)} 判定。
   */
  static String endpointPath(AgentCapability capability) {
    for (String accessor : new String[] {"path", "endpointPath", "httpPath"}) {
      try {
        Method method = capability.getClass().getMethod(accessor);
        Object value = method.invoke(capability);
        if (value instanceof String text && !text.isBlank()) {
          return text;
        }
      } catch (ReflectiveOperationException | RuntimeException ignored) {
        // 该能力没有这个访问器，继续尝试下一个；反射失败绝不能变成"未命中黑名单"以外的结论。
      }
    }
    return null;
  }

  /** 能力类别是否属于 §6.4 的"白名单需显式开启"范围。 */
  public static boolean isWhitelistedCategory(AgentCapability capability) {
    return capability != null && capability.kind() == CapabilityKind.ADMIN;
  }

  private static void expand(String pattern, Set<String> sink) {
    if (pattern == null || pattern.isBlank()) {
      return;
    }
    String normalized = normalizePath(pattern);
    if (normalized.endsWith("/*")) {
      String prefix = normalized.substring(0, normalized.length() - 1);
      sink.add(prefix);
      sink.add(normalized);
    } else {
      sink.add(normalized);
    }
  }

  private static String normalizePath(String path) {
    String normalized = path.trim();
    if (!normalized.startsWith("/")) {
      normalized = "/" + normalized;
    }
    return normalized;
  }

  @Override
  public String toString() {
    return "CapabilityBlacklist[codes=" + blockedCodes.size() + ", paths=" + blockedPaths.size() + "]";
  }

  /** 供配置层注入的端点黑名单模式（保持与 §6.4 表格一一对应）。 */
  public static Set<String> defaultPathPatterns() {
    return DEFAULT_PATH_PATTERNS;
  }

  /** 供配置层注入的能力码黑名单（保持与 §6.4 表格一一对应）。 */
  public static Set<String> defaultCodes() {
    return DEFAULT_CODES;
  }
}
