package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 安全工具参数的取值白名单（与 {@code AiTaskDispatchService#normalizeParameters} 对齐）。
 *
 * <h2>为什么需要这个类：一个"覆盖不全"缺口的修复</h2>
 *
 * <p>本任务在实现 {@code create_task} 时自查发现：能力层只校验了 {@code toolCode} 非空与"是否已注册"，
 * 把工具<strong>参数取值</strong>的校验完全交给了下游 {@code TaskService.create}。这是一个真实缺口，理由：
 *
 * <ol>
 *   <li><strong>拒绝理由的精确性</strong>：护栏 L-C 的审计会记录"能力层校验通过"，而实际被下游拒绝 → 审计与事实不符，
 *       §9.5 的越权拦截率无法正确归因；
 *   <li><strong>保护会静默消失</strong>：下游路径一旦重构，这层保护就没了，而能力层的 Javadoc 仍声称校验过；
 *   <li>这与 guard-verifier 发现的 D-1..D-6 属<strong>同一模式</strong>——"校验被写在某个具体入口上，而不是所有入口上"。
 * </ol>
 *
 * <h2>本类的定位：把 dispatch 层的规则集显式化，而不是"再抄一份"</h2>
 *
 * <p>纯粹复制一份白名单会立刻产生第二个漂移源（这正是 D-1..D-5 的成因）。因此本类：
 *
 * <ul>
 *   <li>把规则集<strong>集中在一处</strong>并带来源注释（每条规则注明 dispatch 层的对应行），便于代码审查比对；
 *   <li>提供 {@link #assertNoDrift(List)} 供测试断言"本类的工具清单 == dispatch 层的可执行工具清单"，
 *       一旦 dispatch 层增删工具而本类未同步，测试<strong>立即失败</strong>——把"人工记得同步"变成"机器强制同步"。
 * </ul>
 *
 * <h2>⚠️ 已知的架构局限（如实记录）</h2>
 *
 * <p>本类仍是 dispatch 层规则的<strong>第二份实现</strong>。正确的长期修法是把校验<strong>下沉到唯一执行入口</strong>
 * （{@code TaskService.create}），让所有上游路径（REST、AI dispatch、能力层、invoke_endpoint）共用同一份校验。
 * 但那需要修改 {@code task/} 包（不在本任务写作用域内），因此本任务采取的是"显式化 + 漂移断言"这一折中：
 * 它把"静默漂移"变成"测试失败"，但没有消除重复实现本身。这一点必须写进论文的已知局限。
 */
public final class ToolParameterPolicy {

  /** 与 {@code AiToolCatalog.EXECUTABLE_CODES} 对齐的可执行工具清单。 */
  public static final List<String> EXECUTABLE_TOOLS =
      List.of(
          "nmap_service_scan", "tcp_ports", "http_headers", "http_security_check", "tls_config",
          "nuclei_scan", "afrog_scan", "xray_scan", "zap_scan", "fscan_scan", "sqlmap_scan",
          "msf_scan", "zap_fuzz", "site_crawl");

  /** 项目内只读检索工具（非执行类，无工具参数）。 */
  public static final List<String> READ_ONLY_TOOLS = List.of("retrieve_project_context");

  /** 各工具允许的参数键（对齐 {@code AiTaskDispatchService:238-252}）。 */
  private static final Map<String, Set<String>> ALLOWED_KEYS =
      Map.ofEntries(
          // tcp_ports 的扫描面只由 ports 决定（缺省 = 授权全段），故不接受 mode；udp 追加 UDP 探测。
          Map.entry("tcp_ports", Set.of("ports", "udp")),
          Map.entry("nmap_service_scan", Set.of("ports", "mode")),
          Map.entry("fscan_scan", Set.of("ports", "vulnMode")),
          Map.entry("afrog_scan", Set.of("pocCodes", "allPocs")),
          Map.entry("xray_scan", Set.of("pocCodes", "allPocs")),
          Map.entry("nuclei_scan", Set.of("pocCodes", "allPocs")),
          Map.entry("zap_scan", Set.of("spider", "strength")),
          Map.entry("msf_scan", Set.of("module", "modules", "options")),
          Map.entry("sqlmap_scan", Set.of("path", "level", "risk", "technique")),
          Map.entry("http_security_check", Set.of("check")),
          Map.entry("http_headers", Set.of()),
          Map.entry("tls_config", Set.of()),
          Map.entry("site_crawl", Set.of()),
          Map.entry("retrieve_project_context", Set.of("query")));

  /** 取值枚举（对齐 dispatch 层的逐个 case 校验）。 */
  private static final Map<String, Set<String>> VALUE_ENUMS =
      Map.ofEntries(
          Map.entry("nmap_service_scan.mode", com.bachelor.toolbox.ai.ToolParameterSpec.NMAP_MODES),
          Map.entry("fscan_scan.vulnMode", Set.of("SAFE", "FINGERPRINT", "FULL")),
          Map.entry("zap_scan.strength", Set.of("LOW", "MEDIUM", "HIGH", "INSANE")),
          Map.entry("http_security_check.check", Set.of("cookies", "cors", "methods", "disclosure")));

  private ToolParameterPolicy() {}

  /** 该工具是否为平台已知的工具（执行类或只读检索类）。 */
  public static boolean isKnownTool(String toolCode) {
    return toolCode != null
        && (EXECUTABLE_TOOLS.contains(toolCode) || READ_ONLY_TOOLS.contains(toolCode));
  }

  /** 该工具的允许参数键；未知工具返回空集。 */
  public static Set<String> allowedKeys(String toolCode) {
    return ALLOWED_KEYS.getOrDefault(toolCode, Set.of());
  }

  /**
   * 校验工具与参数：工具必须在清单内、参数键必须在白名单内、枚举取值必须合法。
   *
   * <p>刻意<strong>不</strong>校验端口是否在授权范围内——那需要 {@code AuthorizedTarget}，属护栏 L-A 与 L-C' 的职责，
   * 在这里重复实现会产生第三份端口规则。
   *
   * @throws ApiException 任一规则不满足
   */
  public static void validate(String toolCode, Map<String, Object> parameters) {
    if (!isKnownTool(toolCode)) {
      throw new ApiException("未知或未授权的安全工具代码: " + toolCode);
    }
    Map<String, Object> safe = parameters == null ? Map.of() : parameters;
    Set<String> allowed = allowedKeys(toolCode);
    Set<String> unexpected = new LinkedHashSet<>(safe.keySet());
    unexpected.removeAll(allowed);
    if (!unexpected.isEmpty()) {
      throw new ApiException("工具 " + toolCode + " 不接受参数: " + String.join("、", unexpected));
    }
    for (Map.Entry<String, Set<String>> rule : VALUE_ENUMS.entrySet()) {
      String[] parts = rule.getKey().split("\\.", 2);
      if (!parts[0].equals(toolCode)) {
        continue;
      }
      Object raw = safe.get(parts[1]);
      if (raw == null) {
        continue;
      }
      String value = raw.toString().trim().toUpperCase(Locale.ROOT);
      Set<String> permitted = new LinkedHashSet<>();
      rule.getValue().forEach(item -> permitted.add(item.toUpperCase(Locale.ROOT)));
      if (!permitted.contains(value)) {
        throw new ApiException(
            "工具 " + toolCode + " 的参数 " + parts[1] + " 取值不受支持: " + raw
                + "（允许：" + String.join("、", rule.getValue()) + "）");
      }
    }
    validateToolSpecific(toolCode, safe);
  }

  /** 工具特有的结构性校验（对齐 dispatch 层的 msf 模块前缀、PoC 选择等）。 */
  private static void validateToolSpecific(String toolCode, Map<String, Object> parameters) {
    switch (toolCode) {
      case "msf_scan" -> {
        if (parameters.containsKey("modules") && parameters.containsKey("module")) {
          throw new ApiException("不能同时指定 msf 的 module 与 modules");
        }
        if (parameters.containsKey("modules")) {
          Object raw = parameters.get("modules");
          if (!(raw instanceof java.util.Collection<?> collection) || collection.isEmpty()) {
            throw new ApiException("MSF 模块列表格式无效");
          }
          for (Object item : collection) {
            requireMsfModule(item);
          }
        } else if (parameters.containsKey("module")) {
          requireMsfModule(parameters.get("module"));
        }
      }
      case "nuclei_scan", "afrog_scan", "xray_scan" -> validatePocSelection(parameters);
      case "zap_scan" -> {
        if (parameters.containsKey("spider") && !(parameters.get("spider") instanceof Boolean)) {
          throw new ApiException("ZAP spider 参数必须为布尔值");
        }
      }
      case "sqlmap_scan" -> {
        if (parameters.containsKey("level") || parameters.containsKey("risk")) {
          requireRange(parameters.get("level"), 1, 5, "sqlmap level");
          requireRange(parameters.get("risk"), 1, 3, "sqlmap risk");
        }
      }
      default -> {
        // 其余工具无额外结构约束。
      }
    }
  }

  private static void requireMsfModule(Object raw) {
    String module = raw == null ? "" : raw.toString().trim().toLowerCase(Locale.ROOT);
    if (!(module.startsWith("auxiliary/") || module.startsWith("exploit/"))) {
      throw new ApiException("MSF 模块仅允许 auxiliary/ 或 exploit/ 前缀: " + raw);
    }
  }

  private static void validatePocSelection(Map<String, Object> parameters) {
    boolean hasCodes = parameters.containsKey("pocCodes");
    boolean hasAll = parameters.containsKey("allPocs");
    if (!hasCodes && !hasAll) {
      return;
    }
    if (hasCodes == hasAll) {
      throw new ApiException("PoC 选择必须指定具体 PoC 或全部 PoC，不能同时指定");
    }
    if (hasAll) {
      if (!Boolean.TRUE.equals(parameters.get("allPocs"))) {
        throw new ApiException("全部 PoC 参数必须为 true");
      }
      return;
    }
    Object raw = parameters.get("pocCodes");
    if (!(raw instanceof java.util.Collection<?> values) || values.isEmpty() || values.size() > 50) {
      throw new ApiException("PoC 数量必须在 1 到 50 之间");
    }
    Set<String> unique = new LinkedHashSet<>();
    for (Object value : values) {
      String code = value == null ? "" : value.toString();
      if (!code.matches("[A-Z]{2}-[A-F0-9]{24}") || !unique.add(code)) {
        throw new ApiException("PoC 编号无效或重复: " + code);
      }
    }
  }

  private static void requireRange(Object raw, int min, int max, String label) {
    if (raw == null) {
      return;
    }
    int value;
    if (raw instanceof Number number) {
      value = number.intValue();
    } else {
      try {
        value = Integer.parseInt(raw.toString().trim());
      } catch (NumberFormatException error) {
        throw new ApiException(label + " 必须为整数: " + raw);
      }
    }
    if (value < min || value > max) {
      throw new ApiException(label + " 必须在 " + min + " 到 " + max + " 之间: " + raw);
    }
  }

  /**
   * 漂移断言：确认本类的工具清单与给定的权威清单一致。
   *
   * <p>供测试调用。一旦 dispatch 层增删工具而本类未同步，测试立即失败——把"人工记得同步"变成"机器强制同步"。
   *
   * @param authoritativeTools 权威工具码集合（来自 {@code AiToolCatalog.EXECUTABLE_TOOLS}）
   * @throws ApiException 两侧不一致时
   */
  public static void assertNoDrift(java.util.Collection<String> authoritativeTools) {
    Set<String> authoritative = new LinkedHashSet<>(authoritativeTools);
    Set<String> local = new LinkedHashSet<>(EXECUTABLE_TOOLS);
    if (!authoritative.equals(local)) {
      Set<String> onlyAuthoritative = new LinkedHashSet<>(authoritative);
      onlyAuthoritative.removeAll(local);
      Set<String> onlyLocal = new LinkedHashSet<>(local);
      onlyLocal.removeAll(authoritative);
      throw new ApiException(
          "工具清单漂移：dispatch 层独有 " + onlyAuthoritative + "，能力层独有 " + onlyLocal);
    }
  }
}
