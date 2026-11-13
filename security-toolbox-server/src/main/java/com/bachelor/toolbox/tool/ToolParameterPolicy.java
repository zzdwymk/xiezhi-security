package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 安全工具参数的取值白名单——<strong>全平台唯一事实来源</strong>（Round 10 下沉到 {@code tool} 包）。
 *
 * <h2>为什么从 ai.capability.core 迁到 tool 包</h2>
 *
 * <p>此前同一套工具/参数白名单存在三份实现：{@code EndpointParameterPolicy}（护栏 L-C'）、
 * 本类（能力层）、{@code ActiveScanService.ruleParameterKeys}（检测规则侧），外加 dispatch 层
 * {@code AiTaskDispatchService.normalizeParameters} 的 switch。多份实现必然漂移（Round 9 实测已发现
 * {@code dir_scan}/{@code zap_fuzz}/{@code udp}/{@code consumeOpenPorts} 等漏项）。
 *
 * <p>根治办法（本类落地）：把本类移到中立的 {@code tool} 包，使其可被 <strong>task 包（唯一执行入口
 * {@code TaskService.create}）</strong> 直接依赖。在 {@code TaskService.create} 的创建/派发漏斗里统一执行
 * 本类的 {@link #validate}，从而让 REST、AI dispatch、能力层、{@code invoke_endpoint} 等<strong>所有入口</strong>
 * 共用同一份校验，而不是各写一份。
 *
 * <p>方法本身的校验规则不变：工具必须在清单内、参数键必须在白名单内、枚举取值/结构性约束必须合法。
 * 这层<strong>不</strong>校验端口是否在授权范围内（那需要 {@code AuthorizedTarget}，属护栏 L-A/L-C' 的职责）。
 */
public final class ToolParameterPolicy {

  /** 与 {@code AiToolCatalog.EXECUTABLE_CODES} 对齐的可执行工具清单。 */
  public static final List<String> EXECUTABLE_TOOLS =
      List.of(
          "nmap_service_scan", "tcp_ports", "http_headers", "http_security_check", "tls_config",
          "nuclei_scan", "afrog_scan", "xray_scan", "zap_scan", "fscan_scan", "sqlmap_scan",
          "msf_scan", "zap_fuzz", "dir_scan", "site_crawl");

  /** 项目内只读检索工具（非执行类，无工具参数）。 */
  public static final List<String> READ_ONLY_TOOLS = List.of("retrieve_project_context");

  /** 各工具允许的参数键（对齐 {@code AiTaskDispatchService:238-252}）。 */
  private static final Map<String, Set<String>> ALLOWED_KEYS =
      Map.ofEntries(
          // tcp_ports 的扫描面只由 ports 决定（缺省 = 授权全段）；udp 追加 UDP 探测。
          Map.entry("tcp_ports", Set.of("ports", "udp")),
          Map.entry("nmap_service_scan", Set.of("ports", "mode", "consumeOpenPorts")),
          Map.entry("fscan_scan", Set.of("ports", "vulnMode")),
          Map.entry("afrog_scan", Set.of("pocCodes", "allPocs")),
          Map.entry("xray_scan", Set.of("pocCodes", "allPocs")),
          Map.entry("nuclei_scan", Set.of("pocCodes", "allPocs")),
          Map.entry("zap_scan", Set.of("spider", "strength")),
          Map.entry("dir_scan", Set.of("dictionary", "concurrency", "depth", "maxRequests", "extensions")),
          Map.entry("zap_fuzz",
              Set.of("fuzzRequestUrl", "method", "fuzzPostBody", "fuzzPayload", "fuzzTargetField")),
          Map.entry("msf_scan", Set.of("module", "modules", "options")),
          Map.entry("sqlmap_scan", Set.of("path", "level", "risk", "technique")),
          Map.entry("http_security_check", Set.of("check")),
          Map.entry("http_headers", Set.of()),
          Map.entry("tls_config", Set.of()),
          Map.entry("site_crawl", Set.of("fuse")),
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
   * <p>刻意<strong>不</strong>校验端口是否在授权范围内——那需要 {@code AuthorizedTarget}，属护栏 L-A 与 L-C' 的职责。
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

  /**
   * 框架内部传输参数（服务端在派发前注入，不是用户可配置的工具选项）。
   *
   * <p>{@code ActiveScanService}/{@code WebTargetResolver} 会在创建任务前把
   * {@code __resolvedWebBases}（预解析 Web 基址）与路径类工具的 {@code path} 注入参数。
   * 这些键属于服务端内部信道，不应被"用户参数白名单"误拦，但它们也<strong>不是</strong>用户可提交的自由参数——
   * 因此在唯一入口校验时把它们从"待校验键集合"中剔除，只对<strong>剩余的用户键</strong>套用白名单。
   */
  private static final Set<String> FRAMEWORK_INJECTED_KEYS =
      Set.of(com.bachelor.toolbox.target.WebTargetResolver.PARAM_RESOLVED_BASES);

  /**
   * 与 {@link #validate} 同语义，但用于 <strong>唯一执行入口</strong>（{@code TaskService.create}）。
   *
   * <p>两点差异（都是为了让"收敛到单一入口"不误伤既有合法路径）：
   * <ol>
   *   <li>先剔除框架注入键（{@link #FRAMEWORK_INJECTED_KEYS} 及 {@code __} 前缀键），只校验剩余用户键；
   *   <li>对<strong>本策略未知</strong>的工具码 fail-open 跳过（交由 {@code registry.require} 负责存在性）。
   * </ol>
   * 对已纳入白名单的工具，剩余用户键仍严格校验（键白名单 + 枚举 + 结构性约束）。
   */
  public static void validateAtExecutionEntry(String toolCode, Map<String, Object> parameters) {
    if (!isKnownTool(toolCode)) {
      // 策略未覆盖该工具：交由注册表存在性校验，此处不拦。
      return;
    }
    Map<String, Object> filtered = new java.util.LinkedHashMap<>();
    if (parameters != null) {
      for (Map.Entry<String, Object> entry : parameters.entrySet()) {
        String key = entry.getKey();
        if (key == null) continue;
        if (key.startsWith("__") || FRAMEWORK_INJECTED_KEYS.contains(key)) {
          continue; // 框架内部信道，非用户参数
        }
        filtered.put(key, entry.getValue());
      }
    }
    validate(toolCode, filtered);
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

  /** 漂移断言：确认本类的工具清单与给定的权威清单一致（供测试调用）。 */
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

  /**
   * 由服务端在派发时注入、因而不出现在"用户可配置键"白名单里的参数。
   *
   * <p>{@code ActiveScanService} 在规则参数校验<b>之后</b>才根据请求注入 PoC 选择，
   * 所以规则侧白名单不含它们并不是漂移。列在这里是让"服务端注入键"成为显式记录。
   */
  private static final Set<String> SERVER_INJECTED_KEYS = Set.of("allPocs", "pocCodes");

  /** 参数键漂移断言：AI 侧允许的参数键必须是检测规则侧允许键的子集。 */
  public static void assertAllowedKeysAreRuleSubset(
      java.util.function.Function<String, Set<String>> ruleKeysFor) {
    for (String toolCode : EXECUTABLE_TOOLS) {
      Set<String> aiKeys = new LinkedHashSet<>(allowedKeys(toolCode));
      aiKeys.removeAll(SERVER_INJECTED_KEYS);
      Set<String> ruleKeys;
      try {
        ruleKeys = ruleKeysFor.apply(toolCode);
      } catch (ApiException unsupportedRuleTool) {
        // 该工具不是检测规则可用的工具（如 site_crawl），无从比较。
        continue;
      }
      Set<String> aiOnly = new LinkedHashSet<>(aiKeys);
      aiOnly.removeAll(ruleKeys);
      if (!aiOnly.isEmpty()) {
        throw new ApiException(
            "参数键漂移：工具 "
                + toolCode
                + " 在 AI 侧允许但检测规则侧不接受 "
                + aiOnly
                + "（AI=" + aiKeys + "，规则=" + ruleKeys + "）");
      }
    }
  }
}
