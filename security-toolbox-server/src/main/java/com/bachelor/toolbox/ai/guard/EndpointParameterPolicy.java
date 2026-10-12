package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.ToolParameterSpec;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 端点级参数策略：把 {@code invoke_endpoint("POST", "/api/tasks", {...})} 这类<strong>参数透传型</strong>端点拉回能力治理
 * （设计文档 §6.5"反向能力映射"、§6.2"间接执行"）。
 *
 * <h2>为什么需要这一层（X-7 漏洞）</h2>
 *
 * <p>实测证据链表明，AI 派发链路上的四道参数护栏<strong>只挂在 {@code AiTaskDispatchService.validateAndNormalize} 上</strong>：
 *
 * <ul>
 *   <li>工具参数白名单 {@code allowedKeys}；
 *   <li>端口必须是授权端口子集；
 *   <li>MSF 模块前缀必须是 {@code auxiliary/} 或 {@code exploit/}；
 *   <li>PoC 编号正则与数量 1..50。
 * </ul>
 *
 * <p>而 {@code TaskService.create} 只做"项目-目标成员关系 + 目标授权"校验，{@code parameters} <strong>原样序列化入库</strong>。
 * 于是：
 *
 * <pre>
 * invoke_endpoint("POST", "/api/tasks",
 *     {projectId, targetId, toolCode:"msf_scan", parameters:{module:"exploit/...", options:{...}}})
 * </pre>
 *
 * <p>只要目标在授权范围内，四道护栏<strong>一道都不生效</strong>，直达执行器。外层 schema 校验（L-C 的形状校验）拦不住它，因为
 * {@code parameters} 的<strong>内容</strong>才是危险所在，而它的类型确实是合法的 {@code object}。
 *
 * <h2>本类的定位</h2>
 *
 * <p>把 {@code AiTaskDispatchService.validateAndNormalize} 的<strong>校验语义</strong>在护栏侧复现一份，用于端点透传参数的
 * 二次校验。刻意<strong>只读复用、不修改</strong> {@code AiTaskDispatchService}（它在别的写作用域，且被既有链路依赖）。
 *
 * <p><strong>漂移风险（如实记录）</strong>：这构成了两份实现。缓解手段是：
 *
 * <ol>
 *   <li>本类只实现"拒绝越权"的下界，不实现 dispatch 层的归一化（规范化输出仍由 dispatch 层负责）；
 *   <li>本类的每条规则都有对应测试（见 {@code EndpointParameterPolicyTest}），且注释里标注了它在 dispatch 层的出处行号；
 *   <li>若将来 dispatch 层新增护栏，必须同步本类——这一点写进类注释，避免后人不知道。
 * </ol>
 *
 * <p>更彻底的修法是"把校验下沉到 {@code TaskService.create}"，那需要改 {@code task/} 写作用域；本类是在不动既有文件前提下的护栏侧
 * 防线。两者不冲突，可叠加。
 */
public final class EndpointParameterPolicy {

  /** 与 {@code AiTaskDispatchService} 一致的工具参数白名单。 */
  private static final Map<String, Set<String>> ALLOWED_TOOL_PARAMETERS =
      Map.ofEntries(
          Map.entry("tcp_ports", Set.of("ports")),
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
          Map.entry("tls_config", Set.of()));

  /** PoC 编号格式，与 {@code AiTaskDispatchService:390} 一致。 */
  private static final String POC_CODE_PATTERN = "[A-Z]{2}-[A-F0-9]{24}";

  /** 需要端口子集校验的工具，与 {@code AiTaskDispatchService:284} 一致。 */
  private static final Set<String> PORT_TOOLS =
      Set.of("tcp_ports", "nmap_service_scan", "fscan_scan");

  /**
   * 需要"主机/URI 授权校验"的工具（D-5 修复）。
   *
   * <p>与 {@code AiTaskDispatchService} 的调用逐工具对齐（10 处 {@code validatedHttpUri}/
   * {@code validatedHost}）：{@code :260,264,269,271,279,285,316,320,324,339}。
   *
   * <p><strong>为什么这是最关键的缺失规则</strong>：没有它，经通用原语提交
   * {@code sqlmap_scan + path="http://169.254.169.254/latest/meta-data/"} 会<strong>绕过云元数据 SSRF 防护</strong>
   * ——授权校验只比对 targetId 对应的主机，而工具实际请求的 URL 由 {@code parameters} 决定。
   */
  private static final Set<String> URI_VALIDATED_TOOLS =
      Set.of(
          "zap_fuzz",
          "sqlmap_scan",
          "http_headers",
          "http_security_check",
          "tls_config",
          "afrog_scan",
          "xray_scan",
          "zap_scan");

  /** 需要"仅校验主机"的工具（D-5）。 */
  private static final Set<String> HOST_VALIDATED_TOOLS =
      Set.of("tcp_ports", "nmap_service_scan", "fscan_scan", "nuclei_scan", "msf_scan");

  private final PortRangeParser portRangeParser;
  private final int maxPortsPerTask;

  /**
   * 目标策略服务（D-5 修复引入）。
   *
   * <p>可为 {@code null}——此时<strong>跳过</strong> URI/主机校验（向后兼容既有测试装配），
   * 但生产装配必须注入（见 {@code AgentCapabilityGuardConfiguration}）。
   *
   * <p>⚠️ 为 {@code null} 时是<strong>降级</strong>而非 fail-closed：这是刻意的取舍，
   * 因为本类被既有多处测试以两参构造装配。生产路径由配置类保证非空。
   */
  private final TargetPolicyService targetPolicyService;

  public EndpointParameterPolicy(PortRangeParser portRangeParser, int maxPortsPerTask) {
    this(portRangeParser, maxPortsPerTask, null);
  }

  public EndpointParameterPolicy(
      PortRangeParser portRangeParser, int maxPortsPerTask, TargetPolicyService targetPolicyService) {
    this.portRangeParser = Objects.requireNonNull(portRangeParser, "端口解析器不能为空");
    this.maxPortsPerTask = Math.max(1, maxPortsPerTask);
    this.targetPolicyService = targetPolicyService;
  }

  /** 是否已装配目标策略服务（未装配时 D-5 校验不可用）。 */
  public boolean hasTargetPolicyService() {
    return targetPolicyService != null;
  }

  /**
   * 校验经 {@code invoke_endpoint} 透传到任务创建接口的参数。
   *
   * @param target 本次调用已通过 L-A 授权校验的目标
   * @param body 端点请求体（含 {@code toolCode} 与 {@code parameters}）
   * @throws ApiException 任一护栏不通过
   */
  public void validateTaskCreationBody(AuthorizedTarget target, Map<String, Object> body) {
    if (body == null) {
      throw new ApiException("任务创建请求体不能为空");
    }
    String toolCode = text(body.get("toolCode"));
    if (toolCode == null) {
      toolCode = text(body.get("tool"));
    }
    if (toolCode == null) {
      throw new ApiException("任务创建必须指定工具（toolCode）");
    }
    Set<String> allowed = ALLOWED_TOOL_PARAMETERS.get(toolCode);
    if (allowed == null) {
      // 与 dispatch 层一致：不在安全白名单内的工具一律拒绝。
      throw new ApiException("工具不在安全白名单内: " + toolCode);
    }

    Object rawParameters = body.get("parameters");
    Map<String, Object> parameters = new LinkedHashMap<>();
    if (rawParameters instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        parameters.put(String.valueOf(entry.getKey()), entry.getValue());
      }
    } else if (rawParameters != null) {
      throw new ApiException("任务参数必须是对象");
    }

    // ① 工具参数白名单
    if (!allowed.containsAll(parameters.keySet())) {
      throw new ApiException("任务参数包含未允许的字段: " + parameters.keySet());
    }

    // ①' D-5：主机/URI 授权校验（最关键——防云元数据 SSRF）
    // 必须在端口校验之前：端口是"打哪些口"，URI 是"打谁"；先确认"打谁"再确认"打哪些口"。
    validateTargetUriOrHost(toolCode, target, parameters);

    // ② 端口必须全部落在授权端口范围内（containsAll 语义，见 §6.1 L-A）
    if (PORT_TOOLS.contains(toolCode)) {
      validatePortSubset(target, parameters);
    }

    // ②' D-1..D-4：取值枚举校验（与执行侧共用 ToolParameterSpec，杜绝漂移）
    validateEnumeratedValues(toolCode, parameters);

    // ③ MSF 模块前缀
    if ("msf_scan".equals(toolCode)) {
      validateMsfModules(parameters);
    }

    // ④ PoC 编号与数量
    if (Set.of("nuclei_scan", "afrog_scan", "xray_scan").contains(toolCode)) {
      validatePocSelection(parameters);
    }
  }

  /**
   * D-5 修复：对含 URL/主机语义的工具参数执行授权校验。
   *
   * <p>与 {@code AiTaskDispatchService} 的 10 处调用逐工具对齐。取值规格来自
   * {@link ToolParameterSpec}（共享），本方法只负责"调用哪个校验器"。
   *
   * <p><strong>未装配 {@link TargetPolicyService} 时跳过</strong>——这是向后兼容的降级，
   * 生产装配必须注入。
   */
  private void validateTargetUriOrHost(
      String toolCode, AuthorizedTarget target, Map<String, Object> parameters) {
    if (targetPolicyService == null) {
      return;
    }
    if (URI_VALIDATED_TOOLS.contains(toolCode)) {
      // zap_fuzz 校验的是参数里的具体 URL；其余校验目标自身的授权 URL。
      if ("zap_fuzz".equals(toolCode)) {
        String url = text(parameters.get("fuzzRequestUrl"));
        if (url != null) {
          targetPolicyService.validatedHttpUri(target, url);
        }
      } else if ("sqlmap_scan".equals(toolCode)) {
        String path = text(parameters.get("path"));
        if (path != null) {
          targetPolicyService.validatedHttpUri(target, path);
        } else {
          targetPolicyService.validatedHttpUri(target);
        }
      } else {
        targetPolicyService.validatedHttpUri(target);
      }
      // tls_config 额外要求 HTTPS（与 dispatch :280-282 一致）。
      if ("tls_config".equals(toolCode)) {
        var uri = targetPolicyService.validatedHttpUri(target);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
          throw new ApiException("TLS 检查仅适用于 HTTPS 授权目标");
        }
      }
      return;
    }
    if (HOST_VALIDATED_TOOLS.contains(toolCode)) {
      targetPolicyService.validatedHost(target);
    }
  }

  /**
   * D-1..D-4 修复：校验取值枚举。
   *
   * <p>取值规格<strong>全部来自 {@link ToolParameterSpec}</strong>——与执行侧共用同一份常量，
   * 因此不存在"两份字面量漂移"的可能。
   *
   * <p>修复前护栏侧<strong>完全没有</strong>这四类校验，导致经通用原语可提交
   * {@code fscan_scan + vulnMode="FULL"}（启用漏洞利用类检测）等越权取值。
   */
  private void validateEnumeratedValues(String toolCode, Map<String, Object> parameters) {
    switch (toolCode) {
      case "http_security_check" -> {
        if (parameters.containsKey("check")) {
          ToolParameterSpec.requireHttpCheck(parameters.get("check"));
        }
      }
      case "nmap_service_scan" -> {
        if (parameters.containsKey("mode")) {
          ToolParameterSpec.requireNmapMode(parameters.get("mode"));
        }
      }
      case "fscan_scan" -> {
        if (parameters.containsKey("vulnMode")) {
          ToolParameterSpec.requireFscanVulnMode(parameters.get("vulnMode"));
        }
      }
      case "zap_scan" -> {
        if (parameters.containsKey("strength")) {
          ToolParameterSpec.requireZapStrength(parameters.get("strength"));
        }
        // 与 dispatch :325-328 一致：spider 必须是布尔。
        if (parameters.containsKey("spider")
            && !(parameters.get("spider") instanceof Boolean)) {
          throw new ApiException("ZAP spider 参数必须为布尔值");
        }
      }
      default -> {
        // 无枚举约束的工具。
      }
    }
  }

  /**
   * 端口子集校验。
   *
   * <p>刻意采用 <strong>{@code containsAll}</strong> 语义（与 {@code AiTaskDispatchService:293-297} 一致）：请求的<em>每一个</em>
   * 端口都必须落在目标授权端口集合内。用"逐个端口是否在范围内"的等价写法同样正确，但显式比对集合能保证与 dispatch 层语义完全一致，
   * 也便于测试断言"部分越权端口同样被拒"。
   */
  private void validatePortSubset(AuthorizedTarget target, Map<String, Object> parameters) {
    Object raw = parameters.get("ports");
    if (raw == null || text(raw) == null) {
      // 未指定端口 → 由执行层回落到目标授权端口，本身不构成越权。
      return;
    }
    String requested = text(raw);
    Set<Integer> authorized;
    Set<Integer> wanted;
    try {
      authorized = portRangeParser.parse(target.getAllowedPorts());
      wanted = portRangeParser.parse(requested, maxPortsPerTask);
    } catch (ApiException | IllegalArgumentException invalid) {
      throw new ApiException("端口范围格式无效: " + invalid.getMessage());
    }
    if (!authorized.containsAll(wanted)) {
      Set<Integer> escaped = new LinkedHashSet<>(wanted);
      escaped.removeAll(authorized);
      throw new ApiException("请求的端口超出目标授权范围: " + escaped);
    }
  }

  /** MSF 模块必须限定在 {@code auxiliary/} 或 {@code exploit/} 前缀下，且 module 与 modules 互斥。 */
  private void validateMsfModules(Map<String, Object> parameters) {
    boolean hasModule = parameters.containsKey("module");
    boolean hasModules = parameters.containsKey("modules");
    if (hasModule && hasModules) {
      throw new ApiException("不能同时指定 msf 模块与模块列表");
    }
    if (hasModules) {
      Object raw = parameters.get("modules");
      if (!(raw instanceof Collection<?> collection) || collection.isEmpty()) {
        throw new ApiException("MSF 模块列表格式无效");
      }
      List<String> normalized = new ArrayList<>();
      for (Object item : collection) {
        String module = text(item);
        if (module == null) {
          throw new ApiException("MSF 模块列表格式无效");
        }
        normalized.add(requireSafeMsfModule(module));
      }
      return;
    }
    String module = text(parameters.get("module"));
    if (module == null) {
      throw new ApiException("必须指定合法的 Metasploit 模块");
    }
    requireSafeMsfModule(module);
  }

  private String requireSafeMsfModule(String module) {
    String normalized = module.trim().toLowerCase(Locale.ROOT);
    if (!(normalized.startsWith("auxiliary/") || normalized.startsWith("exploit/"))) {
      throw new ApiException("MSF 模块仅允许 auxiliary/ 或 exploit/ 前缀: " + module);
    }
    return normalized;
  }

  /** PoC 选择：要么 {@code allPocs=true}，要么给出 1..50 个合法且不重复的编号。 */
  private void validatePocSelection(Map<String, Object> parameters) {
    boolean hasCodes = parameters.containsKey("pocCodes");
    boolean hasAll = parameters.containsKey("allPocs");
    if (hasCodes == hasAll) {
      throw new ApiException("PoC 选择必须指定具体 PoC 或全部 PoC");
    }
    if (hasAll) {
      if (!Boolean.TRUE.equals(parameters.get("allPocs"))) {
        throw new ApiException("全部 PoC 参数必须为 true");
      }
      return;
    }
    Object raw = parameters.get("pocCodes");
    if (!(raw instanceof Collection<?> values) || values.isEmpty() || values.size() > 50) {
      throw new ApiException("PoC 数量必须在 1 到 50 之间");
    }
    Set<String> unique = new LinkedHashSet<>();
    for (Object value : values) {
      String code = text(value);
      if (code == null || !code.matches(POC_CODE_PATTERN) || !unique.add(code)) {
        throw new ApiException("PoC 编号无效或重复");
      }
    }
  }

  /**
   * 判断一个端点路径是否是需要参数策略介入的"参数透传型/触发执行型"端点。
   *
   * <h2>D-6 修复：为什么不再用"单端点硬编码"</h2>
   *
   * <p>原实现只认 {@code POST /api/tasks}，导致实测的<strong>13 个</strong>同类端点全部不受管。
   * 这些端点散布在 5 个控制器，且含 SSE 流式变体（容易漏）——<strong>硬编码必然漏</strong>。
   *
   * <p>本方法采用<strong>双轨判定</strong>：
   *
   * <ol>
   *   <li><strong>语义特征轨</strong>（主）：请求体含 {@code toolCode} + {@code parameters} → 一定是工具执行
   *   <li><strong>路径模式轨</strong>（兜底）：{@code retry}/{@code proxy/start} 等"无 toolCode 但触发执行"的端点
   * </ol>
   *
   * <p><strong>宁可宽，不可漏</strong>：误触发只导致"多校验"（安全），漏触发才是漏洞。
   *
   * @param body 请求体（可为 null）；用于语义特征判定
   */
  public static boolean isTaskCreationEndpoint(String method, String path) {
    return isTaskCreationEndpoint(method, path, null);
  }

  /**
   * 带请求体的判定（D-6 修复的主入口）。
   *
   * @param method HTTP 方法
   * @param path 请求路径（真实路径，可能含具体 ID）
   * @param body 请求体；为 null 时只走路径模式轨
   */
  public static boolean isTaskCreationEndpoint(
      String method, String path, Map<String, Object> body) {
    if (method == null || path == null) {
      return false;
    }
    String normalizedMethod = method.trim().toUpperCase(Locale.ROOT);
    if (!"POST".equals(normalizedMethod) && !"PUT".equals(normalizedMethod)) {
      return false;
    }
    String normalizedPath = path.trim();

    // 轨 ①：语义特征——请求体含"工具执行三元组"（自动覆盖新增端点，无需维护列表）
    if (isToolExecutionBody(body)) {
      return true;
    }

    // 轨 ②：路径模式——覆盖"不通过 body 传 toolCode 但确实触发执行"的端点
    return matchesExecutionPath(normalizedPath);
  }

  /**
   * 请求体是否含"工具执行三元组"（{@code toolCode} + {@code parameters}/{@code targetId}）。
   *
   * <p>这是<strong>语义特征</strong>而非路径匹配：任何端点，只要请求体是这个形状，
   * 就是在创建扫描任务。新增端点自动被覆盖。
   */
  private static boolean isToolExecutionBody(Map<String, Object> body) {
    if (body == null) {
      return false;
    }
    boolean hasTool = body.containsKey("toolCode") || body.containsKey("tool");
    boolean hasPayload = body.containsKey("parameters") || body.containsKey("targetId");
    return hasTool && hasPayload;
  }

  /**
   * 路径模式匹配（D-6 修复的兜底轨）。
   *
   * <p>实测的 13 个"会创建/触发对目标执行"的 POST 端点（Lead 扫描控制器确认）：
   *
   * <table>
   *   <tr><th>控制器</th><th>端点</th></tr>
   *   <tr><td>{@code TaskController}</td><td>{@code /api/tasks}、{@code /api/tasks/{id}/retry}</td></tr>
   *   <tr><td>{@code VulnerabilityRegressionController}</td><td>{@code /api/regression/findings/{id}/retest}</td></tr>
   *   <tr><td>{@code ScanScheduleController}</td><td>{@code /api/scan-schedules}</td></tr>
   *   <tr><td>{@code ProbeController}</td><td>{@code /api/projects/{id}/discovery/probe}</td></tr>
   *   <tr><td>{@code TrafficProxyController}</td><td>{@code /api/traffic/proxy/start}、
   *       {@code /api/traffic/packets/{id}/replay}、{@code .../zap-scan}（含 SSE）、
   *       {@code .../xray-scan}（含 SSE）、{@code .../sqlmap-scan}、{@code .../fuzz}</td></tr>
   * </table>
   *
   * <p><strong>⚠️ 这一轨仍需手工维护</strong>——这是 D-6 的残余风险。真正的根治见
   * "把校验下沉到 {@code TaskService.create}"（P2-6）。
   */
  private static boolean matchesExecutionPath(String path) {
    // 归一化：去掉尾部斜杠，避免 /api/tasks/ 与 /api/tasks 不一致。
    String normalized = path.endsWith("/") && path.length() > 1
        ? path.substring(0, path.length() - 1)
        : path;

    if (EXACT_EXECUTION_PATHS.contains(normalized)) {
      return true;
    }
    for (String pattern : TEMPLATE_EXECUTION_PATTERNS) {
      if (matchesTemplate(pattern, normalized)) {
        return true;
      }
    }
    return false;
  }

  /** 无路径变量的执行端点。 */
  private static final Set<String> EXACT_EXECUTION_PATHS =
      Set.of(
          "/api/tasks",
          "/api/scan-schedules",
          "/api/traffic/proxy/start",
          "/api/traffic/proxy/stop",
          "/api/post-scan-paths/plans");

  /** 含路径变量的执行端点模板（{@code {x}} 匹配任意单段）。 */
  private static final List<String> TEMPLATE_EXECUTION_PATTERNS =
      List.of(
          "/api/tasks/{id}/retry",
          "/api/regression/findings/{id}/retest",
          "/api/projects/{id}/discovery/probe",
          "/api/traffic/packets/{id}/replay",
          "/api/traffic/packets/{id}/zap-scan",
          "/api/traffic/packets/{id}/zap-scan/stream",
          "/api/traffic/packets/{id}/xray-scan",
          "/api/traffic/packets/{id}/xray-scan/stream",
          "/api/traffic/packets/{id}/sqlmap-scan",
          "/api/traffic/packets/{id}/sqlmap-scan/stream",
          "/api/traffic/packets/{id}/fuzz",
          "/api/traffic/suggestions/{id}/execute");

  /**
   * 模板匹配：{@code {x}} 匹配任意非空单段，其余段必须字面相等。
   *
   * <p>刻意<strong>不</strong>复用 {@code EndpointRegistry} 的匹配（那是反向映射，语义不同），
   * 但保持"单段通配"的同样规则。
   */
  private static boolean matchesTemplate(String template, String path) {
    String[] templateSegments = template.split("/");
    String[] pathSegments = path.split("/");
    if (templateSegments.length != pathSegments.length) {
      return false;
    }
    for (int i = 0; i < templateSegments.length; i++) {
      String t = templateSegments[i];
      String p = pathSegments[i];
      if (t.startsWith("{") && t.endsWith("}")) {
        if (p.isEmpty()) {
          return false;
        }
        continue;
      }
      if (!t.equals(p)) {
        return false;
      }
    }
    return true;
  }

  private static String text(Object value) {
    if (value == null) {
      return null;
    }
    String text = String.valueOf(value).trim();
    return text.isEmpty() ? null : text;
  }
}
