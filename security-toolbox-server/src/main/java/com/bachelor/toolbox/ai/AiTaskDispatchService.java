package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AiTaskDispatchService {
  static final int MAX_TASKS_PER_DISPATCH = 8;
  private static final Set<String> SAFE_AI_TOOLS =
      AiToolCatalog.EXECUTABLE_TOOLS;

  private final TargetService targetService;
  private final TargetPolicyService targetPolicyService;
  private final SecurityToolRegistry toolRegistry;
  private final PortRangeParser portRangeParser;
  private final int maxPortsPerTask;
  private final int maxNmapPortsPerTask;
  private final AgentWorkflowSpecService workflowSpecs;

  @Autowired
  public AiTaskDispatchService(
      TargetService targetService,
      TargetPolicyService targetPolicyService,
      SecurityToolRegistry toolRegistry,
      PortRangeParser portRangeParser,
      @Value("${toolbox.execution.max-ports-per-task:65535}") int maxPortsPerTask,
      @Value("${toolbox.execution.max-nmap-ports-per-task:65535}") int maxNmapPortsPerTask,
      AgentWorkflowSpecService workflowSpecs) {
    this.targetService = targetService;
    this.targetPolicyService = targetPolicyService;
    this.toolRegistry = toolRegistry;
    this.portRangeParser = portRangeParser;
    this.maxPortsPerTask = maxPortsPerTask;
    this.maxNmapPortsPerTask = maxNmapPortsPerTask;
    this.workflowSpecs = workflowSpecs;
  }

  public AiTaskDispatchService(
      TargetService targetService,
      TargetPolicyService targetPolicyService,
      SecurityToolRegistry toolRegistry,
      PortRangeParser portRangeParser,
      int maxPortsPerTask,
      int maxNmapPortsPerTask) {
    this(
        targetService,
        targetPolicyService,
        toolRegistry,
        portRangeParser,
        maxPortsPerTask,
        maxNmapPortsPerTask,
        null);
  }

  /**
   * Central preparation step shared by the authorization guard and executor. It applies the
   * immutable AI tool allow-list, validates the target protocol and normalizes port subsets. No
   * task is created by this method.
   */
  public AiPlanResponse prepare(AiPlanRequest request, AiPlanResponse generatedPlan) {
    AuthorizedTarget target = targetService.get(request.targetId());
    if (!target.isEnabled()) {
      throw new ApiException("授权目标未启用");
    }
    List<AiPlanResponse.PlanStep> safeSteps = validateAndNormalize(generatedPlan, target, false);
    return new AiPlanResponse(
        generatedPlan.provider(), generatedPlan.model(), generatedPlan.summary(), false, safeSteps);
  }

  /** Final Java-side workflow closure. The immutable snapshot overrides every policy field. */
  public AiPlanResponse prepareWorkflow(AiAgentRequest request, AiPlanResponse generatedPlan) {
    if (workflowSpecs == null) throw new ApiException("工作流 Harness 未配置");
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        workflowSpecs.freezeSnapshot(
            request.projectId(),
            request.workflowId(),
            request.workflowRevision(),
            request.workflowDigest());
    AuthorizedTarget target = targetService.get(request.targetId());
    if (!target.isEnabled()) throw new ApiException("授权目标未启用");
    if (generatedPlan == null || generatedPlan.steps() == null) {
      throw new ApiException("AI 返回的计划格式不完整");
    }
    if (generatedPlan.steps().stream().anyMatch(Objects::isNull)) {
      throw new ApiException("AI 计划包含未知或未授权的工具");
    }
    // User-authored workflow nodes are distinct work, even when their tools
    // overlap. Trust their identities only after closing against the snapshot.
    AiPlanResponse closed = closeAgainstSnapshot(generatedPlan, snapshot);
    List<AiPlanResponse.PlanStep> safeSteps = validateAndNormalize(closed, target, true);
    return new AiPlanResponse(closed.provider(), closed.model(), closed.summary(), false, safeSteps);
  }

  private AiPlanResponse closeAgainstSnapshot(
      AiPlanResponse plan, AgentWorkflowSpecService.WorkflowSnapshot snapshot) {
    Map<String, Map<String, Object>> byNode = new LinkedHashMap<>();
    for (Map<String, Object> step : snapshot.executableSteps()) {
      String nodeId = Objects.toString(step.get("nodeId"), "");
      if (nodeId.isBlank() || byNode.put(nodeId, step) != null) {
        throw new ApiException("工作流快照包含无效或重复节点");
      }
    }
    Set<String> selected =
        plan.steps().stream()
            .map(AiPlanResponse.PlanStep::workflowNodeId)
            .filter(Objects::nonNull)
            .collect(java.util.stream.Collectors.toSet());
    if (selected.size() != plan.steps().size()) {
      throw new ApiException("AI 计划缺少唯一 workflowNodeId");
    }

    List<AiPlanResponse.PlanStep> closed = new ArrayList<>();
    for (AiPlanResponse.PlanStep proposed : plan.steps()) {
      Map<String, Object> authoritative = byNode.get(proposed.workflowNodeId());
      if (authoritative == null) throw new ApiException("AI 计划引用了不存在的工作流节点");
      String tool = Objects.toString(authoritative.get("tool"), "");
      if (!tool.equals(proposed.toolCode()) || !SAFE_AI_TOOLS.contains(tool)) {
        throw new ApiException("AI 计划节点与工作流工具不匹配");
      }
      List<String> dependencies = stringList(authoritative.get("dependsOnNodeIds"));
      Set<String> requiredExternal =
          dependencies.stream()
              .filter(
                  nodeId -> {
                    Map<String, Object> dependency = byNode.get(nodeId);
                    return dependency != null
                        && SAFE_AI_TOOLS.contains(Objects.toString(dependency.get("tool"), ""));
                  })
              .collect(java.util.stream.Collectors.toSet());
      if (!selected.containsAll(requiredExternal)) {
        throw new ApiException("AI 计划未包含工作流节点的完整依赖闭包");
      }
      closed.add(
          new AiPlanResponse.PlanStep(
              tool,
              proposed.title(),
              proposed.reason(),
              proposed.parameters(),
              proposed.workflowNodeId(),
              integer(authoritative.get("group"), 0),
              dependencies,
              Objects.toString(authoritative.get("risk"), "SAFE"),
              AiToolCatalog.requiresApproval(tool) || Boolean.TRUE.equals(authoritative.get("requiresApproval")),
              proposed.evidenceRefs()));
    }
    return new AiPlanResponse(
        plan.provider(), plan.model(), plan.summary(), plan.requiresConfirmation(), List.copyOf(closed));
  }

  private List<String> stringList(Object value) {
    if (!(value instanceof List<?> list)) return List.of();
    List<String> result = new ArrayList<>();
    for (Object item : list) {
      String text = Objects.toString(item, "");
      if (text.isBlank() || !result.add(text)) throw new ApiException("工作流节点依赖无效");
    }
    return List.copyOf(result);
  }

  private int integer(Object value, int fallback) {
    return value instanceof Number number ? number.intValue() : fallback;
  }

  private List<AiPlanResponse.PlanStep> validateAndNormalize(
      AiPlanResponse plan, AuthorizedTarget target, boolean workflowBound) {
    if (plan == null || plan.steps() == null) {
      throw new ApiException("AI 返回的计划格式不完整");
    }
    if (plan.steps().isEmpty()) {
      return List.of();
    }
    if (plan.steps().size() > MAX_TASKS_PER_DISPATCH) {
      throw new ApiException("单次 AI 派发最多创建 " + MAX_TASKS_PER_DISPATCH + " 个任务");
    }

    Set<String> toolCodes = new LinkedHashSet<>();
    Set<String> stepKeys = new LinkedHashSet<>();
    List<AiPlanResponse.PlanStep> safeSteps = new ArrayList<>();
    for (AiPlanResponse.PlanStep step : plan.steps()) {
      if (step == null || step.toolCode() == null || !SAFE_AI_TOOLS.contains(step.toolCode())) {
        throw new ApiException("AI 计划包含未知或未授权的工具");
      }
      toolCodes.add(step.toolCode());
      String stepKey =
          workflowBound && step.workflowNodeId() != null && !step.workflowNodeId().isBlank()
              ? "node:" + step.workflowNodeId()
              : "http_security_check".equals(step.toolCode())
              ? step.toolCode()
                  + ":"
                  + Objects.toString(
                      step.parameters() == null ? null : step.parameters().get("check"), "")
              : step.toolCode();
      if (!stepKeys.add(stepKey)) {
        throw new ApiException("AI 计划不能重复派发同一种工具");
      }
      toolRegistry.require(step.toolCode());
      Map<String, Object> parameters =
          normalizeParameters(step.toolCode(), step.parameters(), target);
      safeSteps.add(
          new AiPlanResponse.PlanStep(
              step.toolCode(),
              step.title(),
              step.reason(),
              Map.copyOf(parameters),
              step.workflowNodeId(),
              step.group(),
              step.dependsOnNodeIds(),
              step.risk(),
              AiToolCatalog.requiresApproval(step.toolCode()) || step.requiresApproval(),
              step.evidenceRefs()));
    }
    if (!workflowBound && toolCodes.contains("nmap_service_scan") && toolCodes.contains("tcp_ports")) {
      throw new ApiException("Nmap 服务识别与 TCP 端口探测不能在同一计划中重复扫描");
    }
    return List.copyOf(safeSteps);
  }

  private Map<String, Object> normalizeParameters(
      String toolCode, Map<String, Object> rawParameters, AuthorizedTarget target) {
    Map<String, Object> parameters =
        rawParameters == null ? new LinkedHashMap<>() : new LinkedHashMap<>(rawParameters);
    Set<String> allowedKeys =
        switch (toolCode) {
          case "tcp_ports" -> Set.of("ports");
          case "nmap_service_scan" -> Set.of("ports", "mode", "consumeOpenPorts");
          case "fscan_scan" -> Set.of("ports", "vulnMode");
          case "afrog_scan", "xray_scan" -> Set.of("pocCodes", "allPocs");
          case "zap_scan" -> Set.of("spider", "strength");
          case "msf_scan" -> Set.of("module", "modules", "options");
          case "sqlmap_scan" -> Set.of("path", "level", "risk", "technique");
          case "zap_fuzz" -> ZapFuzzAiParameters.KEYS;
          case "nuclei_scan" -> Set.of("pocCodes", "allPocs");
          case "http_security_check" -> Set.of("check");
          case "dir_scan" ->
              Set.of("dictionary", "concurrency", "depth", "maxRequests", "extensions");
          case "site_crawl" -> Set.of();
          case "http_headers", "tls_config" -> Set.of();
          default -> throw new ApiException("AI 工具不在安全白名单内");
        };
    if (!allowedKeys.containsAll(parameters.keySet())) {
      throw new ApiException("AI 计划包含未允许的工具参数");
    }

    switch (toolCode) {
      case "zap_fuzz" -> {
        parameters = ZapFuzzAiParameters.normalize(parameters, true);
        targetPolicyService.validatedHttpUri(target, (String) parameters.get("fuzzRequestUrl"));
      }
      case "sqlmap_scan" -> {
        parameters = SqlmapAiParameters.normalize(parameters, true);
        URI uri = targetPolicyService.validatedHttpUri(target, (String) parameters.get("path"));
        if (uri.getRawQuery() == null || uri.getRawQuery().isBlank()) {
          throw new ApiException("SQL 注入检测需要带查询参数的授权 URL，请补充目标路径和参数");
        }
      }
      case "http_headers" -> targetPolicyService.validatedHttpUri(target);
      case "http_security_check" -> {
        targetPolicyService.validatedHttpUri(target);
        // D-1：取值规格与护栏侧共用 ToolParameterSpec（单一事实来源）。
        String check = ToolParameterSpec.requireHttpCheck(parameters.get("check"));
        parameters.put("check", check);
      }
      case "tls_config" -> {
        URI uri = targetPolicyService.validatedHttpUri(target);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
          throw new ApiException("TLS 检查仅适用于 HTTPS 授权目标");
        }
      }
      case "tcp_ports", "nmap_service_scan", "fscan_scan" -> {
        targetPolicyService.validatedHost(target);
        String requested =
            Objects.toString(parameters.getOrDefault("ports", target.getAllowedPorts()), "");
        int maxPorts =
            Set.of("nmap_service_scan", "nuclei_scan").contains(toolCode)
                ? maxNmapPortsPerTask
                : maxPortsPerTask;
        String canonicalPorts = portRangeParser.canonicalizeCompact(requested, maxPorts);
        if (!portRangeParser
            .parse(target.getAllowedPorts())
            .containsAll(portRangeParser.parse(canonicalPorts, maxPorts))) {
          throw new ApiException("AI 请求的端口超出目标授权范围");
        }
        parameters.put("ports", canonicalPorts);
        if ("nmap_service_scan".equals(toolCode)) {
          // D-2：取值规格与护栏侧共用 ToolParameterSpec。
          String mode =
              ToolParameterSpec.requireNmapMode(
                  parameters.getOrDefault("mode", ToolParameterSpec.NMAP_DEFAULT_MODE));
          parameters.put("mode", mode);
        }
        if ("fscan_scan".equals(toolCode)) {
          // D-3：取值规格与护栏侧共用 ToolParameterSpec。注意 FULL 启用漏洞利用类检测。
          String vulnMode =
              ToolParameterSpec.requireFscanVulnMode(
                  parameters.getOrDefault(
                      "vulnMode", ToolParameterSpec.FSCAN_DEFAULT_VULN_MODE));
          parameters.put("vulnMode", vulnMode);
        }
      }
      case "nuclei_scan" -> {
        targetPolicyService.validatedHost(target);
        if (!parameters.isEmpty()) normalizePocSelection(parameters);
      }
      case "afrog_scan", "xray_scan" -> {
        targetPolicyService.validatedHttpUri(target);
        normalizePocSelection(parameters);
      }
      case "zap_scan" -> {
        targetPolicyService.validatedHttpUri(target);
        if (parameters.containsKey("spider")
            && !(parameters.get("spider") instanceof Boolean)) {
          throw new ApiException("ZAP spider 参数必须为布尔值");
        }
        if (parameters.containsKey("strength")) {
          // D-4：取值规格与护栏侧共用 ToolParameterSpec。
          String strength = ToolParameterSpec.requireZapStrength(parameters.get("strength"));
          parameters.put("strength", strength);
        }
      }
      case "dir_scan" -> {
        // 目录枚举只发 HTTP GET，因此必须有可达的 Web 基址与授权主机校验。
        targetPolicyService.validatedHttpUri(target);
        // D-7：并发与深度取值规格与护栏侧共用 ToolParameterSpec（单一事实来源）。
        int concurrency =
            ToolParameterSpec.requireDirScanConcurrency(
                parameters.getOrDefault(
                    "concurrency", ToolParameterSpec.DIR_SCAN_DEFAULT_CONCURRENCY));
        parameters.put("concurrency", concurrency);
        if (parameters.containsKey("depth")) {
          int depth = ToolParameterSpec.requireDirScanDepth(parameters.get("depth"));
          parameters.put("depth", depth);
        }
        Object dictionary = parameters.get("dictionary");
        if (dictionary instanceof String text && text.length() > 64) {
          throw new ApiException("dir_scan 的 dictionary 名称过长");
        }
        if (dictionary != null && !(dictionary instanceof String)) {
          throw new ApiException("dir_scan 的 dictionary 必须是字符串");
        }
      }
      case "site_crawl" -> {
        // 站点爬取只发只读 GET，校验存在可达 Web 基址即可（授权校验在 ReconService 内部再做一次）。
        targetPolicyService.validatedHttpUri(target);
      }
      case "msf_scan" -> {
        targetPolicyService.validatedHost(target);
        if (parameters.containsKey("modules")) {
          if (parameters.containsKey("module")) {
            throw new ApiException("AI 计划不能同时指定 msf 模块与模块列表");
          }
          Object raw = parameters.get("modules");
          if (!(raw instanceof java.util.Collection<?> collection) || collection.isEmpty()) {
            throw new ApiException("AI MSF 模块列表格式无效");
          }
          List<String> batch = new java.util.ArrayList<>();
          for (Object item : collection) {
            String module = Objects.toString(item, "").trim().toLowerCase(Locale.ROOT);
            if (!(module.startsWith("auxiliary/") || module.startsWith("exploit/"))) {
              throw new ApiException("AI MSF 模块列表仅允许 auxiliary 或 exploit 模块");
            }
            batch.add(module);
          }
          parameters.put("modules", batch);
        } else {
          String module = Objects.toString(parameters.get("module"), "").trim().toLowerCase(Locale.ROOT);
          if (!(module.startsWith("auxiliary/") || module.startsWith("exploit/"))) {
            throw new ApiException("AI 计划必须指定合法的 Metasploit 模块");
          }
          parameters.put("module", module);
        }
      }
      default -> throw new ApiException("AI 工具不在安全白名单内");
    }
    return parameters;
  }

  private void normalizePocSelection(Map<String, Object> parameters) {
    boolean hasCodes = parameters.containsKey("pocCodes");
    boolean hasAll = parameters.containsKey("allPocs");
    if (hasCodes == hasAll) throw new ApiException("PoC 选择必须指定具体 PoC 或全部 PoC");
    if (hasAll) {
      if (!Boolean.TRUE.equals(parameters.get("allPocs"))) {
        throw new ApiException("全部 PoC 参数必须为 true");
      }
      return;
    }
    Object rawCodes = parameters.get("pocCodes");
    if (!(rawCodes instanceof java.util.Collection<?> values)
        || values.isEmpty()
        || values.size() > 50) {
      throw new ApiException("PoC 数量必须在 1 到 50 之间");
    }
    List<String> codes = new ArrayList<>();
    Set<String> unique = new LinkedHashSet<>();
    for (Object value : values) {
      String code = Objects.toString(value, "");
      if (!code.matches("[A-Z]{2}-[A-F0-9]{24}") || !unique.add(code)) {
        throw new ApiException("PoC 编号无效或重复");
      }
      codes.add(code);
    }
    parameters.put("pocCodes", List.copyOf(codes));
  }
}
