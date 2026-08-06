package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AiTaskDispatchService {
  private static final int MAX_TASKS_PER_DISPATCH = 4;
  private static final Set<String> SAFE_AI_TOOLS =
      Set.of(
          "http_headers",
          "http_security_check",
          "tls_config",
          "tcp_ports",
          "nmap_service_scan",
          "nuclei_scan");

  private final AiPlanningService planningService;
  private final TargetService targetService;
  private final TargetPolicyService targetPolicyService;
  private final SecurityToolRegistry toolRegistry;
  private final TaskService taskService;
  private final AuditService auditService;
  private final PortRangeParser portRangeParser;
  private final int maxPortsPerTask;
  private final int maxNmapPortsPerTask;

  public AiTaskDispatchService(
      AiPlanningService planningService,
      TargetService targetService,
      TargetPolicyService targetPolicyService,
      SecurityToolRegistry toolRegistry,
      TaskService taskService,
      AuditService auditService,
      PortRangeParser portRangeParser,
      @Value("${toolbox.execution.max-ports-per-task:65535}") int maxPortsPerTask,
      @Value("${toolbox.execution.max-nmap-ports-per-task:65535}") int maxNmapPortsPerTask) {
    this.planningService = planningService;
    this.targetService = targetService;
    this.targetPolicyService = targetPolicyService;
    this.toolRegistry = toolRegistry;
    this.taskService = taskService;
    this.auditService = auditService;
    this.portRangeParser = portRangeParser;
    this.maxPortsPerTask = maxPortsPerTask;
    this.maxNmapPortsPerTask = maxNmapPortsPerTask;
  }

  public AiDispatchResponse dispatch(AiPlanRequest request) throws Exception {
    AiPlanResponse generatedPlan = planningService.plan(request);
    return dispatchPlanned(request, generatedPlan);
  }

  public AiDispatchResponse dispatchPlanned(AiPlanRequest request, AiPlanResponse generatedPlan)
      throws Exception {
    AuthorizedTarget target = targetService.get(request.targetId());
    AiPlanResponse executablePlan = prepare(request, generatedPlan);

    List<Long> taskIds = new ArrayList<>();
    for (AiPlanResponse.PlanStep step : executablePlan.steps()) {
      SecurityTask task =
          taskService.create(
              new CreateTaskRequest(
                  request.projectId(), target.getId(), step.toolCode(), step.parameters()));
      taskIds.add(task.getId());
    }
    auditService.record(
        "AI_DISPATCH_TASKS",
        request.projectId() == null ? "TARGET" : "PROJECT",
        request.projectId() == null ? target.getId() : request.projectId(),
        "targetId=" + target.getId() + "; prompt=" + request.prompt() + "; taskIds=" + taskIds,
        "ACCEPTED");
    return new AiDispatchResponse(
        target.getId(), executablePlan, taskIds.size(), List.copyOf(taskIds));
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
    List<AiPlanResponse.PlanStep> safeSteps = validateAndNormalize(generatedPlan, target);
    return new AiPlanResponse(
        generatedPlan.provider(), generatedPlan.model(), generatedPlan.summary(), false, safeSteps);
  }

  private List<AiPlanResponse.PlanStep> validateAndNormalize(
      AiPlanResponse plan, AuthorizedTarget target) {
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
          "http_security_check".equals(step.toolCode())
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
              step.toolCode(), step.title(), step.reason(), Map.copyOf(parameters)));
    }
    if (toolCodes.contains("nmap_service_scan") && toolCodes.contains("tcp_ports")) {
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
          case "nmap_service_scan" -> Set.of("ports", "mode");
          case "nuclei_scan" -> Set.of();
          case "http_security_check" -> Set.of("check");
          case "http_headers", "tls_config" -> Set.of();
          default -> throw new ApiException("AI 工具不在安全白名单内");
        };
    if (!allowedKeys.containsAll(parameters.keySet())) {
      throw new ApiException("AI 计划包含未允许的工具参数");
    }

    switch (toolCode) {
      case "http_headers" -> targetPolicyService.validatedHttpUri(target);
      case "http_security_check" -> {
        targetPolicyService.validatedHttpUri(target);
        String check = Objects.toString(parameters.get("check"), "");
        if (!Set.of("cookies", "cors", "methods", "disclosure").contains(check)) {
          throw new ApiException("HTTP 检查类型不受支持");
        }
        parameters.put("check", check);
      }
      case "tls_config" -> {
        URI uri = targetPolicyService.validatedHttpUri(target);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
          throw new ApiException("TLS 检查仅适用于 HTTPS 授权目标");
        }
      }
      case "tcp_ports", "nmap_service_scan" -> {
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
          String mode = Objects.toString(parameters.getOrDefault("mode", "quick"), "");
          if (!Set.of("quick", "service").contains(mode)) {
            throw new ApiException("Nmap mode 仅支持 quick 或 service");
          }
          parameters.put("mode", mode);
        }
      }
      case "nuclei_scan" -> targetPolicyService.validatedHost(target);
      default -> throw new ApiException("AI 工具不在安全白名单内");
    }
    return parameters;
  }
}
