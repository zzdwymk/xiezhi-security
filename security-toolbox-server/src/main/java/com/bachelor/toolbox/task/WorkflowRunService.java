package com.bachelor.toolbox.task;

import com.bachelor.toolbox.ai.AgentWorkflowSpecService;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.ScannerPocSelectionService;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class WorkflowRunService {
  private static final int RUN_HISTORY_LIMIT = 100;
  private static final Set<String> TERMINAL_STATUSES =
      Set.of("SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED");
  private static final Set<String> FAILED_STATUSES = Set.of("FAILED", "TIMEOUT", "REJECTED");

  private final WorkflowRunRepository runs;
  private final SecurityTaskRepository tasks;
  private final TaskService taskService;
  private final AgentWorkflowSpecService workflowSpecs;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final DependencyDetectionService dependencies;
  private final ScannerPocSelectionService scannerPocs;
  private final AuditService audit;
  private final ObjectMapper objectMapper;
  private final WorkflowRunStopTransactionService stopTransactions;

  public WorkflowRunService(
      WorkflowRunRepository runs,
      SecurityTaskRepository tasks,
      TaskService taskService,
      AgentWorkflowSpecService workflowSpecs,
      AssessmentProjectService projects,
      TargetService targets,
      DependencyDetectionService dependencies,
      ScannerPocSelectionService scannerPocs,
      AuditService audit,
      ObjectMapper objectMapper,
      WorkflowRunStopTransactionService stopTransactions) {
    this.runs = runs;
    this.tasks = tasks;
    this.taskService = taskService;
    this.workflowSpecs = workflowSpecs;
    this.projects = projects;
    this.targets = targets;
    this.dependencies = dependencies;
    this.scannerPocs = scannerPocs;
    this.audit = audit;
    this.objectMapper = objectMapper;
    this.stopTransactions = stopTransactions;
  }

  @Transactional(readOnly = true)
  public List<WorkflowRunDtos.Summary> list(Long projectId) {
    projects.get(projectId);
    return runs
        .findAllByProjectIdAndClearedAtIsNullOrderByCreatedAtDesc(
            projectId,
            PageRequests.bounded(
                0,
                RUN_HISTORY_LIMIT,
                1,
                RUN_HISTORY_LIMIT,
                Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"))))
        .stream()
        .map(this::summary)
        .toList();
  }

  @Transactional(readOnly = true)
  public WorkflowRunDtos.Detail get(Long id) {
    WorkflowRun run = requireRun(id);
    return detail(run);
  }

  @Transactional(readOnly = true)
  public WorkflowRunDtos.PreflightResponse preflight(WorkflowRunDtos.SnapshotRequest request) {
    projects.validateProjectTarget(request.projectId(), request.targetId());
    AuthorizedTarget target =
        targets.getCurrentlyAuthorized(request.targetId(), request.projectId());
    AgentWorkflowSpecService.WorkflowSnapshot snapshot = snapshot(request);
    return new WorkflowRunDtos.PreflightResponse(
        snapshot.workflowId(),
        snapshot.revision(),
        snapshot.specDigest(),
        preflightIssues(snapshot, target));
  }

  @Transactional
  public WorkflowRunDtos.Detail start(WorkflowRunDtos.StartRequest request) throws Exception {
    projects.validateProjectTarget(request.projectId(), request.targetId());
    AuthorizedTarget target =
        targets.getCurrentlyAuthorized(request.targetId(), request.projectId());
    String allowedPorts = target.getAllowedPorts();
    AgentWorkflowSpecService.WorkflowSnapshot snapshot = snapshot(request);
    List<Map<String, Object>> steps = workflowSpecs.executableSteps(snapshot);
    if (steps.isEmpty()) throw new ApiException("工作流没有可执行步骤");

    Map<String, WorkflowRunDtos.NodeIssue> issues =
        preflightIssues(snapshot, target).stream()
            .collect(
                Collectors.toMap(
                    WorkflowRunDtos.NodeIssue::nodeId,
                    issue -> issue,
                    (left, right) -> left,
                    LinkedHashMap::new));
    Set<String> skipped = safeIds(request.skippedNodeIds());
    if (!issues.keySet().containsAll(skipped)) {
      throw new ApiException("仅可跳过预检标记为不可用的工作流节点");
    }
    List<WorkflowRunDtos.NodeIssue> unresolved =
        issues.values().stream().filter(issue -> !skipped.contains(issue.nodeId())).toList();
    if (!unresolved.isEmpty()) {
      throw new ApiException(
          "工作流存在不可用步骤："
              + unresolved.stream()
                  .map(issue -> issue.label() + "（" + issue.reason() + "）")
                  .collect(Collectors.joining("；")));
    }

    Set<String> approved = safeIds(request.approvedNodeIds());
    for (Map<String, Object> step : steps) {
      String nodeId = requiredText(step, "nodeId");
      if (Boolean.TRUE.equals(step.get("requiresApproval"))
          && !skipped.contains(nodeId)
          && !approved.contains(nodeId)) {
        throw new ApiException("高风险步骤未获得执行确认：" + label(step));
      }
    }

    WorkflowRun run = new WorkflowRun();
    run.setProjectId(request.projectId());
    run.setTargetId(request.targetId());
    run.setWorkflowId(snapshot.workflowId());
    run.setWorkflowRevision(snapshot.revision());
    run.setWorkflowDigest(snapshot.specDigest());
    run.setSpecJson(objectMapper.writeValueAsString(snapshot.response()));
    run.setStatus("PREPARING");
    run.setProgress(0);
    run.setMessage("正在创建工作流任务");
    run.setStartedAt(Instant.now());
    run = runs.save(run);

    Map<String, Map<String, Object>> stepByNode =
        steps.stream()
            .collect(
                Collectors.toMap(
                    step -> requiredText(step, "nodeId"),
                    step -> step,
                    (left, right) -> left,
                    LinkedHashMap::new));
    Map<String, Long> taskByNode = new LinkedHashMap<>();
    List<Map<String, Object>> ordered =
        steps.stream()
            .sorted(
                Comparator.comparingInt((Map<String, Object> step) -> integer(step.get("group")))
                    .thenComparing(step -> requiredText(step, "nodeId")))
            .toList();

    for (Map<String, Object> step : ordered) {
      String nodeId = requiredText(step, "nodeId");
      String toolCode = requiredText(step, "tool");
      if ("retrieve_project_context".equals(toolCode)) continue;
      List<Long> dependencyTaskIds =
          resolveDependencyTaskIds(step, stepByNode, taskByNode, new LinkedHashSet<>());
      CreateTaskRequest createRequest =
          new CreateTaskRequest(
              request.projectId(),
              request.targetId(),
              toolCode,
              executionParameters(step, allowedPorts));
      String nodeRunId = "workflow-run-" + run.getId() + "." + nodeId;
      WorkflowRunDtos.NodeIssue issue = issues.get(nodeId);
      SecurityTask task;
      if (skipped.contains(nodeId)) {
        task =
            taskService.createSkippedWorkflowTask(
                createRequest,
                snapshot.specDigest(),
                nodeId,
                nodeRunId,
                integer(step.get("group")),
                text(step.get("risk"), "SAFE"),
                Boolean.TRUE.equals(step.get("requiresApproval")),
                dependencyTaskIds,
                run.getId(),
                issue == null ? "预检标记为不可用" : issue.reason());
      } else {
        task =
            taskService.createWorkflowTask(
                createRequest,
                snapshot.specDigest(),
                nodeId,
                nodeRunId,
                integer(step.get("group")),
                text(step.get("risk"), "SAFE"),
                Boolean.TRUE.equals(step.get("requiresApproval")),
                dependencyTaskIds,
                run.getId());
      }
      taskByNode.put(nodeId, task.getId());
    }

    run.setStatus("RUNNING");
    run.setMessage("工作流已启动，共 " + taskByNode.size() + " 个任务");
    runs.save(run);
    audit.record(
        "START_WORKFLOW_RUN",
        "PROJECT",
        request.projectId(),
        "runId=" + run.getId() + "; targetId=" + request.targetId(),
        "ACCEPTED");
    return detail(run);
  }

  public WorkflowRunDtos.Detail stop(Long id) {
    WorkflowRun run = stopTransactions.begin(id);
    if (isRunTerminal(run.getStatus())) return detail(run);
    List<SecurityTask> runTasks = tasks.findAllByWorkflowRunIdOrderByCreatedAtAsc(id);
    for (SecurityTask task : runTasks) {
      if (TERMINAL_STATUSES.contains(task.getStatus())) continue;
      try {
        taskService.cancel(task.getId());
      } catch (ApiException ignored) {
        // A terminal event may have completed the task while the stop request was iterating.
      }
    }
    run = stopTransactions.finish(id);
    audit.record(
        "STOP_WORKFLOW_RUN",
        "PROJECT",
        run.getProjectId(),
        "runId=" + run.getId(),
        "CANCELLED");
    return detail(run);
  }

  @Transactional
  public void clear(Long id) {
    WorkflowRun run = requireRunForUpdate(id);
    if (!isRunTerminal(run.getStatus())) throw new ApiException("运行中的工作流不能清空");
    run.setClearedAt(Instant.now());
    runs.save(run);
    audit.record(
        "CLEAR_WORKFLOW_RUN",
        "PROJECT",
        run.getProjectId(),
        "runId=" + run.getId(),
        "SUCCESS");
  }

  @EventListener
  @Async
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void onTaskTerminal(TaskTerminalEvent event) {
    tasks
        .findById(event.taskId())
        .map(SecurityTask::getWorkflowRunId)
        .filter(Objects::nonNull)
        .flatMap(runs::findByIdForUpdate)
        .ifPresent(
            run -> refresh(run, tasks.findAllByWorkflowRunIdOrderByCreatedAtAsc(run.getId())));
  }

  private AgentWorkflowSpecService.WorkflowSnapshot snapshot(
      WorkflowRunDtos.SnapshotRequest request) {
    return workflowSpecs.freezeSnapshot(
        request.projectId(),
        request.workflowId(),
        request.workflowRevision(),
        request.workflowDigest());
  }

  private AgentWorkflowSpecService.WorkflowSnapshot snapshot(WorkflowRunDtos.StartRequest request) {
    return workflowSpecs.freezeSnapshot(
        request.projectId(),
        request.workflowId(),
        request.workflowRevision(),
        request.workflowDigest());
  }

  private List<WorkflowRunDtos.NodeIssue> preflightIssues(
      AgentWorkflowSpecService.WorkflowSnapshot snapshot, AuthorizedTarget target) {
    String allowedPorts = target.getAllowedPorts();
    Map<String, String> dependencyStatus =
        dependencies.detect().dependencies().stream()
            .collect(
                Collectors.toMap(
                    item -> item.name(),
                    item -> item.status(),
                    (left, right) -> left,
                    LinkedHashMap::new));
    List<WorkflowRunDtos.NodeIssue> issues = new ArrayList<>();
    for (Map<String, Object> step : workflowSpecs.executableSteps(snapshot)) {
      String toolCode = requiredText(step, "tool");
      if ("retrieve_project_context".equals(toolCode)) continue;
      if ("tls_config".equals(toolCode) && !isHttpsTarget(target)) {
        issues.add(
            new WorkflowRunDtos.NodeIssue(
                requiredText(step, "nodeId"),
                toolCode,
                label(step),
                "目标不是 HTTPS，TLS 检查不可用"));
        continue;
      }
      String dependencyName = dependencyName(toolCode);
      if (dependencyName != null
          && !"AVAILABLE".equals(dependencyStatus.getOrDefault(dependencyName, "MISSING"))) {
        issues.add(
            new WorkflowRunDtos.NodeIssue(
                requiredText(step, "nodeId"),
                toolCode,
                label(step),
                dependencyName + " 未安装或不可用"));
        continue;
      }
      if ("afrog_scan".equals(toolCode) || "xray_scan".equals(toolCode)) {
        try {
          scannerPocs.resolve(
              "afrog_scan".equals(toolCode)
                  ? ScannerPocCatalogService.AFROG
                  : ScannerPocCatalogService.XRAY,
              executionParameters(step, allowedPorts),
              false);
        } catch (ApiException ex) {
          issues.add(
              new WorkflowRunDtos.NodeIssue(
                  requiredText(step, "nodeId"), toolCode, label(step), ex.getMessage()));
        }
      }
    }
    return List.copyOf(issues);
  }

  private boolean isHttpsTarget(AuthorizedTarget target) {
    try {
      return "https".equalsIgnoreCase(URI.create(target.getTargetValue()).getScheme());
    } catch (IllegalArgumentException | NullPointerException ignored) {
      return false;
    }
  }

  private void refresh(WorkflowRun run, List<SecurityTask> runTasks) {
    if (isRunTerminal(run.getStatus())) return;
    if (runTasks.isEmpty()) {
      run.setStatus("FAILED");
      run.setProgress(100);
      run.setMessage("工作流未创建任何任务");
      run.setFinishedAt(Instant.now());
      runs.save(run);
      return;
    }
    int terminalCount =
        (int) runTasks.stream().filter(task -> TERMINAL_STATUSES.contains(task.getStatus())).count();
    double totalProgress =
        runTasks.stream()
            .mapToInt(
                task ->
                    TERMINAL_STATUSES.contains(task.getStatus())
                        ? 100
                        : Math.max(0, Math.min(99, task.getProgress())))
            .sum();
    run.setProgress((int) Math.floor(totalProgress / runTasks.size()));
    if (terminalCount < runTasks.size()) {
      if (!"STOPPING".equals(run.getStatus())) run.setStatus("RUNNING");
      run.setMessage(terminalCount + "/" + runTasks.size() + " 个任务已结束");
      runs.save(run);
      return;
    }

    long failed = runTasks.stream().filter(task -> FAILED_STATUSES.contains(task.getStatus())).count();
    long skipped = runTasks.stream().filter(task -> "SKIPPED".equals(task.getStatus())).count();
    long cancelled = runTasks.stream().filter(task -> "CANCELLED".equals(task.getStatus())).count();
    run.setProgress(100);
    run.setFinishedAt(Instant.now());
    if ("STOPPING".equals(run.getStatus()) || (cancelled > 0 && failed == 0)) {
      run.setStatus("STOPPED");
      run.setMessage("工作流已停止，" + cancelled + " 个任务已取消");
    } else if (failed > 0 || skipped > 0) {
      run.setStatus("PARTIAL_FAILED");
      run.setMessage("工作流结束：" + failed + " 个失败，" + skipped + " 个跳过");
    } else {
      run.setStatus("COMPLETED");
      run.setMessage("工作流执行完成");
    }
    runs.save(run);
  }

  private List<Long> resolveDependencyTaskIds(
      Map<String, Object> step,
      Map<String, Map<String, Object>> stepByNode,
      Map<String, Long> taskByNode,
      Set<String> visited) {
    LinkedHashSet<Long> result = new LinkedHashSet<>();
    for (String dependencyNodeId : stringList(step.get("dependsOnNodeIds"))) {
      if (!visited.add(dependencyNodeId)) throw new ApiException("工作流任务依赖存在环路");
      Long dependencyTaskId = taskByNode.get(dependencyNodeId);
      if (dependencyTaskId != null) {
        result.add(dependencyTaskId);
      } else {
        Map<String, Object> dependency = stepByNode.get(dependencyNodeId);
        if (dependency == null) throw new ApiException("工作流任务依赖不存在");
        result.addAll(resolveDependencyTaskIds(dependency, stepByNode, taskByNode, visited));
      }
      visited.remove(dependencyNodeId);
    }
    return List.copyOf(result);
  }

  private WorkflowRun requireRun(Long id) {
    WorkflowRun run = runs.findById(id).orElseThrow(() -> new ApiException("工作流运行记录不存在"));
    projects.get(run.getProjectId());
    if (run.getClearedAt() != null) throw new ApiException("工作流运行记录已清空");
    return run;
  }

  private WorkflowRun requireRunForUpdate(Long id) {
    WorkflowRun run =
        runs.findByIdForUpdate(id).orElseThrow(() -> new ApiException("工作流运行记录不存在"));
    projects.get(run.getProjectId());
    if (run.getClearedAt() != null) throw new ApiException("工作流运行记录已清空");
    return run;
  }

  private WorkflowRunDtos.Detail detail(WorkflowRun run) {
    List<SecurityTask> runTasks = tasks.findAllByWorkflowRunIdOrderByCreatedAtAsc(run.getId());
    return new WorkflowRunDtos.Detail(summary(run, runTasks.size()), readSpec(run), runTasks);
  }

  private WorkflowRunDtos.Summary summary(WorkflowRun run) {
    return summary(run, tasks.findAllByWorkflowRunIdOrderByCreatedAtAsc(run.getId()).size());
  }

  private WorkflowRunDtos.Summary summary(WorkflowRun run, int taskCount) {
    return new WorkflowRunDtos.Summary(
        run.getId(),
        run.getProjectId(),
        run.getTargetId(),
        run.getWorkflowId(),
        run.getWorkflowRevision(),
        run.getWorkflowDigest(),
        run.getStatus(),
        run.getProgress(),
        run.getMessage(),
        taskCount,
        run.getCreatedAt(),
        run.getStartedAt(),
        run.getFinishedAt());
  }

  private Map<String, Object> readSpec(WorkflowRun run) {
    try {
      return objectMapper.readValue(run.getSpecJson(), new TypeReference<Map<String, Object>>() {});
    } catch (Exception ex) {
      throw new ApiException("工作流运行快照已损坏");
    }
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> parameters(Map<String, Object> step) {
    return step.get("parameters") instanceof Map<?, ?> value
        ? new LinkedHashMap<>((Map<String, Object>) value)
        : Map.of();
  }

  private Map<String, Object> executionParameters(
      Map<String, Object> step, String allowedPorts) {
    Map<String, Object> parameters = new LinkedHashMap<>(parameters(step));
    String toolCode = requiredText(step, "tool");
    if (("tcp_ports".equals(toolCode) || "nmap_service_scan".equals(toolCode))
        && text(parameters.get("ports"), "").isBlank()) {
      parameters.put("ports", allowedPorts);
    }
    if ("nmap_service_scan".equals(toolCode)
        && text(parameters.get("mode"), "").isBlank()) {
      parameters.put("mode", "quick");
    }
    if ("http_security_check".equals(toolCode)
        && text(parameters.get("check"), "").isBlank()) {
      parameters.put("check", "cookies");
    }
    if (("afrog_scan".equals(toolCode) || "xray_scan".equals(toolCode))
        && !Boolean.TRUE.equals(parameters.get("allPocs"))
        && !(parameters.get("pocCodes") instanceof Collection<?>)) {
      parameters.put("allPocs", true);
    }
    return parameters;
  }

  private Set<String> safeIds(Collection<String> values) {
    if (values == null) return Set.of();
    return values.stream()
        .filter(Objects::nonNull)
        .map(String::trim)
        .filter(value -> value.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}"))
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  private List<String> stringList(Object value) {
    if (!(value instanceof Collection<?> collection)) return List.of();
    return collection.stream().filter(Objects::nonNull).map(Object::toString).toList();
  }

  private String requiredText(Map<String, Object> values, String key) {
    String value = text(values.get(key), "");
    if (value.isBlank()) throw new ApiException("工作流步骤缺少 " + key);
    return value;
  }

  private String label(Map<String, Object> step) {
    return text(step.get("label"), requiredText(step, "tool"));
  }

  private String text(Object value, String fallback) {
    String text = Objects.toString(value, "").trim();
    return text.isEmpty() ? fallback : text;
  }

  private int integer(Object value) {
    if (value instanceof Number number) return Math.max(0, number.intValue());
    try {
      return Math.max(0, Integer.parseInt(Objects.toString(value, "0")));
    } catch (NumberFormatException ignored) {
      return 0;
    }
  }

  private String dependencyName(String toolCode) {
    return switch (toolCode) {
      case "nmap_service_scan" -> "Nmap";
      case "nuclei_scan" -> "Nuclei";
      case "afrog_scan" -> "Afrog";
      case "xray_scan" -> "Xray";
      default -> null;
    };
  }

  private boolean isRunTerminal(String status) {
    return Set.of("COMPLETED", "PARTIAL_FAILED", "STOPPED", "FAILED").contains(status);
  }
}
