package com.bachelor.toolbox.task;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.settings.BusinessDataOperationGate;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class TaskExecutionService {
  private com.bachelor.toolbox.notification.TaskNotificationPublisher taskNotifications;

  @org.springframework.beans.factory.annotation.Autowired(required = false)
  public void setTaskNotifications(com.bachelor.toolbox.notification.TaskNotificationPublisher value) {
    taskNotifications = value;
  }
  private static final Logger log = LoggerFactory.getLogger(TaskExecutionService.class);
  private static final int PREPARED_PROGRESS = 15;
  private static final int TOOL_PROGRESS_END = 85;
  private static final String EXECUTION_FAILED_MESSAGE = "任务执行失败，请稍后重试";
  private static final String EXECUTION_TIMEOUT_MESSAGE = "任务执行超时，请稍后重试";
  private static final String AUTHORIZATION_CHANGED_MESSAGE = "任务授权状态已变更，请重新确认授权后再试";
  private static final String ZOMBIE_REAPED_MESSAGE = "任务进程已退出，检测到长时间无进度，已自动终止";

  /** How often the zombie-reaper sweep runs. */
  private final long zombieReapIntervalMs;

  /**
   * A RUNNING task whose progress hasn't been refreshed for at least this long and whose worker
   * thread is no longer alive is considered a zombie (the executor process likely died before
   * writing a terminal state) and is force-terminated so its progress animation does not run
   * forever.
   */
  private final long zombieStaleMs;

  private final SecurityTaskRepository taskRepository;
  private final FindingRepository findingRepository;
  private final TargetService targetService;
  private final AssessmentProjectService projectService;
  private final SecurityToolRegistry registry;
  private final AuditService auditService;
  private final ObjectMapper objectMapper;
  private final TaskSnapshotService snapshotService;
  private final TaskExecutionControlService executionControl;
  private final TaskProgressEventService progressEvents;
  private final ProjectAuthorizationService authorization;
  private final BusinessDataOperationGate operationGate;
  private final ApplicationEventPublisher eventPublisher;
  private com.bachelor.toolbox.tool.zap.ZapDiscoverySink zapDiscoverySink;

  @Autowired
  public void setZapDiscoverySink(
      com.bachelor.toolbox.tool.zap.ZapDiscoverySink zapDiscoverySink) {
    this.zapDiscoverySink = zapDiscoverySink;
  }

  @Autowired
  public TaskExecutionService(
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository,
      TargetService targetService,
      AssessmentProjectService projectService,
      SecurityToolRegistry registry,
      AuditService auditService,
      ObjectMapper objectMapper,
      TaskSnapshotService snapshotService,
      TaskExecutionControlService executionControl,
      TaskProgressEventService progressEvents,
      ProjectAuthorizationService authorization,
      BusinessDataOperationGate operationGate,
      ApplicationEventPublisher eventPublisher,
      @Value("${toolbox.task.zombie-reap-interval-ms:60000}") long zombieReapIntervalMs,
      @Value("${toolbox.task.zombie-stale-ms:300000}") long zombieStaleMs) {
    this.taskRepository = taskRepository;
    this.findingRepository = findingRepository;
    this.targetService = targetService;
    this.projectService = projectService;
    this.registry = registry;
    this.auditService = auditService;
    this.objectMapper = objectMapper;
    this.snapshotService = snapshotService;
    this.executionControl = executionControl;
    this.progressEvents = progressEvents;
    this.authorization = authorization;
    this.operationGate = operationGate;
    this.eventPublisher = eventPublisher;
    this.zombieReapIntervalMs = Math.max(5_000, zombieReapIntervalMs);
    this.zombieStaleMs = Math.max(15_000, zombieStaleMs);
  }

  TaskExecutionService(
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository,
      TargetService targetService,
      AssessmentProjectService projectService,
      SecurityToolRegistry registry,
      AuditService auditService,
      ObjectMapper objectMapper,
      TaskSnapshotService snapshotService,
      TaskExecutionControlService executionControl,
      TaskProgressEventService progressEvents) {
    this(
        taskRepository,
        findingRepository,
        targetService,
        projectService,
        registry,
        auditService,
        objectMapper,
        snapshotService,
        executionControl,
        progressEvents,
        null,
        new BusinessDataOperationGate(),
        event -> {},
        60_000,
        300_000);
  }

  TaskExecutionService(
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository,
      TargetService targetService,
      AssessmentProjectService projectService,
      SecurityToolRegistry registry,
      AuditService auditService,
      ObjectMapper objectMapper,
      TaskSnapshotService snapshotService,
      TaskExecutionControlService executionControl,
      TaskProgressEventService progressEvents,
      ProjectAuthorizationService authorization) {
    this(
        taskRepository,
        findingRepository,
        targetService,
        projectService,
        registry,
        auditService,
        objectMapper,
        snapshotService,
        executionControl,
        progressEvents,
        authorization,
        new BusinessDataOperationGate(),
        event -> {},
        60_000,
        300_000);
  }

  /**
   * Reaps task rows stuck in RUNNING whose executor is gone and that have stopped producing any
   * progress for a long time. Without this, a task whose process died mid-run (before its
   * {@code finally} could write a terminal state) stays RUNNING forever, which keeps the taskbar in
   * an endless marquee/animation even though nothing is actually executing.
   */
  @Scheduled(fixedDelayString = "${toolbox.task.zombie-reap-interval-ms:60000}")
  public void reapStaleRunningTasks() {
    Instant now = Instant.now();
    List<SecurityTask> running = taskRepository.findAllByStatusOrderByCreatedAtAsc("RUNNING");
    int reaped = 0;
    for (SecurityTask task : running) {
      if (executionControl.hasActiveWorker(task.getId())) {
        // A live worker is still executing this task; not a zombie.
        continue;
      }
      Instant lastUpdate = task.getProgressUpdatedAt();
      if (lastUpdate == null) {
        lastUpdate = task.getStartedAt() == null ? task.getCreatedAt() : task.getStartedAt();
      }
      if (lastUpdate == null
          || lastUpdate.isAfter(now.minusMillis(zombieStaleMs))) {
        // Still within the reasonable heartbeat window — give it time.
        continue;
      }
      try {
        reapZombie(task, now);
        reaped++;
      } catch (Exception exception) {
        log.warn(
            "回收僵尸任务失败，taskId={}，toolCode={}",
            task.getId(),
            task.getToolCode(),
            exception);
      }
    }
    if (reaped > 0) {
      log.warn("已回收 {} 个僵尸运行任务（进程退出但未写终态）", reaped);
    }
  }

  private void reapZombie(SecurityTask task, Instant now) {
    task.setStatus("TIMEOUT");
    task.setTerminationReason("ZOMBIE_REAPED");
    task.setTimeoutAt(now);
    task.setErrorMessage(ZOMBIE_REAPED_MESSAGE);
    task.setProgressMessage(ZOMBIE_REAPED_MESSAGE);
    task.setProgressUpdatedAt(now);
    task.setFinishedAt(now);
    appendLog(task, "任务进程已退出，长时间无进度，系统已自动终止（僵尸任务回收）");

    SecurityTask saved = taskRepository.save(task);
    if (taskNotifications != null) taskNotifications.publish(saved);
    executionControl.clear(task.getId());
    progressEvents.publish(saved, null);
    eventPublisher.publishEvent(new TaskTerminalEvent(saved.getId()));
    auditService.record(
        "EXECUTE_TOOL",
        "TASK",
        saved.getId(),
        ZOMBIE_REAPED_MESSAGE,
        "TIMEOUT",
        saved.getId(),
        saved.getAuthorizationSnapshotHash());
  }

  @Async
  public void executeAsync(Long taskId) {
    operationGate.withMutation(() -> executeWithSystemAccess(taskId));
  }

  private void executeWithSystemAccess(Long taskId) {
    if (authorization == null) {
      executeUnderGate(taskId);
      return;
    }
    try {
      authorization.callWithSystemAccess(
          () -> {
            executeUnderGate(taskId);
            return null;
          });
    } catch (RuntimeException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IllegalStateException("后台任务授权上下文初始化失败", exception);
    }
  }

  private void executeUnderGate(Long taskId) {
    SecurityTask task =
        taskRepository.findById(taskId).orElseThrow(() -> new ApiException("任务不存在"));
    if (!"PENDING".equals(task.getStatus()) || executionControl.isCancellationRequested(taskId)) {
      return;
    }

    try (TaskExecutionControlService.Permit ignored =
        executionControl.acquire(taskId, task.getTargetId())) {
      executionControl.registerWorker(taskId, Thread.currentThread());
      initializeRunningTask(task);
      try {
        executeTask(taskId, task);
      } catch (TaskCancelledException ignoredException) {
        markCancelled(taskId, task);
      } catch (Exception exception) {
        if (executionControl.isCancellationRequested(taskId)) {
          log.info("安全任务因用户取消而终止，taskId={}", taskId, exception);
          markCancelled(taskId, task);
          return;
        }
        markFailed(taskId, task, exception);
      } finally {
        SecurityTask terminalTask = task;
        if (executionControl.isCancellationRequested(taskId)) {
          terminalTask = taskRepository.findById(taskId).orElse(task);
          if (!"CANCELLED".equals(terminalTask.getStatus())) {
            markCancelled(taskId, terminalTask);
          }
        }
        terminalTask.setFinishedAt(Instant.now());
        taskRepository.save(terminalTask);
        if (taskNotifications != null) taskNotifications.publish(terminalTask);
        progressEvents.publish(terminalTask, null);
        eventPublisher.publishEvent(new TaskTerminalEvent(terminalTask.getId()));
      }
    } finally {
      executionControl.clear(taskId);
      Thread.interrupted();
    }
  }

  private void initializeRunningTask(SecurityTask task) {
    task.setStatus("RUNNING");
    task.setProgress(5);
    task.setProgressDeterminate(false);
    task.setProgressCompleted(null);
    task.setProgressTotal(null);
    task.setProgressMessage("正在加载授权目标和工具配置");
    task.setProgressUpdatedAt(Instant.now());
    task.setStartedAt(Instant.now());
    task.setQueueStartedAt(task.getStartedAt());
    appendLog(task, "任务已启动，正在加载授权目标和工具配置…");
    taskRepository.save(task);
    progressEvents.publish(task, "任务已启动，正在加载授权目标和工具配置…");
  }

  private void executeTask(Long taskId, SecurityTask task) throws Exception {
    if (task.getProjectId() == null) {
      throw new ApiException("任务缺少项目授权上下文");
    }
    AuthorizedTarget target = validateCurrentAuthorization(task);
    SecurityTool tool = registry.require(task.getToolCode());
    snapshotService.assertCurrentMatches(task, target, tool);
    updateProgress(task, 10, false, null, null, "授权快照与工具配置已校验");

    Map<String, Object> parameters =
        objectMapper.readValue(task.getRequestJson(), new TypeReference<Map<String, Object>>() {});
    // Narrow this task's ports to what the preceding probe actually found open. Without this a
    // full-range Nmap -sV re-sweeps all 65535 ports even though the TCP probe already returned the
    // few that answer, which is both slow and redundant. Only applied when the task opted in and a
    // dependency really produced a port list; otherwise the request stands as authored.
    parameters = narrowPortsToDependencyResults(task, parameters);
    appendLog(task, "工具：" + tool.code() + "；目标：" + target.getTargetValue());
    appendLog(task, "参数已校验，准备执行工具…");
    updateProgress(task, PREPARED_PROGRESS, false, null, null, "参数已校验，准备执行工具");
    progressEvents.publish(task, "参数已校验，准备执行工具…");

    ToolExecutionObserver observer = createObserver(taskId, task);
    ToolExecutionResult result;
    try {
      result = tool instanceof com.bachelor.toolbox.tool.ProjectContextRetrievalTool retrieval
          ? retrieval.executeScoped(task.getProjectId(), target, parameters, observer)
          : tool instanceof com.bachelor.toolbox.tool.SiteCrawlTool crawler
              ? crawler.executeScoped(task.getProjectId(), target, parameters, observer)
              : tool.execute(target, parameters, observer);
    } catch (ToolExecutionTimeoutException timeout) {
      if (observer.isCancellationRequested()) {
        throw new TaskCancelledException();
      }
      // Only the already-authorized tool invocation can supply partial observations. A timeout
      // never completes the scan or provides a negative retest verdict, even with no findings.
      ToolExecutionResult partial = timeout.partialResult();
      try {
        task.setResultJson(objectMapper.writeValueAsString(partial));
        saveFindings(task, target, tool, partial);
        appendLog(task, "工具执行超时，已保存部分检测结果；扫描未完成，不能据此判断未发现风险");
      } catch (Exception persistenceFailure) {
        timeout.addSuppressed(persistenceFailure);
      }
      throw timeout;
    }
    if (observer.isCancellationRequested()) {
      throw new TaskCancelledException();
    }

    appendLog(task, "命令执行完成，正在解析输出并生成检测结果…");
    updateProgress(task, 88, false, null, null, "工具执行完成，正在保存检测结果");
    saveFindings(task, target, tool, result);

    if ("zap_scan".equals(tool.code()) && zapDiscoverySink != null) {
      zapDiscoverySink.ingest(task.getProjectId(), task.getTargetId(), target, result);
    }

    task.setResultJson(objectMapper.writeValueAsString(result));
    task.setStatus("SUCCESS");
    task.setProgress(100);
    task.setProgressDeterminate(true);
    task.setProgressCompleted(1L);
    task.setProgressTotal(1L);
    task.setProgressMessage("任务执行完成");
    task.setProgressUpdatedAt(Instant.now());
    appendLog(task, "执行成功：" + result.summary());
    applyRetestVerdict(task);
    auditService.record(
        "EXECUTE_TOOL",
        "TASK",
        taskId,
        tool.code(),
        "SUCCESS",
        taskId,
        task.getAuthorizationSnapshotHash());
  }

  /**
   * Replace a full-range port sweep with the ports a dependency probe actually found open.
   *
   * <p>Only applies when the task declared {@code consumeOpenPorts} and asked to sweep everything
   * (the default {@code 1-65535} or the target's whole allowed range). An explicit narrow port list
   * authored by the planner or the user is left untouched — they asked for those ports for a reason.
   * If no dependency produced a usable list, the request stands as-is so a failed probe does not
   * silently turn the sweep into a no-op.
   */
  private Map<String, Object> narrowPortsToDependencyResults(
      SecurityTask task, Map<String, Object> parameters) {
    Object consume = parameters.get("consumeOpenPorts");
    if (!Boolean.TRUE.equals(consume) && !"true".equalsIgnoreCase(String.valueOf(consume))) {
      return parameters;
    }
    if (!isFullRangeRequest(parameters)) {
      // The planner or user chose specific ports for a reason; never override that.
      return parameters;
    }
    List<Integer> openPorts = openPortsFromDependencies(task);
    if (openPorts.isEmpty()) {
      appendLog(task, "前序端口探测没有给出可用开放端口，按原参数扫描");
      return parameters;
    }
    Map<String, Object> narrowed = new java.util.LinkedHashMap<>(parameters);
    narrowed.put("ports", openPorts.stream().map(String::valueOf)
        .collect(java.util.stream.Collectors.joining(",")));
    narrowed.remove("consumeOpenPorts");
    // The narrowed list itself can name tens of thousands of ports, which would blow past the
    // rolling execution-log cap and bury the very line that explains the narrowing. Log a
    // bounded summary instead: the count plus the first few ports.
    String sample = openPorts.stream().limit(20).map(String::valueOf)
        .collect(java.util.stream.Collectors.joining(","));
    appendLog(task, "按前序探测结果将扫描范围收敛为 " + openPorts.size() + " 个开放端口"
        + (openPorts.size() > 20 ? "（示例 " + sample + " …，完整范围已传入工具）"
            : "：" + sample));
    return narrowed;
  }

  /**
   * True when the request asks for a whole-range sweep ({@code 1-65535} or the target's full allowed
   * range), which is exactly the case where reusing probe results pays off. A narrow request like
   * {@code 443} is left untouched.
   *
   * <p>Deliberately a count of the requested ports, not a parse into ranges: only the rough size of
   * the sweep matters here, and a malformed request simply stays as it is.
   */
  private boolean isFullRangeRequest(Map<String, Object> parameters) {
    Object requested = parameters.getOrDefault("ports", null);
    if (requested == null || String.valueOf(requested).isBlank()) return true;
    java.util.Set<Integer> requestedPorts = new java.util.LinkedHashSet<>();
    for (String part : String.valueOf(requested).split("[,，]")) {
      String token = part.trim();
      if (token.isEmpty()) continue;
      int dash = token.indexOf('-');
      try {
        if (dash < 0) {
          requestedPorts.add(Integer.parseInt(token));
        } else {
          int from = Integer.parseInt(token.substring(0, dash).trim());
          int to = Integer.parseInt(token.substring(dash + 1).trim());
          if (to < from) return false;
          // Expand lazily: a range can name 65535 ports and we only need the count.
          for (int port = from; port <= to; port++) {
            requestedPorts.add(port);
            if (requestedPorts.size() > 60_000) return true;
          }
        }
      } catch (NumberFormatException ex) {
        return false;
      }
    }
    return requestedPorts.size() > 60_000;
  }

  /** Open ports reported by any successful dependency task, deduplicated and ordered. */
  private List<Integer> openPortsFromDependencies(SecurityTask task) {
    // Workflow-dispatched tasks carry their dependencies in successDependencyTaskIds, while
    // directly created tasks use dependencyTaskIds. Read both so either origin can feed the
    // narrowing; a missing or unreadable list simply contributes nothing.
    List<Long> ids = new java.util.ArrayList<>();
    for (String raw : new String[] {task.getDependencyTaskIds(), task.getSuccessDependencyTaskIds()}) {
      if (raw == null || raw.isBlank()) continue;
      try {
        for (Long id : objectMapper.readValue(raw, new TypeReference<List<Long>>() {})) {
          if (id != null && !ids.contains(id)) ids.add(id);
        }
      } catch (Exception ex) {
        // A malformed list must not abort execution; the other field may still be usable.
      }
    }
    if (ids.isEmpty()) return List.of();
    java.util.TreeSet<Integer> ports = new java.util.TreeSet<>();
    for (SecurityTask dependency : taskRepository.findAllById(ids)) {
      if (!"SUCCESS".equals(dependency.getStatus())) continue;
      String resultJson = dependency.getResultJson();
      if (resultJson == null || resultJson.isBlank()) continue;
      try {
        com.fasterxml.jackson.databind.JsonNode root = objectMapper.readTree(resultJson);
        // resultJson is a serialized ToolExecutionResult, so the payload lives under "data".
        com.fasterxml.jackson.databind.JsonNode open = root.path("data").path("openPorts");
        if (!open.isArray()) open = root.path("openPorts");
        if (open.isArray()) {
          for (com.fasterxml.jackson.databind.JsonNode port : open) {
            // tcp_ports reports plain integers; Nmap reports observation objects that carry the
            // port under a "port" key. Accept both so either probe can feed the next stage.
            if (port.canConvertToInt()) {
              ports.add(port.asInt());
            } else if (port.isObject()) {
              com.fasterxml.jackson.databind.JsonNode inner = port.path("port");
              if (inner.canConvertToInt()) ports.add(inner.asInt());
            }
          }
        }
      } catch (Exception ignored) {
        // A dependency whose result cannot be parsed simply contributes nothing.
      }
    }
    return List.copyOf(ports);
  }

  private AuthorizedTarget validateCurrentAuthorization(SecurityTask task) {
    try {
      projectService.validateProjectTarget(task.getProjectId(), task.getTargetId());
      return targetService.getCurrentlyAuthorized(task.getTargetId());
    } catch (ApiException exception) {
      throw new TaskAuthorizationChangedException(exception.getMessage(), exception);
    }
  }

  private ToolExecutionObserver createObserver(Long taskId, SecurityTask task) {
    return new ToolExecutionObserver() {
      private long lastHeartbeatAt;

      @Override
      public void command(java.util.List<String> command) {
        String formattedCommand = CommandLogFormatter.format(command);
        appendLog(task, "执行命令：" + formattedCommand);
        task.setProgressMessage("外部工具已启动，正在执行命令");
        task.setProgressUpdatedAt(Instant.now());
        taskRepository.save(task);
        progressEvents.publish(task, "执行命令：" + formattedCommand);
      }

      @Override
      public void operation(String operation) {
        appendLog(task, "执行操作：" + operation);
        task.setProgressMessage(operation);
        task.setProgressUpdatedAt(Instant.now());
        taskRepository.save(task);
        progressEvents.publish(task, "执行操作：" + operation);
      }

      @Override
      public void progress(long completed, long total, String operation) {
        if (total <= 0) {
          heartbeat(operation);
          return;
        }

        long boundedCompleted = Math.max(0L, Math.min(completed, total));
        int toolPercent = (int) Math.floor((boundedCompleted * 100d) / total);
        int overall =
            PREPARED_PROGRESS
                + (int) Math.floor(toolPercent * (TOOL_PROGRESS_END - PREPARED_PROGRESS) / 100d);
        synchronized (task) {
          boolean percentageChanged = overall > task.getProgress();
          boolean totalChanged = !java.util.Objects.equals(task.getProgressTotal(), total);
          task.setProgress(Math.max(task.getProgress(), overall));
          task.setProgressDeterminate(true);
          task.setProgressCompleted(boundedCompleted);
          task.setProgressTotal(total);
          task.setProgressMessage(nonBlank(operation, "工具正在执行"));
          task.setProgressUpdatedAt(Instant.now());
          if (percentageChanged || totalChanged || boundedCompleted == total) {
            taskRepository.save(task);
            progressEvents.publish(task, null);
          }
        }
      }

      @Override
      public void heartbeat(String operation) {
        long now = System.nanoTime();
        long heartbeatInterval = java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(750);
        if (now - lastHeartbeatAt < heartbeatInterval) {
          return;
        }

        lastHeartbeatAt = now;
        synchronized (task) {
          if (task.getProgressTotal() == null || task.getProgressTotal() <= 0) {
            task.setProgressDeterminate(false);
          }
          task.setProgressMessage(nonBlank(operation, "外部工具正在运行"));
          task.setProgressUpdatedAt(Instant.now());
          taskRepository.save(task);
          progressEvents.publish(task, null);
        }
      }

      @Override
      public boolean isCancellationRequested() {
        return executionControl.isCancellationRequested(taskId)
            || Thread.currentThread().isInterrupted();
      }
    };
  }

  private void saveFindings(
      SecurityTask task, AuthorizedTarget target, SecurityTool tool, ToolExecutionResult result) {
    // 同一逻辑漏洞常因多个 payload / 探测命中产生多条相似记录，先按稳定键合并再落库。
    List<FindingDraft> drafts = deduplicateDrafts(task, tool, result.findings());
    int findingIndex = 0;
    int findingTotal = drafts.size();
    int lastFindingProgress = -1;
    for (FindingDraft draft : drafts) {
      Finding finding = new Finding();
      finding.setTaskId(task.getId());
      finding.setTargetId(target.getId());
      finding.setTitle(draft.title());
      finding.setSeverity(draft.severity());
      finding.setSourceTool(tool.code());
      finding.setRuleCode(task.getRuleCode());
      finding.setVulnerabilityCode(resolveVulnerabilityCode(task, draft));
      finding.setSecurityKey(draft.securityKey() == null ? null : draft.securityKey().trim());
      finding.setDescription(draft.description());
      finding.setEvidence(draft.evidence());
      finding.setRemediation(draft.remediation());
      findingRepository.save(finding);

      findingIndex++;
      int findingProgress =
          88 + (findingTotal == 0 ? 0 : (int) Math.floor(findingIndex * 10d / findingTotal));
      if (findingProgress > lastFindingProgress || findingIndex == findingTotal) {
        lastFindingProgress = findingProgress;
        updateProgress(
            task,
            findingProgress,
            true,
            (long) findingIndex,
            (long) findingTotal,
            "正在保存检测结果 " + findingIndex + "/" + findingTotal);
      }
    }
  }

  private String resolveVulnerabilityCode(SecurityTask task, FindingDraft draft) {
    if (draft.vulnerabilityCode() == null || draft.vulnerabilityCode().isBlank()) {
      return task.getVulnerabilityCode();
    }
    return draft.vulnerabilityCode();
  }

  /**
   * 工具对同一漏洞的不同 payload 常各出一条 FindingDraft，导致结果与复测把同一漏洞反复上报。
   * 先在落库前按稳定键（工具 + 检测规则 + 漏洞码）合并：保留更高等级、合并各命中证据。
   * 无稳定漏洞码的信息项不可合并，逐条独立保留，避免误折叠（如多个开放端口）。
   */
  private List<FindingDraft> deduplicateDrafts(
      SecurityTask task, SecurityTool tool, List<FindingDraft> findings) {
    if (findings == null || findings.size() < 2) {
      return findings == null ? List.of() : findings;
    }
    Map<String, FindingDraft> byKey = new LinkedHashMap<>();
    int index = 0;
    for (FindingDraft draft : findings) {
      String canonical = normalizeKey(resolveVulnerabilityCode(task, draft));
      String location = normalizeKey(draft.securityKey());
      String key =
          tool.code()
              + "|"
              + normalizeKey(task.getRuleCode())
              + "|"
              + canonical
              + "|"
              + location
              + (canonical.isBlank() && location.isBlank() ? "#" + index : "");
      index++;
      FindingDraft existing = byKey.get(key);
      byKey.put(key, existing == null ? draft : mergeDrafts(existing, draft));
    }
    return new ArrayList<>(byKey.values());
  }

  private String normalizeKey(String value) {
    return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
  }

  private FindingDraft mergeDrafts(FindingDraft left, FindingDraft right) {
    boolean rightWins = severityRank(right.severity()) > severityRank(left.severity());
    FindingDraft primary = rightWins ? right : left;
    FindingDraft other = rightWins ? left : right;
    return new FindingDraft(
        chooseBetter(primary.title(), other.title()),
        primary.severity(),
        chooseBetter(primary.description(), other.description()),
        mergeEvidence(left.evidence(), right.evidence()),
        chooseBetter(primary.remediation(), other.remediation()),
        chooseBetter(primary.vulnerabilityCode(), other.vulnerabilityCode()),
        chooseBetter(primary.securityKey(), other.securityKey()));
  }

  private int severityRank(String severity) {
    return switch (String.valueOf(severity).toUpperCase(Locale.ROOT)) {
      case "CRITICAL" -> 5;
      case "HIGH" -> 4;
      case "MEDIUM" -> 3;
      case "LOW" -> 2;
      case "INFO" -> 1;
      default -> 0;
    };
  }

  private static String chooseBetter(String primary, String other) {
    if (primary == null || primary.isBlank()) return other;
    return primary;
  }

  private static String mergeEvidence(String left, String right) {
    String a = left == null ? "" : left.trim();
    String b = right == null ? "" : right.trim();
    if (a.isEmpty()) return b;
    if (b.isEmpty() || a.equals(b)) return a;
    return a + "\n\n" + b;
  }

  // 连续 N 次同入口复测均未复现，才判定为“复测确认已修复”。
  private static final int RETEST_FIX_REQUIRED_PASSES = 2;

  /**
   * 漏洞复测任务成功结束后，据此更新基线漏洞记录：命中 → 重置计数并置 REOPENED；未命中 →
   * 计数 +1，连续 {@link #RETEST_FIX_REQUIRED_PASSES} 次未复现才置 FIXED（verified=true）。
   * 单次未命中不足以判定已修复（sqlmap/Xray 等存在随机性）。
   */
  private void applyRetestVerdict(SecurityTask task) {
    if (task.getSourceFindingId() == null) return;
    Finding baseline = findingRepository.findById(task.getSourceFindingId()).orElse(null);
    if (baseline == null) return;
    if ("FALSE_POSITIVE".equals(baseline.getStatus())) return;

    boolean reoccurred = findingRepository
        .findAllByTaskIdOrderByCreatedAtAsc(task.getId())
        .stream()
        .anyMatch(found -> sameVulnerability(baseline, found));

    if (reoccurred) {
      baseline.setRetestCount(0);
      // 已修复过的漏洞又复现 → 明确标为 REOPENED。
      baseline.setStatus("FIXED".equals(baseline.getStatus()) ? "REOPENED" : baseline.getStatus());
      baseline.setVerified(false);
      baseline.setVerifiedAt(null);
    } else {
      int passes = baseline.getRetestCount() + 1;
      baseline.setRetestCount(passes);
      if (passes >= RETEST_FIX_REQUIRED_PASSES) {
        baseline.setStatus("FIXED");
        baseline.setVerified(true);
        baseline.setVerifiedAt(Instant.now());
        baseline.setVerifiedTaskId(task.getId());
      } else if ("FIXED".equals(baseline.getStatus())) {
        // 已修复的漏洞在复测中被确认仍不再复现，保持 FIXED。
      } else {
        baseline.setStatus("OPEN");
      }
    }
    findingRepository.save(baseline);
    auditService.record(
        "RETEST_VERDICT",
        "FINDING",
        baseline.getId(),
        "retestTaskId=" + task.getId() + "; reoccurred=" + reoccurred + "; passes=" + baseline.getRetestCount(),
        reoccurred ? "REOPENED" : "PENDING");
  }

  private boolean sameVulnerability(Finding baseline, Finding found) {
    if (found == null) return false;
    boolean sameToolRule =
        Objects.equals(baseline.getSourceTool(), found.getSourceTool())
            && Objects.equals(baseline.getRuleCode(), found.getRuleCode());
    if (!sameToolRule) return false;
    if (baseline.getSecurityKey() != null && !baseline.getSecurityKey().isBlank()) {
      return Objects.equals(baseline.getSecurityKey(), found.getSecurityKey());
    }
    return Objects.equals(baseline.getVulnerabilityCode(), found.getVulnerabilityCode());
  }

  private void markCancelled(Long taskId, SecurityTask task) {
    task.setStatus("CANCELLED");
    task.setErrorMessage("用户取消任务");
    task.setTerminationReason("CANCELLED");
    task.setProgressMessage("任务已由用户取消");
    task.setProgressUpdatedAt(Instant.now());
    appendLog(task, "任务已由用户取消");
    auditService.record(
        "EXECUTE_TOOL",
        "TASK",
        taskId,
        task.getToolCode(),
        "CANCELLED",
        taskId,
        task.getAuthorizationSnapshotHash());
  }

  private void markFailed(Long taskId, SecurityTask task, Exception exception) {
    log.error("安全任务执行失败，taskId={}，toolCode={}", taskId, task.getToolCode(), exception);

    boolean timeout = isTimeout(exception);
    boolean authorizationChanged = !timeout && isAuthorizationChanged(exception);
    String userMessage = failureMessage(timeout, authorizationChanged, exception);

    task.setStatus(timeout ? "TIMEOUT" : "FAILED");
    task.setTerminationReason(terminationReason(timeout, authorizationChanged));
    if (timeout) {
      task.setTimeoutAt(Instant.now());
    }
    task.setErrorMessage(userMessage);
    task.setProgressMessage(progressMessage(timeout, authorizationChanged));
    task.setProgressUpdatedAt(Instant.now());
    appendLog(task, "执行失败：" + userMessage);
    auditService.record(
        "EXECUTE_TOOL",
        "TASK",
        taskId,
        userMessage,
        "FAILED",
        taskId,
        task.getAuthorizationSnapshotHash());
  }

  private boolean isTimeout(Exception exception) {
    java.util.Set<Throwable> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
    for (Throwable current = exception; current != null && seen.add(current); current = current.getCause()) {
      if (current instanceof java.net.http.HttpTimeoutException
          || current instanceof java.net.SocketTimeoutException
          || current instanceof java.util.concurrent.TimeoutException) return true;
      String message = current.getMessage();
      if (message != null) {
        String lower = message.toLowerCase();
        if (message.contains("超时")
            || message.contains("超过")
            || lower.contains("timed out")
            || lower.contains("timeout")) {
          return true;
        }
        // 连接已建立，但对端一个字节都不回。JDK HttpClient 在这种情况下抛的是普通
        // IOException（"HTTP/1.1 header parser received no bytes"），而不是超时异常；
        // 若不在这里识别，用户看到的会是更费解的「任务执行失败」，掩盖了「目标不响应」这一事实。
        // 本质仍是目标在规定时间内没有任何响应，按超时归类比按失败归类更准确、更可操作。
        if (lower.contains("header parser received no bytes")
            || lower.contains("received no bytes")
            || lower.contains("connection reset by peer")
            || lower.contains("premature end of content")) {
          return true;
        }
      }
    }
    return false;
  }

  private boolean isAuthorizationChanged(Exception exception) {
    Throwable current = exception;
    while (current != null) {
      if (current instanceof TaskAuthorizationChangedException) {
        return true;
      }
      current = current.getCause();
    }
    return false;
  }

  private String failureMessage(
      boolean timeout, boolean authorizationChanged, Exception exception) {
    if (timeout) {
      return EXECUTION_TIMEOUT_MESSAGE;
    }
    if (authorizationChanged) {
      return AUTHORIZATION_CHANGED_MESSAGE;
    }
    // 业务规则拒绝（如授权边界、端口越界）应如实透出原因，
    // 否则用户只看到“任务执行失败”，无法区分是被拦截还是系统故障。
    String businessMessage = businessRuleMessage(exception);
    if (businessMessage != null) {
      return businessMessage;
    }
    return EXECUTION_FAILED_MESSAGE;
  }

  /**
   * 提取 ApiException 的消息。ApiException 是本系统面向用户的业务异常类型，
   * 其消息在其它接口上同样直接展示，可安全透出，不会泄露内部实现细节。
   */
  private String businessRuleMessage(Exception exception) {
    Throwable current = exception;
    while (current != null) {
      if (current instanceof ApiException
          && current.getMessage() != null
          && !current.getMessage().isBlank()) {
        return current.getMessage();
      }
      current = current.getCause();
    }
    return null;
  }

  private String terminationReason(boolean timeout, boolean authorizationChanged) {
    if (timeout) {
      return "TIMEOUT";
    }
    if (authorizationChanged) {
      return "AUTHORIZATION_CHANGED";
    }
    return "FAILED";
  }

  private String progressMessage(boolean timeout, boolean authorizationChanged) {
    if (timeout) {
      return "任务执行超时";
    }
    if (authorizationChanged) {
      return "任务授权状态已变更";
    }
    return "任务执行失败";
  }

  private static final class TaskCancelledException extends RuntimeException {}

  private void updateProgress(
      SecurityTask task,
      int progress,
      boolean determinate,
      Long completed,
      Long total,
      String message) {
    synchronized (task) {
      task.setProgress(Math.max(task.getProgress(), Math.max(0, Math.min(99, progress))));
      task.setProgressDeterminate(determinate);
      task.setProgressCompleted(completed);
      task.setProgressTotal(total);
      task.setProgressMessage(message);
      task.setProgressUpdatedAt(Instant.now());
      taskRepository.save(task);
      progressEvents.publish(task, null);
    }
  }

  private static String nonBlank(String value, String fallback) {
    return value == null || value.isBlank() ? fallback : value;
  }

  private void appendLog(SecurityTask task, String line) {
    String current = task.getExecutionLog();
    String prefix = current == null || current.isBlank() ? "" : current + "\n";
    String next = prefix + Instant.now() + "  " + line;
    if (next.length() > 12000) {
      task.setExecutionLog(next.substring(next.length() - 12000));
      return;
    }
    task.setExecutionLog(next);
  }
}
