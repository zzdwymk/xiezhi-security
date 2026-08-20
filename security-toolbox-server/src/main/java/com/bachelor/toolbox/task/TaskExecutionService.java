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
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class TaskExecutionService {
  private static final Logger log = LoggerFactory.getLogger(TaskExecutionService.class);
  private static final int PREPARED_PROGRESS = 15;
  private static final int TOOL_PROGRESS_END = 85;
  private static final String EXECUTION_FAILED_MESSAGE = "任务执行失败，请稍后重试";
  private static final String EXECUTION_TIMEOUT_MESSAGE = "任务执行超时，请稍后重试";
  private static final String AUTHORIZATION_CHANGED_MESSAGE = "任务授权状态已变更，请重新确认授权后再试";

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
      ApplicationEventPublisher eventPublisher) {
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
        null);
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
        event -> {});
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
    projectService.validateProjectTarget(task.getProjectId(), task.getTargetId());
    AuthorizedTarget target = targetService.getCurrentlyAuthorized(task.getTargetId());
    SecurityTool tool = registry.require(task.getToolCode());
    snapshotService.assertCurrentMatches(task, target, tool);
    updateProgress(task, 10, false, null, null, "授权快照与工具配置已校验");

    Map<String, Object> parameters =
        objectMapper.readValue(task.getRequestJson(), new TypeReference<Map<String, Object>>() {});
    appendLog(task, "工具：" + tool.code() + "；目标：" + target.getTargetValue());
    appendLog(task, "参数已校验，准备执行工具…");
    updateProgress(task, PREPARED_PROGRESS, false, null, null, "参数已校验，准备执行工具");
    progressEvents.publish(task, "参数已校验，准备执行工具…");

    ToolExecutionObserver observer = createObserver(taskId, task);
    ToolExecutionResult result = tool.execute(target, parameters, observer);
    if (observer.isCancellationRequested()) {
      throw new TaskCancelledException();
    }

    appendLog(task, "命令执行完成，正在解析输出并生成检测结果…");
    updateProgress(task, 88, false, null, null, "工具执行完成，正在保存检测结果");
    saveFindings(task, target, tool, result);

    task.setResultJson(objectMapper.writeValueAsString(result));
    task.setStatus("SUCCESS");
    task.setProgress(100);
    task.setProgressDeterminate(true);
    task.setProgressCompleted(1L);
    task.setProgressTotal(1L);
    task.setProgressMessage("任务执行完成");
    task.setProgressUpdatedAt(Instant.now());
    appendLog(task, "执行成功：" + result.summary());
    auditService.record(
        "EXECUTE_TOOL",
        "TASK",
        taskId,
        tool.code(),
        "SUCCESS",
        taskId,
        task.getAuthorizationSnapshotHash());
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
    int findingIndex = 0;
    int findingTotal = result.findings().size();
    int lastFindingProgress = -1;
    for (FindingDraft draft : result.findings()) {
      Finding finding = new Finding();
      finding.setTaskId(task.getId());
      finding.setTargetId(target.getId());
      finding.setTitle(draft.title());
      finding.setSeverity(draft.severity());
      finding.setSourceTool(tool.code());
      finding.setRuleCode(task.getRuleCode());
      finding.setVulnerabilityCode(resolveVulnerabilityCode(task, draft));
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
    String userMessage = failureMessage(timeout, authorizationChanged);

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
    String message = exception.getMessage();
    return message != null && (message.contains("超时") || message.contains("超过"));
  }

  private boolean isAuthorizationChanged(Exception exception) {
    String message = exception.getMessage();
    return message != null && message.contains("授权");
  }

  private String failureMessage(boolean timeout, boolean authorizationChanged) {
    if (timeout) {
      return EXECUTION_TIMEOUT_MESSAGE;
    }
    if (authorizationChanged) {
      return AUTHORIZATION_CHANGED_MESSAGE;
    }
    return EXECUTION_FAILED_MESSAGE;
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
