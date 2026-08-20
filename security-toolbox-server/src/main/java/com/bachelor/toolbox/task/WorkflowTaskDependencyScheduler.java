package com.bachelor.toolbox.task;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/** Unlocks persisted workflow tasks only after every predecessor completed successfully. */
@Service
public class WorkflowTaskDependencyScheduler {
  private static final Set<String> FAILED_TERMINALS =
      Set.of("FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED");

  private final SecurityTaskRepository tasks;
  private final TaskExecutionService execution;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final ProjectAuthorizationService authorization;
  private final TaskProgressEventService progressEvents;
  private final AuditService audit;
  private final ObjectMapper objectMapper;
  private final WorkflowRunRepository runs;
  private final ApplicationEventPublisher events;

  @Autowired
  public WorkflowTaskDependencyScheduler(
      SecurityTaskRepository tasks,
      TaskExecutionService execution,
      AssessmentProjectService projects,
      TargetService targets,
      ProjectAuthorizationService authorization,
      TaskProgressEventService progressEvents,
      AuditService audit,
      ObjectMapper objectMapper,
      WorkflowRunRepository runs,
      ApplicationEventPublisher events) {
    this.tasks = tasks;
    this.execution = execution;
    this.projects = projects;
    this.targets = targets;
    this.authorization = authorization;
    this.progressEvents = progressEvents;
    this.audit = audit;
    this.objectMapper = objectMapper;
    this.runs = runs;
    this.events = events;
  }

  WorkflowTaskDependencyScheduler(
      SecurityTaskRepository tasks,
      TaskExecutionService execution,
      AssessmentProjectService projects,
      TargetService targets,
      TaskProgressEventService progressEvents,
      AuditService audit,
      ObjectMapper objectMapper) {
    this(
        tasks,
        execution,
        projects,
        targets,
        null,
        progressEvents,
        audit,
        objectMapper,
        null,
        event -> {});
  }

  WorkflowTaskDependencyScheduler(
      SecurityTaskRepository tasks,
      TaskExecutionService execution,
      AssessmentProjectService projects,
      TargetService targets,
      TaskProgressEventService progressEvents,
      AuditService audit,
      ObjectMapper objectMapper,
      WorkflowRunRepository runs,
      ApplicationEventPublisher events) {
    this(
        tasks,
        execution,
        projects,
        targets,
        null,
        progressEvents,
        audit,
        objectMapper,
        runs,
        events);
  }

  @EventListener
  @Async
  public void onTerminal(TaskTerminalEvent ignored) {
    drainBlockedTasks();
  }

  @EventListener(ApplicationReadyEvent.class)
  public void recoverBlockedTasks() {
    drainBlockedTasks();
  }

  synchronized void drainBlockedTasks() {
    if (authorization == null) {
      drainBlockedTasksWithSystemAccess();
      return;
    }
    try {
      authorization.callWithSystemAccess(
          () -> {
            drainBlockedTasksWithSystemAccess();
            return null;
          });
    } catch (RuntimeException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IllegalStateException("工作流依赖调度授权上下文初始化失败", exception);
    }
  }

  private void drainBlockedTasksWithSystemAccess() {
    boolean changed;
    do {
      changed = false;
      for (SecurityTask task : tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED")) {
        if (!runCanExecute(task)) {
          cancelStopped(task);
          changed = true;
          continue;
        }
        List<Long> dependencyIds = dependencyIds(task);
        Map<Long, SecurityTask> dependencies =
            tasks.findAllById(dependencyIds).stream()
                .collect(java.util.stream.Collectors.toMap(SecurityTask::getId, item -> item));
        if (dependencyIds.stream().anyMatch(id -> !dependencies.containsKey(id))) {
          skip(task, "工作流前置任务不存在", "MISSING_DEPENDENCY");
          changed = true;
          continue;
        }
        if (dependencies.values().stream()
            .anyMatch(item -> FAILED_TERMINALS.contains(item.getStatus()))) {
          skip(task, "前置工作流节点未成功，已跳过后继节点", "PREREQUISITE_NOT_COMPLETED");
          changed = true;
          continue;
        }
        if (dependencies.values().stream().allMatch(item -> "SUCCESS".equals(item.getStatus()))) {
          activate(task);
          changed = true;
        }
      }
    } while (changed);
  }

  private void activate(SecurityTask task) {
    if (!runCanExecute(task)) {
      cancelStopped(task);
      return;
    }
    try {
      projects.validateProjectTarget(task.getProjectId(), task.getTargetId());
      targets.getCurrentlyAuthorized(task.getTargetId(), task.getProjectId());
      task.setStatus("PENDING");
      task.setProgressMessage("前置节点已完成，等待本地执行资源");
      task.setProgressUpdatedAt(Instant.now());
      tasks.save(task);
      progressEvents.publish(task, "工作流依赖已满足");
      audit.record(
          "UNLOCK_WORKFLOW_TASK",
          "TASK",
          task.getId(),
          "workflowNodeId=" + task.getWorkflowNodeId(),
          "ACCEPTED");
      execution.executeAsync(task.getId());
    } catch (RuntimeException ex) {
      skip(task, "授权或项目范围已变化，后继节点不再执行", "AUTHORIZATION_CHANGED");
    }
  }

  private boolean runCanExecute(SecurityTask task) {
    if (task.getWorkflowRunId() == null || runs == null) return true;
    return runs
        .findById(task.getWorkflowRunId())
        .map(run -> "RUNNING".equals(run.getStatus()))
        .orElse(false);
  }

  private void cancelStopped(SecurityTask task) {
    task.setStatus("CANCELLED");
    task.setProgressMessage("工作流已停止，任务未执行");
    task.setProgressUpdatedAt(Instant.now());
    task.setTerminationReason("WORKFLOW_STOPPED");
    task.setFinishedAt(Instant.now());
    tasks.save(task);
    progressEvents.publish(task, "工作流已停止，任务未执行");
    audit.record(
        "CANCEL_WORKFLOW_TASK",
        "TASK",
        task.getId(),
        "workflowNodeId=" + task.getWorkflowNodeId(),
        "CANCELLED");
    events.publishEvent(new TaskTerminalEvent(task.getId()));
  }

  private void skip(SecurityTask task, String message, String reason) {
    task.setStatus("SKIPPED");
    task.setProgressMessage(message);
    task.setProgressUpdatedAt(Instant.now());
    task.setTerminationReason(reason);
    task.setFinishedAt(Instant.now());
    tasks.save(task);
    progressEvents.publish(task, message);
    audit.record(
        "SKIP_WORKFLOW_TASK",
        "TASK",
        task.getId(),
        "workflowNodeId=" + task.getWorkflowNodeId() + "; reason=" + reason,
        "SKIPPED");
    events.publishEvent(new TaskTerminalEvent(task.getId()));
  }

  private List<Long> dependencyIds(SecurityTask task) {
    String json = task.getDependencyTaskIds();
    if (json == null || json.isBlank()) return List.of();
    try {
      return objectMapper.readValue(json, new TypeReference<List<Long>>() {});
    } catch (Exception ex) {
      return List.of(Long.MIN_VALUE);
    }
  }
}
