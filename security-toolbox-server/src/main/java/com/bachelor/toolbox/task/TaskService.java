package com.bachelor.toolbox.task;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class TaskService {
  private static final int LIST_LIMIT = 1000;
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final Set<String> RETRYABLE_STATUSES =
      Set.of("FAILED", "TIMEOUT", "REJECTED", "CANCELLED");
  private final SecurityTaskRepository repository;
  private final TargetService targetService;
  private final SecurityToolRegistry registry;
  private final TaskExecutionService executionService;
  private final AuditService auditService;
  private final ObjectMapper objectMapper;
  private final TaskSnapshotService snapshotService;
  private final TaskExecutionControlService executionControl;
  private final AssessmentProjectService projectService;
  private final TaskProgressEventService progressEvents;

  public TaskService(
      SecurityTaskRepository repository,
      TargetService targetService,
      SecurityToolRegistry registry,
      TaskExecutionService executionService,
      AuditService auditService,
      ObjectMapper objectMapper,
      TaskSnapshotService snapshotService,
      TaskExecutionControlService executionControl,
      AssessmentProjectService projectService,
      TaskProgressEventService progressEvents) {
    this.repository = repository;
    this.targetService = targetService;
    this.registry = registry;
    this.executionService = executionService;
    this.auditService = auditService;
    this.objectMapper = objectMapper;
    this.snapshotService = snapshotService;
    this.executionControl = executionControl;
    this.projectService = projectService;
    this.progressEvents = progressEvents;
  }

  public List<SecurityTask> list() {
    List<Long> projectIds = projectService.list().stream().map(project -> project.getId()).toList();
    if (projectIds.isEmpty()) {
      return List.of();
    }
    return repository.findAllByProjectIdIn(
        projectIds, PageRequests.bounded(0, LIST_LIMIT, 1, LIST_LIMIT, LIST_SORT));
  }

  public SecurityTask get(Long id) {
    SecurityTask task = repository.findById(id).orElseThrow(() -> new ApiException("任务不存在"));
    if (task.getProjectId() == null) {
      throw new ApiException("任务不属于评估项目");
    }
    projectService.get(task.getProjectId());
    return task;
  }

  public SecurityTask create(CreateTaskRequest request) throws JsonProcessingException {
    return create(request, null, null);
  }

  public SecurityTask create(CreateTaskRequest request, String ruleCode, String vulnerabilityCode)
      throws JsonProcessingException {
    projectService.validateProjectTarget(request.projectId(), request.targetId());
    var target = targetService.getCurrentlyAuthorized(request.targetId(), request.projectId());
    var tool = registry.require(request.toolCode());
    Map<String, Object> parameters = request.parameters() == null ? Map.of() : request.parameters();
    SecurityTask task = new SecurityTask();
    task.setTargetId(request.targetId());
    task.setProjectId(request.projectId());
    task.setToolCode(request.toolCode());
    task.setRuleCode(ruleCode);
    task.setVulnerabilityCode(vulnerabilityCode);
    task.setStatus("PENDING");
    task.setProgress(0);
    task.setProgressDeterminate(false);
    task.setProgressMessage("等待本地执行资源");
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setQueueEnteredAt(java.time.Instant.now());
    task.setRequestJson(objectMapper.writeValueAsString(parameters));
    snapshotService.capture(task, target, tool);
    return saveAndExecute(task, "CREATE_TASK", null);
  }

  public SecurityTask retry(Long id) {
    SecurityTask original = get(id);
    if (!RETRYABLE_STATUSES.contains(original.getStatus())) {
      throw new ApiException("仅失败、被拒绝或已取消的任务可以重试");
    }
    var target =
        targetService.getCurrentlyAuthorized(original.getTargetId(), original.getProjectId());
    projectService.validateProjectTarget(original.getProjectId(), original.getTargetId());
    var tool = registry.require(original.getToolCode());

    SecurityTask retry = new SecurityTask();
    retry.setTargetId(original.getTargetId());
    retry.setProjectId(original.getProjectId());
    retry.setToolCode(original.getToolCode());
    retry.setRuleCode(original.getRuleCode());
    retry.setVulnerabilityCode(original.getVulnerabilityCode());
    retry.setStatus("PENDING");
    retry.setProgress(0);
    retry.setProgressDeterminate(false);
    retry.setProgressMessage("等待本地执行资源");
    retry.setProgressUpdatedAt(java.time.Instant.now());
    retry.setQueueEnteredAt(java.time.Instant.now());
    retry.setRequestJson(original.getRequestJson());
    retry.setSourceTaskId(original.getId());
    snapshotService.capture(retry, target, tool);
    return saveAndExecute(retry, "RETRY_TASK", original.getId());
  }

  public SecurityTask cancel(Long id) {
    SecurityTask task = get(id);
    if (Set.of("SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED").contains(task.getStatus()))
      throw new ApiException("已结束的任务不能取消");
    String previous = task.getStatus();
    // Interrupt the worker and flip status immediately so the control center
    // stops showing RUNNING after cancel is acknowledged.
    executionControl.requestCancellation(id);
    task.setStatus("CANCELLED");
    task.setProgressMessage("PENDING".equals(previous) ? "任务在排队阶段被取消" : "用户取消任务");
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setTerminationReason("CANCELLED");
    task.setFinishedAt(java.time.Instant.now());
    task.setErrorMessage("用户取消任务");
    repository.save(task);
    progressEvents.publish(task, "用户取消任务");
    auditService.record("CANCEL_TASK", "TASK", id, task.getToolCode(), "CANCELLED");
    return task;
  }

  private SecurityTask saveAndExecute(SecurityTask task, String auditAction, Long sourceTaskId) {
    SecurityTask saved = repository.save(task);
    String detail =
        sourceTaskId == null
            ? saved.getToolCode()
            : saved.getToolCode() + "; sourceTaskId=" + sourceTaskId;
    if (saved.getAuthorizationSnapshotHash() == null) {
      auditService.record(auditAction, "TASK", saved.getId(), detail, "ACCEPTED");
    } else {
      auditService.record(
          auditAction,
          "TASK",
          saved.getId(),
          detail,
          "ACCEPTED",
          saved.getId(),
          saved.getAuthorizationSnapshotHash());
    }
    try {
      executionService.executeAsync(saved.getId());
    } catch (RuntimeException ex) {
      saved.setStatus("REJECTED");
      saved.setProgressMessage("本地任务队列已满");
      saved.setProgressUpdatedAt(java.time.Instant.now());
      saved.setErrorMessage("本地任务队列已满，请稍后重试");
      repository.save(saved);
      throw new ApiException("本地任务队列已满，请稍后重试");
    }
    return saved;
  }
}
