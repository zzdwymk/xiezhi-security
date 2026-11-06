package com.bachelor.toolbox.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

class TaskServiceTests {
  private final SecurityTaskRepository repository = mock(SecurityTaskRepository.class);
  private final TargetService targetService = mock(TargetService.class);
  private final SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
  private final TaskExecutionService executionService = mock(TaskExecutionService.class);
  private final AuditService auditService = mock(AuditService.class);
  private final TaskSnapshotService snapshotService = mock(TaskSnapshotService.class);
  private final TaskExecutionControlService executionControl =
      mock(TaskExecutionControlService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final TaskProgressEventService progressEvents = mock(TaskProgressEventService.class);
  private TaskService service;

  @BeforeEach
  void setUp() {
    service =
        new TaskService(
            repository,
            targetService,
            registry,
            executionService,
            auditService,
            new ObjectMapper(),
            snapshotService,
            executionControl,
            projectService,
            progressEvents);
    when(projectService.get(any())).thenReturn(taskProject());
  }

  @Test
  void retryClonesFailedTaskAndKeepsOriginalHistory() {
    SecurityTask original = task("FAILED");
    when(repository.findById(7L)).thenReturn(Optional.of(original));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(8L);
              return saved;
            });

    SecurityTask retry = service.retry(7L);

    assertNotSame(original, retry);
    assertEquals(8L, retry.getId());
    assertEquals("PENDING", retry.getStatus());
    assertEquals(0, retry.getProgress());
    assertEquals(original.getTargetId(), retry.getTargetId());
    assertEquals(original.getToolCode(), retry.getToolCode());
    assertEquals(original.getRuleCode(), retry.getRuleCode());
    assertEquals(original.getVulnerabilityCode(), retry.getVulnerabilityCode());
    assertEquals(original.getRequestJson(), retry.getRequestJson());
    assertEquals("FAILED", original.getStatus());
    verify(executionService).executeAsync(8L);
    verify(auditService).record("RETRY_TASK", "TASK", 8L, "tcp_ports; sourceTaskId=7", "ACCEPTED");
  }

  @Test
  void cancelCommitsInAnIndependentTransaction() throws Exception {
    Transactional transactional =
        TaskService.class.getDeclaredMethod("cancel", Long.class).getAnnotation(Transactional.class);

    assertNotNull(transactional);
    assertEquals(Propagation.REQUIRES_NEW, transactional.propagation());
  }

  @Test
  void createRetestPersistsItsSourceTaskAndFinding() throws Exception {
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              saved.setId(12L);
              return saved;
            });

    SecurityTask retest =
        service.createRetest(
            new CreateTaskRequest(1L, 3L, "tcp_ports", java.util.Map.of("ports", "80")),
            "RULE-1",
            "VULN-1",
            7L,
            9L);

    assertEquals(7L, retest.getSourceTaskId());
    assertEquals(9L, retest.getSourceFindingId());
    verify(executionService).executeAsync(12L);
    verify(auditService)
        .record("RETEST_TASK", "TASK", 12L, "tcp_ports; sourceTaskId=7", "ACCEPTED");
  }

  @Test
  void retryRejectsNonFailedTask() {
    when(repository.findById(7L)).thenReturn(Optional.of(task("SUCCESS")));

    ApiException error = assertThrows(ApiException.class, () -> service.retry(7L));

    assertEquals("仅失败、被拒绝或已取消的任务可以重试", error.getMessage());
    verify(repository, never()).save(any());
    verify(executionService, never()).executeAsync(any());
  }

  @Test
  void retryMarksNewTaskRejectedWhenQueueIsFull() {
    SecurityTask original = task("REJECTED");
    when(repository.findById(7L)).thenReturn(Optional.of(original));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(9L);
              return saved;
            });
    org.mockito.Mockito.doThrow(new RuntimeException("queue full"))
        .when(executionService)
        .executeAsync(9L);

    assertThrows(ApiException.class, () -> service.retry(7L));

    assertEquals("REJECTED", findSavedRetry().getStatus());
  }

  private SecurityTask task(String status) {
    SecurityTask task = new SecurityTask();
    task.setId(7L);
    task.setTargetId(3L);
    task.setProjectId(1L);
    task.setToolCode("tcp_ports");
    task.setRuleCode("RULE-1");
    task.setVulnerabilityCode("VULN-1");
    task.setStatus(status);
    task.setProgress(100);
    task.setRequestJson("{\"ports\":\"80,443\"}");
    task.setErrorMessage("old failure");
    return task;
  }

  // ---- Node-level workflow retry -------------------------------------------------

  private SecurityTask workflowNode(String status) {
    SecurityTask task = task(status);
    task.setWorkflowDigest("sha256:" + "a".repeat(64));
    task.setWorkflowRunId(42L);
    task.setWorkflowNodeId("headers-01");
    task.setNodeRunId("workflow-run-42.headers-01");
    task.setWorkflowGroup(2);
    task.setDependencyTaskIds("[1]");
    task.setEffectiveRisk("SAFE");
    task.setWorkflowApprovalRequired(true);
    return task;
  }

  private WorkflowRun workflowRun(String status) {
    WorkflowRun run = new WorkflowRun();
    run.setId(42L);
    run.setStatus(status);
    return run;
  }

  private void primeWorkflowRetry(SecurityTask original, WorkflowRun run, String dependencyStatus) {
    when(repository.findById(7L)).thenReturn(Optional.of(original));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(55L);
              return saved;
            });
    WorkflowRunRepository runs = mock(WorkflowRunRepository.class);
    when(runs.findById(42L)).thenReturn(Optional.of(run));
    org.springframework.test.util.ReflectionTestUtils.setField(service, "runRepository", runs);
    org.springframework.test.util.ReflectionTestUtils.setField(
        service,
        "authorization",
        mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class));
    SecurityTask dependency = task(dependencyStatus);
    dependency.setId(1L);
    when(repository.findAllById(eq(List.of(1L)))).thenReturn(List.of(dependency));
  }

  @Test
  void nodeRetryKeepsTheGraphBoundaryInsteadOfCloningAFreeStandingTask() throws Exception {
    primeWorkflowRetry(workflowNode("FAILED"), workflowRun("RUNNING"), "SUCCESS");

    SecurityTask retry = service.retryWorkflowNode(7L, "retry-key-1");

    assertEquals("PENDING", retry.getStatus());
    assertEquals(Long.valueOf(42L), retry.getWorkflowRunId());
    assertEquals("headers-01", retry.getWorkflowNodeId());
    assertEquals("workflow-run-42.headers-01", retry.getNodeRunId());
    assertEquals("sha256:" + "a".repeat(64), retry.getWorkflowDigest());
    // Dependencies and grouping survive, so the retry occupies the same graph position.
    assertEquals("[1]", retry.getDependencyTaskIds());
    assertEquals(Integer.valueOf(2), retry.getWorkflowGroup());
    assertEquals(Long.valueOf(7L), retry.getSourceTaskId());
    // The node was reviewed with the run; a retry is a re-execution, not a new
    // unreviewed action, so it must not demand a second approval.
    assertEquals(Boolean.FALSE, retry.getWorkflowApprovalRequired());
    verify(executionService).executeAsync(55L);
    verify(auditService)
        .record("RETRY_WORKFLOW_NODE", "TASK", 55L, "tcp_ports; sourceTaskId=7", "ACCEPTED");
  }

  @Test
  void nodeRetryRequiresAnIdempotencyKey() {
    when(repository.findById(7L)).thenReturn(Optional.of(workflowNode("FAILED")));

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, " "));

    assertEquals("单节点重试必须提供 Idempotency-Key，避免重复创建任务", error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void nodeRetryRejectsANonWorkflowTask() {
    when(repository.findById(7L)).thenReturn(Optional.of(task("FAILED")));

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, "retry-key-1"));

    assertEquals("该任务不属于工作流或依赖步骤，请使用普通重试", error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void nodeRetrySupportsAnAiDispatchedDependentStep() throws Exception {
    // AI dispatch without a visual workflow uses createDependent: no run, no node id, but
    // real dependency edges. Retrying must keep those edges and still wait for them.
    SecurityTask original = task("FAILED");
    original.setDependencyTaskIds("[1]");
    original.setWorkflowGroup(2);
    original.setEffectiveRisk("SAFE");
    when(repository.findById(7L)).thenReturn(Optional.of(original));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(55L);
              return saved;
            });
    org.springframework.test.util.ReflectionTestUtils.setField(
        service,
        "authorization",
        mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class));
    SecurityTask dependency = task("SUCCESS");
    dependency.setId(1L);
    when(repository.findAllById(eq(List.of(1L)))).thenReturn(List.of(dependency));

    SecurityTask retry = service.retryWorkflowNode(7L, "retry-key-ai");

    // Dependencies survive, so the retry sits in the same graph position and does not scan
    // with empty ports.
    assertEquals("[1]", retry.getDependencyTaskIds());
    assertEquals(Integer.valueOf(2), retry.getWorkflowGroup());
    assertEquals("BLOCKED", retry.getStatus());
    assertEquals("等待前置任务完成", retry.getProgressMessage());
    assertEquals(Long.valueOf(7L), retry.getSourceTaskId());
    org.junit.jupiter.api.Assertions.assertNull(retry.getWorkflowRunId());
    verify(auditService)
        .record("RETRY_TASK", "TASK", 55L, "tcp_ports; sourceTaskId=7", "ACCEPTED");
  }

  @Test
  void nodeRetrySupportsAPreRunTaskThatStillHasAWorkflowDigest() throws Exception {
    // Regression: an older AI dispatch can carry a workflowDigest without ever being bound
    // to a run. Treating that as a run-bound node called findById(null), which throws
    // "The given id must not be null" instead of retrying the step.
    SecurityTask original = task("FAILED");
    original.setWorkflowDigest("sha256:" + "a".repeat(64));
    original.setDependencyTaskIds("[1]");
    when(repository.findById(7L)).thenReturn(Optional.of(original));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(55L);
              return saved;
            });
    org.springframework.test.util.ReflectionTestUtils.setField(
        service,
        "authorization",
        mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class));
    SecurityTask dependency = task("SUCCESS");
    dependency.setId(1L);
    when(repository.findAllById(eq(List.of(1L)))).thenReturn(List.of(dependency));

    SecurityTask retry = service.retryWorkflowNode(7L, "retry-key-digest");

    assertEquals("[1]", retry.getDependencyTaskIds());
    assertEquals("BLOCKED", retry.getStatus());
    // The reviewed snapshot must survive the retry.
    assertEquals("sha256:" + "a".repeat(64), retry.getWorkflowDigest());
    org.junit.jupiter.api.Assertions.assertNull(retry.getWorkflowRunId());
  }

  @Test
  void nodeRetrySupportsALeafStepWithNoDependencies() throws Exception {
    // Regression: a planned root/leaf step has no dependency edges. Requiring edges made
    // the retry refuse with "该任务不属于工作流或依赖步骤" even though the step came from an
    // approved plan and carries its reviewed identity.
    SecurityTask original = task("FAILED");
    original.setWorkflowDigest("sha256:" + "a".repeat(64));
    original.setWorkflowNodeId("service-scan");
    original.setNodeRunId("workflow-run-42.service-scan");
    original.setDependencyTaskIds("[]");
    when(repository.findById(7L)).thenReturn(Optional.of(original));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(56L);
              return saved;
            });
    org.springframework.test.util.ReflectionTestUtils.setField(
        service,
        "authorization",
        mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class));

    SecurityTask retry = service.retryWorkflowNode(7L, "retry-key-leaf");

    // No prerequisites, so the retry can run immediately.
    assertEquals("PENDING", retry.getStatus());
    assertEquals("[]", retry.getDependencyTaskIds());
    assertEquals("service-scan", retry.getWorkflowNodeId());
    assertEquals("workflow-run-42.service-scan", retry.getNodeRunId());
    assertEquals("sha256:" + "a".repeat(64), retry.getWorkflowDigest());
    verify(executionService).executeAsync(56L);
  }

  @Test
  void nodeRetryRejectsABlockedDependentStepBecauseItIsWaitingNotFailing() {
    SecurityTask original = task("BLOCKED");
    original.setDependencyTaskIds("[1]");
    when(repository.findById(7L)).thenReturn(Optional.of(original));

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, "retry-key-1"));

    assertEquals("仅失败、超时、被拒绝或已取消的依赖步骤可以重试", error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void nodeRetryRejectsABlockedNodeBecauseItIsWaitingNotFailing() {
    when(repository.findById(7L)).thenReturn(Optional.of(workflowNode("BLOCKED")));

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, "retry-key-1"));

    assertEquals("仅失败、超时、被拒绝或已取消的依赖步骤可以重试", error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void nodeRetryRejectsAStoppedRun() {
    primeWorkflowRetry(workflowNode("FAILED"), workflowRun("STOPPING"), "SUCCESS");

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, "retry-key-1"));

    assertEquals("工作流已停止，不能单点重试；请重新提交方案并确认执行", error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void nodeRetryRefusesWhileThePrerequisiteStillFails() {
    primeWorkflowRetry(workflowNode("FAILED"), workflowRun("RUNNING"), "FAILED");

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, "retry-key-1"));

    // Retrying now would fail for exactly the same reason as the first attempt.
    org.junit.jupiter.api.Assertions.assertTrue(
        error.getMessage().startsWith("前置节点 #1 未成功"), error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void nodeRetryRefusesWhileThePrerequisiteIsStillRunning() {
    primeWorkflowRetry(workflowNode("FAILED"), workflowRun("RUNNING"), "RUNNING");

    ApiException error =
        assertThrows(ApiException.class, () -> service.retryWorkflowNode(7L, "retry-key-1"));

    assertEquals("前置节点 #1 尚未结束，暂不能重试本节点", error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void ordinaryRetryStillRefusesWorkflowNodes() {
    when(repository.findById(7L)).thenReturn(Optional.of(workflowNode("FAILED")));

    ApiException error = assertThrows(ApiException.class, () -> service.retry(7L));

    assertEquals(
        "工作流任务请重新提交原方案并确认执行，不能以普通重试跳过工作流依赖或审批",
        error.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void createRejectsProjectTargetBeforeLookingUpTargetWhenProjectIsUnauthorized() throws Exception {
    doThrow(new ApiException("无权访问该评估项目")).when(projectService).validateProjectTarget(1L, 3L);

    ApiException error =
        assertThrows(
            ApiException.class,
            () -> service.create(new CreateTaskRequest(1L, 3L, "tcp_ports", java.util.Map.of())));

    assertEquals("无权访问该评估项目", error.getMessage());
    verify(targetService, never()).getCurrentlyAuthorized(any(), any());
    verify(repository, never()).save(any());
    verify(executionService, never()).executeAsync(any());
  }

  @Test
  void getRejectsTaskFromUnauthorizedProject() {
    when(repository.findById(7L)).thenReturn(java.util.Optional.of(task("FAILED")));
    when(projectService.get(1L)).thenThrow(new ApiException("无权访问该评估项目"));

    ApiException error = assertThrows(ApiException.class, () -> service.get(7L));

    assertEquals("无权访问该评估项目", error.getMessage());
  }

  @Test
  void listsTasksOnlyForProjectsVisibleToCurrentUser() {
    SecurityTask visible = task("SUCCESS");
    when(projectService.list()).thenReturn(List.of(taskProject()));
    when(repository.findAllByProjectIdIn(eq(List.of(1L)), any(Pageable.class)))
        .thenReturn(List.of(visible));

    assertEquals(List.of(visible), service.list());

    ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findAllByProjectIdIn(eq(List.of(1L)), pageable.capture());
    assertEquals(0, pageable.getValue().getPageNumber());
    assertEquals(1000, pageable.getValue().getPageSize());
    assertEquals(
        Sort.Direction.DESC, pageable.getValue().getSort().getOrderFor("createdAt").getDirection());
    assertEquals(
        Sort.Direction.DESC, pageable.getValue().getSort().getOrderFor("id").getDirection());
    verify(repository, never()).findAllByProjectIdInOrderByCreatedAtDesc(List.of(1L));
    verify(repository, never()).findAllByOrderByCreatedAtDesc();
  }

  @Test
  void skipsTaskQueryWhenCurrentUserHasNoVisibleProjects() {
    when(projectService.list()).thenReturn(List.of());

    assertEquals(List.of(), service.list());

    verify(repository, never()).findAllByProjectIdIn(any(), any(Pageable.class));
  }

  private com.bachelor.toolbox.project.AssessmentProject taskProject() {
    com.bachelor.toolbox.project.AssessmentProject project =
        new com.bachelor.toolbox.project.AssessmentProject();
    project.setId(1L);
    return project;
  }

  private SecurityTask findSavedRetry() {
    org.mockito.ArgumentCaptor<SecurityTask> captor =
        org.mockito.ArgumentCaptor.forClass(SecurityTask.class);
    verify(repository, times(2)).save(captor.capture());
    SecurityTask retry = captor.getAllValues().get(1);
    assertEquals(0, retry.getProgress());
    assertEquals(false, retry.getProgressDeterminate());
    assertEquals("本地任务队列已满，请稍后重试", retry.getErrorMessage());
    return retry;
  }
}
