package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.TaskService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProjectScopeAiExecutionTests {
  private AssessmentProjectService projects;
  private TargetService targets;
  private AiAuthorizationGuard guard;
  private AiTaskDispatchService dispatcher;
  private AiAgentDispatchRepository dispatches;
  private TaskService taskService;
  private AuditService auditService;
  private CrossTurnRecoveryService recoveryService;
  private SecurityAgentTools tools;
  private SecurityTaskRepository taskRepository;
  private AiExecutionReviewer reviewer;

  @BeforeEach
  void setUp() {
    projects = mock(AssessmentProjectService.class);
    targets = mock(TargetService.class);
    guard = mock(AiAuthorizationGuard.class);
    dispatcher = mock(AiTaskDispatchService.class);
    dispatches = mock(AiAgentDispatchRepository.class);
    taskService = mock(TaskService.class);
    auditService = mock(AuditService.class);
    recoveryService = mock(CrossTurnRecoveryService.class);
    taskRepository = mock(SecurityTaskRepository.class);

    tools =
        new SecurityAgentTools(
            projects,
            targets,
            guard,
            dispatcher,
            dispatches,
            new ObjectMapper(),
            taskService,
            auditService,
            recoveryService);
    reviewer = new AiExecutionReviewer(taskRepository);
  }

  @Test
  void infersScopeModeCorrectly() {
    AiAgentRequest single =
        new AiAgentRequest(
            1L, 10L, "s1", "p", false, null, null, "plan", "turn-1", null, null, null, null, null);
    assertEquals(AiAgentRequest.ScopeMode.SINGLE, single.scopeMode());
    assertFalse(single.isProjectScoped());
    assertEquals(List.of(10L), single.targetIds());

    AiAgentRequest subset =
        new AiAgentRequest(
            1L, null, "s2", "p", false, null, null, "plan", "turn-2", null, null, null, null, null,
            null, null, List.of(11L, 12L), null);
    assertEquals(AiAgentRequest.ScopeMode.PROJECT_SUBSET, subset.scopeMode());
    assertTrue(subset.isProjectScoped());
    assertEquals(11L, subset.targetId()); // auto anchor
    assertEquals(List.of(11L, 12L), subset.targetIds());

    AiAgentRequest all =
        new AiAgentRequest(
            1L, null, "s3", "p", false, null, null, "plan", "turn-3", null, null, null, null, null,
            null, null, null, null);
    assertEquals(AiAgentRequest.ScopeMode.PROJECT_ALL, all.scopeMode());
    assertTrue(all.isProjectScoped());
  }

  @Test
  void reviewerValidatesMultipleAllowedTargets() {
    SecurityTask task1 = new SecurityTask();
    task1.setId(101L);
    task1.setProjectId(1L);
    task1.setTargetId(11L);
    task1.setStatus("SUCCESS");

    SecurityTask task2 = new SecurityTask();
    task2.setId(102L);
    task2.setProjectId(1L);
    task2.setTargetId(12L);
    task2.setStatus("RUNNING");

    when(taskRepository.findById(101L)).thenReturn(Optional.of(task1));
    when(taskRepository.findById(102L)).thenReturn(Optional.of(task2));

    var review = reviewer.review(1L, null, List.of(11L, 12L), List.of(101L, 102L));
    assertEquals("PENDING", review.status());
    assertEquals(2, review.verifiedTaskIds().size());

    // 异源目标拒绝
    task2.setTargetId(99L);
    var rejectedReview = reviewer.review(1L, null, List.of(11L, 12L), List.of(101L, 102L));
    assertEquals("REJECTED", rejectedReview.status());
  }

  @Test
  void executeApprovedPlanFansOutToTargetSubset() throws Exception {
    AiAgentRequest request =
        new AiAgentRequest(
            1L, null, "s1", "p", true, null, null, "plan", "turn-fanout-1", null, null, null, null, null,
            null, null, List.of(11L, 12L), AiAgentRequest.ScopeMode.PROJECT_SUBSET);

    when(projects.targets(1L)).thenReturn(List.of(new ProjectTarget(1L, 11L), new ProjectTarget(1L, 12L)));
    when(dispatches.findById(any())).thenReturn(Optional.empty());

    AiPlanResponse.PlanStep step =
        new AiPlanResponse.PlanStep("tcp_ports", "端口扫描", "探测服务", Map.of("ports", "80"), null, 0, List.of(), "SAFE", false, List.of());
    AiPlanResponse plan = new AiPlanResponse("model", "version", "summary", false, List.of(step));

    when(guard.evaluate(any(), any()))
        .thenReturn(new AiAuthorizationGuard.GuardDecision("ALLOWED", "CONFIRMED_BY_REQUEST", "ok", plan, 0, 0));
    when(dispatcher.prepare(any(), any())).thenReturn(plan);

    AtomicTaskCounter counter = new AtomicTaskCounter();
    when(taskService.createDependent(any(), any(), org.mockito.ArgumentMatchers.anyInt()))
        .thenAnswer(inv -> {
          SecurityTask t = new SecurityTask();
          t.setId(counter.nextId());
          CreateTaskRequest req = inv.getArgument(0);
          t.setTargetId(req.targetId());
          return t;
        });

    AiDispatchResponse response = tools.executeAuthorizedPlan(request, plan, mock(CrossTurnRecoveryService.RecoveryAnchor.class));
    assertEquals(2, response.taskCount());
    assertEquals(2, response.taskIds().size());
    verify(taskService, times(2)).createDependent(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    verify(targets).lockForAgentExecution(11L);
    verify(targets).lockForAgentExecution(12L);
  }

  @Test
  void executeApprovedPlanRejectsTargetsNotBelongingToProject() throws Exception {
    AiAgentRequest request =
        new AiAgentRequest(
            1L, null, "s1", "p", true, null, null, "plan", "turn-fanout-2", null, null, null, null, null,
            null, null, List.of(11L, 999L), AiAgentRequest.ScopeMode.PROJECT_SUBSET);

    when(projects.targets(1L)).thenReturn(List.of(new ProjectTarget(1L, 11L)));

    AiPlanResponse plan = new AiPlanResponse("model", "version", "summary", false, List.of());
    ApiException ex = assertThrows(ApiException.class, () ->
        tools.executeAuthorizedPlan(request, plan, mock(CrossTurnRecoveryService.RecoveryAnchor.class)));

    assertTrue(ex.getMessage().contains("不属于该评估项目"));
    verify(taskService, never()).createDependent(any(), any(), org.mockito.ArgumentMatchers.anyInt());
  }

  @Test
  void executeApprovedPlanFansOutToProjectAll() throws Exception {
    AiAgentRequest request =
        new AiAgentRequest(
            1L, null, "s1", "p", true, null, null, "plan", "turn-all-1", null, null, null, null, null,
            null, null, null, AiAgentRequest.ScopeMode.PROJECT_ALL);

    when(projects.targets(1L)).thenReturn(List.of(new ProjectTarget(1L, 21L), new ProjectTarget(1L, 22L)));
    when(dispatches.findById(any())).thenReturn(Optional.empty());

    AiPlanResponse.PlanStep step =
        new AiPlanResponse.PlanStep("tcp_ports", "端口扫描", "探测服务", Map.of("ports", "80"), null, 0, List.of(), "SAFE", false, List.of());
    AiPlanResponse plan = new AiPlanResponse("model", "version", "summary", false, List.of(step));

    when(guard.evaluate(any(), any()))
        .thenReturn(new AiAuthorizationGuard.GuardDecision("ALLOWED", "CONFIRMED_BY_REQUEST", "ok", plan, 0, 0));
    when(dispatcher.prepare(any(), any())).thenReturn(plan);

    AtomicTaskCounter counter = new AtomicTaskCounter();
    when(taskService.createDependent(any(), any(), org.mockito.ArgumentMatchers.anyInt()))
        .thenAnswer(inv -> {
          SecurityTask t = new SecurityTask();
          t.setId(counter.nextId());
          CreateTaskRequest req = inv.getArgument(0);
          t.setTargetId(req.targetId());
          return t;
        });

    AiDispatchResponse response = tools.executeAuthorizedPlan(request, plan, mock(CrossTurnRecoveryService.RecoveryAnchor.class));
    assertEquals(2, response.taskCount());
    assertEquals(2, response.taskIds().size());
    verify(targets).lockForAgentExecution(21L);
    verify(targets).lockForAgentExecution(22L);
  }

  @Test
  void executeApprovedPlanSkipsInvalidTargetInProjectScope() throws Exception {
    AiAgentRequest request =
        new AiAgentRequest(
            1L, null, "s1", "p", true, null, null, "plan", "turn-skip-1", null, null, null, null, null,
            null, null, List.of(31L, 32L), AiAgentRequest.ScopeMode.PROJECT_SUBSET);

    when(projects.targets(1L)).thenReturn(List.of(new ProjectTarget(1L, 31L), new ProjectTarget(1L, 32L)));
    when(dispatches.findById(any())).thenReturn(Optional.empty());

    // 目标 31 授权失效，32 正常
    org.mockito.Mockito.doThrow(new ApiException("目标授权已过期"))
        .when(projects).validateProjectTarget(1L, 31L);

    AiPlanResponse.PlanStep step =
        new AiPlanResponse.PlanStep("tcp_ports", "端口扫描", "探测服务", Map.of("ports", "80"), null, 0, List.of(), "SAFE", false, List.of());
    AiPlanResponse plan = new AiPlanResponse("model", "version", "summary", false, List.of(step));

    when(guard.evaluate(any(), any()))
        .thenReturn(new AiAuthorizationGuard.GuardDecision("ALLOWED", "CONFIRMED_BY_REQUEST", "ok", plan, 0, 0));
    when(dispatcher.prepare(any(), any())).thenReturn(plan);

    AtomicTaskCounter counter = new AtomicTaskCounter();
    when(taskService.createDependent(any(), any(), org.mockito.ArgumentMatchers.anyInt()))
        .thenAnswer(inv -> {
          SecurityTask t = new SecurityTask();
          t.setId(counter.nextId());
          CreateTaskRequest req = inv.getArgument(0);
          t.setTargetId(req.targetId());
          return t;
        });

    AiDispatchResponse response = tools.executeAuthorizedPlan(request, plan, mock(CrossTurnRecoveryService.RecoveryAnchor.class));
    // 只有 1 个任务（目标 32 的）
    assertEquals(1, response.taskCount());
    assertEquals(1, response.taskIds().size());
  }

  @Test
  void idempotentReplayReturnsPersistedTaskIdsWithoutRecreating() throws Exception {
    AiAgentRequest request =
        new AiAgentRequest(
            1L, null, "s1", "p", true, null, null, "plan", "turn-replay-1", null, null, null, null, null,
            null, null, List.of(41L), AiAgentRequest.ScopeMode.PROJECT_SUBSET);

    when(projects.targets(1L)).thenReturn(List.of(new ProjectTarget(1L, 41L)));

    AiPlanResponse.PlanStep step =
        new AiPlanResponse.PlanStep("tcp_ports", "端口扫描", "探测服务", Map.of("ports", "80"), null, 0, List.of(), "SAFE", false, List.of());
    AiPlanResponse plan = new AiPlanResponse("model", "version", "summary", false, List.of(step));

    AiAgentDispatchRecord existing = new AiAgentDispatchRecord();
    existing.setIdempotencyKey("test-key");
    existing.setProjectId(1L);
    existing.setTargetId(41L);
    // 生成 matching digest
    java.util.Map<String, Object> digestInput = new java.util.LinkedHashMap<>();
    digestInput.put("projectId", 1L);
    digestInput.put("targetId", 41L);
    digestInput.put("scopeMode", "PROJECT_SUBSET");
    digestInput.put("targetIds", List.of(41L));
    digestInput.put("execute", true);
    digestInput.put("workflowId", null);
    digestInput.put("workflowRevision", null);
    digestInput.put("workflowDigest", null);
    digestInput.put("outerNodeId", null);
    digestInput.put("nodeRunId", null);
    digestInput.put("plan", plan);
    String digest = java.util.HexFormat.of().formatHex(
        java.security.MessageDigest.getInstance("SHA-256").digest(new ObjectMapper().writeValueAsString(digestInput).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    existing.setRequestDigest(digest);
    existing.setTaskIds("901,902");

    when(dispatches.findById(any())).thenReturn(Optional.of(existing));
    when(dispatcher.prepare(any(), any())).thenReturn(plan);

    AiDispatchResponse response = tools.executeAuthorizedPlan(request, plan, mock(CrossTurnRecoveryService.RecoveryAnchor.class));
    assertEquals(2, response.taskCount());
    assertEquals(List.of(901L, 902L), response.taskIds());
    // 幂等命中，绝对不调用 taskService 重建任务
    verify(taskService, never()).createDependent(any(), any(), org.mockito.ArgumentMatchers.anyInt());
  }

  private static final class AtomicTaskCounter {
    private long id = 500L;
    synchronized long nextId() { return ++id; }
  }
}
