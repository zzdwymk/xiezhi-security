package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AgentWorkflowSpecService;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse.DependencyStatus;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.ScannerPocSelectionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.scheduling.annotation.Async;

class WorkflowRunServiceTests {
  private static final Long PROJECT_ID = 7L;
  private static final Long TARGET_ID = 9L;
  private static final String DIGEST = "sha256:" + "a".repeat(64);

  private final WorkflowRunRepository runs = mock(WorkflowRunRepository.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final TaskService taskService = mock(TaskService.class);
  private final AgentWorkflowSpecService workflowSpecs = mock(AgentWorkflowSpecService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final TargetService targets = mock(TargetService.class);
  private final DependencyDetectionService dependencies = mock(DependencyDetectionService.class);
  private final ScannerPocSelectionService scannerPocs = mock(ScannerPocSelectionService.class);
  private final AuditService audit = mock(AuditService.class);
  private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
  private final WorkflowRunStopTransactionService stopTransactions =
      mock(WorkflowRunStopTransactionService.class);
  private final List<SecurityTask> createdTasks = new ArrayList<>();
  private final List<CreateTaskRequest> createdRequests = new ArrayList<>();
  private final Map<String, List<Long>> createdDependencies = new LinkedHashMap<>();

  private WorkflowRunService service;

  @BeforeEach
  void setUp() throws Exception {
    service =
        new WorkflowRunService(
            runs,
            tasks,
            taskService,
            workflowSpecs,
            projects,
            targets,
            dependencies,
            scannerPocs,
            audit,
            objectMapper,
            stopTransactions);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(TARGET_ID);
    target.setAllowedPorts("80,443,8000-8002");
    when(targets.getCurrentlyAuthorized(TARGET_ID, PROJECT_ID)).thenReturn(target);
    when(dependencies.detect()).thenReturn(availableDependencies());
    when(runs.save(any(WorkflowRun.class)))
        .thenAnswer(
            invocation -> {
              WorkflowRun run = invocation.getArgument(0);
              if (run.getId() == null) run.setId(42L);
              return run;
            });
    when(tasks.findAllByWorkflowRunIdOrderByCreatedAtAsc(42L))
        .thenAnswer(invocation -> List.copyOf(createdTasks));
    when(taskService.createWorkflowTask(
            any(CreateTaskRequest.class),
            anyString(),
            anyString(),
            anyString(),
            anyInt(),
            anyString(),
            anyBoolean(),
            anyList(),
            eq(42L)))
        .thenAnswer(
            invocation -> {
              CreateTaskRequest request = invocation.getArgument(0);
              String nodeId = invocation.getArgument(2);
              List<Long> dependencyIds = invocation.getArgument(7);
              SecurityTask task = workflowTask(createdTasks.size() + 11L, nodeId, request.toolCode());
              task.setStatus(dependencyIds.isEmpty() ? "PENDING" : "BLOCKED");
              createdTasks.add(task);
              createdRequests.add(request);
              createdDependencies.put(nodeId, List.copyOf(dependencyIds));
              return task;
            });
  }

  @Test
  void startsOnePersistedRunWithDependenciesAndTargetDefaults() throws Exception {
    List<Map<String, Object>> steps =
        List.of(
            step("scan", "nmap_service_scan", 0, false, List.of(), Map.of()),
            step("headers", "http_security_check", 1, false, List.of("scan"), Map.of()));
    stubSnapshot(steps);

    WorkflowRunDtos.Detail detail = service.start(startRequest(List.of(), List.of()));

    assertThat(detail.run().id()).isEqualTo(42L);
    assertThat(detail.run().status()).isEqualTo("RUNNING");
    assertThat(createdTasks).hasSize(2).allMatch(task -> task.getWorkflowRunId().equals(42L));
    assertThat(createdDependencies.get("scan")).isEmpty();
    assertThat(createdDependencies.get("headers")).containsExactly(11L);
    assertThat(createdRequests.get(0).parameters())
        .containsEntry("ports", "80,443,8000-8002")
        .containsEntry("mode", "quick");
    assertThat(createdRequests.get(1).parameters()).containsEntry("check", "cookies");
  }

  @Test
  void rejectsHighRiskNodeWithoutExplicitApproval() {
    List<Map<String, Object>> steps =
        List.of(step("headers", "http_headers", 0, true, List.of(), Map.of()));
    stubSnapshot(steps);

    assertThatThrownBy(() -> service.start(startRequest(List.of(), List.of())))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("高风险步骤未获得执行确认");
    verify(runs, never()).save(any());
  }

  @Test
  void unavailableNodeMustBeExplicitlySkipped() throws Exception {
    List<Map<String, Object>> steps =
        List.of(step("scan", "nmap_service_scan", 0, false, List.of(), Map.of()));
    stubSnapshot(steps);
    when(dependencies.detect())
        .thenReturn(
            new SystemDependenciesResponse(
                "test",
                "test",
                List.of(new DependencyStatus("Nmap", "MISSING", "", "", true, "scanner", ""))));

    assertThatThrownBy(() -> service.start(startRequest(List.of(), List.of())))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("工作流存在不可用步骤");

    SecurityTask skipped = workflowTask(11L, "scan", "nmap_service_scan");
    skipped.setStatus("SKIPPED");
    when(taskService.createSkippedWorkflowTask(
            any(), anyString(), eq("scan"), anyString(), anyInt(), anyString(), anyBoolean(), anyList(), eq(42L), anyString()))
        .thenAnswer(
            invocation -> {
              createdTasks.add(skipped);
              return skipped;
            });

    WorkflowRunDtos.Detail detail = service.start(startRequest(List.of(), List.of("scan")));

    assertThat(detail.tasks()).extracting(SecurityTask::getStatus).containsExactly("SKIPPED");
    verify(taskService).createSkippedWorkflowTask(
        any(), anyString(), eq("scan"), anyString(), anyInt(), anyString(), anyBoolean(), anyList(), eq(42L), anyString());
  }

  @Test
  void stopCancelsEveryNonTerminalTaskAndMarksRunStopped() {
    WorkflowRun run = persistedRun("RUNNING");
    SecurityTask pending = workflowTask(11L, "root", "http_headers");
    pending.setStatus("PENDING");
    SecurityTask blocked = workflowTask(12L, "child", "http_security_check");
    blocked.setStatus("BLOCKED");
    createdTasks.addAll(List.of(pending, blocked));
    when(stopTransactions.begin(42L))
        .thenAnswer(
            ignored -> {
              run.setStatus("STOPPING");
              return run;
            });
    when(stopTransactions.finish(42L))
        .thenAnswer(
            ignored -> {
              run.setStatus("STOPPED");
              run.setProgress(100);
              return run;
            });
    when(taskService.cancel(any(Long.class)))
        .thenAnswer(
            invocation -> {
              Long taskId = invocation.getArgument(0);
              SecurityTask task =
                  createdTasks.stream().filter(item -> item.getId().equals(taskId)).findFirst().orElseThrow();
              task.setStatus("CANCELLED");
              return task;
            });

    WorkflowRunDtos.Detail detail = service.stop(42L);

    verify(taskService).cancel(11L);
    verify(taskService).cancel(12L);
    verify(stopTransactions).begin(42L);
    verify(stopTransactions).finish(42L);
    assertThat(detail.run().status()).isEqualTo("STOPPED");
    assertThat(detail.run().progress()).isEqualTo(100);
  }

  @Test
  void terminalEventCompletesRunAndClearOnlyHidesIt() throws Exception {
    WorkflowRun run = persistedRun("RUNNING");
    SecurityTask task = workflowTask(11L, "root", "http_headers");
    task.setStatus("SUCCESS");
    task.setWorkflowRunId(42L);
    createdTasks.add(task);
    when(tasks.findById(11L)).thenReturn(Optional.of(task));
    when(runs.findById(42L)).thenReturn(Optional.of(run));
    when(runs.findByIdForUpdate(42L)).thenReturn(Optional.of(run));

    service.onTaskTerminal(new TaskTerminalEvent(11L));

    Transactional transaction =
        WorkflowRunService.class
            .getDeclaredMethod("onTaskTerminal", TaskTerminalEvent.class)
            .getAnnotation(Transactional.class);

    assertThat(run.getStatus()).isEqualTo("COMPLETED");
    assertThat(run.getFinishedAt()).isNotNull();
    assertThat(transaction.propagation()).isEqualTo(Propagation.REQUIRES_NEW);
    assertThat(
            WorkflowRunService.class
                .getDeclaredMethod("onTaskTerminal", TaskTerminalEvent.class)
                .isAnnotationPresent(Async.class))
        .isTrue();

    service.clear(42L);

    assertThat(run.getClearedAt()).isNotNull();
    verify(runs, times(2)).save(run);
    verify(tasks, never()).delete(any());
  }

  @Test
  void lateTerminalEventCannotRewriteStoppedRun() {
    WorkflowRun run = persistedRun("STOPPED");
    SecurityTask task = workflowTask(11L, "root", "http_headers");
    task.setStatus("FAILED");
    createdTasks.add(task);
    when(tasks.findById(11L)).thenReturn(Optional.of(task));
    when(runs.findByIdForUpdate(42L)).thenReturn(Optional.of(run));

    service.onTaskTerminal(new TaskTerminalEvent(11L));

    assertThat(run.getStatus()).isEqualTo("STOPPED");
    verify(runs, never()).save(run);
  }

  private void stubSnapshot(List<Map<String, Object>> steps) {
    AgentWorkflowSpecService.WorkflowSnapshot snapshot = snapshot(steps);
    when(workflowSpecs.freezeSnapshot(PROJECT_ID, "workflow-1", 3L, DIGEST))
        .thenReturn(snapshot);
    when(workflowSpecs.executableSteps(snapshot)).thenReturn(steps);
  }

  private AgentWorkflowSpecService.WorkflowSnapshot snapshot(List<Map<String, Object>> steps) {
    return new AgentWorkflowSpecService.WorkflowSnapshot(
        "workflow-1",
        PROJECT_ID,
        3L,
        DIGEST,
        "admin",
        Instant.parse("2026-08-18T00:00:00Z"),
        Map.of("version", 1, "steps", steps),
        steps);
  }

  private WorkflowRunDtos.StartRequest startRequest(
      List<String> approvedNodeIds, List<String> skippedNodeIds) {
    return new WorkflowRunDtos.StartRequest(
        PROJECT_ID,
        TARGET_ID,
        "workflow-1",
        3L,
        DIGEST,
        approvedNodeIds,
        skippedNodeIds);
  }

  private Map<String, Object> step(
      String nodeId,
      String tool,
      int group,
      boolean requiresApproval,
      List<String> dependsOn,
      Map<String, Object> parameters) {
    Map<String, Object> step = new LinkedHashMap<>();
    step.put("nodeId", nodeId);
    step.put("tool", tool);
    step.put("label", nodeId);
    step.put("group", group);
    step.put("risk", requiresApproval ? "CAUTION" : "SAFE");
    step.put("requiresApproval", requiresApproval);
    step.put("dependsOnNodeIds", dependsOn);
    step.put("parameters", parameters);
    return step;
  }

  private SecurityTask workflowTask(Long id, String nodeId, String toolCode) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setProjectId(PROJECT_ID);
    task.setTargetId(TARGET_ID);
    task.setToolCode(toolCode);
    task.setWorkflowNodeId(nodeId);
    task.setWorkflowRunId(42L);
    task.setProgress(0);
    return task;
  }

  private WorkflowRun persistedRun(String status) {
    WorkflowRun run = new WorkflowRun();
    run.setId(42L);
    run.setProjectId(PROJECT_ID);
    run.setTargetId(TARGET_ID);
    run.setWorkflowId("workflow-1");
    run.setWorkflowRevision(3L);
    run.setWorkflowDigest(DIGEST);
    run.setSpecJson("{}");
    run.setStatus(status);
    run.setProgress(0);
    return run;
  }

  private SystemDependenciesResponse availableDependencies() {
    return new SystemDependenciesResponse(
        "test",
        "test",
        List.of(new DependencyStatus("Nmap", "AVAILABLE", "1", "nmap", true, "scanner", "")));
  }
}
