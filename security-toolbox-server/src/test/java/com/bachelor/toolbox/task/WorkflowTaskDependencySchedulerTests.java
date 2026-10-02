package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;

class WorkflowTaskDependencySchedulerTests {
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final TaskExecutionService execution = mock(TaskExecutionService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final TargetService targets = mock(TargetService.class);
  private final TaskProgressEventService progress = mock(TaskProgressEventService.class);
  private final AuditService audit = mock(AuditService.class);
  private final WorkflowRunRepository runs = mock(WorkflowRunRepository.class);
  private final ApplicationEventPublisher events = mock(ApplicationEventPublisher.class);

  @BeforeEach
  void allowUncontendedActivation() {
    when(tasks.activateBlockedWorkflowTask(anyLong(), anyString(), any())).thenReturn(1);
  }

  @Test
  void consumesTerminalEventsOutsideThePublishingTransaction() throws Exception {
    assertThat(
            WorkflowTaskDependencyScheduler.class
                .getDeclaredMethod("onTerminal", TaskTerminalEvent.class)
                .isAnnotationPresent(Async.class))
        .isTrue();
  }
  private final WorkflowTaskDependencyScheduler scheduler =
      new WorkflowTaskDependencyScheduler(
          tasks, execution, projects, targets, progress, audit, new ObjectMapper(), runs, events);

  @Test
  void unlocksSuccessorOnlyAfterEveryDependencySucceeds() {
    SecurityTask first = task(1L, "SUCCESS", "root");
    SecurityTask second = task(2L, "SUCCESS", "sibling");
    SecurityTask blocked = task(3L, "BLOCKED", "child");
    blocked.setDependencyTaskIds("[1,2]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(blocked), List.of());
    when(tasks.findAllById(List.of(1L, 2L))).thenReturn(List.of(first, second));

    scheduler.drainBlockedTasks();

    assertThat(blocked.getStatus()).isEqualTo("PENDING");
    verify(projects).validateProjectTarget(7L, 9L);
    verify(targets).getCurrentlyAuthorized(9L, 7L);
    verify(execution).executeAsync(3L);
  }

  @Test
  void skipsSuccessorWhenAnyDependencyFails() {
    SecurityTask failed = task(1L, "FAILED", "root");
    SecurityTask blocked = task(2L, "BLOCKED", "child");
    blocked.setDependencyTaskIds("[1]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(blocked), List.of());
    when(tasks.findAllById(List.of(1L))).thenReturn(List.of(failed));

    scheduler.drainBlockedTasks();

    assertThat(blocked.getStatus()).isEqualTo("SKIPPED");
    assertThat(blocked.getTerminationReason()).isEqualTo("PREREQUISITE_NOT_COMPLETED");
    verify(execution, never()).executeAsync(2L);
    verify(events).publishEvent(new TaskTerminalEvent(2L));
  }

  @Test
  void doesNotActivateSuccessorWhenWorkflowIsStopping() {
    SecurityTask first = task(1L, "SUCCESS", "root");
    SecurityTask blocked = task(2L, "BLOCKED", "child");
    blocked.setWorkflowRunId(42L);
    blocked.setDependencyTaskIds("[1]");
    WorkflowRun run = new WorkflowRun();
    run.setId(42L);
    run.setStatus("STOPPING");
    when(runs.findById(42L)).thenReturn(Optional.of(run));
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(blocked), List.of());
    when(tasks.findAllById(List.of(1L))).thenReturn(List.of(first));

    scheduler.drainBlockedTasks();

    assertThat(blocked.getStatus()).isEqualTo("CANCELLED");
    assertThat(blocked.getTerminationReason()).isEqualTo("WORKFLOW_STOPPED");
    verify(execution, never()).executeAsync(2L);
  }

  @Test
  void independentSerialBarrierFailureDoesNotSkipNextBranch() {
    SecurityTask failedBarrier = task(1L, "FAILED", "independent-caution");
    SecurityTask blocked = task(2L, "BLOCKED", "next-branch");
    blocked.setDependencyTaskIds("[1]");
    blocked.setSuccessDependencyTaskIds("[]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(blocked), List.of());
    when(tasks.findAllById(List.of(1L))).thenReturn(List.of(failedBarrier));

    scheduler.drainBlockedTasks();

    assertThat(blocked.getStatus()).isEqualTo("PENDING");
    verify(execution).executeAsync(2L);
  }

  @Test
  void graphJoinStillRequiresEveryBranchSuccessWithSeparateSerialBarrier() {
    SecurityTask good = task(1L, "SUCCESS", "branch-a");
    SecurityTask failed = task(2L, "FAILED", "branch-b");
    SecurityTask barrier = task(3L, "SUCCESS", "independent-barrier");
    SecurityTask join = task(4L, "BLOCKED", "join");
    join.setDependencyTaskIds("[1,2,3]");
    join.setSuccessDependencyTaskIds("[1,2]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(join), List.of());
    when(tasks.findAllById(List.of(1L, 2L, 3L))).thenReturn(List.of(good, failed, barrier));

    scheduler.drainBlockedTasks();

    assertThat(join.getStatus()).isEqualTo("SKIPPED");
    verify(execution, never()).executeAsync(4L);
  }

  @Test
  void runningSerialBarrierStillPreventsParallelActivation() {
    SecurityTask running = task(1L, "RUNNING", "barrier");
    SecurityTask blocked = task(2L, "BLOCKED", "next-branch");
    blocked.setDependencyTaskIds("[1]");
    blocked.setSuccessDependencyTaskIds("[]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED")).thenReturn(List.of(blocked));
    when(tasks.findAllById(List.of(1L))).thenReturn(List.of(running));

    scheduler.drainBlockedTasks();

    assertThat(blocked.getStatus()).isEqualTo("BLOCKED");
    verify(execution, never()).executeAsync(2L);
  }

  @Test
  void joinWithSuccessfulGraphParentsMayProceedAfterIndependentBarrierFails() {
    SecurityTask parent = task(1L, "SUCCESS", "parent");
    SecurityTask barrier = task(2L, "TIMEOUT", "independent-barrier");
    SecurityTask child = task(3L, "BLOCKED", "child");
    child.setDependencyTaskIds("[1,2]");
    child.setSuccessDependencyTaskIds("[1]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(child), List.of());
    when(tasks.findAllById(List.of(1L, 2L))).thenReturn(List.of(parent, barrier));

    scheduler.drainBlockedTasks();

    assertThat(child.getStatus()).isEqualTo("PENDING");
    verify(execution).executeAsync(3L);
  }

  @ParameterizedTest
  @ValueSource(strings = {"null", "[null]", "[0]", "{}"})
  void malformedPersistedGraphDependenciesFailClosedInsteadOfBreakingTheDrain(String json) {
    SecurityTask parent = task(1L, "SUCCESS", "parent");
    SecurityTask child = task(2L, "BLOCKED", "child");
    child.setDependencyTaskIds("[1]");
    child.setSuccessDependencyTaskIds(json);
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED"))
        .thenReturn(List.of(child), List.of());
    when(tasks.findAllById(List.of(1L))).thenReturn(List.of(parent));

    scheduler.drainBlockedTasks();

    assertThat(child.getStatus()).isEqualTo("SKIPPED");
    assertThat(child.getTerminationReason()).isEqualTo("MISSING_DEPENDENCY");
    verify(execution, never()).executeAsync(2L);
  }

  @Test
  void runsBackgroundDependencyChecksWithSystemAccess() throws Exception {
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    when(authorization.callWithSystemAccess(any(Callable.class)))
        .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED")).thenReturn(List.of());
    WorkflowTaskDependencyScheduler backgroundScheduler =
        new WorkflowTaskDependencyScheduler(
            tasks,
            execution,
            projects,
            targets,
            authorization,
            progress,
            audit,
            new ObjectMapper(),
            runs,
            events);

    backgroundScheduler.drainBlockedTasks();

    verify(authorization).callWithSystemAccess(any(Callable.class));
  }

  @Test
  void cancellationCommittedDuringAuthorizationCannotBeOverwrittenByActivation() {
    SecurityTask first = task(1L, "SUCCESS", "root");
    SecurityTask blocked = task(2L, "BLOCKED", "child");
    blocked.setDependencyTaskIds("[1]");
    when(tasks.findAllByStatusOrderByCreatedAtAsc("BLOCKED")).thenReturn(List.of(blocked));
    when(tasks.findAllById(List.of(1L))).thenReturn(List.of(first));
    when(tasks.activateBlockedWorkflowTask(anyLong(), anyString(), any())).thenReturn(0);

    scheduler.drainBlockedTasks();

    verify(execution, never()).executeAsync(2L);
    verify(tasks, never()).save(any());
  }

  private SecurityTask task(Long id, String status, String nodeId) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setProjectId(7L);
    task.setTargetId(9L);
    task.setToolCode("http_headers");
    task.setWorkflowNodeId(nodeId);
    task.setStatus(status);
    task.setProgress(0);
    return task;
  }
}
