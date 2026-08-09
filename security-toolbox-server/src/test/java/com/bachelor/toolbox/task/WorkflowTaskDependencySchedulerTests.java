package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class WorkflowTaskDependencySchedulerTests {
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final TaskExecutionService execution = mock(TaskExecutionService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final TargetService targets = mock(TargetService.class);
  private final TaskProgressEventService progress = mock(TaskProgressEventService.class);
  private final AuditService audit = mock(AuditService.class);
  private final WorkflowTaskDependencyScheduler scheduler =
      new WorkflowTaskDependencyScheduler(
          tasks, execution, projects, targets, progress, audit, new ObjectMapper());

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
