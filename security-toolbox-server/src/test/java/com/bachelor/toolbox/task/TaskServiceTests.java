package com.bachelor.toolbox.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
