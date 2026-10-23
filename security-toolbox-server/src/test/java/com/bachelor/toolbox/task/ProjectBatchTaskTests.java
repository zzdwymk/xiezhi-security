package com.bachelor.toolbox.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** 覆盖“直接按授权项目对项目内目标批量执行”的核心路径。 */
class ProjectBatchTaskTests {
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
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    when(projectService.validateProjectExecution(1L)).thenReturn(project);
    when(registry.require(any())).thenReturn(mock(SecurityTool.class));
    when(repository.save(any(SecurityTask.class)))
        .thenAnswer(
            invocation -> {
              SecurityTask saved = invocation.getArgument(0);
              if (saved.getId() == null) saved.setId(100L + System.nanoTime() % 1000);
              return saved;
            });
    when(repository.countByTargetIdAndStatusIn(anyLong(), any())).thenReturn(0L);
  }

  private AuthorizedTarget target(long id, String name) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(id);
    target.setName(name);
    return target;
  }

  @Test
  void createsOneTaskForEveryProjectTargetWhenTargetIdsAreEmpty() throws Exception {
    when(projectService.targets(1L))
        .thenReturn(List.of(new ProjectTarget(1L, 11L), new ProjectTarget(1L, 12L)));
    when(targetService.get(11L)).thenReturn(target(11L, "甲"));
    when(targetService.get(12L)).thenReturn(target(12L, "乙"));
    when(targetService.getCurrentlyAuthorized(any(), any())).thenReturn(target(11L, "甲"));

    ProjectBatchTaskResult result =
        service.createBatchForProject(
            new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of("ports", "80"), null));

    assertEquals(2, result.total());
    assertEquals(2, result.succeeded());
    assertEquals(0, result.failed());
    assertEquals("CREATED", result.items().get(0).status());
    assertEquals("甲", result.items().get(0).targetName());
    assertTrue(result.items().get(0).taskId() != null);
    verify(projectService).validateProjectTarget(1L, 11L);
    verify(projectService).validateProjectTarget(1L, 12L);
  }

  @Test
  void onlyExecutesRequestedSubsetOfTargets() {
    when(projectService.targets(1L))
        .thenReturn(List.of(new ProjectTarget(1L, 11L), new ProjectTarget(1L, 12L)));
    when(targetService.get(12L)).thenReturn(target(12L, "乙"));
    when(targetService.getCurrentlyAuthorized(any(), any())).thenReturn(target(12L, "乙"));

    ProjectBatchTaskResult result =
        service.createBatchForProject(
            new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), List.of(12L)));

    assertEquals(1, result.total());
    assertEquals(1, result.succeeded());
    verify(projectService, never()).validateProjectTarget(1L, 11L);
    verify(projectService).validateProjectTarget(1L, 12L);
  }

  @Test
  void rejectsSubsetTargetOutsideProject() {
    when(projectService.targets(1L)).thenReturn(List.of(new ProjectTarget(1L, 11L)));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                service.createBatchForProject(
                    new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), List.of(99L))));

    assertTrue(error.getMessage().contains("不属于该评估项目"));
    verify(repository, never()).save(any());
  }

  @Test
  void reportsPerTargetFailureAndContinuesForOthers() {
    when(projectService.targets(1L))
        .thenReturn(List.of(new ProjectTarget(1L, 11L), new ProjectTarget(1L, 12L)));
    when(targetService.get(11L)).thenReturn(target(11L, "甲"));
    when(targetService.get(12L)).thenReturn(target(12L, "乙"));
    when(targetService.getCurrentlyAuthorized(any(), any())).thenReturn(target(11L, "甲"));
    // 目标 11 授权校验失败，目标 12 继续执行。
    doThrow(new ApiException("目标不属于该评估项目"))
        .when(projectService)
        .validateProjectTarget(1L, 11L);

    ProjectBatchTaskResult result =
        service.createBatchForProject(
            new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), null));

    assertEquals(2, result.total());
    assertEquals(1, result.succeeded());
    assertEquals(1, result.failed());
    assertEquals("FAILED", result.items().get(0).status());
    assertEquals("目标不属于该评估项目", result.items().get(0).message());
    assertEquals("CREATED", result.items().get(1).status());
  }

  @Test
  void skipsTargetWhoseActiveTaskQuotaIsExhausted() {
    when(projectService.targets(1L))
        .thenReturn(List.of(new ProjectTarget(1L, 11L), new ProjectTarget(1L, 12L)));
    when(targetService.get(11L)).thenReturn(target(11L, "甲"));
    when(targetService.get(12L)).thenReturn(target(12L, "乙"));
    when(targetService.getCurrentlyAuthorized(any(), any())).thenReturn(target(12L, "乙"));
    when(repository.countByTargetIdAndStatusIn(11L, List.of("BLOCKED", "PENDING", "RUNNING")))
        .thenReturn(4L);
    when(repository.countByTargetIdAndStatusIn(12L, List.of("BLOCKED", "PENDING", "RUNNING")))
        .thenReturn(0L);

    ProjectBatchTaskResult result =
        service.createBatchForProject(
            new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), null));

    assertEquals(2, result.total());
    assertEquals(1, result.succeeded());
    assertEquals(1, result.failed());
    assertTrue(result.items().get(0).message().contains("配额不足"));
    verify(projectService, never()).validateProjectTarget(1L, 11L);
    verify(projectService).validateProjectTarget(1L, 12L);
  }

  @Test
  void rejectsWholeBatchWhenProjectIsNotActive() {
    when(projectService.validateProjectExecution(1L))
        .thenThrow(new ApiException("项目未处于进行中状态"));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                service.createBatchForProject(
                    new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), null)));

    assertEquals("项目未处于进行中状态", error.getMessage());
    verify(projectService, never()).targets(anyLong());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsEmptyProject() {    when(projectService.targets(1L)).thenReturn(List.of());

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                service.createBatchForProject(
                    new ProjectBatchTaskRequest(1L, "tcp_ports", Map.of(), null)));

    assertTrue(error.getMessage().contains("没有可执行的授权目标"));
  }
}
