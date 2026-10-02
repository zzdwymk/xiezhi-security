package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

class TaskExecutionServiceTests {
  @ParameterizedTest
  @CsvSource(
      value = {
        "数据库连接失败：jdbc:secret|FAILED|FAILED|任务执行失败，请稍后重试|任务执行失败",
        "外部工具执行超时：token=secret|TIMEOUT|TIMEOUT|任务执行超时，请稍后重试|任务执行超时",
        "HTTP connect timed out: token=secret|TIMEOUT|TIMEOUT|任务执行超时，请稍后重试|任务执行超时",
        "Wrapped MSF deadline: token=secret|TIMEOUT|TIMEOUT|任务执行超时，请稍后重试|任务执行超时",
        "请求端口超出授权目标的允许端口范围|FAILED|FAILED|任务执行失败，请稍后重试|任务执行失败",
        "授权快照不一致：hash=secret|FAILED|AUTHORIZATION_CHANGED|任务授权状态已变更，请重新确认授权后再试|任务授权状态已变更"
      },
      delimiter = '|')
  void hidesInternalFailureAcrossTaskAndAuditOutputs(
      String internalMessage,
      String expectedStatus,
      String expectedTerminationReason,
      String expectedErrorMessage,
      String expectedProgressMessage)
      throws Exception {
    SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
    FindingRepository findingRepository = mock(FindingRepository.class);
    TargetService targetService = mock(TargetService.class);
    AssessmentProjectService projectService = mock(AssessmentProjectService.class);
    SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
    AuditService auditService = mock(AuditService.class);
    TaskSnapshotService snapshotService = mock(TaskSnapshotService.class);
    TaskProgressEventService progressEvents = mock(TaskProgressEventService.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    TaskExecutionControlService executionControl = new TaskExecutionControlService(1, 1);
    when(authorization.callWithSystemAccess(any(Callable.class)))
        .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());

    SecurityTask task = task();
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("https://example.test");
    SecurityTool tool = mock(SecurityTool.class);

    when(taskRepository.findById(42L)).thenReturn(Optional.of(task));
    when(targetService.getCurrentlyAuthorized(7L)).thenReturn(target);
    when(registry.require("TEST_TOOL")).thenReturn(tool);
    when(tool.code()).thenReturn("TEST_TOOL");
    if ("AUTHORIZATION_CHANGED".equals(expectedTerminationReason)) {
      doThrow(new TaskAuthorizationChangedException(internalMessage))
          .when(snapshotService)
          .assertCurrentMatches(
              any(SecurityTask.class), any(AuthorizedTarget.class), any(SecurityTool.class));
    } else if (internalMessage.startsWith("HTTP connect timed out")) {
      when(tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
          .thenThrow(new IllegalStateException("tool failed", new java.net.http.HttpConnectTimeoutException(internalMessage)));
    } else if (internalMessage.startsWith("Wrapped MSF deadline")) {
      ApiException failure = new ApiException("Metasploit 模块未完成");
      failure.initCause(new TimeoutException(internalMessage));
      when(tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
          .thenThrow(failure);
    } else {
      when(tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
          .thenThrow(new IllegalStateException(internalMessage));
    }

    TaskExecutionService service =
        new TaskExecutionService(
            taskRepository,
            findingRepository,
            targetService,
            projectService,
            registry,
            auditService,
            new ObjectMapper(),
            snapshotService,
            executionControl,
            progressEvents,
            authorization);

    service.executeAsync(42L);

    assertThat(task.getStatus()).isEqualTo(expectedStatus);
    assertThat(task.getTerminationReason()).isEqualTo(expectedTerminationReason);
    assertThat(task.getErrorMessage()).isEqualTo(expectedErrorMessage);
    assertThat(task.getProgressMessage()).isEqualTo(expectedProgressMessage);
    assertThat(task.getFinishedAt()).isNotNull();
    if ("TIMEOUT".equals(expectedStatus)) assertThat(task.getTimeoutAt()).isNotNull();
    assertThat(task.getExecutionLog())
        .contains("执行失败：" + expectedErrorMessage)
        .doesNotContain(internalMessage)
        .doesNotContain("secret");

    ArgumentCaptor<String> auditDetail = ArgumentCaptor.forClass(String.class);
    verify(auditService)
        .record(
            eq("EXECUTE_TOOL"),
            eq("TASK"),
            eq(42L),
            auditDetail.capture(),
            eq("FAILED"),
            eq(42L),
            eq("authorization-hash"));
    verify(projectService).validateProjectTarget(1L, 7L);
    verify(authorization).callWithSystemAccess(any(Callable.class));
    assertThat(auditDetail.getValue())
        .isEqualTo(expectedErrorMessage)
        .doesNotContain(internalMessage)
        .doesNotContain("secret");
  }

  @Test
  void userCancellationWinsOverWrappedModuleTimeoutAndCannotPublishSuccess() throws Exception {
    SecurityTaskRepository repository = mock(SecurityTaskRepository.class);
    FindingRepository findings = mock(FindingRepository.class);
    TargetService targets = mock(TargetService.class);
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
    AuditService audit = mock(AuditService.class);
    TaskSnapshotService snapshots = mock(TaskSnapshotService.class);
    TaskProgressEventService progress = mock(TaskProgressEventService.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    TaskExecutionControlService control = new TaskExecutionControlService(1, 1);
    when(authorization.callWithSystemAccess(any(Callable.class)))
        .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());
    SecurityTask task = task();
    task.setToolCode("msf_scan");
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("https://example.test");
    SecurityTool tool = mock(SecurityTool.class);
    when(repository.findById(42L)).thenReturn(Optional.of(task));
    when(targets.getCurrentlyAuthorized(7L)).thenReturn(target);
    when(registry.require("msf_scan")).thenReturn(tool);
    when(tool.code()).thenReturn("msf_scan");
    when(tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
        .thenAnswer(invocation -> {
          control.requestCancellation(42L);
          ApiException failure = new ApiException("Metasploit 模块未完成");
          failure.initCause(new TimeoutException("private module detail"));
          throw failure;
        });

    new TaskExecutionService(repository, findings, targets, projects, registry, audit,
        new ObjectMapper(), snapshots, control, progress, authorization).executeAsync(42L);

    assertThat(task.getStatus()).isEqualTo("CANCELLED");
    assertThat(task.getTerminationReason()).isEqualTo("CANCELLED");
    assertThat(task.getProgressMessage()).isEqualTo("任务已由用户取消");
    assertThat(task.getFinishedAt()).isNotNull();
    assertThat(task.getTimeoutAt()).isNull();
    assertThat(task.getResultJson()).isNull();
    assertThat(task.getExecutionLog()).doesNotContain("private module detail");
    verifyNoInteractions(findings);
    verify(audit).record("EXECUTE_TOOL", "TASK", 42L, "msf_scan", "CANCELLED", 42L, "authorization-hash");
    assertThat(Thread.currentThread().isInterrupted()).isFalse();
  }

  private SecurityTask task() {
    SecurityTask task = new SecurityTask();
    task.setId(42L);
    task.setTargetId(7L);
    task.setProjectId(1L);
    task.setToolCode("TEST_TOOL");
    task.setStatus("PENDING");
    task.setRequestJson("{}");
    task.setAuthorizationSnapshotHash("authorization-hash");
    return task;
  }
}
