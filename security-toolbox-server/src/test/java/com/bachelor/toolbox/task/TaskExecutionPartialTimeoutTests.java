package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.tool.ToolExecutionTimeoutException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TaskExecutionPartialTimeoutTests {
  @Test
  void timeoutRetainsStructuredFindingsAndResultWhilePublishingOnlyFailure() throws Exception {
    Fixture fixture = new Fixture();
    ToolExecutionResult partial = partialResult(List.of(observation()));
    fixture.toolTimesOut(partial);

    fixture.execute();

    fixture.assertTimedOut();
    JsonNode saved = fixture.mapper.readTree(fixture.task.getResultJson());
    assertThat(saved.path("data").path("partial").asBoolean()).isTrue();
    assertThat(saved.path("data").path("scanCompleted").asBoolean()).isFalse();
    assertThat(saved.path("data").path("terminationReason").asText()).isEqualTo("TIMEOUT");
    assertThat(saved.path("summary").asText()).contains("未完成");
    assertThat(saved.path("findings").get(0).path("evidence").asText())
        .isEqualTo("已读取的模板匹配：nuclei-fixture");
    assertThat(fixture.persistedFindings).singleElement().satisfies(finding -> {
      assertThat(finding.getTaskId()).isEqualTo(42L);
      assertThat(finding.getTargetId()).isEqualTo(7L);
      assertThat(finding.getSourceTool()).isEqualTo("nuclei_scan");
      assertThat(finding.getRuleCode()).isEqualTo("NUCLEI_SCAN");
      assertThat(finding.getVulnerabilityCode()).isEqualTo("CVE-TEST-001");
      assertThat(finding.getSecurityKey()).isEqualTo("example.test:443/path");
      assertThat(finding.getSeverity()).isEqualTo("HIGH");
      assertThat(finding.getEvidence()).isEqualTo("已读取的模板匹配：nuclei-fixture");
    });
    assertThat(fixture.task.getExecutionLog()).contains("扫描未完成，不能据此判断未发现风险");
    verify(fixture.projects).validateProjectTarget(1L, 7L);
    verify(fixture.targets).getCurrentlyAuthorized(7L);
    verify(fixture.snapshots).assertCurrentMatches(fixture.task, fixture.target, fixture.tool);
    verify(fixture.tool).execute(eq(fixture.target), eq(Map.of()), any(ToolExecutionObserver.class));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void incompleteRetestNeverChangesBaselineOrCountsAsSuccessfulPass(boolean hasFinding)
      throws Exception {
    Fixture fixture = new Fixture();
    Finding baseline = new Finding();
    baseline.setId(99L);
    baseline.setStatus("OPEN");
    baseline.setRetestCount(1);
    baseline.setVulnerabilityCode("CVE-TEST-001");
    baseline.setSourceTool("nuclei_scan");
    baseline.setRuleCode("NUCLEI_SCAN");
    baseline.setSecurityKey("example.test:443/path");
    fixture.task.setSourceFindingId(99L);
    when(fixture.findings.findById(99L)).thenReturn(Optional.of(baseline));
    when(fixture.findings.findAllByTaskIdOrderByCreatedAtAsc(42L))
        .thenAnswer(invocation -> fixture.persistedFindings);
    fixture.toolTimesOut(partialResult(hasFinding ? List.of(observation()) : List.of()));

    fixture.execute();

    fixture.assertTimedOut();
    assertThat(fixture.task.getResultJson()).isNotNull();
    assertThat(baseline.getStatus()).isEqualTo("OPEN");
    assertThat(baseline.getRetestCount()).isEqualTo(1);
    assertThat(baseline.isVerified()).isFalse();
    assertThat(baseline.getVerifiedAt()).isNull();
    assertThat(baseline.getVerifiedTaskId()).isNull();
    verify(fixture.findings, never()).findById(99L);
    verify(fixture.findings, never()).findAllByTaskIdOrderByCreatedAtAsc(42L);
    verify(fixture.findings, never()).save(baseline);
    assertThat(fixture.persistedFindings).hasSize(hasFinding ? 1 : 0);
  }

  @Test
  void cancellationBeforeTimeoutHandlingDiscardsPartialAndRemainsCancelled() throws Exception {
    Fixture fixture = new Fixture();
    when(fixture.tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
        .thenAnswer(invocation -> {
          fixture.control.requestCancellation(42L);
          throw new ToolExecutionTimeoutException("private timeout detail", partialResult(List.of(observation())));
        });

    fixture.execute();

    assertThat(fixture.task.getStatus()).isEqualTo("CANCELLED");
    assertThat(fixture.task.getTerminationReason()).isEqualTo("CANCELLED");
    assertThat(fixture.task.getTimeoutAt()).isNull();
    assertThat(fixture.task.getResultJson()).isNull();
    assertThat(fixture.task.getFinishedAt()).isNotNull();
    assertThat(fixture.savedStatuses).doesNotContain("SUCCESS", "TIMEOUT");
    verifyNoInteractions(fixture.findings);
    verify(fixture.audit).record("EXECUTE_TOOL", "TASK", 42L, "nuclei_scan", "CANCELLED", 42L, "authorization-hash");
    verifyNoMoreInteractions(fixture.audit);
    assertThat(Thread.currentThread().isInterrupted()).isFalse();
  }

  @Test
  void ordinaryTimeoutStillHasNoResultOrFindings() throws Exception {
    Fixture fixture = new Fixture();
    when(fixture.tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
        .thenThrow(new TimeoutException("private timeout detail"));

    fixture.execute();

    fixture.assertTimedOut();
    assertThat(fixture.task.getResultJson()).isNull();
    verifyNoInteractions(fixture.findings);
  }

  @Test
  void partialTimeoutDoesNotBypassCurrentProjectScope() throws Exception {
    Fixture fixture = new Fixture();
    doThrow(new ApiException("目标不属于此项目"))
        .when(fixture.projects).validateProjectTarget(1L, 7L);
    fixture.toolTimesOut(partialResult(List.of(observation())));

    fixture.execute();

    fixture.assertAuthorizationRejected();
    verifyNoInteractions(fixture.targets, fixture.registry, fixture.findings);
    verify(fixture.tool, never()).execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class));
  }

  @Test
  void partialTimeoutDoesNotBypassExpiredTargetAuthorization() throws Exception {
    Fixture fixture = new Fixture();
    when(fixture.targets.getCurrentlyAuthorized(7L)).thenThrow(new ApiException("授权已过期"));
    fixture.toolTimesOut(partialResult(List.of(observation())));

    fixture.execute();

    fixture.assertAuthorizationRejected();
    verifyNoInteractions(fixture.registry, fixture.findings);
    verify(fixture.tool, never()).execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class));
  }

  @Test
  void partialTimeoutDoesNotBypassSnapshotMismatch() throws Exception {
    Fixture fixture = new Fixture();
    doThrow(new TaskAuthorizationChangedException("授权快照不匹配"))
        .when(fixture.snapshots).assertCurrentMatches(fixture.task, fixture.target, fixture.tool);
    fixture.toolTimesOut(partialResult(List.of(observation())));

    fixture.execute();

    fixture.assertAuthorizationRejected();
    verifyNoInteractions(fixture.findings);
    verify(fixture.tool, never()).execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class));
  }

  @Test
  void persistenceFailureCannotReplaceTimeoutWithSuccessOrOrdinaryFailure() throws Exception {
    Fixture fixture = new Fixture();
    ToolExecutionTimeoutException timeout = new ToolExecutionTimeoutException(
        "private timeout detail", partialResult(List.of(observation())));
    when(fixture.tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
        .thenThrow(timeout);
    IllegalStateException databaseFailure = new IllegalStateException("private database detail");
    doThrow(databaseFailure).when(fixture.findings).save(any(Finding.class));

    fixture.execute();

    fixture.assertTimedOut();
    assertThat(fixture.task.getResultJson()).isNotNull();
    assertThat(timeout.getSuppressed()).containsExactly(databaseFailure);
    assertThat(fixture.task.getExecutionLog()).doesNotContain("private database detail");
  }

  private static FindingDraft observation() {
    return new FindingDraft(
        "已观察到的模板命中", "HIGH", "超时前读取到的检测结果", "已读取的模板匹配：nuclei-fixture",
        "人工确认受影响入口", "CVE-TEST-001", "example.test:443/path");
  }

  private static ToolExecutionResult partialResult(List<FindingDraft> findings) {
    return new ToolExecutionResult(
        "扫描超时，检测未完成；保留已观察到的结果",
        Map.of("partial", true, "scanCompleted", false, "terminationReason", "TIMEOUT"), findings);
  }

  private static final class Fixture {
    final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    final FindingRepository findings = mock(FindingRepository.class);
    final TargetService targets = mock(TargetService.class);
    final AssessmentProjectService projects = mock(AssessmentProjectService.class);
    final SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
    final AuditService audit = mock(AuditService.class);
    final TaskSnapshotService snapshots = mock(TaskSnapshotService.class);
    final TaskProgressEventService progress = mock(TaskProgressEventService.class);
    final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    final TaskExecutionControlService control = new TaskExecutionControlService(1, 1);
    final ObjectMapper mapper = new ObjectMapper();
    final SecurityTask task = new SecurityTask();
    final AuthorizedTarget target = new AuthorizedTarget();
    final SecurityTool tool = mock(SecurityTool.class);
    final List<Finding> persistedFindings = new ArrayList<>();
    final List<String> savedStatuses = new ArrayList<>();

    Fixture() throws Exception {
      task.setId(42L);
      task.setTargetId(7L);
      task.setProjectId(1L);
      task.setToolCode("nuclei_scan");
      task.setRuleCode("NUCLEI_SCAN");
      task.setStatus("PENDING");
      task.setRequestJson("{}");
      task.setAuthorizationSnapshotHash("authorization-hash");
      target.setId(7L);
      target.setTargetValue("https://example.test");
      when(authorization.callWithSystemAccess(any(Callable.class)))
          .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());
      when(tasks.findById(42L)).thenReturn(Optional.of(task));
      when(tasks.save(any(SecurityTask.class))).thenAnswer(invocation -> {
        SecurityTask saved = invocation.getArgument(0);
        savedStatuses.add(saved.getStatus());
        return saved;
      });
      when(targets.getCurrentlyAuthorized(7L)).thenReturn(target);
      when(registry.require("nuclei_scan")).thenReturn(tool);
      when(tool.code()).thenReturn("nuclei_scan");
      when(findings.save(any(Finding.class))).thenAnswer(invocation -> {
        Finding saved = invocation.getArgument(0);
        persistedFindings.add(saved);
        return saved;
      });
    }

    void toolTimesOut(ToolExecutionResult result) throws Exception {
      when(tool.execute(any(AuthorizedTarget.class), anyMap(), any(ToolExecutionObserver.class)))
          .thenThrow(new ToolExecutionTimeoutException("private timeout detail", result));
    }

    void execute() {
      new TaskExecutionService(tasks, findings, targets, projects, registry, audit, mapper,
          snapshots, control, progress, authorization).executeAsync(42L);
    }

    void assertTimedOut() {
      assertThat(task.getStatus()).isEqualTo("TIMEOUT");
      assertThat(task.getTerminationReason()).isEqualTo("TIMEOUT");
      assertThat(task.getTimeoutAt()).isNotNull();
      assertThat(task.getFinishedAt()).isNotNull();
      assertThat(task.getProgress()).isLessThan(100);
      assertThat(task.getProgressMessage()).isEqualTo("任务执行超时");
      assertThat(task.getErrorMessage()).isEqualTo("任务执行超时，请稍后重试");
      assertThat(task.getExecutionLog()).doesNotContain("执行成功", "private timeout detail");
      assertThat(savedStatuses).contains("TIMEOUT").doesNotContain("SUCCESS");
      verify(audit).record("EXECUTE_TOOL", "TASK", 42L, "任务执行超时，请稍后重试", "FAILED", 42L, "authorization-hash");
      verifyNoMoreInteractions(audit);
    }

    void assertAuthorizationRejected() {
      assertThat(task.getStatus()).isEqualTo("FAILED");
      assertThat(task.getTerminationReason()).isEqualTo("AUTHORIZATION_CHANGED");
      assertThat(task.getTimeoutAt()).isNull();
      assertThat(task.getResultJson()).isNull();
      assertThat(savedStatuses).doesNotContain("SUCCESS", "TIMEOUT");
      verify(audit).record("EXECUTE_TOOL", "TASK", 42L,
          "任务授权状态已变更，请重新确认授权后再试", "FAILED", 42L, "authorization-hash");
      verifyNoMoreInteractions(audit);
    }
  }
}
