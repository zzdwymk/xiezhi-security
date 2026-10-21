package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class AiAuthorizationGuardTests {
  @Test
  void previewDoesNotRequireCurrentAuthorizationWindow() {
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    TargetService targets = mock(TargetService.class);
    AiTaskDispatchService dispatcher = mock(AiTaskDispatchService.class);
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    AiAuthorizationGuard guard =
        new AiAuthorizationGuard(projects, targets, dispatcher, tasks, 20, 4);

    AiPlanResponse proposed = plan();
    when(dispatcher.prepare(any(), any())).thenReturn(proposed);
    AiAgentRequest request = request(false);

    AiAuthorizationGuard.GuardDecision decision = guard.evaluate(request, proposed);

    assertThat(decision.status()).isEqualTo("AWAITING_APPROVAL");
    assertThat(decision.approvalStatus()).isEqualTo("REQUIRED");
    assertThat(decision.reason()).contains("确认执行时").contains("授权有效期");
    verify(projects).validateProjectTargetMembership(7L, 9L);
    verify(projects, never()).validateProjectTarget(7L, 9L);
    verify(targets, never()).getCurrentlyAuthorized(9L);
  }

  @Test
  void confirmedExecutionRequiresCurrentAuthorizationWindow() {
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    TargetService targets = mock(TargetService.class);
    AiTaskDispatchService dispatcher = mock(AiTaskDispatchService.class);
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    AiAuthorizationGuard guard =
        new AiAuthorizationGuard(projects, targets, dispatcher, tasks, 20, 4);

    AiPlanResponse proposed = plan();
    when(dispatcher.prepare(any(), any())).thenReturn(proposed);
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(null);

    AiAuthorizationGuard.GuardDecision decision = guard.evaluate(request(true), proposed);

    assertThat(decision.mayExecute()).isTrue();
    assertThat(decision.status()).isEqualTo("ALLOWED");
    assertThat(decision.approvalStatus()).isEqualTo("CONFIRMED_BY_REQUEST");
    verify(projects).validateProjectTarget(7L, 9L);
    verify(targets).getCurrentlyAuthorized(9L);
  }

  @Test
  void sixStepApprovedPlanExceedsDefaultTargetQuotaWithoutAnyExistingTasks() {
    QuotaFixture fixture = quotaFixture(20, 4, 0, 0, plan(6));

    assertThatThrownBy(() -> fixture.guard().evaluateApproved(request(true), fixture.plan()))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标 AI 计划超出任务配额（本次 6 项，上限 4 项），请拆分方案后重新确认");
    verifyCountQueriesOnly(fixture.tasks());
  }

  @Test
  void fourStepApprovedPlanFitsDefaultTargetQuotaExactly() {
    QuotaFixture fixture = quotaFixture(20, 4, 0, 0, plan(4));

    AiAuthorizationGuard.GuardDecision decision =
        fixture.guard().evaluateApproved(request(true), fixture.plan());

    assertThat(decision.mayExecute()).isTrue();
    assertThat(decision.activeProjectTasks()).isZero();
    assertThat(decision.activeTargetTasks()).isZero();
    verifyCountQueriesOnly(fixture.tasks());
  }

  @Test
  void existingTargetTasksProduceTemporaryQuotaRefusalWithCounts() {
    QuotaFixture fixture = quotaFixture(20, 4, 3, 3, plan(2));

    assertThatThrownBy(() -> fixture.guard().evaluateApproved(request(true), fixture.plan()))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标 AI 任务配额不足（本次 2 项，未结束 3 项，上限 4 项），请等待现有任务完成后重试");
    verifyCountQueriesOnly(fixture.tasks());
  }

  @Test
  void targetPlanOversizeTakesPrecedenceOverTemporaryProjectOccupancy() {
    QuotaFixture fixture = quotaFixture(20, 4, 18, 0, plan(6));

    assertThatThrownBy(() -> fixture.guard().evaluateApproved(request(true), fixture.plan()))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标 AI 计划超出任务配额（本次 6 项，上限 4 项），请拆分方案后重新确认");
  }

  @Test
  void planLargerThanProjectQuotaRequiresSplittingEvenWhenProjectIsEmpty() {
    QuotaFixture fixture = quotaFixture(3, 8, 0, 0, plan(4));

    assertThatThrownBy(() -> fixture.guard().evaluateApproved(request(true), fixture.plan()))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目 AI 计划超出任务配额（本次 4 项，上限 3 项），请拆分方案后重新确认");
  }

  @Test
  void projectOccupancyProducesTemporaryRefusalBeforeTargetOccupancy() {
    QuotaFixture fixture = quotaFixture(20, 4, 19, 3, plan(2));

    assertThatThrownBy(() -> fixture.guard().evaluateApproved(request(true), fixture.plan()))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目 AI 任务配额不足（本次 2 项，未结束 19 项，上限 20 项），请等待现有任务完成后重试");
  }

  @Test
  void occupiedProjectAndTargetQuotasAllowTheirExactRemainingCapacity() {
    QuotaFixture fixture = quotaFixture(20, 4, 18, 2, plan(2));

    AiAuthorizationGuard.GuardDecision decision =
        fixture.guard().evaluateApproved(request(true), fixture.plan());

    assertThat(decision.mayExecute()).isTrue();
    assertThat(decision.activeProjectTasks()).isEqualTo(18);
    assertThat(decision.activeTargetTasks()).isEqualTo(2);
  }

  @Test
  void oversizedPreviewRemainsReviewableButCannotAuthorizeExecution() {
    QuotaFixture fixture = quotaFixture(20, 4, 0, 0, plan(6));

    AiAuthorizationGuard.GuardDecision decision =
        fixture.guard().evaluate(request(false), fixture.plan());

    assertThat(decision.status()).isEqualTo("AWAITING_APPROVAL");
    assertThat(decision.approvalStatus()).isEqualTo("REQUIRED");
    assertThat(decision.mayExecute()).isFalse();
    assertThat(decision.normalizedPlan().steps()).hasSize(6);
    verify(fixture.projects(), never()).validateProjectTarget(7L, 9L);
    verify(fixture.targets(), never()).getCurrentlyAuthorized(9L);
  }

  @Test
  void administratorApprovalDoesNotBypassQuotaForStepsRequiringApproval() {
    AiPlanResponse safe = plan(6);
    AiPlanResponse approvalRequired = new AiPlanResponse(
        safe.provider(), safe.model(), safe.summary(), true,
        safe.steps().stream().map(step -> new AiPlanResponse.PlanStep(
            step.toolCode(), step.title(), step.reason(), step.parameters(), null,
            0, List.of(), "SAFE", true, List.of())).toList());
    QuotaFixture fixture = quotaFixture(20, 4, 0, 0, approvalRequired);

    assertThat(fixture.guard().evaluate(request(true), approvalRequired).mayExecute()).isFalse();
    assertThatThrownBy(() -> fixture.guard().evaluateApproved(request(true), approvalRequired))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标 AI 计划超出任务配额（本次 6 项，上限 4 项），请拆分方案后重新确认");
  }

  @Test
  void directConfirmedExecutionEnforcesTheSameTargetQuotaAsApprovedExecution() {
    QuotaFixture fixture = quotaFixture(20, 4, 0, 0, plan(6));

    assertThatThrownBy(() -> fixture.guard().evaluate(request(true), fixture.plan()))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标 AI 计划超出任务配额（本次 6 项，上限 4 项），请拆分方案后重新确认");
  }

  private record QuotaFixture(AiAuthorizationGuard guard, AssessmentProjectService projects,
      TargetService targets, SecurityTaskRepository tasks, AiPlanResponse plan) {}

  private QuotaFixture quotaFixture(int projectLimit, int targetLimit, long activeProject,
      long activeTarget, AiPlanResponse proposed) {
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    TargetService targets = mock(TargetService.class);
    AiTaskDispatchService dispatcher = mock(AiTaskDispatchService.class);
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    when(dispatcher.prepare(any(), any())).thenReturn(proposed);
    when(tasks.countByProjectIdAndStatusIn(7L, List.of("BLOCKED", "PENDING", "RUNNING")))
        .thenReturn(activeProject);
    when(tasks.countByTargetIdAndStatusIn(9L, List.of("BLOCKED", "PENDING", "RUNNING")))
        .thenReturn(activeTarget);
    return new QuotaFixture(new AiAuthorizationGuard(
        projects, targets, dispatcher, tasks, projectLimit, targetLimit),
        projects, targets, tasks, proposed);
  }

  /**
   * A continuation round re-evaluates a finished batch and may propose the next step. It never
   * asks to execute ({@code execute=false}), so its proposal must land in the approval queue
   * rather than being dropped as "just a preview" or auto-run. This pins that contract: the
   * loop keeps turning only because each new proposal reaches an administrator.
   */
  @Test
  void continuationProposalEntersApprovalQueueInsteadOfExecuting() {
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    TargetService targets = mock(TargetService.class);
    AiTaskDispatchService dispatcher = mock(AiTaskDispatchService.class);
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    AiAuthorizationGuard guard =
        new AiAuthorizationGuard(projects, targets, dispatcher, tasks, 20, 4);

    AiPlanResponse proposed = plan();
    when(dispatcher.prepare(any(), any())).thenReturn(proposed);
    // A continuation carries execute=false and a non-AUTO intent, so it is a preview.
    AiAgentRequest request =
        new AiAgentRequest(
            7L, 9L, "continuation-session", "读取结果后继续验证", false, null, List.of(),
            "review", "resume-turn");
    assertThat(request.automaticExecutionIntent()).isFalse();
    assertThat(request.executionRequested()).isFalse();

    AiAuthorizationGuard.GuardDecision decision = guard.evaluate(request, proposed);

    assertThat(decision.status()).isEqualTo("AWAITING_APPROVAL");
    assertThat(decision.approvalStatus()).isEqualTo("REQUIRED");
    assertThat(decision.mayExecute()).isFalse();
    assertThat(decision.normalizedPlan().steps()).hasSize(1);
  }

  private void verifyCountQueriesOnly(SecurityTaskRepository tasks) {
    verify(tasks).countByProjectIdAndStatusIn(7L, List.of("BLOCKED", "PENDING", "RUNNING"));
    verify(tasks).countByTargetIdAndStatusIn(9L, List.of("BLOCKED", "PENDING", "RUNNING"));
    verifyNoMoreInteractions(tasks);
  }

  private AiAgentRequest request(boolean execute) {
    return new AiAgentRequest(
        7L,
        9L,
        "guard-test",
        "请扫描端口",
        execute,
        null,
        List.of(),
        "standard",
        "turn-guard-test");
  }

  private AiPlanResponse plan() {
    return new AiPlanResponse(
        "test",
        "test-model",
        "端口检查计划",
        true,
        List.of(
            new AiPlanResponse.PlanStep("tcp_ports", "授权端口探测", "验证授权端口", Map.of("ports", "80"))));
  }

  private AiPlanResponse plan(int count) {
    List<String> toolCodes = List.of("tcp_ports", "nmap_service_scan", "http_headers",
        "site_crawl", "dir_scan", "http_security_check");
    return new AiPlanResponse("test", "test-model", "quota-test", true,
        IntStream.range(0, count).mapToObj(index -> new AiPlanResponse.PlanStep(
            toolCodes.get(index), toolCodes.get(index), "quota-test", Map.of())).toList());
  }
}
