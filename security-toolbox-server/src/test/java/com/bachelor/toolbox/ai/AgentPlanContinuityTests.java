package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalService;
import com.bachelor.toolbox.settings.BusinessDataOperationGate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
class AgentPlanContinuityTests {
  @Test
  void missingOriginalPlanCannotBecomeAModelInventedContinuation() throws Exception {
    Fixture f = new Fixture();
    f.executionDecision.set("EXECUTE");
    f.relation.set("CONTINUE");
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.automatic("继续", "no-original")))
        .isInstanceOf(ApiException.class).hasMessageContaining("没有已交付的原方案");
    verifyNoInteractions(f.approvals);
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
  }
  @Test
  void semanticNewRequestAndRevisionDoNotNeedMagicWordsButContinuationStillPinsThePlan() throws Exception {
    Fixture f = new Fixture();
    f.run(false);
    f.executionDecision.set("EXECUTE");
    f.relation.set("REVISE");
    f.proposal.set(AiPlanContinuityServiceTests.plan("quick"));
    var revised = f.orchestrator.run(AiPlanContinuityServiceTests.automatic("换一种更轻量的方式", "semantic-revision"));
    assertThat(revised.approvalId()).isEqualTo(777L);
    assertThat(revised.plan().steps().get(0).parameters()).containsEntry("mode", "quick");
    assertThat(revised.taskIds()).isEmpty();
    f.relation.set("CONTINUE");
    f.proposal.set(AiPlanContinuityServiceTests.withDirectoryScan());
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.automatic("加上目录扫描", "mislabelled-continuation")))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
    verify(f.approvals, times(1)).requestAiPlan(any(), any(), any());
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
    verify(f.runtime, atLeastOnce()).withConversationState(argThat(state ->
        Boolean.TRUE.equals(state.get("planAvailable")) && state.get("latestPlan") != null
            && state.get("projectId").equals(5L) && state.get("targetId").equals(8L)));
  }

  @Test
  void continuedExplanationDoesNotRequestApprovalOrCreateAnAction() throws Exception {
    Fixture f = new Fixture();
    f.proposal.set(new AiPlanResponse("langchain-grounded", "model", "解释响应头的安全意义。", false, List.of()));
    f.orchestrator.run(AiPlanContinuityServiceTests.automatic("介绍HTTP响应头", "qa"));
    f.proposal.set(new AiPlanResponse("langchain-grounded", "model", "接着解释CSP的作用。", false, List.of()));
    var response = f.orchestrator.run(AiPlanContinuityServiceTests.automatic("继续", "continue-explanation"));
    assertThat(response.message()).contains("CSP");
    assertThat(response.plan().steps()).isEmpty();
    assertThat(response.approvalId()).isNull();
    verifyNoInteractions(f.approvals);
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
  }
  @ParameterizedTest
  @ValueSource(strings = {"继续", "接着来", "照这个来"})
  void naturalFollowUpRequestsApprovalForTheUnchangedLatestPlan(String current) throws Exception {
    Fixture f = new Fixture();
    f.run(false);
    f.executionDecision.set("EXECUTE");
    var response = f.orchestrator.run(AiPlanContinuityServiceTests.automatic(current, "continue-turn"));
    assertThat(response.approvalId()).isEqualTo(777L);
    assertThat(response.plan()).isEqualTo(f.proposal.get());
    assertThat(response.taskIds()).isEmpty();
    assertThat(f.base.memory.recentChatMessages("session").stream()
        .filter(message -> "user".equals(message.get("role"))).toList().get(1).get("content"))
        .isEqualTo(current).doesNotContain("历史和引用");
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void naturalContinueCannotAuthorizeModelDriftButAnExplicitNewToolRequestCan() throws Exception {
    Fixture f = new Fixture();
    f.run(false);
    f.executionDecision.set("EXECUTE");
    f.proposal.set(AiPlanContinuityServiceTests.withDirectoryScan());
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.automatic("继续", "continue-turn")))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
    verifyNoInteractions(f.approvals);
    var response = f.orchestrator.run(AiPlanContinuityServiceTests.automatic("目录也扫一下", "directory-turn"));
    assertThat(response.approvalId()).isEqualTo(777L);
    assertThat(response.plan().steps()).hasSize(2);
    assertThat(response.taskIds()).isEmpty();
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void automaticDirectoryScanRevisionCreatesANewApprovalAndNeverDispatchesOrMutatesOldPlan() throws Exception {
    Fixture f = new Fixture();
    var original = f.run(true);
    var oldPlan = original.plan();
    f.proposal.set(AiPlanContinuityServiceTests.withDirectoryScan());
    f.executionDecision.set("EXECUTE");
    var newTicket = new ProjectApproval(); newTicket.setId(778L);
    when(f.approvals.requestAiPlan(any(), any(), any())).thenReturn(newTicket);
    var events = new ArrayList<AiAgentEvent>();
    var revised = f.orchestrator.run(AiPlanContinuityServiceTests.automatic("加上目录扫描", "revision"), events::add);
    assertThat(revised.approvalId()).isEqualTo(778L).isNotEqualTo(original.approvalId());
    assertThat(revised.approvalStatus()).isEqualTo("REQUIRED");
    assertThat(revised.executed()).isFalse();
    assertThat(revised.taskIds()).isEmpty();
    assertThat(revised.plan().steps()).extracting(AiPlanResponse.PlanStep::toolCode)
        .containsExactly("nmap_service_scan", "dir_scan");
    assertThat(f.base.open().previous().plan()).isEqualTo(revised.plan());
    assertThat(oldPlan.steps()).hasSize(1);
    verify(f.runtime).plan(any(), contains("本轮用户原句明确要求修订方案"), any());
    verify(f.approvals).requestAiPlan(argThat(request -> "revision".equals(request.turnId())), eq(revised.plan()), any());
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
    assertThat(events).anySatisfy(event -> {
      assertThat(event.type()).isEqualTo("approval");
      assertThat(event.data()).containsEntry("approvalId", 778L);
    });
  }

  @Test
  void explicitPlanOnlyRevisionSavesLatestPlanWithoutApprovalAndLaterConfirmationRequestsIt() throws Exception {
    Fixture f = new Fixture();
    f.run(false);
    f.proposal.set(AiPlanContinuityServiceTests.withDirectoryScan());
    var preview = f.orchestrator.run(AiPlanContinuityServiceTests.automatic("先只修改方案，加上目录扫描，不要执行", "preview"));
    assertThat(preview.approvalId()).isNull();
    assertThat(preview.approvalStatus()).isEqualTo("NOT_REQUIRED");
    assertThat(preview.message()).contains("可在当前会话明确说明修改要求");
    assertThat(preview.plan().steps()).hasSize(2);
    verifyNoInteractions(f.approvals);
    f.executionDecision.set("EXECUTE");
    var confirmed = f.orchestrator.run(AiPlanContinuityServiceTests.automatic("确认执行", "confirm"));
    assertThat(confirmed.plan()).isEqualTo(preview.plan());
    assertThat(confirmed.approvalId()).isEqualTo(777L);
    assertThat(confirmed.taskIds()).isEmpty();
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void automaticConfirmationCannotSmuggleANewDirectoryScanViaModelOutput() throws Exception {
    Fixture f = new Fixture();
    f.run(false);
    f.proposal.set(AiPlanContinuityServiceTests.withDirectoryScan());
    f.executionDecision.set("EXECUTE");
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.automatic("确认执行", "confirm")))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
    verifyNoInteractions(f.approvals);
    assertThat(f.base.open().previous().plan().steps()).hasSize(1);
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void previousPlanIsServerContextAndChangedExecutionCannotCreateApproval() throws Exception {
    Fixture f = new Fixture();
    f.run(false);
    var original = f.base.open().previous();
    f.proposal.set(AiPlanContinuityServiceTests.plan("quick"));
    var events = new ArrayList<AiAgentEvent>();
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.request(true), events::add))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class)
        .hasMessageContaining("service").hasMessageContaining("quick").hasMessageContaining("重新规划");
    verify(f.runtime).plan(any(), contains("服务端已验证且已成功交付的上次结构化方案"), any());
    verifyNoInteractions(f.approvals);
    verify(f.tools, never()).executeAuthorizedPlan(any(), any());
    assertThat(f.base.open().previous()).isEqualTo(original);
    assertThat(events).anySatisfy(event -> {
      assertThat(event.type()).isEqualTo("error");
      assertThat(event.data()).containsEntry("code", "PLAN_CONTINUITY_MISMATCH")
          .containsEntry("executed", false).containsEntry("taskIds", List.of());
      assertThat(event.data().get("changes").toString()).contains("oldValue=\"service\"", "newValue=\"quick\"");
    });
    assertThat(events).noneMatch(event -> event.type().equals("done") || event.type().equals("approval"));
  }

  @Test
  void samePlanCreatesTicketWithConsistentResponseDoneAndMemoryDespiteModelClaims() {
    Fixture f = new Fixture();
    f.run(false);
    var events = new ArrayList<AiAgentEvent>();
    var response = f.orchestrator.run(AiPlanContinuityServiceTests.request(true), events::add);
    assertThat(response.approvalId()).isEqualTo(777L);
    assertThat(response.approvalStatus()).isEqualTo("REQUIRED");
    assertThat(response.message()).contains("等待管理员确认", "尚未创建检测任务", "nmap_service_scan", "service", "80,443")
        .doesNotContain("无需人工审批", "已经执行");
    assertThat(response.executed()).isFalse();
    assertThat(response.taskIds()).isEmpty();
    assertThat(events).anySatisfy(event -> {
      assertThat(event.type()).isEqualTo("done");
      assertThat(event.message()).isEqualTo(response.message());
    });
    assertThat(f.base.memory.recentChatMessages("session").stream().filter(m -> m.get("role").equals("assistant")))
        .allSatisfy(m -> assertThat(m.get("content")).contains("service", "80,443").doesNotContain("无需人工审批", "已经执行"));
    verify(f.approvals).requestAiPlan(any(), eq(f.proposal.get()), any());
  }

  @Test
  void firstEverExecuteStillCreatesOriginalApproval() {
    Fixture f = new Fixture();
    var response = f.run(true);
    assertThat(response.approvalId()).isEqualTo(777L);
    verify(f.approvals).requestAiPlan(any(), eq(f.proposal.get()), any());
  }

  @ParameterizedTest
  @ValueSource(strings = {"guard", "review", "audit", "done-sink"})
  void failedCandidateCannotOverwriteDeliveredBaseline(String failure) {
    Fixture f = new Fixture();
    f.run(false);
    var original = f.base.open().previous();
    f.proposal.set(AiPlanContinuityServiceTests.plan("quick"));
    if (failure.equals("guard")) doThrow(new ApiException("fixture guard error")).when(f.guard).evaluate(any(), any());
    if (failure.equals("review")) when(f.reviewer.review(anyLong(), anyLong(), anyList())).thenThrow(new ApiException("fixture review error"));
    if (failure.equals("audit")) doThrow(new ApiException("fixture audit error")).when(f.audit)
        .recordStructured(anyString(), anyString(), anyLong(), anyMap(), eq("SUCCESS"));
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.automatic(
        "先只修改方案，把识别模式改成quick，不要执行", "revision"), event -> {
      if (failure.equals("done-sink") && event.type().equals("done")) throw new ApiException("fixture disconnected sink");
    })).isInstanceOf(ApiException.class);
    assertThat(f.base.open().previous()).isEqualTo(original);
    verifyNoInteractions(f.approvals);
  }

  @Test
  void normalQuestionOrExplicitPlanOnlyCannotSilentlyChangeSameSessionBaseline() {
    Fixture f = new Fixture();
    f.run(false);
    f.proposal.set(AiPlanContinuityServiceTests.plan("quick"));
    assertThatThrownBy(() -> f.run(false)).isInstanceOf(AiPlanContinuityService.PlanChangedException.class)
        .hasMessageContaining("新建会话重新规划");
    assertThat(f.base.open().previous().plan().steps().get(0).parameters()).containsEntry("mode", "service");
    verifyNoInteractions(f.approvals);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void promotionWriteFailureKeepsOneSuccessTerminalAndBlocksFutureExecution(boolean hasPrevious,
      org.springframework.boot.test.system.CapturedOutput output) {
    var memory = spy(new AiConversationMemoryService(20, 20, 120));
    Fixture f = new Fixture(memory);
    if (hasPrevious) f.run(false);
    var previous = f.base.open().previous();
    f.proposal.set(AiPlanContinuityServiceTests.plan(hasPrevious ? "service" : "quick"));
    doThrow(new ApiException("fixture promotion disk write failed")).when(memory)
        .saveDeliveredPlan(eq("session"), contains("\"pending\":null"));
    var events = new ArrayList<AiAgentEvent>();
    var response = f.orchestrator.run(AiPlanContinuityServiceTests.request(false), events::add);
    assertThat(response.message()).contains(hasPrevious ? "service" : "quick");
    assertThat(events.stream().filter(event -> event.type().equals("done")).count()).isEqualTo(1);
    assertThat(events).noneMatch(event -> event.type().equals("error"));
    assertThat(output.getAll()).contains("AI_PLAN_DELIVERY_PERSISTENCE_FAILED", "pending snapshot blocks execution");
    assertThat(f.base.open().deliveryPending()).isTrue();
    assertThat(f.base.open().previous()).isEqualTo(previous);
    var rejected = new ArrayList<AiAgentEvent>();
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.request(true), rejected::add))
        .isInstanceOf(AiPlanContinuityService.PlanDeliveryPendingException.class).hasMessageContaining("重新规划");
    assertThat(rejected).anySatisfy(event -> assertThat(event.data()).containsEntry("code", "PLAN_DELIVERY_UNCONFIRMED"));
    verifyNoInteractions(f.approvals);
  }

  @Test
  void stagingWriteFailureHappensBeforeApprovalAndDoesNotEmitDone() {
    var memory = spy(new AiConversationMemoryService(20, 20, 120));
    Fixture f = new Fixture(memory);
    doThrow(new ApiException("fixture staging write failed")).when(memory)
        .saveDeliveredPlan(eq("session"), contains("\"pending\":{\"version\":1"));
    var events = new ArrayList<AiAgentEvent>();
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.request(true), events::add))
        .hasMessageContaining("fixture staging write failed");
    verifyNoInteractions(f.approvals);
    assertThat(events).noneMatch(event -> event.type().equals("done") || event.type().equals("approval"));
    assertThat(f.base.open().previous()).isNull();
  }

  @Test
  void explanationWithoutStepsDoesNotReplaceOrClearPendingBaseline() {
    Fixture f = new Fixture();
    f.run(false);
    var original = f.base.open().previous();
    f.base.service.stage(f.base.service.prepare(AiPlanContinuityServiceTests.request(false), "session",
        f.proposal.get(), f.base.open()));
    f.proposal.set(new AiPlanResponse("langchain-grounded", "model", "service表示服务识别", false, List.of()));
    assertThat(f.run(false).message()).contains("service表示服务识别");
    assertThat(f.base.open().previous()).isEqualTo(original);
    assertThat(f.base.open().deliveryPending()).isTrue();
    verifyNoInteractions(f.approvals);
  }

  @Test
  void informationalAuditFailureCannotEmitSuccessThenError() {
    Fixture f = new Fixture();
    f.proposal.set(new AiPlanResponse("langchain-grounded", "model", "service表示服务识别", false, List.of()));
    doThrow(new ApiException("fixture audit write failed")).when(f.audit)
        .recordStructured(anyString(), anyString(), anyLong(), anyMap(), eq("SUCCESS"));
    var events = new ArrayList<AiAgentEvent>();
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.request(false), events::add))
        .hasMessageContaining("fixture audit write failed");
    assertThat(events).noneMatch(event -> event.type().equals("done"));
    assertThat(events.stream().filter(event -> event.type().equals("error")).count()).isEqualTo(1);
  }

  static class Fixture {
    final AiPlanContinuityServiceTests.Fixture base;
    final SecurityAgentTools tools = mock(SecurityAgentTools.class);
    final AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    final AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    final AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    final ProjectApprovalService approvals = mock(ProjectApprovalService.class);
    final AuditService audit = mock(AuditService.class);
    final AtomicReference<AiPlanResponse> proposal = new AtomicReference<>(AiPlanContinuityServiceTests.plan("service"));
    final AtomicReference<String> executionDecision = new AtomicReference<>("PLAN_ONLY");
    final AtomicReference<String> relation = new AtomicReference<>("NONE");
    final AgentOrchestrator orchestrator;
    Fixture() { this(new AiConversationMemoryService(20, 20, 120)); }
    Fixture(AiConversationMemoryService memory) {
      base = new AiPlanContinuityServiceTests.Fixture(memory);
      when(tools.inspectProjectContext(5L, 8L)).thenReturn("Authorized 192.168.136.132 ports80,443");
      when(runtime.enabled()).thenReturn(true);
      when(runtime.plan(any(), anyString(), any())).thenAnswer(ignored ->
          new AiAgentRuntimeClient.RuntimePlanResult(proposal.get(), proposal.get().summary(),
              proposal.get().requiresConfirmation() ? "APPROVAL_REQUIRED" : "COMPLETED", "runtime-run",
              AiAgentRuntimeClient.POLICY_REVISION, 1,
              new AiAgentRuntimeClient.RuntimeProvenance(1, List.of("ev-a"), "sha256:" + "a".repeat(64),
                  "langchain-grounded", "EVIDENCE_FINALIZED"), executionDecision.get(), null, relation.get()));
      when(guard.evaluate(any(), any())).thenAnswer(invocation -> {
        var request = (AiAgentRequest) invocation.getArgument(0);
        var plan = (AiPlanResponse) invocation.getArgument(1);
        boolean needsApproval = plan.steps().stream().anyMatch(AiPlanResponse.PlanStep::requiresApproval);
        return new AiAuthorizationGuard.GuardDecision(request.executionRequested() ? "ALLOWED" : needsApproval ? "AWAITING_APPROVAL" : "PLAN_ONLY",
            request.executionRequested() ? "CONFIRMED_BY_REQUEST" : needsApproval ? "REQUIRED" : "NOT_REQUIRED", "guard checked",
            invocation.getArgument(1), 0, 0);
      });
      when(reviewer.review(5L, 8L, List.of())).thenReturn(new AiAgentResponse.AgentReview("NOT_REQUIRED", "no tasks", false, List.of()));
      var ticket = new ProjectApproval(); ticket.setId(777L);
      when(approvals.requestAiPlan(any(), any(), any())).thenReturn(ticket);
      orchestrator = new AgentOrchestrator(base.memory, tools, runtime, mock(AiProjectIndexService.class),
          mock(AiPlanningService.class), guard, reviewer, null, audit, new BusinessDataOperationGate(), approvals);
      orchestrator.setPlanContinuity(base.service);
    }
    AiAgentResponse run(boolean execute) { return orchestrator.run(AiPlanContinuityServiceTests.request(execute)); }
  }
}
