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
    f.proposal.set(AiPlanContinuityServiceTests.plan("service"));
    if (failure.equals("guard")) doThrow(new ApiException("fixture guard error")).when(f.guard).evaluate(any(), any());
    if (failure.equals("review")) when(f.reviewer.review(anyLong(), anyLong(), anyList())).thenThrow(new ApiException("fixture review error"));
    if (failure.equals("audit")) doThrow(new ApiException("fixture audit error")).when(f.audit)
        .recordStructured(anyString(), anyString(), anyLong(), anyMap(), eq("SUCCESS"));
    assertThatThrownBy(() -> f.orchestrator.run(AiPlanContinuityServiceTests.request(false), event -> {
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
    final AgentOrchestrator orchestrator;
    Fixture() { this(new AiConversationMemoryService(20, 20, 120)); }
    Fixture(AiConversationMemoryService memory) {
      base = new AiPlanContinuityServiceTests.Fixture(memory);
      when(tools.inspectProjectContext(5L, 8L)).thenReturn("Authorized 192.168.136.132 ports80,443");
      when(runtime.enabled()).thenReturn(true);
      when(runtime.plan(any(), anyString(), any())).thenAnswer(ignored ->
          new AiAgentRuntimeClient.RuntimePlanResult(proposal.get(), proposal.get().summary(), "COMPLETED", "runtime-run",
              AiAgentRuntimeClient.POLICY_REVISION, 1,
              new AiAgentRuntimeClient.RuntimeProvenance(1, List.of("ev-a"), "sha256:" + "a".repeat(64),
                  "langchain-grounded", "EVIDENCE_FINALIZED")));
      when(guard.evaluate(any(), any())).thenAnswer(invocation -> {
        var request = (AiAgentRequest) invocation.getArgument(0);
        return new AiAuthorizationGuard.GuardDecision(request.executionRequested() ? "ALLOWED" : "PLAN_ONLY",
            request.executionRequested() ? "CONFIRMED_BY_REQUEST" : "NOT_REQUIRED", "guard checked",
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
