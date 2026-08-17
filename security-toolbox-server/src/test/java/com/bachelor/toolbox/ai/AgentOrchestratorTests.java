package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AgentOrchestratorTests {
  @Test
  void directlyAnswersReferencedAuditWithoutProjectIndexOrPlan() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AiContextService context = mock(AiContextService.class);
    AuditService audit = mock(AuditService.class);
    when(context.answerAuditQuestion(anyLong(), anyLong(), any(), any(), anyString(), anyString()))
        .thenReturn(Optional.of("**结论**\n\n操作已正常处理。\n\n**进一步核查方向**\n\n- 核对任务结果"));

    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, context, audit);
    AiAgentRequest request =
        new AiAgentRequest(
            5L,
            8L,
            "audit-answer",
            "请结合这条审计日志判断是否符合预期",
            true,
            null,
            List.of(new AiPlanRequest.ContextRef("audit", 114L, 8L, "审计记录 #114")),
            "analyze",
            "turn-audit-answer");

    AiAgentResponse response = orchestrator.run(request);

    assertThat(response.executed()).isFalse();
    assertThat(response.message()).contains("结论", "进一步核查方向");
    verify(context).answerAuditQuestion(eq(5L), eq(8L), isNull(), anyList(), anyString(), eq("analyze"));
    verifyNoInteractions(index, runtime, planner, guard, reviewer, tools);
  }
  @Test
  void expiredProjectCanStillAnswerInformationalQuestionWithoutStrictGuard() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("项目=过期项目；项目授权状态=项目授权已过期；目标=测试站点");
    when(planner.planStreaming(any(AiPlanRequest.class), any()))
        .thenReturn(
            new AiPlanResponse("test", "test-model", "这是一个已登记的安全评估项目，历史资料仍可查看。", false, List.of()));
    when(runtime.enabled()).thenReturn(false);

    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    AiAgentResponse response =
        orchestrator.run(
            new AiAgentRequest(
                5L,
                8L,
                "expired-info",
                "介绍一下项目",
                false,
                null,
                List.of(),
                "standard",
                "turn-expired-info"));

    assertThat(response.executed()).isFalse();
    assertThat(response.guardStatus()).isEqualTo("NOT_APPLICABLE");
    assertThat(response.approvalStatus()).isEqualTo("NOT_REQUIRED");
    assertThat(response.message()).contains("安全评估项目");
    verify(tools).inspectProjectContext(5L, 8L);
    verify(tools, never()).inspectAuthorizedScope(any(), any());
    verifyNoInteractions(guard, reviewer);
  }

  @Test
  void runtimeProtocolViolationFailsClosedWithoutRulePlannerOrToolExecution() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any()))
        .thenThrow(new AiAgentRuntimeClient.RuntimeProtocolException("unknown event"));

    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    AiAgentRequest request =
        new AiAgentRequest(
            5L,
            8L,
            "protocol-failure",
            "scan headers",
            true,
            null,
            List.of(),
            "standard",
            "turn-protocol-failure",
            "workflow-protocol-failure",
            7L,
            "sha256:" + "a".repeat(64),
            "ledger-agent",
            "node-protocol-failure");

    assertThatThrownBy(() -> orchestrator.run(request))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("Harness 协议校验");
    verify(planner, never()).planStreaming(any(), any());
    verify(tools, never()).executeAuthorizedPlan(any(), any());
    verifyNoInteractions(guard, reviewer);

    ArgumentCaptor<AiAgentRequest> runtimeRequest = ArgumentCaptor.forClass(AiAgentRequest.class);
    verify(runtime).plan(runtimeRequest.capture(), anyString(), any());
    assertThat(runtimeRequest.getValue().workflowId()).isEqualTo(request.workflowId());
    assertThat(runtimeRequest.getValue().workflowRevision()).isEqualTo(request.workflowRevision());
    assertThat(runtimeRequest.getValue().workflowDigest()).isEqualTo(request.workflowDigest());
    assertThat(runtimeRequest.getValue().outerNodeId()).isEqualTo(request.outerNodeId());
    assertThat(runtimeRequest.getValue().nodeRunId()).isEqualTo(request.nodeRunId());
  }

  @Test
  void runtimeUnavailableFallbackCannotExecuteWithoutTrustedV3LedgerChain() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any()))
        .thenThrow(new AiAgentRuntimeClient.RuntimeUnavailableException("offline"));
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    AiAgentRequest request =
        new AiAgentRequest(
            5L,
            8L,
            "runtime-unavailable",
            "scan headers",
            true,
            null,
            List.of(),
            "standard",
            "turn-runtime-unavailable");

    assertThatThrownBy(() -> orchestrator.run(request))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("v3 Ledger 证据链");
    verify(planner, never()).planStreaming(any(AiPlanRequest.class), any());
    verifyNoInteractions(guard);
    verify(tools, never()).executeAuthorizedPlan(any(), any());
    verifyNoInteractions(reviewer);
  }

  @Test
  void ragDisabledActionPlanCannotExecute() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    AiPlanResponse legacyPlan = actionablePlan("langgraph-runtime");
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            legacyPlan,
            legacyPlan.summary(),
            "COMPLETED",
            "runtime-rag-disabled-action",
            AiAgentRuntimeClient.POLICY_REVISION,
            3,
            new AiAgentRuntimeClient.RuntimeProvenance(
                0, List.of(), "", "langchain-legacy", "RAG_DISABLED"));
    AiAgentRequest request = request("rag-disabled-action", true, "turn-rag-disabled-action");

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any())).thenReturn(runtimeResult);
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);

    assertThatThrownBy(() -> orchestrator.run(request))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("v3 Ledger 证据链");
    verifyNoInteractions(guard, reviewer);
    verify(tools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void verifiedLocalGroundedFallbackDispatchesThroughGuardAndReview() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    AiPlanResponse runtimePlan = actionablePlan("langgraph-runtime");
    AiAgentRequest request = request("runtime-local-fallback", true, "turn-local-fallback");
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            runtimePlan,
            runtimePlan.summary(),
            "COMPLETED",
            "runtime-local-fallback",
            AiAgentRuntimeClient.POLICY_REVISION,
            11,
            new AiAgentRuntimeClient.RuntimeProvenance(
                1,
                List.of("ev-a"),
                "sha256:" + "a".repeat(64),
                "local-grounded-fallback",
                "EVIDENCE_FINALIZED"));
    AiAuthorizationGuard.GuardDecision decision =
        new AiAuthorizationGuard.GuardDecision(
            "ALLOWED", "CONFIRMED_BY_REQUEST", "authorized", runtimePlan, 0, 0);
    AiAgentResponse.AgentReview review =
        new AiAgentResponse.AgentReview("VERIFIED", "verified", false, List.of(42L));

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any())).thenReturn(runtimeResult);
    when(guard.evaluate(same(request), same(runtimePlan))).thenReturn(decision);
    when(tools.executeAuthorizedPlan(same(request), same(runtimePlan)))
        .thenReturn(new AiDispatchResponse(8L, runtimePlan, 1, List.of(42L)));
    when(reviewer.review(5L, 8L, List.of(42L))).thenReturn(review);
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    List<AiAgentEvent> events = new ArrayList<>();

    AiAgentResponse response = orchestrator.run(request, events::add);

    assertThat(response.executed()).isTrue();
    assertThat(response.taskIds()).containsExactly(42L);
    verify(guard).evaluate(same(request), same(runtimePlan));
    verify(tools).executeAuthorizedPlan(same(request), same(runtimePlan));
    verify(reviewer).review(5L, 8L, List.of(42L));
    AiAgentEvent done =
        events.stream().filter(event -> "done".equals(event.type())).findFirst().orElseThrow();
    assertThat(done.data())
        .containsEntry("fallback", true)
        .containsEntry("fallbackReason", "PYTHON_MODEL_FALLBACK")
        .containsEntry("plannerSource", "local-grounded-fallback");
  }

  @Test
  void clearingSessionAuditsItsProjectAndTargetScope() {
    AiConversationMemoryService memory = mock(AiConversationMemoryService.class);
    AuditService audit = mock(AuditService.class);
    when(memory.clear("session-delete"))
        .thenReturn(new AiConversationMemoryService.SessionScope(5L, 8L));
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(
            memory,
            mock(SecurityAgentTools.class),
            mock(AiAgentRuntimeClient.class),
            mock(AiProjectIndexService.class),
            mock(AiPlanningService.class),
            mock(AiAuthorizationGuard.class),
            mock(AiExecutionReviewer.class),
            audit);

    assertThat(orchestrator.clearSession("session-delete")).isTrue();

    verify(audit)
        .recordStructured(
            "AI_CONVERSATION_DELETE",
            "AI_CONVERSATION",
            "session-delete",
            Map.of(
                "sessionId", "session-delete",
                "cleared", true,
                "projectId", 5L,
                "targetId", 8L),
            "SUCCESS");
  }

  @Test
  void postDispatchFailureAuditsCommittedTaskIds() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    AiPlanResponse runtimePlan = actionablePlan("runtime-grounded");
    AiAgentRequest request = request("post-dispatch-failure", true, "turn-post-dispatch-failure");
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            runtimePlan,
            runtimePlan.summary(),
            "COMPLETED",
            "runtime-run-post-dispatch",
            AiAgentRuntimeClient.POLICY_REVISION,
            6,
            new AiAgentRuntimeClient.RuntimeProvenance(
                1,
                List.of("ev-a"),
                "sha256:" + "a".repeat(64),
                "langchain-grounded",
                "EVIDENCE_FINALIZED"));
    AiAuthorizationGuard.GuardDecision decision =
        new AiAuthorizationGuard.GuardDecision(
            "ALLOWED", "CONFIRMED_BY_REQUEST", "authorized", runtimePlan, 0, 0);

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any())).thenReturn(runtimeResult);
    when(guard.evaluate(same(request), same(runtimePlan))).thenReturn(decision);
    when(tools.executeAuthorizedPlan(same(request), same(runtimePlan)))
        .thenReturn(new AiDispatchResponse(8L, runtimePlan, 1, List.of(42L)));
    when(reviewer.review(5L, 8L, List.of(42L))).thenThrow(new ApiException("review failed"));
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);

    assertThatThrownBy(() -> orchestrator.run(request))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("任务已经创建")
        .hasMessageContaining("不要创建新 Turn 重试");

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> detailCaptor = ArgumentCaptor.forClass(Map.class);
    verify(audit)
        .recordStructured(
            eq("AI_AGENT_TURN"),
            eq("PROJECT"),
            eq(5L),
            detailCaptor.capture(),
            eq("FAILED"));
    assertThat(detailCaptor.getValue())
        .containsEntry("executed", true)
        .containsEntry("taskIds", List.of(42L));
    verify(tools, times(1)).executeAuthorizedPlan(same(request), same(runtimePlan));
  }

  @Test
  void postDispatchSinkFailureStillAuditsCommittedTaskIds() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    AiPlanResponse runtimePlan = actionablePlan("runtime-grounded");
    AiAgentRequest request = request("post-dispatch-sink", true, "turn-post-dispatch-sink");
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            runtimePlan,
            runtimePlan.summary(),
            "COMPLETED",
            "runtime-run-post-dispatch-sink",
            AiAgentRuntimeClient.POLICY_REVISION,
            6,
            new AiAgentRuntimeClient.RuntimeProvenance(
                1,
                List.of("ev-a"),
                "sha256:" + "a".repeat(64),
                "langchain-grounded",
                "EVIDENCE_FINALIZED"));
    AiAuthorizationGuard.GuardDecision decision =
        new AiAuthorizationGuard.GuardDecision(
            "ALLOWED", "CONFIRMED_BY_REQUEST", "authorized", runtimePlan, 0, 0);

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any())).thenReturn(runtimeResult);
    when(guard.evaluate(same(request), same(runtimePlan))).thenReturn(decision);
    when(tools.executeAuthorizedPlan(same(request), same(runtimePlan)))
        .thenReturn(new AiDispatchResponse(8L, runtimePlan, 1, List.of(84L)));
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);

    assertThatThrownBy(
            () ->
                orchestrator.run(
                    request,
                    event -> {
                      if ("tool_call".equals(event.type()) || "error".equals(event.type())) {
                        throw new IllegalStateException("client disconnected");
                      }
                    }))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("任务已经创建");

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> detailCaptor = ArgumentCaptor.forClass(Map.class);
    verify(audit)
        .recordStructured(
            eq("AI_AGENT_TURN"),
            eq("PROJECT"),
            eq(5L),
            detailCaptor.capture(),
            eq("FAILED"));
    assertThat(detailCaptor.getValue())
        .containsEntry("executed", true)
        .containsEntry("taskIds", List.of(84L));
    verify(tools, times(1)).executeAuthorizedPlan(same(request), same(runtimePlan));
    verifyNoInteractions(reviewer);
  }

  @Test
  void successfulRuntimePlanDispatchesExactlyOnceAndAuditsProvenance() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    AiPlanResponse runtimePlan = actionablePlan("runtime-grounded");
    AiAgentRequest request = request("runtime-success", true, "turn-runtime-success");
    AiAgentRuntimeClient.RuntimeProvenance runtimeProvenance =
        new AiAgentRuntimeClient.RuntimeProvenance(
            2,
            List.of("ev-a", "ev-b"),
            "sha256:" + "a".repeat(64),
            "langchain",
            "EVIDENCE_FINALIZED");
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            runtimePlan,
            "runtime answer",
            "COMPLETED",
            "runtime-run-1",
            AiAgentRuntimeClient.POLICY_REVISION,
            6,
            runtimeProvenance);
    AiAuthorizationGuard.GuardDecision decision =
        new AiAuthorizationGuard.GuardDecision(
            "ALLOWED", "CONFIRMED_BY_REQUEST", "authorized", runtimePlan, 0, 0);
    AiAgentResponse.AgentReview review =
        new AiAgentResponse.AgentReview("VERIFIED", "verified", false, List.of(42L));

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any())).thenReturn(runtimeResult);
    when(guard.evaluate(same(request), same(runtimePlan))).thenReturn(decision);
    when(tools.executeAuthorizedPlan(same(request), same(runtimePlan)))
        .thenReturn(new AiDispatchResponse(8L, runtimePlan, 1, List.of(42L)));
    when(reviewer.review(5L, 8L, List.of(42L))).thenReturn(review);
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    List<AiAgentEvent> events = new ArrayList<>();

    AiAgentResponse response = orchestrator.run(request, events::add);

    assertThat(response.executed()).isTrue();
    assertThat(response.taskIds()).containsExactly(42L);
    verify(tools, times(1)).executeAuthorizedPlan(same(request), same(runtimePlan));
    verify(planner, never()).planStreaming(any(), any());
    AiAgentEvent done =
        events.stream().filter(event -> "done".equals(event.type())).findFirst().orElseThrow();
    assertThat(done.contractVersion()).isEqualTo(3);
    assertThat(done.data())
        .containsEntry("fallback", false)
        .containsEntry("retrievalRoundCount", 2)
        .containsEntry("plannerSource", "langchain")
        .containsEntry("runtimeRunId", "runtime-run-1");

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> detailCaptor = ArgumentCaptor.forClass(Map.class);
    verify(audit)
        .recordStructured(
            eq("AI_AGENT_TURN"),
            eq("PROJECT"),
            eq(5L),
            detailCaptor.capture(),
            eq("SUCCESS"));
    assertThat(detailCaptor.getValue())
        .containsEntry("schemaVersion", 3)
        .containsEntry("turnId", "turn-runtime-success")
        .containsEntry("executed", true)
        .containsEntry("taskIds", List.of(42L))
        .containsEntry("retrievalRoundCount", 2)
        .containsEntry("evidenceIds", List.of("ev-a", "ev-b"))
        .containsEntry("indexRevision", "sha256:" + "a".repeat(64))
        .containsEntry("plannerSource", "langchain")
        .containsEntry("terminationReason", "EVIDENCE_FINALIZED")
        .containsEntry("fallback", false)
        .containsEntry("fallbackReason", "NONE")
        .containsEntry("runtimeRunId", "runtime-run-1");
  }

  @Test
  void ragDisabledRuntimeMarksFallbackInFinalEventAndAudit() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    AiPlanResponse answerPlan =
        new AiPlanResponse("langgraph-runtime", "runtime", "legacy answer", false, List.of());
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            answerPlan,
            "legacy answer",
            "COMPLETED",
            "runtime-rag-disabled",
            AiAgentRuntimeClient.POLICY_REVISION,
            3,
            new AiAgentRuntimeClient.RuntimeProvenance(
                0, List.of(), "", "langchain", "RAG_DISABLED"));
    AiAgentRequest request = request("rag-disabled", false, "turn-rag-disabled");

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any())).thenReturn(runtimeResult);
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    List<AiAgentEvent> events = new ArrayList<>();

    AiAgentResponse response = orchestrator.run(request, events::add);

    assertThat(response.executed()).isFalse();
    AiAgentEvent done =
        events.stream().filter(event -> "done".equals(event.type())).findFirst().orElseThrow();
    assertThat(done.data())
        .containsEntry("fallback", true)
        .containsEntry("fallbackReason", "PYTHON_RAG_DISABLED")
        .containsEntry("terminationReason", "RAG_DISABLED")
        .containsEntry("plannerSource", "langchain");
    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> detailCaptor = ArgumentCaptor.forClass(Map.class);
    verify(audit)
        .recordStructured(anyString(), anyString(), eq(5L), detailCaptor.capture(), eq("SUCCESS"));
    assertThat(detailCaptor.getValue())
        .containsEntry("fallback", true)
        .containsEntry("fallbackReason", "PYTHON_RAG_DISABLED")
        .containsEntry("runtimeRunId", "runtime-rag-disabled");
    verify(tools, never()).executeAuthorizedPlan(any(), any());
    verifyNoInteractions(guard, reviewer);
  }

  @Test
  void runtimeV3MetadataIsPublicAndSensitivePayloadsAreStrippedRecursively() throws Exception {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    SecurityAgentTools tools = mock(SecurityAgentTools.class);
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiProjectIndexService index = mock(AiProjectIndexService.class);
    AiPlanningService planner = mock(AiPlanningService.class);
    AiAuthorizationGuard guard = mock(AiAuthorizationGuard.class);
    AiExecutionReviewer reviewer = mock(AiExecutionReviewer.class);
    AuditService audit = mock(AuditService.class);
    String workflowDigest = "sha256:" + "b".repeat(64);
    String ledgerDigest = "sha256:" + "c".repeat(64);
    AiPlanResponse answerPlan =
        new AiPlanResponse("langgraph-runtime", "runtime", "public answer", false, List.of());
    AiAgentRuntimeClient.RuntimeEvent runtimeEvent =
        mock(AiAgentRuntimeClient.RuntimeEvent.class);
    when(runtimeEvent.eventId()).thenReturn("runtime-event-v3");
    when(runtimeEvent.type()).thenReturn("finish");
    when(runtimeEvent.node()).thenReturn("finish");
    when(runtimeEvent.innerStep()).thenReturn("finish");
    when(runtimeEvent.message()).thenReturn("completed");
    when(runtimeEvent.data())
        .thenReturn(
            Map.of(
                "status",
                "COMPLETED",
                "prompt",
                "private prompt marker",
                "chainOfThought",
                "private reasoning marker",
                "credentials",
                Map.of("token", "private credential marker"),
                "items",
                List.of(
                    Map.of(
                        "evidenceId",
                        "ev-1",
                        "contentDigest",
                        "sha256:" + "d".repeat(64),
                        "evidenceBody",
                        "private evidence marker"))));
    when(runtimeEvent.runId()).thenReturn("runtime-run-v3");
    when(runtimeEvent.stateVersion()).thenReturn(7);
    when(runtimeEvent.policyRevision()).thenReturn(AiAgentRuntimeClient.POLICY_REVISION);
    when(runtimeEvent.contractVersion()).thenReturn(3);
    when(runtimeEvent.workflowDigest()).thenReturn(workflowDigest);
    when(runtimeEvent.outerNodeId()).thenReturn("ledger-agent");
    when(runtimeEvent.nodeRunId()).thenReturn("node-run-v3");
    when(runtimeEvent.ledgerSequence()).thenReturn(7L);
    when(runtimeEvent.ledgerEntryDigest()).thenReturn(ledgerDigest);
    when(runtimeEvent.terminationReason()).thenReturn("EVIDENCE_FINALIZED");
    AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
        new AiAgentRuntimeClient.RuntimePlanResult(
            answerPlan,
            "public answer",
            "COMPLETED",
            "runtime-run-v3",
            AiAgentRuntimeClient.POLICY_REVISION,
            7,
            new AiAgentRuntimeClient.RuntimeProvenance(
                1,
                List.of("ev-1"),
                "sha256:" + "e".repeat(64),
                "langchain",
                "EVIDENCE_FINALIZED"));

    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(AiAgentRequest.class), anyString(), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              java.util.function.Consumer<AiAgentRuntimeClient.RuntimeEvent> sink =
                  invocation.getArgument(2, java.util.function.Consumer.class);
              sink.accept(runtimeEvent);
              return runtimeResult;
            });
    AgentOrchestrator orchestrator =
        new AgentOrchestrator(memory, tools, runtime, index, planner, guard, reviewer, audit);
    List<AiAgentEvent> events = new ArrayList<>();

    AiAgentResponse response =
        orchestrator.run(request("runtime-public-v3", false, "turn-runtime-public-v3"), events::add);

    assertThat(response.executed()).isFalse();
    AiAgentEvent event =
        events.stream()
            .filter(candidate -> "runtime-event-v3".equals(candidate.data().get("runtimeEventId")))
            .findFirst()
            .orElseThrow();
    assertThat(event.contractVersion()).isEqualTo(3);
    assertThat(event.workflowDigest()).isEqualTo(workflowDigest);
    assertThat(event.outerNodeId()).isEqualTo("ledger-agent");
    assertThat(event.nodeRunId()).isEqualTo("node-run-v3");
    assertThat(event.innerStep()).isEqualTo("finish");
    assertThat(event.ledgerSequence()).isEqualTo(7L);
    assertThat(event.ledgerEntryDigest()).isEqualTo(ledgerDigest);
    assertThat(event.terminationReason()).isEqualTo("EVIDENCE_FINALIZED");
    assertThat(event.data().toString())
        .doesNotContain(
            "private prompt marker",
            "private reasoning marker",
            "private credential marker",
            "private evidence marker");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) event.data().get("items");
    assertThat(items)
        .singleElement()
        .satisfies(item -> assertThat(item).containsEntry("evidenceId", "ev-1"));
  }

  private static AiPlanResponse actionablePlan(String provider) {
    return new AiPlanResponse(
        provider,
        "runtime",
        "Inspect authorized headers",
        true,
        List.of(
            new AiPlanResponse.PlanStep(
                "http_headers", "Headers", "Inspect response headers", Map.of())));
  }

  private static AiAgentRequest request(String sessionId, boolean execute, String turnId) {
    return new AiAgentRequest(
        5L,
        8L,
        sessionId,
        "scan headers",
        execute,
        null,
        List.of(),
        "standard",
        turnId);
  }
}
