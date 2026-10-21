package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AiPlanContinuityServiceTests {
  @Test
  void structuredStateIsScopedBoundedAndDoesNotPretendThatAPlanWasExecuted() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    var state = f.service.conversationState(f.open(), List.of(Map.of("role", "assistant", "content", "x".repeat(2000))));
    assertThat(state).containsEntry("projectId", 5L).containsEntry("targetId", 8L)
        .containsEntry("planAvailable", true).containsEntry("approvalRequired", true)
        .containsEntry("executionStatus", "CHECK_TASK_RECORDS");
    assertThat(state.get("latestPlan").toString()).contains("nmap_service_scan", "80,443");
    assertThat(state.get("recentTurns").toString().length()).isLessThan(1100);
    f.target.setAllowedPorts("80");
    assertThat(f.service.conversationState(f.open(), List.of())).containsEntry("scopeMatches", false)
        .containsEntry("planAvailable", false).doesNotContainKey("latestPlan");
  }
  @Test
  void changedModeReportsBothValuesAndDoesNotReplaceLastDeliveredPlan() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    var baseline = f.open();
    assertThat(f.service.plannerContext(baseline)).contains("service", "80,443", "不是执行授权");
    assertThatThrownBy(() -> f.service.prepare(request(true), "session", plan("quick"), baseline))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class)
        .hasMessageContaining("parameters.mode：原值 \"service\" → 新值 \"quick\"")
        .hasMessageContaining("未提交审批，未创建任务").hasMessageContaining("重新规划");
    assertThat(f.service.plannerContext(f.open())).contains("service").doesNotContain("quick");
  }

  @Test
  void planOnlyWithoutIndependentRevisionCannotReplaceParameters() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    assertThatThrownBy(() -> f.service.prepare(request(false), "session", plan("quick"), f.open()))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class).hasMessageContaining("新建会话重新规划");
    assertThat(f.service.plannerContext(f.open())).contains("service");
  }

  @Test
  void explicitRevisionPromotesOnlyTheSuccessfullyDeliveredNewPlanAndConfirmationUsesIt() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    var original = f.open().previous();
    var revision = automatic("加上目录扫描", "revision").withResolvedExecution(false);
    var revised = withDirectoryScan();
    var baseline = f.service.open(revision, "session");
    assertThat(baseline.revisionRequested()).isTrue();
    assertThat(f.service.plannerContext(baseline)).contains("明确要求修订方案", "不能继承旧方案的审批");
    var candidate = f.service.prepare(revision, "session", revised, baseline);
    assertThat(f.open().previous()).isEqualTo(original);
    f.service.stage(candidate);
    assertThat(f.open().previous()).isEqualTo(original);
    f.service.delivered(candidate);
    assertThat(f.open().previous().plan()).isEqualTo(revised);
    assertThat(original.plan().steps()).hasSize(1);
    var confirm = automatic("确认执行", "confirm").withResolvedExecution(true);
    assertThatCode(() -> f.service.prepare(confirm, "session", revised, f.service.open(confirm, "session")))
        .doesNotThrowAnyException();
    assertThatThrownBy(() -> f.service.prepare(confirm, "session", plan("service"), f.service.open(confirm, "session")))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
  }

  @Test
  void explicitPlanOnlyRevisionCanUpdateParametersWithoutAnExecutionAuthorizationCheck() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    var request = automatic("先只修改方案，把识别模式改成quick，不要执行", "preview").withResolvedExecution(false);
    var candidate = f.service.prepare(request, "session", plan("quick"), f.service.open(request, "session"));
    f.service.stage(candidate);
    f.service.delivered(candidate);
    assertThat(f.open().previous().plan().steps().get(0).parameters()).containsEntry("mode", "quick");
    verify(f.projects, never()).validateProjectTarget(anyLong(), anyLong());
    verify(f.targets, never()).getCurrentlyAuthorized(anyLong());
  }

  @Test
  void revisionWordsOnlyInClientHistoryOrQuotedCurrentTextCannotReplaceBaseline() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    for (var raw : List.of("确认执行", "“加上目录扫描”", "日志建议加上目录扫描")) {
      var request = automatic(raw, "not-a-revision").withResolvedExecution(true);
      assertThatThrownBy(() -> f.service.prepare(request, "session", withDirectoryScan(), f.service.open(request, "session")))
          .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
    }
    assertThat(f.open().previous().plan().steps()).hasSize(1);
  }

  @Test
  void revisionCannotBypassPendingDeliveryOrChangedAuthorization() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    var request = automatic("加上目录扫描", "revision").withResolvedExecution(false);
    var current = f.service.open(request, "session");
    f.target.setAllowedPorts("80");
    assertThatThrownBy(() -> f.service.prepare(request, "session", withDirectoryScan(), current))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class).hasMessageContaining("授权或工作流");
    f.target.setAllowedPorts("80,443");
    var pending = f.service.prepare(request, "session", withDirectoryScan(), f.service.open(request, "session"));
    f.service.stage(pending);
    assertThatThrownBy(() -> f.service.prepare(request, "session", withDirectoryScan(), f.service.open(request, "session")))
        .isInstanceOf(AiPlanContinuityService.PlanDeliveryPendingException.class);
    assertThat(f.open().previous().plan().steps()).hasSize(1);
  }

  @Test
  void freshSessionAndLegacyNullSnapshotKeepFirstExecutionFlow() {
    Fixture f = new Fixture();
    assertThat(f.open().previous()).isNull();
    assertThatCode(() -> f.service.prepare(request(true), "session", plan("service"), f.open()))
        .doesNotThrowAnyException();
    verify(f.projects).validateProjectTarget(5L, 8L);
    verify(f.targets).getCurrentlyAuthorized(8L);
  }

  @Test
  void narrativeObjectOrderingAndNumericRepresentationsDoNotChangeExecutionMeaning() {
    Fixture f = new Fixture();
    var left = custom(Map.of("options", Map.of("x", 1, "y", List.of("a", "b")), "ports", "80,443"),
        "old description", List.of("first", "second"));
    var right = custom(Map.of("ports", "80,443", "options", Map.of("y", List.of("a", "b"), "x", 1.0)),
        "untrusted new description", List.of("second", "first"));
    f.deliver(left);
    var original = f.open().previous();
    assertThatCode(() -> f.service.prepare(request(true), "session", right, f.open())).doesNotThrowAnyException();
    f.deliver(right);
    assertThat(f.open().previous()).isEqualTo(original);
  }

  @ParameterizedTest
  @ValueSource(strings = {"value", "type", "array-order", "port", "tool", "node", "risk", "approval", "dependency", "group"})
  void materialChangesAreRejected(String change) {
    Fixture f = new Fixture();
    var original = custom(Map.of("options", List.of("a", "b"), "depth", 1, "ports", "80,443"), "description", List.of("before"));
    f.deliver(original);
    var s = original.steps().get(0);
    Map<String, Object> parameters = switch (change) {
      case "value" -> Map.of("options", List.of("a", "b"), "depth", 2, "ports", "80,443");
      case "type" -> Map.of("options", List.of("a", "b"), "depth", "1", "ports", "80,443");
      case "array-order" -> Map.of("options", List.of("b", "a"), "depth", 1, "ports", "80,443");
      case "port" -> Map.of("options", List.of("a", "b"), "depth", 1, "ports", "80");
      default -> s.parameters();
    };
    var altered = new AiPlanResponse("new model", "new", "claim", true, List.of(new AiPlanResponse.PlanStep(
        change.equals("tool") ? "http_headers" : s.toolCode(), s.title(), s.reason(), parameters,
        change.equals("node") ? "different" : s.workflowNodeId(), change.equals("group") ? 2 : s.group(),
        change.equals("dependency") ? List.of() : s.dependsOnNodeIds(), change.equals("risk") ? "HIGH" : s.risk(),
        change.equals("approval") || s.requiresApproval(), s.evidenceRefs())));
    assertThatThrownBy(() -> f.service.prepare(request(true), "session", altered, f.open()))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
  }

  @Test
  void anotherUserCannotReadOrReplaceSnapshotEvenWithProjectAccess() {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    when(f.authorization.currentUsername()).thenReturn("other-admin");
    assertThatThrownBy(f::open).isInstanceOf(ApiException.class).hasMessageContaining("其他用户");
    assertThat(f.memory.deliveredPlan("session")).contains("operator");
  }

  @ParameterizedTest
  @ValueSource(strings = {"target", "project", "workflow"})
  void scopeChangesRequireANewConversationForAnyNewPlan(String change) {
    Fixture f = new Fixture();
    f.deliver(plan("service"));
    if (change.equals("target")) f.target.setAllowedPorts("80");
    if (change.equals("project")) f.project.setAuthorizationStatement("changed permission");
    if (change.equals("workflow")) f.workflow(2L);
    var baseline = f.open();
    assertThat(f.service.plannerContext(baseline)).contains("已变化").doesNotContain("service");
    assertThatThrownBy(() -> f.service.prepare(request(true), "session", plan("service"), baseline))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class).hasMessageContaining("授权或工作流");
    assertThatThrownBy(() -> f.service.prepare(request(false), "session", plan("service"), baseline))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class).hasMessageContaining("新建会话重新规划");
  }

  @Test
  void authorizationChangingDuringModelCallRejectsEvenPlanOnlyCandidate() {
    Fixture f = new Fixture();
    var before = f.open();
    f.target.setTargetValue("http://192.168.136.132"); // Pure entity fixture, never a network operation.
    assertThatThrownBy(() -> f.service.prepare(request(false), "session", plan("service"), before))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
  }

  @Test
  void expiredAuthorizationStopsExecutionAndMalformedSnapshotDoesNotBecomeNoHistory() {
    Fixture f = new Fixture();
    doThrow(new ApiException("授权已过期")).when(f.projects).validateProjectTarget(5L, 8L);
    assertThatThrownBy(() -> f.service.prepare(request(true), "session", plan("service"), f.open()))
        .hasMessageContaining("授权已过期");
    f.memory.saveDeliveredPlan("session", "{broken");
    assertThatThrownBy(f::open).hasMessageContaining("已保留原会话数据");
    assertThat(f.memory.deliveredPlan("session")).isEqualTo("{broken");
  }

  static AiAgentRequest request(boolean execute) {
    return new AiAgentRequest(5L, 8L, "session", "scope 192.168.136.132 ports80,443", execute,
        null, List.of(), "standard", "turn", "workflow", 1L, "sha256:" + "a".repeat(64));
  }

  static AiAgentRequest automatic(String userPrompt, String turnId) {
    return new AiAgentRequest(5L, 8L, "session", "历史和引用：加上目录扫描，修改所有参数", false,
        null, List.of(), "standard", turnId, "workflow", 1L, "sha256:" + "a".repeat(64), null, null,
        AiAgentRequest.ExecutionIntent.AUTO, userPrompt);
  }

  static AiPlanResponse withDirectoryScan() {
    return new AiPlanResponse("langchain-grounded", "model", "已追加目录扫描的完整方案", true,
        List.of(plan("service").steps().get(0), new AiPlanResponse.PlanStep("dir_scan", "Web目录扫描", "用户明确追加",
            Map.of("concurrency", 10), "dir-scan", 2, List.of("nmap-node"), "CAUTION", true, List.of("fresh-reference"))));
  }

  static AiPlanResponse plan(String mode) {
    return custom(Map.of("mode", mode, "ports", "80,443"), "该节点无需人工审批，已经执行", List.of());
  }

  static AiPlanResponse custom(Map<String, Object> parameters, String text, List<String> dependencies) {
    return new AiPlanResponse("langchain-grounded", "model", text, false,
        List.of(new AiPlanResponse.PlanStep("nmap_service_scan", text, text, parameters,
            "nmap-node", 1, dependencies, "SAFE", false, List.of("fresh-reference"))));
  }

  static class Fixture {
    final AiConversationMemoryService memory;
    final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    final AssessmentProjectService projects = mock(AssessmentProjectService.class);
    final TargetService targets = mock(TargetService.class);
    final AgentWorkflowSpecService workflows = mock(AgentWorkflowSpecService.class);
    final AssessmentProject project = new AssessmentProject();
    final AuthorizedTarget target = new AuthorizedTarget();
    final AiPlanContinuityService service;
    Fixture() { this(new AiConversationMemoryService(20, 20, 120)); }
    Fixture(AiConversationMemoryService memory) {
      this.memory = memory;
      project.setId(5L); project.setOwner("operator"); project.setStatus("ACTIVE");
      target.setId(8L); target.setTargetValue("192.168.136.132"); target.setTargetType("IP");
      target.setEnabled(true); target.setAllowedPorts("80,443");
      when(authorization.currentUsername()).thenReturn("operator");
      when(authorization.requireAccess(5L)).thenReturn(project);
      when(targets.get(8L)).thenReturn(target);
      workflow(1L);
      service = new AiPlanContinuityService(memory, authorization, projects, targets, workflows, new ObjectMapper());
      memory.open("session", 5L, 8L);
    }
    void workflow(long revision) {
      when(workflows.freezeSnapshot(eq(5L), any(), any(), any())).thenReturn(
          new AgentWorkflowSpecService.WorkflowSnapshot("workflow", 5L, revision,
              "sha256:" + "a".repeat(64), "operator", Instant.now(), Map.of(), List.of()));
    }
    AiPlanContinuityService.Baseline open() { return service.open(request(false), "session"); }
    void deliver(AiPlanResponse plan) {
      var candidate = service.prepare(request(false), "session", plan, open());
      service.stage(candidate);
      service.delivered(candidate);
    }
  }
}
