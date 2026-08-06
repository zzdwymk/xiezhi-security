package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.List;
import java.util.Map;
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

  private AiAgentRequest request(boolean execute) {
    return new AiAgentRequest(7L, 9L, "guard-test", "请扫描端口", execute, null, List.of(), "standard");
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
}
