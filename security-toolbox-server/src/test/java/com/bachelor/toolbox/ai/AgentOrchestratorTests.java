package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.audit.AuditService;
import java.util.List;
import org.junit.jupiter.api.Test;

class AgentOrchestratorTests {
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
                5L, 8L, "expired-info", "介绍一下项目", false, null, List.of(), "standard"));

    assertThat(response.executed()).isFalse();
    assertThat(response.guardStatus()).isEqualTo("NOT_APPLICABLE");
    assertThat(response.approvalStatus()).isEqualTo("NOT_REQUIRED");
    assertThat(response.message()).contains("安全评估项目");
    verify(tools).inspectProjectContext(5L, 8L);
    verify(tools, never()).inspectAuthorizedScope(any(), any());
    verifyNoInteractions(guard, reviewer);
  }
}
