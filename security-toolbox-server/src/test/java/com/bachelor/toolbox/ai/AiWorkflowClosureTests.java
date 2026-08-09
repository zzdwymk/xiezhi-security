package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiWorkflowClosureTests {
  private static final String DIGEST = "sha256:" + "a".repeat(64);
  private final TargetService targets = mock(TargetService.class);
  private final TargetPolicyService policies = mock(TargetPolicyService.class);
  private final SecurityToolRegistry tools = mock(SecurityToolRegistry.class);
  private final AgentWorkflowSpecService workflows = mock(AgentWorkflowSpecService.class);
  private final AiTaskDispatchService dispatcher =
      new AiTaskDispatchService(
          targets, policies, tools, new PortRangeParser(), 1024, 1024, workflows);

  @BeforeEach
  void setUp() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(2L);
    target.setEnabled(true);
    target.setAllowedPorts("80,443");
    when(targets.get(2L)).thenReturn(target);
    when(policies.validatedHttpUri(target)).thenReturn(URI.create("https://example.test"));
    when(tools.require("http_headers")).thenReturn(mock(SecurityTool.class));
  }

  @Test
  void snapshotOverwritesForgedPolicyFields() {
    Map<String, Object> authoritative =
        Map.of(
            "nodeId", "headers-01",
            "tool", "http_headers",
            "parameters", Map.of(),
            "risk", "SAFE",
            "requiresApproval", false,
            "group", 2,
            "dependsOnNodeIds", List.of("context-01"));
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST))
        .thenReturn(snapshot(List.of(authoritative)));
    AiPlanResponse proposed =
        new AiPlanResponse(
            "python",
            "model",
            "summary",
            false,
            List.of(
                new AiPlanResponse.PlanStep(
                    "http_headers",
                    "headers",
                    "reason",
                    Map.of(),
                    "headers-01",
                    0,
                    List.of(),
                    "CAUTION",
                    true,
                    List.of("ev-1"))));

    AiPlanResponse closed = dispatcher.prepareWorkflow(request(), proposed);

    AiPlanResponse.PlanStep step = closed.steps().get(0);
    assertThat(step.workflowNodeId()).isEqualTo("headers-01");
    assertThat(step.group()).isEqualTo(2);
    assertThat(step.dependsOnNodeIds()).containsExactly("context-01");
    assertThat(step.risk()).isEqualTo("SAFE");
    assertThat(step.requiresApproval()).isFalse();
  }

  @Test
  void rejectsToolThatDoesNotMatchSelectedNode() {
    Map<String, Object> authoritative =
        Map.of(
            "nodeId", "headers-01",
            "tool", "http_headers",
            "parameters", Map.of(),
            "risk", "SAFE",
            "requiresApproval", false,
            "group", 0,
            "dependsOnNodeIds", List.of());
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST))
        .thenReturn(snapshot(List.of(authoritative)));
    AiPlanResponse proposed =
        new AiPlanResponse(
            "python",
            "model",
            "summary",
            false,
            List.of(
                new AiPlanResponse.PlanStep(
                    "tls_config",
                    "tls",
                    "reason",
                    Map.of(),
                    "headers-01",
                    0,
                    List.of(),
                    "SAFE",
                    false,
                    List.of())));

    assertThatThrownBy(() -> dispatcher.prepareWorkflow(request(), proposed))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("节点与工作流工具不匹配");
  }

  private AiAgentRequest request() {
    return new AiAgentRequest(
        1L,
        2L,
        "session",
        "check",
        true,
        null,
        List.of(),
        "execute",
        "turn-1",
        "wf-1",
        4L,
        DIGEST,
        "ledger-agent",
        "node-run-1");
  }

  private AgentWorkflowSpecService.WorkflowSnapshot snapshot(
      List<Map<String, Object>> steps) {
    return new AgentWorkflowSpecService.WorkflowSnapshot(
        "wf-1", 1L, 4L, DIGEST, "admin", Instant.EPOCH, Map.of("version", 2), steps);
  }
}
