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
    target.setTargetValue("192.168.136.132");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443");
    when(targets.get(2L)).thenReturn(target);
    when(policies.validatedHttpUri(target)).thenReturn(URI.create("https://example.test"));
    when(tools.require("http_headers")).thenReturn(mock(SecurityTool.class));
    when(tools.require("nmap_service_scan")).thenReturn(mock(SecurityTool.class));
    when(tools.require("tcp_ports")).thenReturn(mock(SecurityTool.class));
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
  void olderSnapshotCannotRemoveSqlmapApprovalAfterParameterValidation() {
    var target = targets.get(2L);
    when(policies.validatedHttpUri(target, "/Less-1/?id=1"))
        .thenReturn(URI.create("http://127.0.0.1/Less-1/?id=1"));
    when(tools.require("sqlmap_scan")).thenReturn(mock(SecurityTool.class));
    Map<String, Object> parameters = Map.of("path", "/Less-1/?id=1", "level", 3, "risk", 1, "technique", "BEUT");
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST)).thenReturn(snapshot(List.of(Map.of(
        "nodeId", "sqlmap-01", "tool", "sqlmap_scan", "parameters", parameters,
        "risk", "SAFE", "requiresApproval", false, "group", 0, "dependsOnNodeIds", List.of()))));
    AiPlanResponse proposed = new AiPlanResponse("python", "model", "SQL检测", false, List.of(
        new AiPlanResponse.PlanStep("sqlmap_scan", "SQLMap", "requested", parameters, "sqlmap-01",
            0, List.of(), "SAFE", false, List.of("ev-1"))));
    var closed = dispatcher.prepareWorkflow(request(), proposed).steps().get(0);
    assertThat(closed.requiresApproval()).isTrue();
    assertThat(closed.parameters()).isEqualTo(parameters);
    assertThat(closed.workflowNodeId()).isEqualTo("sqlmap-01");
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

  private Map<String, Object> scanNode(String id, String tool) {
    return Map.of("nodeId", id, "tool", tool, "parameters", Map.of("ports", "80"),
        "group", 0, "dependsOnNodeIds", List.of(), "risk", "SAFE", "requiresApproval", false);
  }

  private AiPlanResponse scanPlan(String secondTool, String secondNode, String ports) {
    return new AiPlanResponse("python", "model", "explicit workflow", false, List.of(
        new AiPlanResponse.PlanStep("nmap_service_scan", "Nmap", "workflow", Map.of("ports", "80"),
            "nmap-01", 0, List.of(), "SAFE", false, List.of()),
        new AiPlanResponse.PlanStep(secondTool, "port scan", "workflow", Map.of("ports", ports),
            secondNode, 0, List.of(), "SAFE", false, List.of())));
  }

  @Test
  void explicitSnapshotAllowsNmapAndTcpNodesWithoutApplyingFreePlanMutualExclusion() {
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST)).thenReturn(snapshot(List.of(
        scanNode("nmap-01", "nmap_service_scan"), scanNode("tcp-01", "tcp_ports"))));
    assertThat(dispatcher.prepareWorkflow(request(), scanPlan("tcp_ports", "tcp-01", "80")).steps())
        .extracting(AiPlanResponse.PlanStep::workflowNodeId).containsExactly("nmap-01", "tcp-01");
  }

  @Test
  void explicitSnapshotAllowsDistinctNodesOfTheSameTool() {
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST)).thenReturn(snapshot(List.of(
        scanNode("nmap-01", "nmap_service_scan"), scanNode("nmap-02", "nmap_service_scan"))));
    assertThat(dispatcher.prepareWorkflow(request(), scanPlan("nmap_service_scan", "nmap-02", "80")).steps()).hasSize(2);
  }

  @Test
  void workflowCannotUseUnknownOrDuplicateNodeIdentity() {
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST)).thenReturn(snapshot(List.of(
        scanNode("nmap-01", "nmap_service_scan"), scanNode("tcp-01", "tcp_ports"))));
    assertThatThrownBy(() -> dispatcher.prepareWorkflow(request(), scanPlan("tcp_ports", "forged-node", "80")))
        .isInstanceOf(ApiException.class).hasMessageContaining("不存在的工作流节点");
    assertThatThrownBy(() -> dispatcher.prepareWorkflow(request(), scanPlan("nmap_service_scan", "nmap-01", "80")))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void malformedNullWorkflowStepIsRejectedWithoutNullPointerException() {
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST)).thenReturn(snapshot(List.of()));
    var malformed = new AiPlanResponse("python", "model", "bad", false,
        java.util.Arrays.asList((AiPlanResponse.PlanStep) null));
    assertThatThrownBy(() -> dispatcher.prepareWorkflow(request(), malformed))
        .isInstanceOf(ApiException.class).hasMessageContaining("未知或未授权");
  }

  @Test
  void explicitMixedWorkflowStillRejectsOutOfAuthorizationPorts() {
    when(workflows.freezeSnapshot(1L, "wf-1", 4L, DIGEST)).thenReturn(snapshot(List.of(
        scanNode("nmap-01", "nmap_service_scan"), scanNode("tcp-01", "tcp_ports"))));
    assertThatThrownBy(() -> dispatcher.prepareWorkflow(request(), scanPlan("tcp_ports", "tcp-01", "22")))
        .isInstanceOf(ApiException.class).hasMessageContaining("授权");
  }

  @Test
  void freePlanCannotBypassDeduplicationByAddingUntrustedNodeIds() {
    scanNode("nmap-01", "nmap_service_scan"); scanNode("tcp-01", "tcp_ports");
    // 端口范围完全相同且 Nmap 未开启 consumeOpenPorts 时才判定为重复扫描；
    // 提示要求调用方二选一（开启复用或去掉一个步骤），因此断言校验这个可操作建议。
    assertThatThrownBy(() -> dispatcher.prepare(new AiPlanRequest(2L, "scan"), scanPlan("tcp_ports", "tcp-01", "80")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("consumeOpenPorts")
        .hasMessageContaining("端口范围完全相同");
    assertThatThrownBy(() -> dispatcher.prepare(new AiPlanRequest(2L, "scan"), scanPlan("nmap_service_scan", "nmap-02", "80")))
        .isInstanceOf(ApiException.class).hasMessageContaining("重复派发");
  }

  private AgentWorkflowSpecService.WorkflowSnapshot snapshot(
      List<Map<String, Object>> steps) {
    return new AgentWorkflowSpecService.WorkflowSnapshot(
        "wf-1", 1L, 4L, DIGEST, "admin", Instant.EPOCH, Map.of("version", 2), steps);
  }
}
