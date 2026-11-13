package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.tool.ToolParameterPolicy;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 审批快照重校验（TOCTOU 纵深）——Round 9。
 *
 * <p>审批与执行是两个独立事务。管理员批准后、执行前，目标授权端口/范围可能被收窄，
 * 工具参数规格可能漂移。{@code AiPlanApprovalService.revalidateApprovedPlan} 在“持锁后、派发前”
 * 重新校验已保存的方案，堵住审批 ↔ 执行之间的窗口。本类锁定该行为。
 */
@DisplayName("审批快照重校验（TOCTOU）Round 9")
class AiPlanApprovalRevalidationTests {
  private final ProjectApprovalRepository approvals = mock(ProjectApprovalRepository.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final SecurityAgentTools tools = mock(SecurityAgentTools.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final TargetService targets = mock(TargetService.class);
  private final PortRangeParser parser = new PortRangeParser();
  private final AiPlanApprovalService service = new AiPlanApprovalService(
      approvals, authorization, tools, new ObjectMapper(), projects, targets, parser);

  private static AiPlanResponse plan(AiPlanResponse.PlanStep... steps) {
    return new AiPlanResponse("p", "m", "s", false, List.of(steps));
  }

  private static AiPlanResponse.PlanStep step(String tool, Map<String, Object> params) {
    return new AiPlanResponse.PlanStep(tool, "t", "r", params, null, 0, List.of(), "SAFE", false, List.of());
  }

  private static AiAgentRequest req(Long targetId) {
    return new AiAgentRequest(7L, targetId, "sess", "prompt", true, null, null, null,
        "turn-1", null, null, null, null, null, null, null, List.of(), AiAgentRequest.ScopeMode.SINGLE);
  }

  private AuthorizedTarget target(String ports) {
    AuthorizedTarget t = new AuthorizedTarget();
    t.setId(9L);
    t.setTargetValue("192.168.222.158");
    t.setTargetType("IP");
    t.setAllowedPorts(ports);
    t.setEnabled(true);
    return t;
  }

  @Test
  @DisplayName("REVAL-1 端口仍在授权范围内 → 通过")
  void portsStillAuthorizedPasses() {
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target("80,443"));
    assertThatCode(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L),
        plan(step("tcp_ports", Map.of("ports", "80,443")))))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("REVAL-2 审批后端口被收窄，方案请求越权端口 → 拒绝（TOCTOU 窗口）")
  void portShrunkAfterApprovalDenied() {
    // 审批时可能是 80,443,3306；执行前收窄为 80,443。
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target("80,443"));
    assertThatThrownBy(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L),
        plan(step("tcp_ports", Map.of("ports", "3306")))))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("端口");
  }

  @Test
  @DisplayName("REVAL-3 工具参数键不符合白名单（规格漂移）→ 拒绝")
  void driftedParameterKeyDenied() {
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target("80,443"));
    assertThatThrownBy(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L),
        plan(step("http_headers", Map.of("unexpectedKey", "x")))))
        .isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("REVAL-4 工具已不在可执行白名单 → 拒绝")
  void unknownToolDenied() {
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target("80,443"));
    assertThatThrownBy(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L),
        plan(step("totally_unknown_tool", Map.of()))))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("白名单");
  }

  @Test
  @DisplayName("REVAL-5 端口参数不可解析 → 拒绝（fail-closed）")
  void unparseablePortDenied() {
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target("80,443"));
    assertThatThrownBy(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L),
        plan(step("tcp_ports", Map.of("ports", "abc")))))
        .isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("REVAL-6 空方案 → 直接通过（无步骤无需校验）")
  void emptyPlanPasses() {
    assertThatCode(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L), plan()))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("REVAL-7 新增 dir_scan/zap_fuzz 工具的合法参数键不再被误拒（漂移修复联动）")
  void dirScanLegalKeysPassDriftFix() {
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target("80,443"));
    assertThatCode(() -> service.revalidateApprovedPlan(
        7L, new ProjectApproval(), req(9L),
        plan(step("dir_scan", Map.of("dictionary", "common", "concurrency", 5)))))
        .doesNotThrowAnyException();
  }
}
