package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class AiPlanningServiceTests {
  @Test
  void fallbackUsesNucleiForExplicitVulnerabilityScan() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(12L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("1-65535");
    when(targets.getCurrentlyAuthorized(12L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(12L, "执行通用漏洞扫描"));

    assertThat(response.steps())
        .extracting(AiPlanResponse.PlanStep::toolCode)
        .contains("nuclei_scan");
  }

  @Test
  void answersProgramUsageWithoutDispatchingScan() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(11L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("1-65535");
    when(targets.getCurrentlyAuthorized(11L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(11L, "怎么新增目标"));

    assertThat(response.steps()).isEmpty();
    assertThat(response.summary()).contains("授权目标").contains("1-65535");
  }

  @Test
  void greetingDoesNotCreateFallbackScan() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(8L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("1-65535");
    when(targets.getCurrentlyAuthorized(8L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(8L, "你好"));

    assertThat(response.steps()).isEmpty();
    assertThat(response.summary()).contains("你好");
  }

  @Test
  void projectIntroductionIsAnsweredWithoutCreatingAPlan() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(13L);
    target.setTargetValue("https://example.test");
    target.setTargetType("URL");
    target.setAllowedPorts("443");
    when(targets.getCurrentlyAuthorized(13L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response =
        service.plan(new AiPlanRequest(13L, "介绍一下项目\n\n服务端授权上下文：项目=毕业设计；项目状态=ACTIVE"));

    assertThat(response.steps()).isEmpty();
    assertThat(response.summary()).contains("獬豸（Xiezhi）授权安全测试平台");
  }

  @Test
  void resultQuestionContainingVulnerabilityWordsDoesNotTriggerScan() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(14L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443");
    when(targets.getCurrentlyAuthorized(14L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(14L, "发现开放端口也算漏洞吗？"));

    assertThat(response.steps()).isEmpty();
  }

  @Test
  void fallbackUsesQuickNmapForFullPortIntent() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(9L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("1-65535");
    when(targets.getCurrentlyAuthorized(9L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(9L, "扫描全部端口"));

    assertThat(response.steps()).hasSize(1);
    assertThat(response.steps().get(0).toolCode()).isEqualTo("nmap_service_scan");
    assertThat(response.steps().get(0).parameters())
        .containsEntry("ports", "1-65535")
        .containsEntry("mode", "quick");
  }

  @Test
  void fallbackUsesQuickNmapForBroadAssessmentOfFullAuthorization() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(10L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("1-65535");
    when(targets.getCurrentlyAuthorized(10L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    AiPlanningService service =
        new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(10L, "全面检查并识别服务版本"));

    assertThat(response.steps()).hasSize(1);
    assertThat(response.steps().get(0).toolCode()).isEqualTo("nmap_service_scan");
    assertThat(response.steps().get(0).parameters()).containsEntry("mode", "quick");
  }

  @Test
  void validatesCurrentAuthorizationAndProjectMembershipBeforeCallingModel() throws Exception {
    TargetService targets = mock(TargetService.class);
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(15L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443");
    when(targets.getCurrentlyAuthorized(15L)).thenReturn(target);

    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.responsesMode()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    when(client.chat(anyMap()))
        .thenReturn(
            new ObjectMapper()
                .readTree(
                    """
                    {"choices":[{"message":{"content":"已完成","tool_calls":[]}}]}
                    """));
    AiPlanningService service =
        new AiPlanningService(
            targets, mock(AuditService.class), new ObjectMapper(), client, null, projects);

    service.plan(new AiPlanRequest(6L, 15L, "检查授权范围", null, null, null));

    var order = inOrder(targets, projects, client);
    order.verify(targets).getCurrentlyAuthorized(15L);
    order.verify(projects).validateProjectTargetMembership(6L, 15L);
    order.verify(client).enabled();
    order.verify(client).responsesMode();
    order.verify(client).chat(anyMap());
  }

  @Test
  void currentAuthorizationFailureUsesChineseErrorAndSkipsModelCall() {
    TargetService targets = mock(TargetService.class);
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    when(targets.getCurrentlyAuthorized(16L)).thenThrow(new ApiException("目标授权已过期"));
    AiModelClient client = mock(AiModelClient.class);
    AiPlanningService service =
        new AiPlanningService(
            targets, mock(AuditService.class), new ObjectMapper(), client, null, projects);

    assertThatThrownBy(() -> service.plan(new AiPlanRequest(6L, 16L, "扫描端口", null, null, null)))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标授权已过期");
    verifyNoInteractions(projects, client);
  }

  @Test
  void projectMembershipFailureUsesChineseErrorAndSkipsModelCall() {
    TargetService targets = mock(TargetService.class);
    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(17L);
    when(targets.getCurrentlyAuthorized(17L)).thenReturn(target);
    org.mockito.Mockito.doThrow(new ApiException("目标不属于该评估项目"))
        .when(projects)
        .validateProjectTargetMembership(6L, 17L);
    AiModelClient client = mock(AiModelClient.class);
    AiPlanningService service =
        new AiPlanningService(
            targets, mock(AuditService.class), new ObjectMapper(), client, null, projects);

    assertThatThrownBy(() -> service.plan(new AiPlanRequest(6L, 17L, "扫描端口", null, null, null)))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标不属于该评估项目");
    verifyNoInteractions(client);
  }
}
