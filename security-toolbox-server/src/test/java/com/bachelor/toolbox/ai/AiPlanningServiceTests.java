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
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings = {
      "执行通用漏洞扫描", "怎么新增目标", "你好", "介绍一下项目", "发现开放端口也算漏洞吗？", "扫描全部端口", "全面检查并识别服务版本"})
  void everyRequestRequiresTheConfiguredModel(String prompt) {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(12L);
    when(targets.getCurrentlyAuthorized(12L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    AiPlanningService service = new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    assertThatThrownBy(() -> service.plan(new AiPlanRequest(12L, prompt)))
        .isInstanceOf(ApiException.class).hasMessageContaining("AI 模型未启用");
    org.mockito.Mockito.verify(client, org.mockito.Mockito.never()).chat(anyMap());
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings = {"你好", "怎么新增目标", "介绍一下项目", "扫描全部端口"})
  void templatesAreOnlyModelInputAndNeverOverrideItsAnswer(String prompt) throws Exception {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(12L);
    target.setTargetType("IP");
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("1-65535");
    when(targets.getCurrentlyAuthorized(12L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.chat(anyMap())).thenReturn(new ObjectMapper().readTree(
        "{\"choices\":[{\"message\":{\"content\":\"模型结合最新问题给出的答案\",\"tool_calls\":[]}}]}"));
    AiPlanningService service = new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    AiPlanResponse response = service.plan(new AiPlanRequest(12L, prompt));

    assertThat(response.summary()).isEqualTo("模型结合最新问题给出的答案");
    assertThat(response.provider()).isEqualTo("openai-compatible");
    assertThat(response.steps()).isEmpty();
    org.mockito.Mockito.verify(client).chat(org.mockito.ArgumentMatchers.argThat(body ->
        body.get("messages").toString().contains("本地参考草稿") && body.get("messages").toString().contains(prompt)));
  }

  @Test
  void blankModelResponseFailsInsteadOfReturningAClarificationTemplate() throws Exception {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(12L);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("80");
    when(targets.getCurrentlyAuthorized(12L)).thenReturn(target);
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.chat(anyMap())).thenReturn(new ObjectMapper().readTree("{\"choices\":[{\"message\":{}}]}"));
    AiPlanningService service = new AiPlanningService(targets, mock(AuditService.class), new ObjectMapper(), client);

    assertThatThrownBy(() -> service.plan(new AiPlanRequest(12L, "你好")))
        .isInstanceOf(ApiException.class).hasMessageContaining("未能生成有效回答");
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
