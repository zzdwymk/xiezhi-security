package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AiPlanningModelNormalizationTests {
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  @SuppressWarnings("unchecked")
  void normalizesChatStepsAndRemovesTcpProbeWhenNmapIsPresent() throws Exception {
    TargetService targets = targetsWith(target(21L, "127.0.0.1", "IP", "80,443"));
    AiModelClient client = chatClient();
    JsonNode modelResponse =
        objectMapper.readTree(
            """
            {
              "choices": [{
                "message": {
                  "content": "已生成检测计划",
                  "tool_calls": [
                    {
                      "function": {
                        "name": "tcp_ports",
                        "arguments": "{\\\"ports\\\":\\\"80,443\\\"}"
                      }
                    },
                    {
                      "function": {
                        "name": "nmap_service_scan",
                        "arguments": "{\\\"ports\\\":\\\"80,443\\\",\\\"mode\\\":\\\"service\\\"}"
                      }
                    }
                  ]
                }
              }]
            }
            """);
    when(client.chat(anyMap())).thenReturn(modelResponse);
    AiPlanningService service = service(targets, client);

    AiPlanResponse response = service.plan(new AiPlanRequest(21L, "扫描端口并识别服务"));

    assertThat(response.provider()).isEqualTo("openai-compatible");
    assertThat(response.requiresConfirmation()).isTrue();
    assertThat(response.steps())
        .singleElement()
        .satisfies(
            step -> {
              assertThat(step.toolCode()).isEqualTo("nmap_service_scan");
              assertThat(step.parameters())
                  .containsEntry("ports", "80,443")
                  .containsEntry("mode", "service");
            });

    ArgumentCaptor<Map<String, Object>> request = ArgumentCaptor.forClass(Map.class);
    verify(client).chat(request.capture());
    assertThat(systemMessage(request.getValue()))
        .contains("獬豸（Xiezhi）授权安全测试平台")
        .contains("所有执行均需用户确认")
        .contains("nmap_service_scan");
  }

  @Test
  void chatModelFailureFallsBackWithoutLeakingExceptionDetails() {
    TargetService targets = targetsWith(target(22L, "127.0.0.1", "IP", "80,443"));
    AiModelClient client = chatClient();
    when(client.chat(anyMap()))
        .thenThrow(new IllegalStateException("upstream body contains sk-private"));
    AiPlanningService service = service(targets, client);

    AiPlanResponse response = service.plan(new AiPlanRequest(22L, "扫描端口"));

    assertThat(response.provider()).isEqualTo("local-rule-fallback");
    assertThat(response.steps())
        .extracting(AiPlanResponse.PlanStep::toolCode)
        .containsExactly("tcp_ports");
    assertThat(response.toString())
        .doesNotContain("sk-private")
        .doesNotContain("IllegalStateException");
  }

  @Test
  void streamingModelFailureEmitsOnlyStableChineseFallbackStatus() throws Exception {
    TargetService targets = targetsWith(target(23L, "https://example.test", "URL", "443"));
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.responsesMode()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.completeResponsesStream(anyString(), anyString(), any()))
        .thenThrow(new IllegalStateException("remote stack and secret sk-private"));
    AiPlanningService service = service(targets, client);
    List<AiModelClient.AiModelStreamEvent> events = new ArrayList<>();

    AiPlanResponse response = service.planStreaming(new AiPlanRequest(23L, "执行漏洞扫描"), events::add);

    assertThat(response.provider()).isEqualTo("local-rule-fallback");
    assertThat(events)
        .extracting(AiModelClient.AiModelStreamEvent::text)
        .contains("AI 服务未完成计划，已切换本地安全规则")
        .allMatch(text -> !text.contains("sk-private"));
    assertThat(response.toString()).doesNotContain("sk-private");
  }

  @Test
  void parsesResponsesJsonFromExplanatoryMarkdownFence() throws Exception {
    TargetService targets = targetsWith(target(24L, "https://example.test", "URL", "443"));
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.responsesMode()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.completeResponsesStream(anyString(), anyString(), any()))
        .thenReturn(
            """
            以下是根据授权范围生成的计划：
            ```json
            {
              "summary": "已生成受控计划",
              "steps": [{
                "toolCode": "http_headers",
                "title": "响应头检查",
                "reason": "检查安全响应头",
                "parameters": {}
              }]
            }
            ```
            请确认后再执行。
            """);
    AiPlanningService service = service(targets, client);

    AiPlanResponse response = service.plan(new AiPlanRequest(24L, "检查 HTTP 响应头"));

    assertThat(response.provider()).isEqualTo("openai-compatible");
    assertThat(response.summary()).isEqualTo("已生成受控计划");
    assertThat(response.steps())
        .extracting(AiPlanResponse.PlanStep::toolCode)
        .containsExactly("http_headers");
  }

  @Test
  void deduplicatesModelStepsInFirstOccurrenceOrder() throws Exception {
    TargetService targets = targetsWith(target(25L, "https://example.test", "URL", "80,443"));
    AiModelClient client = chatClient();
    JsonNode modelResponse =
        objectMapper.readTree(
            """
{
  "choices": [{
    "message": {
      "content": "已生成检测计划",
      "tool_calls": [
        {"function":{"name":"http_headers","arguments":"{}"}},
        {"function":{"name":"tcp_ports","arguments":"{\\"ports\\":\\"80,443\\"}"}},
        {"function":{"name":"nmap_service_scan","arguments":"{\\"ports\\":\\"80,443\\",\\"mode\\":\\"service\\"}"}},
        {"function":{"name":"nmap_service_scan","arguments":"{\\"ports\\":\\"80\\",\\"mode\\":\\"quick\\"}"}},
        {"function":{"name":"http_security_check","arguments":"{\\"check\\":\\"cookies\\"}"}},
        {"function":{"name":"http_security_check","arguments":"{\\"check\\":\\"cookies\\"}"}},
        {"function":{"name":"http_security_check","arguments":"{\\"check\\":\\"cors\\"}"}},
        {"function":{"name":"nuclei_scan","arguments":"{}"}},
        {"function":{"name":"nuclei_scan","arguments":"{}"}}
      ]
    }
  }]
}
""");
    when(client.chat(anyMap())).thenReturn(modelResponse);
    AiPlanningService service = service(targets, client);

    AiPlanResponse response = service.plan(new AiPlanRequest(25L, "全面检查"));

    assertThat(response.steps())
        .extracting(AiPlanResponse.PlanStep::toolCode)
        .containsExactly(
            "http_headers",
            "nmap_service_scan",
            "http_security_check",
            "http_security_check",
            "nuclei_scan");
    assertThat(response.steps().get(1).parameters())
        .containsEntry("ports", "80,443")
        .containsEntry("mode", "service");
    assertThat(response.steps().subList(2, 4))
        .extracting(step -> step.parameters().get("check"))
        .containsExactly("cookies", "cors");
  }

  private AiPlanningService service(TargetService targets, AiModelClient client) {
    return new AiPlanningService(targets, mock(AuditService.class), objectMapper, client);
  }

  private AiModelClient chatClient() {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.responsesMode()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
    return client;
  }

  private TargetService targetsWith(AuthorizedTarget target) {
    TargetService targets = mock(TargetService.class);
    when(targets.getCurrentlyAuthorized(target.getId())).thenReturn(target);
    return targets;
  }

  private AuthorizedTarget target(Long id, String value, String type, String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(id);
    target.setTargetValue(value);
    target.setTargetType(type);
    target.setAllowedPorts(allowedPorts);
    return target;
  }

  @SuppressWarnings("unchecked")
  private String systemMessage(Map<String, Object> request) {
    List<Map<String, Object>> messages = (List<Map<String, Object>>) request.get("messages");
    return messages.get(0).get("content").toString();
  }
}
