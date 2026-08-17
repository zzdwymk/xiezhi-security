package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AiWorkflowSuggestServiceTests {
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void returnsLocalStructuralSuggestionsWhenModelIsDisabled() {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    AiWorkflowSuggestService service = new AiWorkflowSuggestService(client, objectMapper);

    Map<String, Object> result = service.suggest(null);

    assertThat(result).containsEntry("source", "local-rules").containsEntry("model", "local-rules");
    assertThat(result.get("note").toString()).contains("未启用大模型");
    assertThat(suggestions(result))
        .extracting(suggestion -> suggestion.get("kind"))
        .containsExactly("gap", "empty");
  }

  @Test
  void normalizesModelSuggestionsAndDropsUnknownToolActions() throws Exception {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.complete(anyString(), anyString()))
        .thenReturn(
            """
            ```json
            [
              {
                "kind": "coverage",
                "severity": "info",
                "title": "补充服务识别",
                "detail": "先确认开放服务。",
                "action": {
                  "type": "add_tool",
                  "tool": "nmap_service_scan",
                  "phase": "mapping"
                }
              },
              {
                "title": "忽略未知动作",
                "detail": "建议内容仍可展示。",
                "action": {
                  "type": "add_tool",
                  "tool": "arbitrary_command",
                  "phase": "mapping"
                }
              }
            ]
            ```
            """);
    AiWorkflowSuggestService service = new AiWorkflowSuggestService(client, objectMapper);

    Map<String, Object> result = service.suggest(connectedContextWorkflow());

    assertThat(result)
        .containsEntry("source", "llm+local")
        .containsEntry("model", "test-model")
        .containsEntry("note", "");
    List<Map<String, Object>> suggestions = suggestions(result);
    assertThat(suggestions).hasSize(2);
    assertThat(action(suggestions.get(0)))
        .containsEntry("type", "add_tool")
        .containsEntry("tool", "nmap_service_scan")
        .containsEntry("phase", "mapping");
    assertThat(suggestions.get(1)).doesNotContainKey("action");
  }

  @Test
  void modelFailureUsesChineseFallbackWithoutLeakingExceptionDetails() throws Exception {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.complete(anyString(), anyString()))
        .thenThrow(new IllegalStateException("upstream secret token sk-private"));
    AiWorkflowSuggestService service = new AiWorkflowSuggestService(client, objectMapper);

    Map<String, Object> result = service.suggest(connectedContextWorkflow());

    assertThat(result)
        .containsEntry("source", "local-rules")
        .containsEntry("model", "local-rules")
        .containsEntry("note", "大模型暂时不可用，已提供结构建议");
    assertThat(result.toString())
        .doesNotContain("sk-private")
        .doesNotContain("IllegalStateException");
  }

  @Test
  void acceptsDistinctAfrogAndXraySuggestionActions() throws Exception {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.complete(anyString(), anyString()))
        .thenReturn(
            """
            [
              {
                "kind": "scanner",
                "severity": "info",
                "title": "补充 Afrog",
                "detail": "增加独立扫描器。",
                "action": {"type": "add_tool", "tool": "afrog_scan", "phase": "discovery"}
              },
              {
                "kind": "scanner",
                "severity": "info",
                "title": "补充 Xray",
                "detail": "增加独立扫描器。",
                "action": {"type": "add_tool", "tool": "xray_scan", "phase": "discovery"}
              }
            ]
            """);
    AiWorkflowSuggestService service = new AiWorkflowSuggestService(client, objectMapper);

    List<Map<String, Object>> suggestions = suggestions(service.suggest(connectedContextWorkflow()));

    assertThat(suggestions).hasSize(2);
    assertThat(suggestions)
        .extracting(item -> action(item).get("tool"))
        .containsExactly("afrog_scan", "xray_scan");
  }

  @Test
  void appliesOrderAndApprovalAdviceToEveryScannerTool() {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    AiWorkflowSuggestService service = new AiWorkflowSuggestService(client, objectMapper);

    for (String scanner : List.of("nuclei_scan", "afrog_scan", "xray_scan")) {
      Map<String, Object> result =
          service.suggest(
              Map.of(
                  "graph",
                  Map.of(
                      "nodes",
                      List.of(Map.of("id", scanner, "type", "tool", "tool", scanner)),
                      "edges",
                      List.of())));
      assertThat(suggestions(result))
          .extracting(item -> item.get("kind"))
          .contains("order", "risk");
    }
  }

  private Map<String, Object> connectedContextWorkflow() {
    return Map.of(
        "graph",
        Map.of(
            "nodes",
                List.of(
                    Map.of("id", "start", "type", "start"),
                    Map.of(
                        "id", "context",
                        "type", "tool",
                        "tool", "retrieve_project_context")),
            "edges", List.of(Map.of("source", "start", "target", "context"))));
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> suggestions(Map<String, Object> result) {
    return (List<Map<String, Object>>) result.get("suggestions");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> action(Map<String, Object> suggestion) {
    return (Map<String, Object>) suggestion.get("action");
  }
}
