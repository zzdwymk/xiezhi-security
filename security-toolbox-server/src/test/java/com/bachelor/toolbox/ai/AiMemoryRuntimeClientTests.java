package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.web.server.ResponseStatusException;

class AiMemoryRuntimeClientTests {
  private HttpServer server;
  private AiAgentRuntimeClient client;
  private int responseStatus = 200;
  private String responseBody = "{}";
  private String requestBody;
  private String requestUri;

  @BeforeEach
  void startStub() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      requestUri = exchange.getRequestURI().toString();
      requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(responseStatus, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    server.start();
    client = newClient(true);
  }

  @AfterEach
  void stopStub() { server.stop(0); }

  private AiAgentRuntimeClient newClient(boolean enabled) {
    return new AiAgentRuntimeClient(new ObjectMapper(), mock(AssessmentProjectService.class),
        mock(TargetService.class), mock(SecurityTaskRepository.class), mock(AgentWorkflowSpecService.class),
        enabled, "http://127.0.0.1:" + server.getAddress().getPort(), 8090,
        "test-token", "test-signing-secret", 1, 20);
  }

  private void save() {
    client.appendMemory(7, 9, "conv-test", "Summary", "Public answer", "session-a", "2026-09-29T12:00:00Z");
  }

  @ParameterizedTest
  @ValueSource(strings = {"save", "list", "delete", "clear"})
  void runtimeFailureIsNotReportedAsSuccessOrEmptyData(String operation) {
    responseStatus = 503;
    responseBody = "{\"detail\":\"private-upstream-detail\"}";
    assertThatThrownBy(() -> invoke(operation)).isInstanceOfSatisfying(ResponseStatusException.class, error -> {
      assertThat(error.getStatusCode().value()).isEqualTo(503);
      assertThat(error.getReason()).contains("AI 对话记忆").doesNotContain("private-upstream-detail");
    });
  }

  @ParameterizedTest
  @ValueSource(strings = {"save", "list", "delete", "clear"})
  void malformedAcknowledgementIsNotSuccess(String operation) {
    responseBody = "{}";
    assertThatThrownBy(() -> invoke(operation)).isInstanceOf(ResponseStatusException.class);
  }

  @Test
  void saveRequiresAnAcknowledgementAndPreservesConversationScope() throws Exception {
    responseBody = "{\"status\":\"APPENDED\"}";
    save();
    var document = new ObjectMapper().readTree(requestBody).path("documents").get(0);
    assertThat(document.path("metadata").path("conversationId").asText()).isEqualTo("session-a");
    assertThat(document.path("metadata").path("targetId").asText()).isEqualTo("9");
    assertThat(document.path("source").asText()).isEqualTo("conversation");
    assertThat(requestUri).isEqualTo("/index/project/7/documents");
  }

  @Test
  void returnsActualDeleteAndListResults() {
    responseBody = "{\"deleted\":false}";
    assertThat(client.deleteMemory(7, "missing")).isFalse();
    responseBody = "{\"deleted\":true}";
    assertThat(client.deleteMemory(7, "present")).isTrue();
    responseBody = "{\"documents\":[]}";
    assertThat(client.listMemories(7)).isEmpty();
    responseBody = "{\"deleted\":2}";
    assertThat(client.clearMemories(7)).isEqualTo(2);
  }

  @Test
  void disabledRuntimeDoesNotClaimToSaveOrReadMemory() {
    client = newClient(false);
    assertThatThrownBy(this::save).isInstanceOf(ResponseStatusException.class);
    assertThatThrownBy(() -> client.listMemories(7)).isInstanceOf(ResponseStatusException.class);
    assertThat(requestUri).isNull();
  }

  private Object invoke(String operation) {
    return switch (operation) {
      case "save" -> { save(); yield null; }
      case "list" -> client.listMemories(7);
      case "delete" -> client.deleteMemory(7, "conv-test");
      case "clear" -> client.clearMemories(7);
      default -> throw new IllegalArgumentException(operation);
    };
  }
}
