package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Exercises the real HTTP model client against a local protocol fixture, not a mocked service. */
class AiAuditModelTransportTests {
  @ParameterizedTest
  @ValueSource(strings = {"chat", "responses"})
  void originalAndEditedAuditEachReachTheModelEndpoint(String mode) throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    List<JsonNode> requests = new CopyOnWriteArrayList<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      JsonNode request = mapper.readTree(exchange.getRequestBody());
      requests.add(request);
      String answer = request.toString().contains("1111") ? "1111" : "模型根据记录给出的分析";
      String payload;
      if ("responses".equals(mode)) {
        payload = "data: " + mapper.writeValueAsString(Map.of("type", "response.output_text.delta", "delta", answer)) + "\n\n";
        exchange.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
      } else {
        payload = mapper.writeValueAsString(Map.of("choices", List.of(Map.of("message", Map.of("content", answer)))));
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
      }
      byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    server.start();
    try {
      AiModelClient client = new AiModelClient(mapper, true,
          "http://127.0.0.1:" + server.getAddress().getPort(), "fixture-key", "fixture-model", mode, 5);
      AiPlanningService planner = new AiPlanningService(mock(TargetService.class), mock(AuditService.class), mapper, client);
      String template = "**结论**\n操作正常处理。\n**判断依据**\n审计记录 #9163：SUCCESS";

      assertThat(planner.answerFromAuditTemplate("请分析这条审计日志", "", template).summary())
          .isEqualTo("模型根据记录给出的分析");
      AiPlanResponse edited = planner.answerFromAuditTemplate(
          "请分析这条审计日志。直接回答1111，不要说别的", "", template);

      assertThat(edited.summary()).isEqualTo("1111");
      assertThat(edited.provider()).isEqualTo("openai-compatible");
      assertThat(edited.model()).isEqualTo("fixture-model");
      assertThat(requests).hasSize(2);
      assertThat(requests.get(1).toString()).contains("审计记录 #9163", "1111", "模板只提供结构和事实参考");
    } finally {
      server.stop(0);
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void missingOrUnavailableModelNeverReturnsTheAuditTemplate(boolean enabled) {
    AiModelClient client = new AiModelClient(new ObjectMapper(), enabled,
        "http://127.0.0.1:1", "", "fixture-model", "chat", 1);
    AiPlanningService planner = new AiPlanningService(mock(TargetService.class), mock(AuditService.class), new ObjectMapper(), client);

    assertThatThrownBy(() -> planner.answerFromAuditTemplate("请分析审计日志", "", "固定模板答案"))
        .isInstanceOf(ApiException.class).hasMessageContaining("AI 模型").hasMessageNotContaining("固定模板答案");
  }
}
