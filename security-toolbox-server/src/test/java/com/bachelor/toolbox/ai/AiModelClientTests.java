package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AiModelClientTests {
  @Test
  void permitsHttpsRemoteAndHttpLoopbackAiEndpointsOnly() {
    assertThat(AiModelClient.validatedBaseUrl("https://api.openai.com/"))
        .isEqualTo("https://api.openai.com");
    assertThat(AiModelClient.validatedBaseUrl("http://127.0.0.1:11434"))
        .isEqualTo("http://127.0.0.1:11434");
    assertThat(AiModelClient.validatedBaseUrl("http://[::1]:11434"))
        .isEqualTo("http://[::1]:11434");

    assertThatThrownBy(() -> AiModelClient.validatedBaseUrl("http://api.example.com"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("必须使用 HTTPS");
    assertThatThrownBy(() -> AiModelClient.validatedBaseUrl("https://user:pass@api.example.com"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void repairsUtf8TextDecodedAsLatin1() {
    String mojibake = "\u00e4\u00bd\u00a0\u00e5\u00a5\u00bd\u00ef\u00bc\u0081";

    assertThat(AiModelClient.repairUtf8Mojibake(mojibake)).isEqualTo("\u4f60\u597d\uff01");
  }

  @Test
  void parsesResponsesSseTextDeltas() throws Exception {
    AiModelClient client =
        new AiModelClient(
            new ObjectMapper(), true, "http://127.0.0.1:1", "", "test-model", "responses", 1);
    String stream =
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"你\"}\n\n"
            + "data: {\"type\":\"response.output_text.delta\",\"delta\":\"好\"}\n\n"
            + "data: [DONE]\n";

    assertThat(client.parseResponseStream(stream)).isEqualTo("你好");
  }

  @Test
  void fallsBackToCompletedResponseTextWhenThereAreNoDeltas() throws Exception {
    AiModelClient client =
        new AiModelClient(
            new ObjectMapper(), true, "http://127.0.0.1:1", "", "test-model", "responses", 1);
    String stream =
        "data:"
            + " {\"type\":\"response.completed\",\"response\":{\"output\":[{\"content\":[{\"type\":\"output_text\",\"text\":\"完成\"}]}]}}\n";

    assertThat(client.parseResponseStream(stream)).isEqualTo("完成");
  }

  @Test
  void exposesOnlyExplicitReasoningSummaryAndOutputActivity() throws Exception {
    AiModelClient client =
        new AiModelClient(
            new ObjectMapper(), true, "http://127.0.0.1:1", "", "test-model", "responses", 1);
    String stream =
        "data: {\"type\":\"response.created\"}\n\n"
            + "data: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"检查授权范围\"}\n\n"
            + "data:"
            + " {\"type\":\"response.reasoning.encrypted_content.delta\",\"delta\":\"hidden-cot\"}\n\n"
            + "data:"
            + " {\"type\":\"response.output_text.delta\",\"delta\":\"{\\\"steps\\\":[]}\"}\n\n";
    List<AiModelClient.AiModelStreamEvent> events = new ArrayList<>();

    String result = client.parseResponseStream(stream, events::add);

    assertThat(result).isEqualTo("{\"steps\":[]}");
    assertThat(events)
        .anyMatch(
            event -> "reasoning_summary".equals(event.type()) && "检查授权范围".equals(event.text()));
    assertThat(events).anyMatch(event -> "output_delta".equals(event.type()));
    assertThat(events).noneMatch(event -> event.text().contains("hidden-cot"));
  }

  @Test
  void endlessModelStreamAbortsAtTotalLineCap() throws Exception {
    // Round 61：被攻陷/故障的模型提供方持续发数（读超时只防空闲）时，
    // SSE 消费必须在总行数上限处中止（与 R46 RuntimeClient 同族修复）。
    AiModelClient client =
        new AiModelClient(
            new ObjectMapper(), true, "http://127.0.0.1:1", "", "test-model", "responses", 1);
    StringBuilder endless = new StringBuilder();
    for (int i = 0; i < 150_000; i++) {
      endless.append("data: {\"type\":\"response.created\"}\n\n");
    }
    assertThatThrownBy(() -> client.parseResponseStream(endless.toString()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("总时长/行数限制");
  }

  @Test
  void oversizedModelOutputAbortsAtCharacterCap() throws Exception {
    // Round 61：output StringBuilder 逐 delta 无界累积 -> 达 4MB 字符上限即中止。
    AiModelClient client =
        new AiModelClient(
            new ObjectMapper(), true, "http://127.0.0.1:1", "", "test-model", "responses", 1);
    StringBuilder stream = new StringBuilder();
    for (int i = 0; i < 6; i++) {
      // 单行 delta < 1MB（行上限），6 条累计 > 4MB（输出上限）
      stream.append("data: {\"type\":\"response.output_text.delta\",\"delta\":\"")
          .append("x".repeat(900_000))
          .append("\"}\n\n");
    }
    assertThatThrownBy(() -> client.parseResponseStream(stream.toString()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("输出超过大小限制");
  }
}
