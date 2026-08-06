package com.bachelor.toolbox.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
public class AiModelClient {
  private final boolean enabled;
  private final String apiKey;
  private final String model;
  private final String apiMode;
  private final RestClient restClient;
  private final ObjectMapper objectMapper;

  public AiModelClient(
      ObjectMapper objectMapper,
      @Value("${toolbox.ai.enabled:false}") boolean enabled,
      @Value("${toolbox.ai.base-url}") String baseUrl,
      @Value("${toolbox.ai.api-key:}") String apiKey,
      @Value("${toolbox.ai.model}") String model,
      @Value("${toolbox.ai.api-mode:chat}") String apiMode,
      @Value("${toolbox.ai.timeout-seconds:180}") int timeoutSeconds) {
    this.objectMapper = objectMapper;
    this.enabled = enabled;
    this.apiKey = apiKey == null ? "" : apiKey.trim();
    this.model = model;
    this.apiMode = "responses".equalsIgnoreCase(apiMode) ? "responses" : "chat";
    SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
    requestFactory.setConnectTimeout(Duration.ofSeconds(timeoutSeconds <= 0 ? 30 : timeoutSeconds));
    requestFactory.setReadTimeout(
        timeoutSeconds <= 0 ? Duration.ZERO : Duration.ofSeconds(timeoutSeconds));
    this.restClient =
        RestClient.builder()
            .baseUrl(validatedBaseUrl(baseUrl))
            .requestFactory(requestFactory)
            .build();
  }

  public boolean enabled() {
    return enabled;
  }

  public boolean responsesMode() {
    return "responses".equals(apiMode);
  }

  public String model() {
    return model;
  }

  static String validatedBaseUrl(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("AI API 地址不能为空");
    }
    final URI uri;
    try {
      uri = URI.create(value.strip());
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException("AI API 地址格式不正确", ex);
    }
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
    if (!("http".equals(scheme) || "https".equals(scheme))
        || host.isBlank()
        || uri.getUserInfo() != null
        || uri.getQuery() != null
        || uri.getFragment() != null) {
      throw new IllegalArgumentException("AI API 地址必须是无账号、查询参数和锚点的 HTTP(S) 地址");
    }
    boolean loopback =
        "localhost".equals(host)
            || "127.0.0.1".equals(host)
            || "::1".equals(host)
            || "[::1]".equals(host);
    if ("http".equals(scheme) && !loopback) {
      throw new IllegalArgumentException("远程 AI API 必须使用 HTTPS；HTTP 仅允许本机回环地址");
    }
    String normalized = value.strip();
    return normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized;
  }

  public JsonNode chat(Map<String, Object> body) {
    RestClient.RequestBodySpec request = restClient.post().uri("/v1/chat/completions");
    authorize(request, false);
    return request.body(body).retrieve().body(JsonNode.class);
  }

  public String complete(String system, String user) throws Exception {
    return responsesMode() ? responses(system, user) : chatText(system, user);
  }

  public String completeResponsesStream(
      String system, String user, Consumer<AiModelStreamEvent> listener) throws Exception {
    if (!responsesMode()) {
      throw new IllegalStateException("当前 AI API 模式不是 Responses");
    }
    Consumer<AiModelStreamEvent> safeListener = listener == null ? ignored -> {} : listener;
    RestClient.RequestBodySpec request = responsesRequest();
    return request
        .body(responsesBody(system, user))
        .exchange(
            (httpRequest, response) -> {
              if (response.getStatusCode().isError()) {
                String errorBody =
                    new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8);
                throw new IllegalStateException(
                    "AI Responses 请求失败（HTTP "
                        + response.getStatusCode().value()
                        + "）: "
                        + errorBody);
              }
              try (BufferedReader reader =
                  new BufferedReader(
                      new InputStreamReader(response.getBody(), StandardCharsets.UTF_8))) {
                String text = readResponseStream(reader, safeListener);
                if (text.isBlank()) {
                  throw new IllegalStateException("AI Responses 接口未返回文本内容");
                }
                return repairUtf8Mojibake(text.strip());
              }
            });
  }

  private String chatText(String system, String user) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("model", model);
    body.put(
        "messages",
        List.of(
            Map.of("role", "system", "content", system), Map.of("role", "user", "content", user)));
    JsonNode root = chat(body);
    String content =
        root == null ? "" : root.path("choices").path(0).path("message").path("content").asText("");
    if (content.isBlank()) {
      throw new IllegalStateException("AI 未返回回答内容");
    }
    return repairUtf8Mojibake(content.strip());
  }

  private String responses(String system, String user) throws Exception {
    RestClient.RequestBodySpec request = responsesRequest();
    String stream = request.body(responsesBody(system, user)).retrieve().body(String.class);
    String text = parseResponseStream(stream);
    if (text.isBlank()) {
      throw new IllegalStateException("AI Responses 接口未返回文本内容");
    }
    return repairUtf8Mojibake(text.strip());
  }

  static String repairUtf8Mojibake(String value) {
    if (value == null || value.isBlank()) {
      return value;
    }
    long suspiciousBefore = mojibakeScore(value);
    if (suspiciousBefore == 0 || value.chars().anyMatch(character -> character > 255)) {
      return value;
    }
    String repaired =
        new String(value.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    if (repaired.indexOf('\uFFFD') >= 0 || mojibakeScore(repaired) >= suspiciousBefore) {
      return value;
    }
    return repaired;
  }

  private static long mojibakeScore(String value) {
    return value
        .chars()
        .filter(
            character ->
                switch (character) {
                  case 'Ã', 'Â', 'ä', 'å', 'æ', 'ç', 'è', 'é', 'ï', 'ð' -> true;
                  default -> false;
                })
        .count();
  }

  private Map<String, Object> responsesBody(String system, String user) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("model", model);
    body.put("instructions", system);
    body.put(
        "input",
        List.of(
            Map.of(
                "type", "message",
                "role", "user",
                "content", List.of(Map.of("type", "input_text", "text", user)))));
    body.put("tools", List.of());
    body.put("tool_choice", "auto");
    body.put("parallel_tool_calls", true);
    body.put("reasoning", Map.of("effort", "medium", "summary", "auto"));
    body.put("text", Map.of("verbosity", "low"));
    body.put("stream", true);
    body.put("store", false);
    body.put("prompt_cache_key", "security-toolbox");
    return body;
  }

  private RestClient.RequestBodySpec responsesRequest() {
    RestClient.RequestBodySpec request =
        restClient
            .post()
            .uri("/v1/responses")
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.TEXT_EVENT_STREAM)
            .header("OpenAI-Beta", "responses=experimental")
            .header("originator", "codex_cli_rs")
            .header(HttpHeaders.USER_AGENT, "codex_cli_rs/security-toolbox");
    authorize(request, true);
    return request;
  }

  String parseResponseStream(String stream) throws Exception {
    if (stream == null || stream.isBlank()) {
      return "";
    }
    try (BufferedReader reader = new BufferedReader(new StringReader(stream))) {
      return readResponseStream(reader, ignored -> {});
    }
  }

  String parseResponseStream(String stream, Consumer<AiModelStreamEvent> listener)
      throws Exception {
    if (stream == null || stream.isBlank()) {
      return "";
    }
    try (BufferedReader reader = new BufferedReader(new StringReader(stream))) {
      return readResponseStream(reader, listener == null ? ignored -> {} : listener);
    }
  }

  private String readResponseStream(BufferedReader reader, Consumer<AiModelStreamEvent> listener)
      throws IOException {
    StringBuilder output = new StringBuilder();
    String completedText = "";
    String line;
    while ((line = reader.readLine()) != null) {
      if (!line.startsWith("data:")) {
        continue;
      }
      String data = line.substring(5).trim();
      if (data.isEmpty() || "[DONE]".equals(data)) {
        continue;
      }
      JsonNode event = objectMapper.readTree(data);
      String type = event.path("type").asText("").toLowerCase(Locale.ROOT);
      // Every upstream event proves that the connection is active. The socket read timeout
      // therefore acts as an idle timeout and is reset whenever CCS sends another event.
      listener.accept(new AiModelStreamEvent("activity", safeStatus(type)));
      if ("response.output_text.delta".equals(type)) {
        String delta = event.path("delta").asText("");
        output.append(delta);
        listener.accept(new AiModelStreamEvent("output_delta", delta));
      } else if (type.contains("reasoning_summary") && type.endsWith(".delta")) {
        // Responses reasoning summaries are explicitly produced for display. Never expose
        // encrypted_content or any unrequested internal reasoning fields.
        String delta = event.path("delta").asText("");
        if (!delta.isBlank()) {
          listener.accept(new AiModelStreamEvent("reasoning_summary", delta));
        }
      } else if ("response.completed".equals(type)) {
        completedText = extractResponseText(event.path("response"));
      } else if (type.endsWith("error") || "error".equals(type)) {
        throw new IllegalStateException(
            event.path("error").path("message").asText("AI Responses 请求失败"));
      }
    }
    return output.length() > 0 ? output.toString() : completedText;
  }

  private String safeStatus(String type) {
    return switch (type) {
      case "response.created" -> "AI 已连接，开始分析授权请求";
      case "response.in_progress", "response.queued" -> "AI 正在分析目标与授权范围";
      case "response.output_item.added", "response.content_part.added" -> "AI 正在组织可执行检测计划";
      case "response.completed" -> "AI 已完成计划生成";
      default -> "AI 正在处理请求";
    };
  }

  private String extractResponseText(JsonNode response) {
    StringBuilder text = new StringBuilder();
    for (JsonNode output : response.path("output")) {
      for (JsonNode content : output.path("content")) {
        if ("output_text".equals(content.path("type").asText()) || content.has("text")) {
          text.append(content.path("text").asText(""));
        }
      }
    }
    return text.toString();
  }

  private void authorize(RestClient.RequestBodySpec request, boolean ccsFallback) {
    if (!apiKey.isBlank()) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey);
    } else if (ccsFallback) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer ccs-proxy");
    }
  }

  public record AiModelStreamEvent(String type, String text) {}
}
