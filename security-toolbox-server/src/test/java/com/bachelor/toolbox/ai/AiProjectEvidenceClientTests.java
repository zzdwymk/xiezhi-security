package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class AiProjectEvidenceClientTests {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String QUERY = "已观察到的风险 Evidence";
  private static final String DIGEST = "sha256:" + "a".repeat(64);
  private HttpServer server;
  private AiAgentRuntimeClient client;
  private volatile int responseStatus = 200;
  private volatile String responseBody;
  private volatile String requestBody;
  private volatile String requestUri;
  private volatile String requestMethod;
  private volatile String requestAuthorization;
  private volatile String requestToken;
  private final AtomicInteger requests = new AtomicInteger();

  @BeforeEach
  void startServer() throws Exception {
    responseBody = bundle().toString();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      requests.incrementAndGet();
      requestMethod = exchange.getRequestMethod();
      requestUri = exchange.getRequestURI().toString();
      requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      requestAuthorization = exchange.getRequestHeaders().getFirst("X-AI-Project-Authorization");
      requestToken = exchange.getRequestHeaders().getFirst("X-AI-Runtime-Token");
      byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(responseStatus, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    });
    server.start();
    client = newClient(true);
  }

  @AfterEach
  void stopServer() {
    server.stop(0);
  }

  @ParameterizedTest
  @ValueSource(strings = {"bm25", "real_embedding"})
  void sendsSignedScopedQueryAndReturnsCompleteValidatedBundle(String method) throws Exception {
    ObjectNode expected = bundle();
    expected.put("retrievalMethod", method);
    ObjectNode projectItem = item().put("evidenceId", "ev-project").put("source", "project");
    projectItem.putNull("targetId");
    ((ArrayNode) expected.get("items")).add(projectItem);
    responseBody = expected.toString();

    Map<String, Object> result = client.retrieveProjectEvidence(7L, 9L, "  " + QUERY + "  ");

    assertThat(MAPPER.<JsonNode>valueToTree(result)).isEqualTo(expected);
    assertThat(requests.get()).isEqualTo(1);
    assertThat(requestMethod).isEqualTo("POST");
    assertThat(requestUri).isEqualTo("/index/project/7/query");
    assertThat(MAPPER.readTree(requestBody))
        .isEqualTo(MAPPER.valueToTree(Map.of("targetId", 9, "query", QUERY, "topK", 5)));
    assertThat(requestToken).isEqualTo("fixture-token");
    String[] authorization = requestAuthorization.split(":");
    assertThat(authorization).hasSize(5);
    assertThat(authorization[0]).isEqualTo("v1");
    assertThat(authorization[1]).isEqualTo("7");
    assertThat(authorization[2]).isEqualTo("index-read");
    assertThat(Long.parseLong(authorization[3]))
        .isBetween(Instant.now().getEpochSecond() + 45, Instant.now().getEpochSecond() + 65);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec("fixture-signing-secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    String signedMessage = String.join(":", authorization[0], authorization[1], authorization[2], authorization[3]);
    assertThat(authorization[4]).isEqualTo(HexFormat.of().formatHex(mac.doFinal(signedMessage.getBytes(StandardCharsets.UTF_8))));
  }

  @Test
  void actualEmptyRetrievalStillReturnsProvenance() {
    ObjectNode expected = bundle();
    expected.putArray("items");
    responseBody = expected.toString();
    assertThat(MAPPER.<JsonNode>valueToTree(client.retrieveProjectEvidence(7L, 9L, QUERY))).isEqualTo(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"\u00a0", "\u2007", "\u202f"})
  void unicodeOuterSpacesMatchPythonStripWithoutChangingInternalQuery(String padding) throws Exception {
    String query = "项目" + padding + "检索  Evidence";
    ObjectNode expected = bundle().put("query", query);
    responseBody = expected.toString();
    Map<String, Object> result = client.retrieveProjectEvidence(7L, 9L, padding + query + padding);
    assertThat(MAPPER.readTree(requestBody).get("query").textValue()).isEqualTo(query);
    assertThat(MAPPER.<JsonNode>valueToTree(result)).isEqualTo(expected);
  }

  @Test
  void acceptsExactSnippetBudgetAndSchemaTextLimitsWithoutDiscardingFields() {
    ObjectNode expected = bundle();
    ArrayNode items = expected.putArray("items");
    for (int i = 0; i < 6; i++) {
      items.add(item().put("evidenceId", "ev-" + i).put("documentId", "d".repeat(128))
          .put("title", "t".repeat(300)).put("source", "s".repeat(200))
          .put("snippet", "片".repeat(2000)).put("score", 0));
    }
    responseBody = expected.toString();
    assertThat(MAPPER.<JsonNode>valueToTree(client.retrieveProjectEvidence(7L, 9L, QUERY))).isEqualTo(expected);
  }

  @Test
  void unicodeCodePointsMatchPythonQuerySnippetAndTotalBudgetLimits() throws Exception {
    String query = "😀".repeat(2000);
    ObjectNode expected = bundle().put("query", query);
    ArrayNode items = expected.putArray("items");
    for (int i = 0; i < 6; i++) {
      items.add(item().put("evidenceId", "ev-" + i).put("snippet", "😀".repeat(2000)));
    }
    responseBody = expected.toString();
    Map<String, Object> result = client.retrieveProjectEvidence(7L, 9L, query);
    assertThat(MAPPER.readTree(requestBody).get("query").textValue()).isEqualTo(query);
    assertThat(MAPPER.<JsonNode>valueToTree(result)).isEqualTo(expected);
  }

  @ParameterizedTest(name = "invalid input: {0}")
  @MethodSource("invalidInputs")
  void rejectsInvalidInputsBeforeSendingAnyRequest(String label, Long projectId, Long targetId, String query) {
    assertThatThrownBy(() -> client.retrieveProjectEvidence(projectId, targetId, query))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(requests.get()).isZero();
  }

  static Stream<Arguments> invalidInputs() {
    return Stream.of(
        Arguments.of("missing project", null, 9L, QUERY),
        Arguments.of("zero project", 0L, 9L, QUERY),
        Arguments.of("negative project", -1L, 9L, QUERY),
        Arguments.of("missing target", 7L, null, QUERY),
        Arguments.of("zero target", 7L, 0L, QUERY),
        Arguments.of("negative target", 7L, -1L, QUERY),
        Arguments.of("missing query", 7L, 9L, null),
        Arguments.of("empty query", 7L, 9L, ""),
        Arguments.of("blank query", 7L, 9L, "   "),
        Arguments.of("unicode blank query", 7L, 9L, "\u00a0\u2007\u202f"),
        Arguments.of("oversize query", 7L, 9L, "q".repeat(2001)),
        Arguments.of("oversize unicode query", 7L, 9L, "😀".repeat(2001)),
        Arguments.of("oversize raw query", 7L, 9L, " ".repeat(2000) + "q"),
        Arguments.of("NUL", 7L, 9L, "q\u0000"),
        Arguments.of("line feed", 7L, 9L, "q\n"),
        Arguments.of("carriage return", 7L, 9L, "q\r"),
        Arguments.of("tab", 7L, 9L, "q\t"),
        Arguments.of("DEL", 7L, 9L, "q\u007f"),
        Arguments.of("C1", 7L, 9L, "q\u0085"));
  }

  @ParameterizedTest
  @ValueSource(ints = {401, 403, 422, 500, 503})
  void upstreamFailureCannotBecomeEmptySuccessfulRetrieval(int status) {
    responseStatus = status;
    responseBody = "{\"detail\":\"private-upstream-detail\"}";
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeUnavailableException.class)
        .hasMessage("项目依据检索暂时不可用，请稍后重试");
    assertThat(requests.get()).isEqualTo(1);
  }

  @Test
  void disabledRuntimeDoesNotSendRequestOrReturnEmptyData() {
    client = newClient(false);
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeUnavailableException.class);
    assertThat(requests.get()).isZero();
  }

  @Test
  void unavailableLoopbackRuntimeFailsInsteadOfReturningEmptyData() {
    server.stop(0);
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeUnavailableException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "{", "[]", "null", "{}"})
  void incompleteJsonCannotBeReturnedAsEvidence(String response) {
    responseBody = response;
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
  }

  @Test
  void rejectsDuplicateResponseKeysAndTrailingJson() {
    responseBody = bundle().toString().replace("\"projectId\":7", "\"projectId\":8,\"projectId\":7");
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
    responseBody = bundle() + " {}";
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
  }

  @ParameterizedTest(name = "invalid bundle: {0}")
  @MethodSource("invalidBundles")
  void rejectsWrongScopeMalformedProvenanceAndUnboundedEvidence(String label, Consumer<ObjectNode> mutation) {
    ObjectNode invalid = bundle();
    mutation.accept(invalid);
    responseBody = invalid.toString();
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
  }

  static Stream<Arguments> invalidBundles() {
    return Stream.of(
        mutation("other project", root -> root.put("projectId", 8)),
        mutation("string project", root -> root.put("projectId", "7")),
        mutation("floating project", root -> root.put("projectId", 7.0)),
        mutation("overflow project", root -> root.put("projectId", new BigInteger("18446744073709551623"))),
        mutation("missing project", root -> root.remove("projectId")),
        mutation("other target", root -> root.put("targetId", 10)),
        mutation("null target", root -> root.putNull("targetId")),
        mutation("string target", root -> root.put("targetId", "9")),
        mutation("conversation scope", root -> root.put("conversationId", "other-chat")),
        mutation("missing conversation scope", root -> root.remove("conversationId")),
        mutation("query mismatch", root -> root.put("query", QUERY.toLowerCase())),
        mutation("query normalization", root -> root.put("query", QUERY + " ")),
        mutation("wrong round", root -> root.put("round", 1)),
        mutation("floating round", root -> root.put("round", 0.0)),
        mutation("unknown retrieval method", root -> root.put("retrievalMethod", "fallback")),
        mutation("invalid revision", root -> root.put("indexRevision", "a".repeat(64))),
        mutation("unknown bundle field", root -> root.put("untrusted", true)),
        mutation("missing items", root -> root.remove("items")),
        mutation("null items", root -> root.putNull("items")),
        mutation("object items", root -> root.putObject("items")),
        mutation("unknown item field", root -> first(root).put("untrusted", true)),
        mutation("other item target", root -> first(root).put("targetId", 10)),
        mutation("floating item target", root -> first(root).put("targetId", 9.0)),
        mutation("null nonproject target", root -> first(root).putNull("targetId")),
        mutation("project item other target", root -> first(root).put("source", "project").put("targetId", 10)),
        mutation("conversation source", root -> first(root).put("source", "conversation")),
        mutation("mixed case conversation source", root -> first(root).put("source", "ConverSation")),
        mutation("padded conversation source", root -> first(root).put("source", "\u00a0CONVERSATION\u202f")),
        mutation("conversation source without target", root -> first(root).put("source", "conversation").putNull("targetId")),
        mutation("negative score", root -> first(root).put("score", -0.1)),
        mutation("string score", root -> first(root).put("score", "1.0")),
        mutation("nonfinite score", root -> first(root).put("score", Double.POSITIVE_INFINITY)),
        mutation("invalid content digest", root -> first(root).put("contentDigest", "sha256:" + "A".repeat(64))),
        mutation("invalid evidence identifier", root -> first(root).put("evidenceId", "not an id")),
        mutation("duplicate evidence", root -> ((ArrayNode) root.get("items")).add(first(root).deepCopy())),
        mutation("too many items", root -> fillItems(root, 11, 1)),
        mutation("too much snippet text", root -> fillItems(root, 7, 2000)),
        mutation("oversize unicode snippet", root -> first(root).put("snippet", "😀".repeat(2001))),
        mutation("control in snippet", root -> first(root).put("snippet", "text\u0000")));
  }

  @ParameterizedTest
  @ValueSource(strings = {"evidenceId", "documentId", "title", "source", "snippet", "score", "targetId", "contentDigest"})
  void everyItemFieldIsRequired(String field) {
    ObjectNode invalid = bundle();
    first(invalid).remove(field);
    responseBody = invalid.toString();
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
  }

  @ParameterizedTest
  @MethodSource("boundedTextFields")
  void itemTextCannotBeBlankOrExceedSchemaLimit(String field, int limit) {
    ObjectNode invalid = bundle();
    first(invalid).put(field, " ");
    responseBody = invalid.toString();
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
    first(invalid).put(field, "a".repeat(limit + 1));
    responseBody = invalid.toString();
    assertThatThrownBy(() -> client.retrieveProjectEvidence(7L, 9L, QUERY))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
  }

  static Stream<Arguments> boundedTextFields() {
    return Stream.of(Arguments.of("evidenceId", 128), Arguments.of("documentId", 128),
        Arguments.of("title", 300), Arguments.of("source", 200), Arguments.of("snippet", 2000));
  }

  private static Arguments mutation(String label, Consumer<ObjectNode> mutation) {
    return Arguments.of(label, mutation);
  }

  private static void fillItems(ObjectNode root, int count, int snippetLength) {
    ArrayNode items = root.putArray("items");
    for (int i = 0; i < count; i++) {
      items.add(item().put("evidenceId", "ev-" + i).put("snippet", "a".repeat(snippetLength)));
    }
  }

  private static ObjectNode first(ObjectNode root) {
    return (ObjectNode) root.get("items").get(0);
  }

  private static ObjectNode item() {
    return MAPPER.createObjectNode().put("evidenceId", "ev-task-42")
        .put("documentId", "task-42").put("title", "实际扫描结果")
        .put("source", "task").put("snippet", "已观察匹配，扫描未完成")
        .put("score", 1.5).put("targetId", 9).put("contentDigest", DIGEST);
  }

  private static ObjectNode bundle() {
    ObjectNode bundle = MAPPER.createObjectNode().put("projectId", 7).put("targetId", 9)
        .putNull("conversationId").put("query", QUERY).put("round", 0)
        .put("retrievalMethod", "bm25").put("indexRevision", DIGEST);
    bundle.putArray("items").add(item());
    return bundle;
  }

  private AiAgentRuntimeClient newClient(boolean enabled) {
    return new AiAgentRuntimeClient(MAPPER, mock(AssessmentProjectService.class),
        mock(TargetService.class), mock(SecurityTaskRepository.class), mock(AgentWorkflowSpecService.class),
        enabled, "http://127.0.0.1:" + server.getAddress().getPort(), 8090,
        "fixture-token", "fixture-signing-secret", 1, 20);
  }
}
