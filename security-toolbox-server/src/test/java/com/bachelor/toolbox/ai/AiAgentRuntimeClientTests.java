package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * Fixture-based tests for the v3 runtime protocol validation in {@link AiAgentRuntimeClient}.
 *
 * <p>These tests do not require a live Python runtime. They feed NDJSON event streams directly to
 * {@link AiAgentRuntimeClient#consumeStream}, exercising the candidate digest chain, state
 * version continuity, event ordering, and fail-closed behavior.
 */
class AiAgentRuntimeClientTests {

  private static final String GENESIS_DIGEST = "sha256:" + "0".repeat(64);
  private static final String WORKFLOW_DIGEST = "sha256:" + "a".repeat(64);
  private static final String WORKFLOW_ID = "wf-test-01";
  private static final long WORKFLOW_REVISION = 1L;
  private static final String OUTER_NODE_ID = "ledger-agent";
  private static final String NODE_RUN_ID = "node-run-01";
  private static final String POLICY_REVISION = "java-authoritative-v1";
  private static final String RUN_ID = "run-v3-fixture-0001";

  private final ObjectMapper mapper = new ObjectMapper();

  private AiAgentRuntimeClient newClient() {
    return newClientWithLedger(null);
  }

  private AiAgentRuntimeClient newClientWithLedger(AgentLedgerService ledger) {
    return new AiAgentRuntimeClient(
        mapper,
        mock(AssessmentProjectService.class),
        mock(TargetService.class),
        mock(SecurityTaskRepository.class),
        mock(AgentWorkflowSpecService.class),
        true,
        "http://127.0.0.1:8090",
        8090,
        "test-token",
        "test-signing-secret",
        30,
        20,
        ledger);
  }

  private AiAgentRequest request() {
    return new AiAgentRequest(
        71L,
        91L,
        "fixture-session",
        "介绍一下项目",
        false,
        null,
        java.util.List.of(),
        "standard",
        "turn-fixture-01",
        WORKFLOW_ID,
        WORKFLOW_REVISION,
        WORKFLOW_DIGEST,
        OUTER_NODE_ID,
        NODE_RUN_ID);
  }

  /**
   * Build a v3 runtime event envelope with a correct candidate digest chain entry.
   *
   * @param type event type (route, plan, authorization_guard, finish, ...)
   * @param node node name, also used as innerStep
   * @param data event data payload (will be sanitized to public fields only)
   * @param sequence 1-based state version / ledger sequence
   * @param previousDigest the previous event's ledgerEntryDigest (or genesis)
   * @return a JSON object node ready to be serialized as one NDJSON line
   */
  private ObjectNode v3Event(String type, String node, ObjectNode data, int sequence, String previousDigest) {
    ObjectNode event = mapper.createObjectNode();
    event.put("eventId", UUID.randomUUID().toString());
    event.put("type", type);
    event.put("node", node);
    event.put("message", type + " event");
    event.put("timestamp", "2026-08-08T00:00:%02d+00:00".formatted(sequence));
    event.set("data", data);
    event.put("contractVersion", 3);
    event.put("runId", RUN_ID);
    event.put("workflowDigest", WORKFLOW_DIGEST);
    event.put("outerNodeId", OUTER_NODE_ID);
    event.put("nodeRunId", NODE_RUN_ID);
    event.put("innerStep", node);
    event.put("stateVersion", sequence);
    event.put("ledgerSequence", sequence);
    event.put("policyRevision", POLICY_REVISION);
    event.put("ledgerEntryDigest", candidateDigest(event, previousDigest));
    return event;
  }

  /** Compute the candidate digest the same way the Java client and Python runtime do. */
  private String candidateDigest(ObjectNode event, String previousDigest) {
    Map<String, Object> publicEvent = new LinkedHashMap<>();
    publicEvent.put("eventId", event.get("eventId").asText());
    publicEvent.put("type", event.get("type").asText());
    publicEvent.put("node", event.get("node").asText());
    publicEvent.put("innerStep", event.get("innerStep").asText());
    publicEvent.put("message", event.get("message").asText());
    publicEvent.put("timestamp", event.get("timestamp").asText());
    publicEvent.put("data", mapper.convertValue(event.get("data"), Map.class));
    publicEvent.put("contractVersion", event.get("contractVersion").asInt());
    publicEvent.put("runId", event.get("runId").asText());
    publicEvent.put("workflowDigest", event.get("workflowDigest").asText());
    publicEvent.put("outerNodeId", event.get("outerNodeId").asText());
    publicEvent.put("nodeRunId", event.get("nodeRunId").asText());
    publicEvent.put("stateVersion", event.get("stateVersion").asInt());
    publicEvent.put("ledgerSequence", event.get("ledgerSequence").asLong());
    publicEvent.put("policyRevision", event.get("policyRevision").asText());
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("previousLedgerEntryDigest", previousDigest);
    payload.put("event", publicEvent);
    try {
      ObjectMapper canonical = mapper.copy();
      canonical.enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
      byte[] bytes = canonical.writeValueAsBytes(payload);
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
      return "sha256:" + HexFormat.of().formatHex(digest);
    } catch (Exception ex) {
      throw new IllegalStateException("cannot compute candidate digest", ex);
    }
  }

  private String toNdjson(ObjectNode... events) {
    StringBuilder sb = new StringBuilder();
    for (ObjectNode event : events) {
      sb.append(event.toString()).append("\n");
    }
    return sb.toString();
  }

  /** A minimal legal RAG_DISABLED GENERAL_QA stream: route -> plan -> authorization_guard -> finish. */
  private ObjectNode[] legalGeneralQaStream() {
    ObjectNode routeData = mapper.createObjectNode();
    routeData.put("status", "RAG_DISABLED");
    routeData.put("intent", "GENERAL_QA");
    routeData.put("needsRetrieval", false);
    routeData.putNull("retrievalQuery");
    routeData.put("publicReasonCode", "GENERAL_KNOWLEDGE");

    ObjectNode planData = mapper.createObjectNode();
    planData.put("summary", "general answer");
    planData.put("answer", "这是一个通用回答。");
    planData.put("intent", "answer");
    planData.put("knowledgeMode", "GENERAL");
    planData.set("evidenceRefs", mapper.createArrayNode());
    planData.put("actionCount", 0);
    planData.put("source", "rule-fallback");
    planData.putNull("warning");
    planData.set("actions", mapper.createArrayNode());
    planData.set("steps", mapper.createArrayNode());
    planData.put("stage", "engage");
    planData.put("legacyNode", "planner");

    ObjectNode guardData = mapper.createObjectNode();
    guardData.put("status", "NOT_APPLICABLE");
    guardData.put("executionRequired", false);
    guardData.put("stage", "engage");
    guardData.put("legacyNode", "authorization_guard");

    ObjectNode planNode = mapper.createObjectNode();
    planNode.put("summary", "general answer");
    planNode.put("answer", "这是一个通用回答。");
    planNode.put("intent", "answer");
    planNode.set("actions", mapper.createArrayNode());
    planNode.put("source", "rule-fallback");

    ObjectNode reviewNode = mapper.createObjectNode();
    reviewNode.put("status", "REVIEWED");
    reviewNode.put("referenceCount", 0);
    reviewNode.put("proposalCount", 0);

    ObjectNode finishData = mapper.createObjectNode();
    finishData.put("status", "COMPLETED");
    finishData.put("answer", "这是一个通用回答。");
    finishData.set("plan", planNode);
    finishData.set("review", reviewNode);
    finishData.set("violations", mapper.createArrayNode());
    finishData.put("retrievalRoundCount", 0);
    finishData.set("evidenceIds", mapper.createArrayNode());
    finishData.putNull("indexRevision");
    finishData.put("plannerSource", "rule-fallback");
    finishData.putNull("terminationReason");

    ObjectNode route = v3Event("route", "route", routeData, 1, GENESIS_DIGEST);
    ObjectNode plan = v3Event("plan", "engage", planData, 2, route.get("ledgerEntryDigest").asText());
    ObjectNode guard = v3Event("authorization_guard", "engage", guardData, 3, plan.get("ledgerEntryDigest").asText());
    ObjectNode finish = v3Event("finish", "finish", finishData, 4, guard.get("ledgerEntryDigest").asText());
    return new ObjectNode[] {route, plan, guard, finish};
  }

  @Test
  void legalV3GeneralQaStreamProducesCompletedResult() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    java.util.List<AiAgentRuntimeClient.RuntimeEvent> seen = new java.util.ArrayList<>();
    AiAgentRuntimeClient.RuntimePlanResult result =
        client.consumeStream(RUN_ID, toNdjson(events), request(), seen::add);

    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(result.runId()).isEqualTo(RUN_ID);
    assertThat(result.policyRevision()).isEqualTo(POLICY_REVISION);
    assertThat(result.plan().steps()).isEmpty();
    assertThat(result.provenance().retrievalRoundCount()).isEqualTo(0);
    assertThat(result.provenance().plannerSource()).isEqualTo("rule-fallback");
    assertThat(seen).hasSize(4);
    assertThat(seen).extracting(AiAgentRuntimeClient.RuntimeEvent::type)
        .containsExactly("route", "plan", "authorization_guard", "finish");
    assertThat(seen).extracting(AiAgentRuntimeClient.RuntimeEvent::ledgerSequence)
        .containsExactly(1L, 2L, 3L, 4L);
  }

  @Test
  void tamperedCandidateDigestIsRejectedBeforeAnyLedgerWrite() {
    AgentLedgerService ledger = mock(AgentLedgerService.class);
    AiAgentRuntimeClient client = newClientWithLedger(ledger);
    ObjectNode[] events = legalGeneralQaStream();
    // Tamper with the plan event's data without recalculating the digest.
    events[1].withObject("data").put("summary", "tampered summary");
    AiAgentRequest req = request();

    assertThatThrownBy(() -> client.consumeStream(RUN_ID, toNdjson(events), req, null))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("候选 Ledger 摘要链无效");
    verifyNoInteractions(ledger);
  }

  @Test
  void truncatedStreamMissingFinishIsRejectedBeforeAnyLedgerWrite() {
    AgentLedgerService ledger = mock(AgentLedgerService.class);
    AiAgentRuntimeClient client = newClientWithLedger(ledger);
    ObjectNode[] events = legalGeneralQaStream();
    // Drop the finish event so the stream ends after authorization_guard.
    String ndjson = toNdjson(events[0], events[1], events[2]);

    assertThatThrownBy(() -> client.consumeStream(RUN_ID, ndjson, request(), null))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("终态前中断");
    verifyNoInteractions(ledger);
  }

  @Test
  void duplicateEventIdIsRejected() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    // Force the plan event to reuse the route event's eventId.
    events[1].put("eventId", events[0].get("eventId").asText());
    // Recompute the plan digest so the only violation is the duplicate eventId.
    events[1].put("ledgerEntryDigest", candidateDigest(events[1], events[0].get("ledgerEntryDigest").asText()));

    assertThatThrownBy(() -> client.consumeStream(RUN_ID, toNdjson(events), request(), null))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("重复使用 eventId");
  }

  @Test
  void mismatchedWorkflowDigestIsRejected() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    // Change the finish event's workflowDigest without recalculating the chain.
    events[3].put("workflowDigest", "sha256:" + "b".repeat(64));
    events[3].put("ledgerEntryDigest", candidateDigest(events[3], events[2].get("ledgerEntryDigest").asText()));

    assertThatThrownBy(() -> client.consumeStream(RUN_ID, toNdjson(events), request(), null))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("运行标识或状态版本不连续");
  }

  @Test
  void outOfOrderLedgerSequenceIsRejected() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    // Jump the plan event's ledgerSequence from 2 to 5 while keeping stateVersion at 2.
    events[1].put("ledgerSequence", 5);
    events[1].put("ledgerEntryDigest", candidateDigest(events[1], events[0].get("ledgerEntryDigest").asText()));

    assertThatThrownBy(() -> client.consumeStream(RUN_ID, toNdjson(events), request(), null))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("运行标识或状态版本不连续");
  }

  @Test
  void eventAfterFinishIsRejected() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    // Append an extra route event after finish.
    ObjectNode extra = v3Event("route", "route", mapper.createObjectNode(), 5, events[3].get("ledgerEntryDigest").asText());

    assertThatThrownBy(() -> client.consumeStream(RUN_ID, toNdjson(events[0], events[1], events[2], events[3], extra), request(), null))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("终态后继续发送事件");
  }
}
