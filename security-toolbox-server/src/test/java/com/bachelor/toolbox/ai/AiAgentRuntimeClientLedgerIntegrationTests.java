package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Integration tests that wire a real {@link AgentLedgerService} behind {@link
 * AiAgentRuntimeClient#consumeStream}, verifying that a legal v3 stream persists a continuous
 * authoritative ledger, that terminal entries reject further appends, and that replaying the
 * same nodeRun is idempotent.
 */
@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:runtime-ledger;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
class AiAgentRuntimeClientLedgerIntegrationTests {

  private static final String GENESIS_DIGEST = "sha256:" + "0".repeat(64);
  private static final String WORKFLOW_DIGEST = "sha256:" + "a".repeat(64);
  private static final String WORKFLOW_ID = "wf-int-01";
  private static final long WORKFLOW_REVISION = 1L;
  private static final String OUTER_NODE_ID = "ledger-agent";
  private static final String NODE_RUN_ID = "node-run-int-01";
  private static final String POLICY_REVISION = "java-authoritative-v1";
  private static final String RUN_ID = "run-int-0001";

  @Autowired private AgentLedgerRecordRepository repository;
  @Autowired private PlatformTransactionManager transactionManager;

  private AgentLedgerService ledger;
  private final ObjectMapper mapper = new ObjectMapper();

  @BeforeEach
  void setUp() {
    repository.deleteAllInBatch();
    ledger = new AgentLedgerService(repository, new ObjectMapper(), transactionManager);
  }

  @AfterEach
  void tearDown() {
    repository.deleteAllInBatch();
  }

  private AiAgentRuntimeClient newClient() {
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
        "int-session",
        "介绍一下项目",
        false,
        null,
        java.util.List.of(),
        "standard",
        "turn-int-01",
        WORKFLOW_ID,
        WORKFLOW_REVISION,
        WORKFLOW_DIGEST,
        OUTER_NODE_ID,
        NODE_RUN_ID);
  }

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
  void legalStreamPersistsContinuousAuthoritativeLedger() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    java.util.List<AiAgentRuntimeClient.RuntimeEvent> seen = new java.util.ArrayList<>();
    AiAgentRuntimeClient.RuntimePlanResult result =
        client.consumeStream(RUN_ID, toNdjson(events), request(), seen::add);

    assertThat(result.status()).isEqualTo("COMPLETED");

    // The authoritative ledger must contain exactly the 4 events in sequence.
    java.util.List<AgentLedgerRecord> records =
        ledger.read(RUN_ID, NODE_RUN_ID);
    assertThat(records).hasSize(4);
    assertThat(records).extracting(AgentLedgerRecord::getSequence)
        .containsExactly(1L, 2L, 3L, 4L);
    assertThat(records).extracting(AgentLedgerRecord::getEventType)
        .containsExactly("route", "plan", "authorization_guard", "finish");
    assertThat(records).extracting(AgentLedgerRecord::getStatus)
        .containsExactly("IN_PROGRESS", "IN_PROGRESS", "IN_PROGRESS", "COMPLETED");

    // The authoritative hash chain must be continuous and verifiable.
    AgentLedgerService.VerificationResult verification = ledger.verify(RUN_ID, NODE_RUN_ID);
    assertThat(verification.valid()).isTrue();
    assertThat(verification.terminal()).isTrue();
    assertThat(verification.entryCount()).isEqualTo(4);

    // The authoritative entry digests must differ from the candidate digests.
    assertThat(records.get(0).getEntryDigest()).isNotEqualTo(events[0].get("ledgerEntryDigest").asText());
    assertThat(records.get(0).getPreviousEntryDigest()).isNull();
    assertThat(records.get(1).getPreviousEntryDigest()).isEqualTo(records.get(0).getEntryDigest());
    assertThat(records.get(2).getPreviousEntryDigest()).isEqualTo(records.get(1).getEntryDigest());
    assertThat(records.get(3).getPreviousEntryDigest()).isEqualTo(records.get(2).getEntryDigest());

    // The published events must carry the authoritative digests, not the candidate digests.
    assertThat(seen).hasSize(4);
    assertThat(seen.get(0).ledgerEntryDigest()).isEqualTo(records.get(0).getEntryDigest());
    assertThat(seen.get(3).ledgerEntryDigest()).isEqualTo(records.get(3).getEntryDigest());
  }

  @Test
  void terminalLedgerRejectsFurtherAppendAfterLegalStream() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    client.consumeStream(RUN_ID, toNdjson(events), request(), null);

    // The ledger is now terminal (COMPLETED). A direct append at sequence 5 must be rejected.
    AgentLedgerService.AppendRequest afterFinish =
        new AgentLedgerService.AppendRequest(
            RUN_ID,
            WORKFLOW_ID,
            WORKFLOW_REVISION,
            WORKFLOW_DIGEST,
            OUTER_NODE_ID,
            NODE_RUN_ID,
            5L,
            "review",
            "review",
            "REVIEWED",
            "sha256:" + "c".repeat(64),
            "sha256:" + "d".repeat(64),
            java.util.List.<String>of(),
            java.util.List.<String>of(),
            POLICY_REVISION,
            "none",
            Long.valueOf(71L),
            Long.valueOf(91L));

    assertThatThrownBy(() -> ledger.append(afterFinish))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("终态");
    assertThat(ledger.read(RUN_ID, NODE_RUN_ID)).hasSize(4);
  }

  @Test
  void replayingSameNodeRunIsIdempotentAndProducesNoDuplicateRecords() {
    AiAgentRuntimeClient client = newClient();
    ObjectNode[] events = legalGeneralQaStream();
    AiAgentRequest req = request();

    // First run persists 4 ledger entries.
    AiAgentRuntimeClient.RuntimePlanResult first =
        client.consumeStream(RUN_ID, toNdjson(events), req, null);
    assertThat(first.status()).isEqualTo("COMPLETED");

    // Replay the exact same stream (same eventIds, same candidate digests).
    AiAgentRuntimeClient.RuntimePlanResult replay =
        client.consumeStream(RUN_ID, toNdjson(events), req, null);
    assertThat(replay.status()).isEqualTo("COMPLETED");

    // The ledger must still contain exactly 4 entries, not 8.
    java.util.List<AgentLedgerRecord> records = ledger.read(RUN_ID, NODE_RUN_ID);
    assertThat(records).hasSize(4);
    assertThat(ledger.verify(RUN_ID, NODE_RUN_ID).valid()).isTrue();
    assertThat(repository.count()).isEqualTo(4);
  }
}