package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

/**
 * Replays a captured production stream (from the live desktop runtime) through
 * {@link AiAgentRuntimeClient#consumeStream} so an exact Java-side rejection is reproduced
 * with the runtime's own bytes. The fixture is skipped when the capture file is absent.
 */
class CapturedStreamReplayTest {

  private static final String RUN_ID_FILE = "runid.txt";

  private static String readRunId() throws Exception {
    Path marker = Path.of(System.getProperty("java.io.tmpdir"), RUN_ID_FILE);
    return Files.exists(marker) ? Files.readString(marker, StandardCharsets.UTF_8).trim() : "";
  }

  private static String readWorkflowDigest() throws Exception {
    Path marker = Path.of(System.getProperty("java.io.tmpdir"), "wfdigest.txt");
    return Files.exists(marker) ? Files.readString(marker, StandardCharsets.UTF_8).trim()
        : "sha256:" + "0".repeat(64);
  }

  private static String readNodeRunId() throws Exception {
    Path marker = Path.of(System.getProperty("java.io.tmpdir"), "noderunid.txt");
    return Files.exists(marker) ? Files.readString(marker, StandardCharsets.UTF_8).trim() : "node-test-01";
  }

  private static Path fixture() {
    return Path.of(System.getProperty("java.io.tmpdir"), "replica.ndjson");
  }

  static boolean fixtureExists() {
    return Files.exists(fixture());
  }
  private static String readConversationId() throws Exception {
    Path marker = Path.of(System.getProperty("java.io.tmpdir"), "convid.txt");
    return Files.exists(marker) ? Files.readString(marker, StandardCharsets.UTF_8).trim() : "replica-session";
  }

  @Test
  @EnabledIf("fixtureExists")
  void replaysCapturedAutoPlanStream() throws Exception {
    String ndjson = Files.readString(fixture(), StandardCharsets.UTF_8);
    String runId = readRunId();
    String workflowDigest = readWorkflowDigest();
    String nodeRunId = readNodeRunId();
    AiAgentRuntimeClient client = new AiAgentRuntimeClient(
        new ObjectMapper(),
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
        null);
    AiAgentRequest request = new AiAgentRequest(
        129L, 129L, readConversationId(),
        "192.168.222.139 这个目标，接下来你觉得该怎么推进？",
        true, null, java.util.List.of(), "standard", "turn-replica",
        "9f11ce0e-0722-4624-a321-d5cab66a89c8", 1L, workflowDigest, "ledger-agent", nodeRunId);
    try {
      var result = client.consumeStream(runId, ndjson, request, null);
      System.out.println("REPLAY OK status=" + result.status()
          + " steps=" + result.plan().steps().size()
          + " decision=" + result.executionDecision());
    } catch (AiAgentRuntimeClient.RuntimeProtocolException ex) {
      // Print the exact rejection message to the test output — this is the whole point.
      System.out.println("REPLAY REJECTED: " + ex.getMessage()); for (String line : ndjson.split("\n")) { if (line.contains("\"tool\"") && !line.contains("\"type\":\"plan\"")) continue; if (line.contains("workflowNodeId")) { /* find tools */ } } System.out.println("--- plan tools ---"); for (String line : ndjson.split("\n")) { java.util.regex.Matcher mm = java.util.regex.Pattern.compile("\"tool\":\"([a-z_]+)\"").matcher(line); while (mm.find()) System.out.println("tool=" + mm.group(1)); }
      throw ex;
    }
  }
}



