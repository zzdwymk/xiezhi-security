package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.TaskExecutionService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@EnabledIfEnvironmentVariable(named = "AI_RUNTIME_E2E", matches = "true")
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:agent-runtime-e2e;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=runtime-e2e-admin-password",
      "toolbox.auth.jwt-secret=runtime-e2e-jwt-secret-with-more-than-thirty-two-bytes",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.ai.enabled=false",
      "toolbox.ai.agent.runtime-enabled=true",
      "toolbox.recon.passive-sources-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false"
    })
@AutoConfigureMockMvc
class AiPythonAgentRouteEndToEndTests {
  @Autowired private MockMvc mockMvc;
  @Autowired private SecurityTaskRepository tasks;
  @Autowired private AuditLogRepository audits;
  @MockBean private TaskExecutionService executionService;

  @BeforeEach
  void resetSideEffects() {
    tasks.deleteAll();
    audits.deleteAll();
    clearInvocations(executionService);
  }

  @DynamicPropertySource
  static void runtimeProperties(DynamicPropertyRegistry registry) {
    registry.add("toolbox.ai.agent.runtime-base-url", () -> System.getenv("AI_RUNTIME_URL"));
    registry.add("toolbox.ai.agent.runtime-token", () -> System.getenv("AI_RUNTIME_TOKEN"));
    registry.add(
        "toolbox.ai.agent.runtime-project-signing-secret",
        () -> System.getenv("AI_RUNTIME_PROJECT_SIGNING_SECRET"));
  }

  @Test
  void springAgentRouteUsesPythonPlannerAndJavaHarness() throws Exception {
    String jwt = login();
    long[] scope = createActiveTarget(jwt, "Runtime E2E");
    long projectId = scope[0];
    long targetId = scope[1];

    mockMvc
        .perform(
            post("/api/ai/agent")
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"projectId":%d,"targetId":%d,"sessionId":"ci-agent-route","turnId":"ci-agent-route-turn","prompt":"请扫描端口和服务","execute":true,"mode":"standard"}
                    """
                        .formatted(projectId, targetId)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.plan.provider").value("langgraph-runtime"))
        .andExpect(jsonPath("$.plan.steps[0].toolCode").value("nmap_service_scan"))
        .andExpect(jsonPath("$.guardStatus").value("ALLOWED"))
        .andExpect(jsonPath("$.executed").value(true))
        .andExpect(jsonPath("$.taskIds[0]").isNumber());

    assertThat(tasks.count()).isEqualTo(1);
    assertThat(audits.findAll())
        .extracting(AuditLog::getAction)
        .contains("CREATE_WORKFLOW_TASK", "AI_DISPATCH_TASKS", "AI_AGENT_TURN");
    AuditLog turnAudit =
        audits.findAll().stream()
            .filter(audit -> "AI_AGENT_TURN".equals(audit.getAction()))
            .findFirst()
            .orElseThrow();
    JsonNode provenance = new ObjectMapper().readTree(turnAudit.getDetail());
    assertThat(provenance.path("schemaVersion").asInt()).isEqualTo(3);
    assertThat(provenance.path("fallback").asBoolean()).isFalse();
    assertThat(provenance.path("retrievalRoundCount").asInt()).isEqualTo(1);
    assertThat(provenance.path("evidenceIds").isEmpty()).isFalse();
    assertThat(provenance.path("plannerSource").asText()).isEqualTo("langchain-grounded");
    assertThat(provenance.path("runtimeRunId").asText()).isNotBlank();
    verify(executionService, timeout(1_000)).executeAsync(anyLong());
  }

  @Test
  void maliciousMixedLlmPlanFailsClosedBeforeTaskCreation() throws Exception {
    String jwt = login();
    long[] scope = createActiveTarget(jwt, "Malicious Runtime E2E");

    mockMvc
        .perform(
            post("/api/ai/agent")
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"projectId":%d,"targetId":%d,"sessionId":"ci-malicious-route","turnId":"ci-malicious-route-turn","prompt":"MALICIOUS_MIXED_PLAN","execute":true,"mode":"standard"}
                    """
                        .formatted(scope[0], scope[1])))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("安全停止")));

    assertThat(tasks.count()).isZero();
    assertThat(audits.findAll())
        .extracting(AuditLog::getAction)
        .doesNotContain("CREATE_TASK", "AI_DISPATCH_TASKS");
    verifyNoInteractions(executionService);
  }

  @Test
  void rewrittenQueryStillDispatchesExactlyOnceThroughJavaBoundary() throws Exception {
    String jwt = login();
    long[] scope = createActiveTarget(jwt, "Rewrite E2E 改写查询");
    MvcResult streaming =
        mockMvc
            .perform(
                post("/api/ai/agent/stream")
                    .header("Authorization", "Bearer " + jwt)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        """
                        {"projectId":%d,"targetId":%d,"sessionId":"ci-rewrite-route","turnId":"ci-rewrite-route-turn","prompt":"MOCK_REWRITE_ONCE 请扫描端口和服务","execute":true,"mode":"standard"}
                        """
                            .formatted(scope[0], scope[1])))
            .andExpect(request().asyncStarted())
            .andReturn();
    String ndjson =
        mockMvc
            .perform(asyncDispatch(streaming))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    ObjectMapper mapper = new ObjectMapper();
    List<JsonNode> events = new ArrayList<>();
    for (String line : ndjson.lines().toList()) {
      if (!line.isBlank()) events.add(mapper.readTree(line));
    }

    assertThat(tasks.count()).isEqualTo(1);
    List<String> runtimeTypes =
        events.stream()
            .filter(event -> event.path("data").has("runtimeEventId"))
            .map(event -> event.path("type").asText())
            .toList();
    assertThat(runtimeTypes)
        .startsWith("route", "evidence", "rewrite", "evidence", "plan")
        .endsWith("finish");
    JsonNode done =
        events.stream()
            .filter(event -> "done".equals(event.path("type").asText()))
            .findFirst()
            .orElseThrow();
    assertThat(done.path("data").path("retrievalRoundCount").asInt()).isEqualTo(2);
    assertThat(done.path("data").path("plannerSource").asText())
        .isEqualTo("langchain-grounded");
    assertThat(done.path("data").path("fallback").asBoolean()).isFalse();
    assertThat(done.path("data").path("response").path("executed").asBoolean()).isTrue();
    assertThat(done.path("data").path("response").path("taskIds").size()).isEqualTo(1);
    assertThat(
            audits.findAll().stream()
                .filter(audit -> "AI_DISPATCH_TASKS".equals(audit.getAction()))
                .count())
        .isEqualTo(1);
    verify(executionService, timeout(1_000).times(1)).executeAsync(anyLong());
  }

  private long[] createActiveTarget(String jwt, String projectName) throws Exception {
    Instant now = Instant.now();
    String projectJson =
        mockMvc
            .perform(
                post("/api/projects")
                    .header("Authorization", "Bearer " + jwt)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        """
                        {"name":"%s","authorizationStatement":"CI authorized local test","authorizationValidFrom":"%s","authorizationExpiresAt":"%s","owner":"admin"}
                        """
                            .formatted(
                                projectName, now.minusSeconds(60), now.plusSeconds(3600))))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();
    long projectId = new ObjectMapper().readTree(projectJson).path("id").asLong();
    String targetJson =
        mockMvc
            .perform(
                post("/api/targets")
                    .header("Authorization", "Bearer " + jwt)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        """
                        {"name":"Runtime local target","targetValue":"127.0.0.1","targetType":"IP","authorizationNote":"CI authorized","allowedPorts":"80,443","enabled":true,"projectId":%d}
                        """
                            .formatted(projectId)))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();
    long targetId = new ObjectMapper().readTree(targetJson).path("id").asLong();
    mockMvc
        .perform(
            post("/api/projects/" + projectId + "/status")
                .header("Authorization", "Bearer " + jwt)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"ACTIVE\"}"))
        .andExpect(status().isOk());
    return new long[] {projectId, targetId};
  }

  private String login() throws Exception {
    String response =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        "{\"username\":\"admin\",\"password\":\"runtime-e2e-admin-password\"}"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return new ObjectMapper().readTree(response).path("token").asText();
  }
}
