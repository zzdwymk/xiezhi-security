package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@EnabledIfEnvironmentVariable(named = "AI_RUNTIME_E2E", matches = "true")
class AiPythonRuntimeEndToEndTests {
  @Test
  void actionablePlanTraversesTheRealPythonLangGraphContract() {
    String baseUrl = System.getenv().getOrDefault("AI_RUNTIME_URL", "http://127.0.0.1:8090");
    String token = System.getenv("AI_RUNTIME_TOKEN");
    String signingSecret = System.getenv("AI_RUNTIME_PROJECT_SIGNING_SECRET");

    AssessmentProjectService projects = mock(AssessmentProjectService.class);
    TargetService targets = mock(TargetService.class);
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    AgentWorkflowSpecService workflows = mock(AgentWorkflowSpecService.class);
    AssessmentProject project = new AssessmentProject();
    project.setId(71L);
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(60));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(91L);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("80,443");
    target.setEnabled(true);
    when(projects.get(71L)).thenReturn(project);
    when(targets.getCurrentlyAuthorized(91L)).thenReturn(target);
    when(tasks.countByProjectIdAndStatusIn(71L, List.of("PENDING", "RUNNING"))).thenReturn(0L);
    when(workflows.executableSteps()).thenReturn(List.of());

    AiAgentRuntimeClient client =
        new AiAgentRuntimeClient(
            new ObjectMapper(),
            projects,
            targets,
            tasks,
            workflows,
            true,
            baseUrl,
            8090,
            token,
            signingSecret,
            30,
            20);
    client.indexProject(
        71L,
        List.of(
            new AiAgentRuntimeClient.IndexDocument(
                "授权服务扫描范围",
                "当前目标允许扫描端口和服务，授权端口为 80 和 443。",
                "project",
                Map.of("targetId", "91"))));
    List<AiAgentRuntimeClient.RuntimeEvent> events = new ArrayList<>();
    AiAgentRuntimeClient.RuntimePlanResult result =
        client.plan(
            new AiAgentRequest(
                71L,
                91L,
                "ci-runtime-session",
                "请扫描端口和服务",
                true,
                null,
                List.of(),
                "standard",
                "ci-runtime-turn"),
            "请扫描端口和服务",
            events::add);

    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(result.plan().steps())
        .extracting(AiPlanResponse.PlanStep::toolCode)
        .contains("nmap_service_scan");
    assertThat(events)
        .extracting(AiAgentRuntimeClient.RuntimeEvent::type)
        .contains("plan", "authorization_guard", "tool", "review", "finish");
    assertThat(events)
        .extracting(AiAgentRuntimeClient.RuntimeEvent::type)
        .startsWith("route", "evidence", "plan")
        .endsWith("finish");
    assertThat(events)
        .extracting(AiAgentRuntimeClient.RuntimeEvent::runId)
        .containsOnly(result.runId());
    assertThat(events)
        .extracting(AiAgentRuntimeClient.RuntimeEvent::stateVersion)
        .containsExactlyElementsOf(
            java.util.stream.IntStream.rangeClosed(1, events.size()).boxed().toList());
    assertThat(result.policyRevision()).isEqualTo("java-authoritative-v1");
    assertThat(events.stream().filter(event -> "finish".equals(event.type())).findFirst())
        .get()
        .extracting(event -> event.rawData().path("plan").path("source").asText())
        .isEqualTo("langchain-grounded");
    assertThat(result.provenance().retrievalRoundCount()).isEqualTo(1);
    assertThat(result.provenance().evidenceIds()).isNotEmpty();
    assertThat(result.provenance().plannerSource()).isEqualTo("langchain-grounded");

    Object graph = client.graph();
    assertThat(graph).isInstanceOf(JsonNode.class);
    JsonNode graphJson = (JsonNode) graph;
    assertThat(graphJson.path("source").asText()).isEqualTo("langgraph");
    assertThat(graphJson.path("compiled").path("nodes").isArray()).isTrue();
  }
}
