package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

class AiRuntimeScannerParametersTests {
  private final ObjectMapper mapper = new ObjectMapper();
  private final AgentWorkflowSpecService workflows = mock(AgentWorkflowSpecService.class);
  private final AiAgentRuntimeClient client = new AiAgentRuntimeClient(
      mapper, mock(AssessmentProjectService.class), mock(TargetService.class),
      mock(SecurityTaskRepository.class), workflows,
      true, "http://127.0.0.1:8090", 8090, "test-token", "test-signing-secret", 30, 20);

  @Test
  void forwardsAllNewScannerNodesToThePythonWorkflow() {
    when(workflows.executableSteps()).thenReturn(List.of(
        Map.of("nodeId", "zap", "tool", "zap_scan", "parameters", Map.of("spider", false)),
        Map.of("nodeId", "fscan", "tool", "fscan_scan", "parameters", Map.of("vulnMode", "SAFE")),
        Map.of("nodeId", "msf", "tool", "msf_scan", "parameters", Map.of("module", "auxiliary/scanner/http/http_version"))));
    List<Map<String, Object>> forwarded = ReflectionTestUtils.invokeMethod(client, "loadWorkflowSteps");
    assertThat(forwarded).extracting(step -> step.get("tool"))
        .containsExactly("zap_scan", "fscan_scan", "msf_scan");
  }

  @ParameterizedTest
  @ValueSource(strings = {"zap_scan", "fscan_scan", "msf_scan"})
  void acceptsNewScannerActionsFromTheRuntimePlan(String tool) {
    Map<String, Object> selectedParameters = "msf_scan".equals(tool)
        ? Map.of("module", "auxiliary/scanner/http/http_version") : Map.of();
    Map<String, Object> action = Map.of(
        "actionId", "a".repeat(32), "workflowNodeId", "scanner-node", "tool", tool,
        "parameters", selectedParameters, "risk", "CAUTION", "requiresApproval", true,
        "group", 0, "dependsOnNodeIds", List.of(), "evidenceRefs", List.of("evidence-1"));
    Object parsed = ReflectionTestUtils.invokeMethod(client, "toPlan", mapper.valueToTree(Map.of(
        "summary", "Authorized scanner plan", "answer", "Plan ready", "intent", "plan",
        "source", "langchain-grounded", "knowledgeMode", "PROJECT_EVIDENCE",
        "evidenceRefs", List.of("evidence-1"), "actions", List.of(action))), Set.of("evidence-1"), false);
    AiPlanResponse plan = (AiPlanResponse) ReflectionTestUtils.getField(parsed, "plan");
    assertThat(plan.steps()).singleElement().satisfies(step -> {
      assertThat(step.toolCode()).isEqualTo(tool);
      assertThat(step.parameters()).isEqualTo(selectedParameters);
      assertThat(step.requiresApproval()).isTrue();
    });
  }

  @Test
  void acceptsFscanModeAndExplicitPortSubset() throws Exception {
    assertThat(parameters("fscan_scan", "{\"ports\":\"80,443\",\"vulnMode\":\"SAFE\"}"))
        .containsEntry("ports", "80,443").containsEntry("vulnMode", "SAFE");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "{\"vulnMode\":\"brute\"}", "{\"vulnMode\":true}", "{\"ports\":443}",
      "{\"ports\":\"80\",\"command\":\"custom\"}"})
  void rejectsFscanCoercionsAndUnsupportedOptions(String json) {
    assertThatThrownBy(() -> parameters("fscan_scan", json)).isInstanceOf(RuntimeException.class);
  }

  @Test
  void acceptsMsfSingleAndBatchModulesWithoutChangingTheirParameters() throws Exception {
    assertThat(parameters("msf_scan", "{\"module\":\"auxiliary/scanner/http/http_version\",\"options\":{\"SSL\":\"true\"}}"))
        .containsEntry("module", "auxiliary/scanner/http/http_version")
        .containsEntry("options", Map.of("SSL", "true"));
    assertThat(parameters("msf_scan", "{\"modules\":[\"auxiliary/scanner/http/http_version\",\"auxiliary/scanner/ssl/ssl_version\"]}"))
        .containsEntry("modules", List.of("auxiliary/scanner/http/http_version", "auxiliary/scanner/ssl/ssl_version"));
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "{}", "{\"module\":\"auxiliary/scanner/http/http_version\",\"modules\":[\"auxiliary/scanner/http/http_version\"]}",
      "{\"modules\":[]}", "{\"modules\":[\"auxiliary/a\",\"auxiliary/a\"]}",
      "{\"module\":\"auxiliary/../payload\"}", "{\"module\":\"post/example\"}",
      "{\"module\":\"auxiliary/a;run\"}"})
  void rejectsAmbiguousOrMalformedMsfModuleSelection(String json) {
    assertThatThrownBy(() -> parameters("msf_scan", json)).isInstanceOf(RuntimeException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "RHOST", "RHOSTS", "RPORT", "LHOST", "LPORT", "PAYLOAD", "CMD", "COMMAND", "SHELL", "CHOST", "CPORT"})
  void rejectsMsfOptionsThatOverrideTheJavaExecutionBoundary(String key) {
    String json = "{\"module\":\"auxiliary/scanner/http/http_version\",\"options\":{\"" + key + "\":\"value\"}}";
    assertThatThrownBy(() -> parameters("msf_scan", json)).isInstanceOf(RuntimeException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"{\"SSL\":true}", "{\"ssl\":\"true\"}", "{\"SSL\":\"true;run\"}", "{\"SSL\":\"true\\nrun\"}", "{\"SSL\":\"\"}"})
  void rejectsNonTextOrUnsafeMsfOptionValues(String options) {
    String json = "{\"module\":\"auxiliary/scanner/http/http_version\",\"options\":" + options + "}";
    assertThatThrownBy(() -> parameters("msf_scan", json)).isInstanceOf(RuntimeException.class);
  }

  private Map<String, Object> parameters(String tool, String json) throws Exception {
    return ReflectionTestUtils.invokeMethod(client, "strictParameters", tool, mapper.readTree(json));
  }
}
