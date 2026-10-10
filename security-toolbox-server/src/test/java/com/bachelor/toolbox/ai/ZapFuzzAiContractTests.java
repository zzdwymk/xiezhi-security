package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

class ZapFuzzAiContractTests {
  private final ObjectMapper mapper = new ObjectMapper();
  private final AgentWorkflowSpecService workflows = mock(AgentWorkflowSpecService.class);
  private final AiAgentRuntimeClient runtime = new AiAgentRuntimeClient(
      mapper, mock(AssessmentProjectService.class), mock(TargetService.class),
      mock(SecurityTaskRepository.class), workflows,
      true, "http://127.0.0.1:8090", 8090, "test-token", "test-signing-secret", 30, 20);

  private Map<String, Object> parameters() {
    return Map.of("fuzzRequestUrl", "http://127.0.0.1/?id=1", "method", "GET",
        "fuzzTargetField", "id", "fuzzPayload", " literal value ");
  }

  @Test
  void runtimeAcceptsOneConcreteMutationAndWorkflowCannotRemoveApproval() {
    Object decoded = ReflectionTestUtils.invokeMethod(runtime, "strictParameters", "zap_fuzz", mapper.valueToTree(parameters()));
    assertThat(decoded).isEqualTo(parameters());
    when(workflows.executableSteps()).thenReturn(List.of(Map.of("nodeId", "zap-one", "tool", "zap_fuzz",
        "parameters", parameters(), "requiresApproval", false)));
    List<Map<String, Object>> forwarded = ReflectionTestUtils.invokeMethod(runtime, "loadWorkflowSteps");
    assertThat(forwarded).singleElement().satisfies(step -> {
      assertThat(step).containsEntry("tool", "zap_fuzz").containsEntry("requiresApproval", true)
          .containsEntry("parameters", parameters());
    });
  }

  @Test
  void runtimeRejectsActionClaimingApprovalIsUnnecessary() {
    Map<String, Object> action = Map.of("actionId", "a".repeat(32), "workflowNodeId", "zap-one",
        "tool", "zap_fuzz", "parameters", parameters(), "risk", "SAFE", "requiresApproval", false,
        "group", 0, "dependsOnNodeIds", List.of(), "evidenceRefs", List.of("ev-1"));
    assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(runtime, "toPlan", mapper.valueToTree(Map.of(
        "summary", "One mutation", "answer", "Plan ready", "intent", "plan", "source", "langchain-grounded",
        "knowledgeMode", "PROJECT_EVIDENCE", "evidenceRefs", List.of("ev-1"), "actions", List.of(action))),
        Set.of("ev-1"), false)).isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
        .hasMessageContaining("必须要求审批");
  }

  @ParameterizedTest
  @ValueSource(strings = {"{\"method\":\"DELETE\"}", "{\"method\":\"get\"}",
      "{\"fuzzPayload\":1}", "{\"fuzzPayload\":\"\"}", "{\"fuzzTargetField\":\" \"}",
      "{\"fuzzPostBody\":\"id=1\"}", "{\"fuzzRequestUrl\":\"/relative\"}",
      "{\"fuzzRequestUrl\":\"file:///test\"}", "{\"fuzzRequestUrl\":\"http://u:p@host/\"}",
      "{\"fuzzRequestUrl\":\"http://host/#\"}", "{\"fuzzRequestUrl\":\"http://host:65536/\"}",
      "{\"fuzzTargetField\":\"missing\"}", "{\"fuzzRequestUrl\":\"http://127.0.0.1/?id=1&id=2\"}",
      "{\"fuzzRequestUrl\":\"http://127.0.0.1/?id=%xx\"}", "{\"fuzzRequestUrl\":\"http://127.0.0.1/\"}",
      "{\"payloadFile\":\"wordlist\"}", "{\"command\":\"run\"}", "{\"__resolvedWebBases\":[\"http://host\"]}"})
  void runtimeRejectsUnsupportedOrAmbiguousParameters(String patch) throws Exception {
    Map<String, Object> input = new LinkedHashMap<>(parameters());
    input.putAll(mapper.readValue(patch, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}));
    assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(runtime, "strictParameters", "zap_fuzz", mapper.valueToTree(input)))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
  }

  @Test
  void finalParametersRequireConcreteFieldsAndRejectExcessLengthOrControls() {
    for (String required : List.of("fuzzRequestUrl", "fuzzTargetField", "fuzzPayload")) {
      Map<String, Object> input = new LinkedHashMap<>(parameters()); input.remove(required);
      assertThatThrownBy(() -> ZapFuzzAiParameters.normalize(input, true)).isInstanceOf(ApiException.class);
    }
    for (Map.Entry<String, String> patch : Map.of("fuzzRequestUrl", "http://127.0.0.1/" + "x".repeat(2000),
        "fuzzTargetField", "f".repeat(129), "fuzzPayload", "v".repeat(1001),
        "fuzzPostBody", "f".repeat(4001)).entrySet()) {
      Map<String, Object> input = new LinkedHashMap<>(parameters()); input.put(patch.getKey(), patch.getValue());
      assertThatThrownBy(() -> ZapFuzzAiParameters.normalize(input, true)).isInstanceOf(ApiException.class);
    }
    Map<String, Object> input = new LinkedHashMap<>(parameters()); input.put("fuzzPayload", "value\r\nHeader: x");
    assertThatThrownBy(() -> ZapFuzzAiParameters.normalize(input, true)).isInstanceOf(ApiException.class);
  }

  @Test
  void requestIsBoundToAuthorizedHostAndPortBeforePlanCanBeApproved() {
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L); target.setEnabled(true); target.setTargetType("URL");
    target.setTargetValue("http://127.0.0.1/"); target.setAllowedPorts("80,443");
    when(targets.get(7L)).thenReturn(target);
    PortRangeParser ports = new PortRangeParser();
    AiTaskDispatchService dispatch = new AiTaskDispatchService(targets, new TargetPolicyService(false, ports),
        mock(SecurityToolRegistry.class), ports, 20, 65535);
    AiPlanResponse prepared = dispatch.prepare(new AiPlanRequest(7L, "One mutation"), plan(parameters()));
    assertThat(prepared.steps()).singleElement().satisfies(step -> {
      assertThat(step.requiresApproval()).isTrue();
      assertThat(step.parameters()).isEqualTo(parameters());
    });
    for (String url : List.of("http://127.0.0.2/?id=1", "http://127.0.0.1:22/?id=1")) {
      Map<String, Object> input = new LinkedHashMap<>(parameters()); input.put("fuzzRequestUrl", url);
      assertThatThrownBy(() -> dispatch.prepare(new AiPlanRequest(7L, "One mutation"), plan(input)))
          .isInstanceOf(ApiException.class);
    }
  }

  @Test
  void nucleiRuntimeKeepsLegacyDefaultOrExplicitBoundedSelection() {
    for (Map<String, Object> input : List.<Map<String, Object>>of(Map.of(), Map.of("allPocs", true),
        Map.of("pocCodes", List.of("NU-" + "A".repeat(24))))) {
      assertThat((Object) ReflectionTestUtils.invokeMethod(runtime, "strictParameters", "nuclei_scan", mapper.valueToTree(input)))
          .isEqualTo(input);
    }
    for (Map<String, Object> input : List.<Map<String, Object>>of(Map.of("allPocs", false),
        Map.of("allPocs", "true"), Map.of("pocCodes", List.of("https://host/template")),
        Map.of("allPocs", true, "pocCodes", List.of("NU-" + "A".repeat(24))))) {
      assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(runtime, "strictParameters", "nuclei_scan", mapper.valueToTree(input)))
          .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
    }
  }

  private AiPlanResponse plan(Map<String, Object> input) {
    return new AiPlanResponse("fixture", "model", "One mutation", false, List.of(
        new AiPlanResponse.PlanStep("zap_fuzz", "ZAP single mutation", "requested", input)));
  }
}
