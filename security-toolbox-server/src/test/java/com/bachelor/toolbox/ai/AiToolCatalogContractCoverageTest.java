package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Drift guard: every tool registered in {@link AiToolCatalog} must be fully handled by the
 * runtime contract in {@link AiAgentRuntimeClient#strictParameters}.
 *
 * <p>Both sides of {@code strictParameters} are hand-written switches — the allowed parameter-key
 * set and the value parser. When a new tool is added to the catalog but its parameter parsing is
 * forgotten, the tool passes every other layer and the whole AI turn dies at plan validation with
 * a whitelist rejection. Before this test existed, {@code site_crawl} shipped exactly that way:
 * registered in the catalog, whitelisted on the Python side, parsed by the Python value switch,
 * and rejected by the Java value switch as "unknown tool".
 *
 * <p>With this guard, forgetting a branch fails a test instead of a user turn. Parameter parsing
 * itself is intentionally NOT auto-derived: per-tool value bounds are a security boundary, and a
 * tool with no AI-proposable parameters is expressed as an explicit empty branch.
 */
class AiToolCatalogContractCoverageTest {

  private final AiAgentRuntimeClient client = new AiAgentRuntimeClient(
      new ObjectMapper(),
      org.mockito.Mockito.mock(AssessmentProjectService.class),
      org.mockito.Mockito.mock(TargetService.class),
      org.mockito.Mockito.mock(SecurityTaskRepository.class),
      org.mockito.Mockito.mock(AgentWorkflowSpecService.class),
      true,
      "http://127.0.0.1:8090",
      8090,
      "test-token",
      "test-signing-secret",
      30,
      20,
      null);

  private static List<String> catalogCodes() {
    return AiToolCatalog.RUNTIME_CODES;
  }

  private Object invokeStrictParameters(String toolCode) throws Exception {
    return invokeStrictParameters(toolCode, new ObjectMapper().createObjectNode());
  }

  private Object invokeStrictParameters(
      String toolCode, com.fasterxml.jackson.databind.JsonNode raw) throws Exception {
    Method method = AiAgentRuntimeClient.class.getDeclaredMethod(
        "strictParameters", String.class, com.fasterxml.jackson.databind.JsonNode.class);
    method.setAccessible(true);
    return method.invoke(client, toolCode, raw);
  }

  @Test
  void everyDeclaredParameterKeyIsAcceptedByStrictParameters() throws Exception {
    // The catalog advertises a set of parameter keys; strictParameters has its own allow-list.
    // When the two drift, the runtime produces a schema-valid tool call that Java then rejects as
    // "parameters 包含未知字段" — the failure only shows up end-to-end. This pins them together.
    ObjectMapper mapper = new ObjectMapper();
    for (String code : catalogCodes()) {
      Map<String, Object> schema = AiToolCatalog.parameterSchema(code);
      Object properties = schema.get("properties");
      if (!(properties instanceof Map<?, ?> declared)) continue;
      for (Object key : declared.keySet()) {
        com.fasterxml.jackson.databind.node.ObjectNode raw = mapper.createObjectNode();
        raw.put(String.valueOf(key), "x");
        try {
          invokeStrictParameters(code, raw);
        } catch (java.lang.reflect.InvocationTargetException wrapped) {
          Throwable cause = wrapped.getCause() == null ? wrapped : wrapped.getCause();
          assertThat(cause)
              .as("catalog key '%s' of tool '%s' must be accepted by strictParameters",
                  key, code)
              .hasMessageNotContaining("包含未知字段");
        }
      }
    }
  }

  @Test
  void everyCatalogToolHasAValueParsingBranch() throws Exception {
    for (String code : catalogCodes()) {
      // An empty parameters object may legitimately fail field-required validation for tools
      // with mandatory inputs (query, check, sqlmap path...) — value completeness is enforced
      // later at dispatch. What it must NEVER do is be rejected as an unknown tool: that means
      // the value-parsing switch forgot this tool entirely, the site_crawl regression.
      try {
        invokeStrictParameters(code);
      } catch (java.lang.reflect.InvocationTargetException wrapped) {
        Throwable cause = wrapped.getCause() == null ? wrapped : wrapped.getCause();
        assertThat(cause)
            .as("catalog tool '%s' must not be rejected as unknown by strictParameters; "
                + "add a case to the second switch", code)
            .hasMessageNotContaining("计划包含未知工具");
      }
    }
  }

  @Test
  void unknownToolIsRejectedWithItsName() throws Exception {
    // The rejection must name the tool so failures pinpoint the offending proposal.
    try {
      invokeStrictParameters("totally_unknown_tool");
      throw new AssertionError("unknown tool was not rejected");
    } catch (java.lang.reflect.InvocationTargetException wrapped) {
      assertThat(wrapped.getCause())
          .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class)
          .hasMessageContaining("totally_unknown_tool");
    }
  }

  @Test
  void allowedKeySwitchCoversEveryCatalogTool() throws Exception {
    // The first switch (allowed parameter keys) must resolve for every catalog tool. Missing
    // required keys on an empty object are fine; the unknown-tool default is not. Required-key
    // completeness is asserted where values are actually enforced — dispatch validation.
    for (String code : catalogCodes()) {
      try {
        Object parameters = invokeStrictParameters(code);
        assertThat(parameters).isInstanceOf(java.util.Map.class);
      } catch (java.lang.reflect.InvocationTargetException wrapped) {
        Throwable cause = wrapped.getCause() == null ? wrapped : wrapped.getCause();
        assertThat(cause)
            .as("catalog tool '%s' must not be rejected as unknown by strictParameters", code)
            .hasMessageNotContaining("计划包含未知工具");
      }
      assertThat(AiToolCatalog.parameterSchema(code))
          .as("catalog tool '%s' must declare a parameter schema", code)
          .isNotNull();
    }
  }
}


