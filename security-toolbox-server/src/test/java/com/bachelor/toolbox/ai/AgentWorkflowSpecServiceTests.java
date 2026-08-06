package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AgentWorkflowSpecServiceTests {
  private AgentWorkflowSpecRepository repository;
  private AgentWorkflowSpecService service;

  @BeforeEach
  void setUp() {
    repository = mock(AgentWorkflowSpecRepository.class);
    when(repository.findById(1L)).thenReturn(Optional.empty());
    when(repository.save(any(AgentWorkflowSpec.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    service = new AgentWorkflowSpecService(repository, new ObjectMapper());
  }

  @Test
  void v2GraphComputesParallelGroupsFromEdges() {
    Map<String, Object> saved =
        service.save(
            v2Graph(
                List.of(
                    edge("__start__", "engage"),
                    edge("engage", "port-scan"),
                    edge("engage", "header-scan"),
                    edge("port-scan", "validation"),
                    edge("header-scan", "validation"),
                    edge("validation", "__end__"))));

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> steps = (List<Map<String, Object>>) saved.get("steps");
    Map<String, Integer> groups = new LinkedHashMap<>();
    for (Map<String, Object> step : steps) {
      groups.put(String.valueOf(step.get("nodeId")), ((Number) step.get("group")).intValue());
    }
    assertEquals(groups.get("port-scan"), groups.get("header-scan"));
    assertEquals(groups.get("port-scan") + 1, groups.get("validation"));
    verify(repository).save(any(AgentWorkflowSpec.class));
  }

  @Test
  void v2GraphRejectsCycles() {
    Map<String, Object> body =
        v2Graph(
            List.of(
                edge("__start__", "engage"),
                edge("engage", "port-scan"),
                edge("port-scan", "validation"),
                edge("validation", "port-scan"),
                edge("validation", "__end__")));
    assertThrows(ApiException.class, () -> service.save(body));
  }

  @Test
  void v2GraphRejectsMissingStartEndAndIsolatedNodes() {
    Map<String, Object> missingStart =
        v2Graph(
            List.of(
                edge("engage", "port-scan"),
                edge("port-scan", "header-scan"),
                edge("header-scan", "validation"),
                edge("validation", "__end__")));
    @SuppressWarnings("unchecked")
    Map<String, Object> graph = (Map<String, Object>) missingStart.get("graph");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> nodes = (List<Map<String, Object>>) graph.get("nodes");
    graph.put("nodes", nodes.subList(1, nodes.size()));
    assertThrows(ApiException.class, () -> service.save(missingStart));

    Map<String, Object> isolated =
        v2Graph(
            List.of(
                edge("__start__", "engage"),
                edge("engage", "port-scan"),
                edge("port-scan", "header-scan"),
                edge("header-scan", "validation"),
                edge("validation", "__end__")));
    @SuppressWarnings("unchecked")
    Map<String, Object> isolatedGraph = (Map<String, Object>) isolated.get("graph");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> isolatedNodes =
        (List<Map<String, Object>>) isolatedGraph.get("nodes");
    isolatedNodes.add(node("orphan", "phase", null, "report"));
    assertThrows(ApiException.class, () -> service.save(isolated));
  }

  @Test
  void v2GraphRejectsStepBoundToDifferentToolNode() {
    Map<String, Object> body =
        v2Graph(
            List.of(
                edge("__start__", "engage"),
                edge("engage", "port-scan"),
                edge("engage", "header-scan"),
                edge("port-scan", "validation"),
                edge("header-scan", "validation"),
                edge("validation", "__end__")));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> steps = (List<Map<String, Object>>) body.get("steps");
    steps.get(0).put("nodeId", "header-scan");
    assertThrows(ApiException.class, () -> service.save(body));
  }

  @Test
  void legacyStepsOnlyWorkflowRemainsCompatible() {
    Map<String, Object> body =
        Map.of(
            "steps",
            List.of(
                Map.of(
                    "tool",
                    "http_headers",
                    "parameters",
                    Map.of(),
                    "risk",
                    "SAFE",
                    "requiresApproval",
                    false,
                    "group",
                    3)));
    Map<String, Object> saved = service.save(body);
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> steps = (List<Map<String, Object>>) saved.get("steps");
    assertEquals(3, ((Number) steps.get(0).get("group")).intValue());
  }

  private Map<String, Object> v2Graph(List<Map<String, Object>> edges) {
    List<Map<String, Object>> nodes =
        new ArrayList<>(
            List.of(
                node("__start__", "start", null, "engagement"),
                node("engage", "phase", null, "engagement"),
                node("port-scan", "tool", "tcp_ports", "mapping"),
                node("header-scan", "tool", "http_headers", "mapping"),
                node("validation", "tool", "nuclei_scan", "validation"),
                node("__end__", "end", null, "report")));
    List<Map<String, Object>> steps =
        List.of(
            step("port-scan", "tcp_ports"),
            step("header-scan", "http_headers"),
            step("validation", "nuclei_scan"));
    Map<String, Object> graph = new LinkedHashMap<>();
    graph.put("nodes", nodes);
    graph.put("edges", new ArrayList<>(edges));
    Map<String, Object> root = new LinkedHashMap<>();
    root.put("version", 2);
    root.put("preset", "red-team-lifecycle");
    root.put("steps", steps);
    root.put("graph", graph);
    return root;
  }

  private Map<String, Object> node(String id, String type, String tool, String phase) {
    Map<String, Object> node = new LinkedHashMap<>();
    node.put("id", id);
    node.put("type", type);
    node.put("label", id);
    node.put("phase", phase);
    node.put("position", Map.of("x", 10, "y", 20));
    if (tool != null) node.put("tool", tool);
    return node;
  }

  private Map<String, Object> edge(String source, String target) {
    return Map.of("id", source + "-" + target, "source", source, "target", target);
  }

  private Map<String, Object> step(String nodeId, String tool) {
    Map<String, Object> step = new LinkedHashMap<>();
    step.put("nodeId", nodeId);
    step.put("tool", tool);
    step.put("parameters", Map.of());
    step.put("risk", "SAFE");
    step.put("requiresApproval", false);
    step.put("group", 0);
    return step;
  }
}
