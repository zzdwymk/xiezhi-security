package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AgentWorkflowSpecServiceTests {
  private AgentWorkflowSpecRepository repository;
  private ProjectAuthorizationService authorization;
  private AgentWorkflowSpecService service;
  private List<AgentWorkflowSpec> stored;

  @BeforeEach
  void setUp() {
    repository = mock(AgentWorkflowSpecRepository.class);
    authorization = mock(ProjectAuthorizationService.class);
    stored = new ArrayList<>();
    when(authorization.currentUsername()).thenReturn("alice");
    when(repository.findFirstByScopeIdOrderByRevisionDesc(any()))
        .thenAnswer(
            invocation -> {
              Long scopeId = invocation.getArgument(0);
              return stored.stream()
                  .filter(item -> scopeId.equals(item.getScopeId()))
                  .max(java.util.Comparator.comparingLong(AgentWorkflowSpec::getRevision));
            });
    when(repository.findByWorkflowIdAndRevision(any(), any()))
        .thenAnswer(
            invocation -> {
              String workflowId = invocation.getArgument(0);
              Long revision = invocation.getArgument(1);
              return stored.stream()
                  .filter(
                      item ->
                          workflowId.equals(item.getWorkflowId())
                              && revision.equals(item.getRevision()))
                  .findFirst();
            });
    when(repository.save(any(AgentWorkflowSpec.class)))
        .thenAnswer(
            invocation -> {
              AgentWorkflowSpec value = invocation.getArgument(0);
              value.setId((long) stored.size() + 1);
              stored.add(value);
              return value;
            });
    service = new AgentWorkflowSpecService(repository, new ObjectMapper(), authorization);
  }

  @Test
  void v2GraphComputesParallelGroupsFromEdges() {
    Map<String, Object> saved =
        service.save(
            101L,
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
    assertThrows(ApiException.class, () -> service.save(101L, body));
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
    assertThrows(ApiException.class, () -> service.save(101L, missingStart));

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
    assertThrows(ApiException.class, () -> service.save(101L, isolated));
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
    assertThrows(ApiException.class, () -> service.save(101L, body));
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
    Map<String, Object> saved = service.save(101L, body);
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> steps = (List<Map<String, Object>>) saved.get("steps");
    assertEquals(3, ((Number) steps.get(0).get("group")).intValue());
  }

  @Test
  void revisionsAreAppendOnlyAndDigestIgnoresClientMetadata() {
    Map<String, Object> body = v2Graph(validEdges());
    body.put("workflowId", "forged");
    body.put("revision", 999);
    body.put("specDigest", "sha256:" + "0".repeat(64));

    Map<String, Object> first = service.save(101L, body);
    Map<String, Object> second = service.save(101L, body);

    assertEquals(1L, first.get("revision"));
    assertEquals(2L, second.get("revision"));
    assertEquals(first.get("workflowId"), second.get("workflowId"));
    assertEquals(first.get("specDigest"), second.get("specDigest"));
    assertTrue(String.valueOf(first.get("specDigest")).matches("sha256:[0-9a-f]{64}"));
    assertEquals("alice", second.get("updatedBy"));
    assertEquals(2, stored.size());
    assertNotEquals(stored.get(0).getId(), stored.get(1).getId());
  }

  @Test
  void projectsHaveIndependentWorkflowHistories() {
    Map<String, Object> projectA = service.save(101L, v2Graph(validEdges()));
    Map<String, Object> projectB = service.save(202L, v2Graph(validEdges()));

    assertEquals(1L, projectA.get("revision"));
    assertEquals(1L, projectB.get("revision"));
    assertNotEquals(projectA.get("workflowId"), projectB.get("workflowId"));
    assertEquals(projectA.get("workflowId"), service.read(101L).get("workflowId"));
    assertEquals(projectB.get("workflowId"), service.read(202L).get("workflowId"));
    verify(authorization).requireManage(101L);
    verify(authorization).requireManage(202L);
    verify(authorization).requireAccess(101L);
    verify(authorization).requireAccess(202L);
  }

  @Test
  void frozenSnapshotDoesNotChangeWhenANewerRevisionIsSaved() {
    Map<String, Object> first = service.save(101L, v2Graph(validEdges()));
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        service.freezeSnapshot(
            101L,
            String.valueOf(first.get("workflowId")),
            ((Number) first.get("revision")).longValue(),
            String.valueOf(first.get("specDigest")));

    Map<String, Object> changed = v2Graph(validEdges());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> changedSteps = (List<Map<String, Object>>) changed.get("steps");
    changedSteps.get(0).put("parameters", Map.of("ports", "443"));
    Map<String, Object> second = service.save(101L, changed);

    assertEquals(1L, snapshot.revision());
    assertEquals(first.get("specDigest"), snapshot.specDigest());
    assertNotEquals(snapshot.specDigest(), second.get("specDigest"));
    assertEquals(Map.of(), snapshot.executableSteps().get(0).get("parameters"));
    assertThrows(
        UnsupportedOperationException.class,
        () -> snapshot.executableSteps().get(0).put("tool", "nuclei_scan"));
  }

  @Test
  void snapshotDigestMismatchFailsClosed() {
    Map<String, Object> saved = service.save(101L, v2Graph(validEdges()));
    assertThrows(
        ApiException.class,
        () ->
            service.freezeSnapshot(
                101L,
                String.valueOf(saved.get("workflowId")),
                ((Number) saved.get("revision")).longValue(),
                "sha256:" + "f".repeat(64)));
  }

  @Test
  void runtimeStepsAreVisibleOnlyInsideTheBoundTurn() {
    service.save(101L, v2Graph(validEdges()));
    AgentWorkflowSpecService.WorkflowSnapshot snapshot = service.freezeSnapshot(101L);
    assertEquals(List.of(), service.executableSteps());
    service.withSnapshot(snapshot, () -> assertEquals(3, service.executableSteps().size()));
    assertEquals(List.of(), service.executableSteps());
    assertEquals("red-team-lifecycle", snapshot.spec().get("preset"));
  }

  @Test
  void newProjectGetsExecutableStandardRuntimeDefault() {
    AgentWorkflowSpecService.WorkflowSnapshot snapshot = service.freezeSnapshot(303L);

    assertEquals("runtime-default", snapshot.spec().get("preset"));
    assertEquals(
        List.of(
            "retrieve_project_context",
            "nmap_service_scan",
            "http_headers",
            "tls_config",
            "http_security_check",
            "nuclei_scan",
            "afrog_scan",
            "xray_scan"),
        snapshot.executableSteps().stream().map(step -> step.get("tool")).toList());
    assertEquals(1, snapshot.executableSteps().get(1).get("group"));
    assertEquals(List.of("context"), snapshot.executableSteps().get(1).get("dependsOnNodeIds"));
    assertEquals("CAUTION", snapshot.executableSteps().get(5).get("risk"));
    assertEquals(true, snapshot.executableSteps().get(5).get("requiresApproval"));
    assertEquals(Map.of("allPocs", true), snapshot.executableSteps().get(6).get("parameters"));
    assertEquals(Map.of("allPocs", true), snapshot.executableSteps().get(7).get("parameters"));
    assertEquals(5, snapshot.executableSteps().get(7).get("group"));
  }

  @Test
  void graphKeepsThreeScannerToolsDistinctAndSequential() {
    List<Map<String, Object>> nodes =
        List.of(
            node("__start__", "start", null, "engagement"),
            node("nuclei", "tool", "nuclei_scan", "discovery"),
            node("afrog", "tool", "afrog_scan", "discovery"),
            node("xray", "tool", "xray_scan", "discovery"),
            node("__end__", "end", null, "report"));
    List<Map<String, Object>> steps =
        List.of(
            scannerStep("nuclei", "nuclei_scan", Map.of()),
            scannerStep("afrog", "afrog_scan", Map.of("allPocs", true)),
            scannerStep(
                "xray",
                "xray_scan",
                Map.of("pocCodes", List.of("XR-AAAAAAAAAAAAAAAAAAAAAAAA"))));
    Map<String, Object> saved =
        service.save(
            101L,
            Map.of(
                "version",
                2,
                "steps",
                steps,
                "graph",
                Map.of(
                    "nodes",
                    nodes,
                    "edges",
                    List.of(
                        edge("__start__", "nuclei"),
                        edge("nuclei", "afrog"),
                        edge("afrog", "xray"),
                        edge("xray", "__end__")))));

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> savedSteps = (List<Map<String, Object>>) saved.get("steps");
    assertEquals(
        List.of("nuclei_scan", "afrog_scan", "xray_scan"),
        savedSteps.stream().map(step -> step.get("tool")).toList());
    assertEquals(List.of(0, 1, 2), savedSteps.stream().map(step -> step.get("group")).toList());
    assertEquals(Map.of("allPocs", true), savedSteps.get(1).get("parameters"));
    assertEquals(
        Map.of("pocCodes", List.of("XR-AAAAAAAAAAAAAAAAAAAAAAAA")),
        savedSteps.get(2).get("parameters"));
  }

  private List<Map<String, Object>> validEdges() {
    return List.of(
        edge("__start__", "engage"),
        edge("engage", "port-scan"),
        edge("engage", "header-scan"),
        edge("port-scan", "validation"),
        edge("header-scan", "validation"),
        edge("validation", "__end__"));
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

  private Map<String, Object> scannerStep(
      String nodeId, String tool, Map<String, Object> parameters) {
    Map<String, Object> step = step(nodeId, tool);
    step.put("parameters", parameters);
    step.put("risk", "CAUTION");
    step.put("requiresApproval", true);
    return step;
  }
}
