package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/**
 * Stores and validates the user-composed workflow.
 *
 * <p>Version 2 adds a graph alongside the legacy {@code steps} array. The graph is deliberately
 * validated at the server boundary: a malformed or cyclic graph cannot create an executor loop, and
 * tool steps are assigned deterministic topological groups so siblings can run in parallel while
 * connected nodes remain sequential. A legacy steps-only document remains valid and keeps its
 * caller-provided groups.
 */
@Service
public class AgentWorkflowSpecService {
  private static final long SINGLETON_ID = 1L;
  private static final int MAX_SPEC_BYTES = 512 * 1024;
  private static final int MAX_NODES = 128;
  private static final int MAX_EDGES = 256;
  private static final int MAX_STEPS = 16;
  private static final Pattern NODE_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
  private static final Set<String> RUNTIME_TOOLS =
      Set.of(
          "retrieve_project_context",
          "nmap_service_scan",
          "tcp_ports",
          "http_headers",
          "http_security_check",
          "tls_config",
          "nuclei_scan");
  private static final Set<String> PHASES =
      Set.of(
          "engagement",
          "recon",
          "mapping",
          "discovery",
          "validation",
          "impact",
          "retest",
          "report",
          // These aliases were used by an earlier visual editor.
          "scope",
          "finding",
          "closure");

  private final AgentWorkflowSpecRepository repository;
  private final ObjectMapper objectMapper;

  public AgentWorkflowSpecService(
      AgentWorkflowSpecRepository repository, ObjectMapper objectMapper) {
    this.repository = repository;
    this.objectMapper = objectMapper;
  }

  public Object read() {
    return repository
        .findById(SINGLETON_ID)
        .map(AgentWorkflowSpec::getSpecJson)
        .map(this::parse)
        .orElseGet(Map::of);
  }

  public Map<String, Object> save(Map<String, Object> body) {
    if (body == null || body.isEmpty()) {
      throw new ApiException("工作流内容不能为空");
    }
    Map<String, Object> copy = copyMap(body);
    Map<String, Object> normalized = normalize(copy);
    String json = write(normalized);
    if (json.getBytes(StandardCharsets.UTF_8).length > MAX_SPEC_BYTES) {
      throw new ApiException("工作流配置过大");
    }
    AgentWorkflowSpec spec = repository.findById(SINGLETON_ID).orElseGet(AgentWorkflowSpec::new);
    spec.setId(SINGLETON_ID);
    spec.setSpecJson(json);
    spec.setUpdatedAt(Instant.now());
    repository.save(spec);
    return normalized;
  }

  /**
   * Returns safe executable steps for the local AI runtime. Invalid old records are treated as an
   * empty workflow instead of preventing the rest of the agent from starting; newly saved records
   * have already passed {@link #normalize(Map)}.
   */
  public List<Map<String, Object>> executableSteps() {
    Optional<AgentWorkflowSpec> stored = repository.findById(SINGLETON_ID);
    if (stored.isEmpty()) return List.of();
    Map<String, Object> root = parseMap(stored.get().getSpecJson());
    if (root.isEmpty()) return List.of();
    try {
      return stepsFromNormalized(normalize(root));
    } catch (RuntimeException ignored) {
      try {
        return normalizeLegacySteps(root.get("steps"));
      } catch (RuntimeException invalidLegacyRecord) {
        return List.of();
      }
    }
  }

  /** Package-visible for focused tests without touching persistence. */
  Map<String, Object> normalize(Map<String, Object> source) {
    Map<String, Object> root = copyMap(source);
    int version = integer(root.get("version"), 1, 1, 2, "工作流版本仅支持 1 或 2");
    if (version >= 2 || root.containsKey("graph")) {
      root.put("version", 2);
      normalizeGraph(root);
    } else {
      root.put("steps", normalizeLegacySteps(root.get("steps")));
    }
    return root;
  }

  private void normalizeGraph(Map<String, Object> root) {
    Object graphValue = root.get("graph");
    if (!(graphValue instanceof Map<?, ?> rawGraph)) {
      throw new ApiException("V2 工作流缺少 graph 图结构");
    }
    Map<String, Object> graph = copyMap(rawGraph);
    List<Map<String, Object>> nodes = objectList(graph.get("nodes"), "graph.nodes");
    List<Map<String, Object>> edges = objectList(graph.get("edges"), "graph.edges");
    if (nodes.isEmpty()) throw new ApiException("工作流图至少需要一个节点");
    if (nodes.size() > MAX_NODES) throw new ApiException("工作流节点数量超过限制");
    if (edges.size() > MAX_EDGES) throw new ApiException("工作流连线数量超过限制");

    Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
    for (Map<String, Object> node : nodes) {
      String id = text(node.get("id"));
      if (id == null
          || !NODE_ID.matcher(id).matches() && !"__start__".equals(id) && !"__end__".equals(id)) {
        throw new ApiException("工作流节点 ID 格式无效");
      }
      if (!byId.isEmpty() && byId.containsKey(id)) throw new ApiException("工作流节点 ID 不能重复");
      String phase = text(node.get("phase"));
      if (phase != null && !PHASES.contains(phase)) throw new ApiException("工作流阶段名称不受支持：" + phase);
      String tool = text(node.get("tool"));
      if (tool != null && !RUNTIME_TOOLS.contains(tool))
        throw new ApiException("工作流工具不受支持：" + tool);
      validatePosition(node.get("position"));
      byId.put(id, node);
    }
    Object positionsValue = graph.get("positions");
    if (positionsValue != null) {
      if (!(positionsValue instanceof Map<?, ?> positions)) {
        throw new ApiException("graph.positions 必须是对象");
      }
      for (Map.Entry<?, ?> entry : positions.entrySet()) {
        String id = text(entry.getKey());
        if (id == null || !byId.containsKey(id))
          throw new ApiException("graph.positions 引用了不存在的节点");
        validatePosition(entry.getValue());
      }
    }
    if (!byId.containsKey("__start__") || !byId.containsKey("__end__")) {
      throw new ApiException("工作流必须包含 __start__ 和 __end__ 节点");
    }

    Map<String, List<String>> outgoing = new LinkedHashMap<>();
    Map<String, List<String>> incoming = new LinkedHashMap<>();
    Map<String, Integer> indegree = new LinkedHashMap<>();
    byId.keySet()
        .forEach(
            id -> {
              outgoing.put(id, new ArrayList<>());
              incoming.put(id, new ArrayList<>());
              indegree.put(id, 0);
            });
    Set<String> edgeKeys = new HashSet<>();
    for (Map<String, Object> edge : edges) {
      String source = text(edge.get("source"));
      String target = text(edge.get("target"));
      if (source == null
          || target == null
          || !byId.containsKey(source)
          || !byId.containsKey(target)) {
        throw new ApiException("工作流连线引用了不存在的节点");
      }
      if (source.equals(target) || !edgeKeys.add(source + "\u0000" + target)) {
        throw new ApiException("工作流连线不能自环或重复");
      }
      outgoing.get(source).add(target);
      incoming.get(target).add(source);
      indegree.put(target, indegree.get(target) + 1);
    }

    List<String> topological = topologicalOrder(byId.keySet(), outgoing, indegree);
    if (topological.size() != byId.size()) throw new ApiException("工作流连线存在循环");
    Set<String> fromStart = reachable("__start__", outgoing);
    Set<String> toEnd = reverseReachable("__end__", incoming);
    if (!fromStart.contains("__end__")) throw new ApiException("工作流必须从 __start__ 到达 __end__");
    for (String id : byId.keySet()) {
      if (!fromStart.contains(id) || !toEnd.contains(id)) {
        throw new ApiException("工作流存在不在起止路径上的孤立节点：" + id);
      }
    }

    Map<String, Integer> depth = new LinkedHashMap<>();
    byId.keySet().forEach(id -> depth.put(id, 0));
    for (String source : topological) {
      for (String target : outgoing.get(source)) {
        depth.put(target, Math.max(depth.get(target), depth.get(source) + 1));
      }
    }
    List<Integer> toolDepths =
        byId.values().stream()
            .filter(node -> text(node.get("tool")) != null)
            .map(node -> depth.get(text(node.get("id"))))
            .distinct()
            .sorted()
            .toList();
    Map<Integer, Integer> groupByDepth = new HashMap<>();
    for (int i = 0; i < toolDepths.size(); i++) groupByDepth.put(toolDepths.get(i), i);

    List<Map<String, Object>> normalizedSteps =
        normalizeGraphSteps(root.get("steps"), byId, depth, groupByDepth);
    graph.put("nodes", nodes);
    graph.put("edges", edges);
    root.put("graph", graph);
    root.put("steps", normalizedSteps);
  }

  private List<Map<String, Object>> normalizeGraphSteps(
      Object value,
      Map<String, Map<String, Object>> nodes,
      Map<String, Integer> depth,
      Map<Integer, Integer> groupByDepth) {
    List<Map<String, Object>> rawSteps = objectList(value, "steps");
    if (rawSteps.size() > MAX_STEPS) throw new ApiException("工作流工具步骤数量超过限制");
    List<Map<String, Object>> toolNodes =
        nodes.values().stream().filter(node -> text(node.get("tool")) != null).toList();
    if (toolNodes.size() != rawSteps.size()) {
      throw new ApiException("工作流图中的工具节点必须与 steps 一一对应");
    }
    Set<String> used = new HashSet<>();
    List<Map<String, Object>> result = new ArrayList<>();
    for (Map<String, Object> raw : rawSteps) {
      String tool = text(raw.get("tool"));
      if (tool == null || !RUNTIME_TOOLS.contains(tool)) throw new ApiException("工作流工具不受支持");
      String nodeId = text(raw.get("nodeId"));
      if (nodeId == null) nodeId = text(raw.get("id"));
      if (nodeId == null
          || !nodes.containsKey(nodeId)
          || text(nodes.get(nodeId).get("tool")) == null) {
        nodeId =
            toolNodes.stream()
                .filter(
                    node ->
                        !used.contains(text(node.get("id"))) && tool.equals(text(node.get("tool"))))
                .map(node -> text(node.get("id")))
                .findFirst()
                .orElse(null);
      }
      if (nodeId == null
          || !nodes.containsKey(nodeId)
          || !tool.equals(text(nodes.get(nodeId).get("tool")))) {
        throw new ApiException("steps 与工具节点的 nodeId/tool 不匹配");
      }
      if (!used.add(nodeId)) throw new ApiException("同一个工具节点不能重复绑定 steps");
      Map<String, Object> normalized = copyMap(raw);
      normalized.put("nodeId", nodeId);
      normalized.put("group", groupByDepth.getOrDefault(depth.get(nodeId), 0));
      normalized.put(
          "parameters",
          raw.get("parameters") instanceof Map<?, ?> ? raw.get("parameters") : Map.of());
      normalized.put("risk", text(raw.get("risk")) == null ? "SAFE" : text(raw.get("risk")));
      normalized.put("requiresApproval", Boolean.TRUE.equals(raw.get("requiresApproval")));
      result.add(normalized);
    }
    return result;
  }

  private List<Map<String, Object>> normalizeLegacySteps(Object value) {
    List<Map<String, Object>> raw = objectList(value, "steps");
    if (raw.size() > MAX_STEPS) throw new ApiException("工作流工具步骤数量超过限制");
    List<Map<String, Object>> result = new ArrayList<>();
    for (Map<String, Object> step : raw) {
      String tool = text(step.get("tool"));
      if (tool == null || !RUNTIME_TOOLS.contains(tool)) throw new ApiException("工作流工具不受支持");
      Map<String, Object> normalized = copyMap(step);
      normalized.put("group", integer(step.get("group"), 0, 0, 32, "工作流并行组无效"));
      normalized.put(
          "parameters",
          step.get("parameters") instanceof Map<?, ?> ? step.get("parameters") : Map.of());
      result.add(normalized);
    }
    return result;
  }

  private List<Map<String, Object>> stepsFromNormalized(Map<String, Object> root) {
    return normalizeLegacySteps(root.get("steps"));
  }

  private List<String> topologicalOrder(
      Set<String> ids, Map<String, List<String>> outgoing, Map<String, Integer> indegree) {
    Map<String, Integer> remaining = new LinkedHashMap<>(indegree);
    Deque<String> queue = new ArrayDeque<>();
    ids.stream().filter(id -> remaining.get(id) == 0).forEach(queue::addLast);
    List<String> order = new ArrayList<>();
    while (!queue.isEmpty()) {
      String source = queue.removeFirst();
      order.add(source);
      for (String target : outgoing.get(source)) {
        int value = remaining.merge(target, -1, Integer::sum);
        if (value == 0) queue.addLast(target);
      }
    }
    return order;
  }

  private Set<String> reachable(String start, Map<String, List<String>> graph) {
    return traverse(start, graph);
  }

  private Set<String> reverseReachable(String end, Map<String, List<String>> incoming) {
    return traverse(end, incoming);
  }

  private Set<String> traverse(String start, Map<String, List<String>> graph) {
    Set<String> visited = new LinkedHashSet<>();
    Deque<String> queue = new ArrayDeque<>();
    queue.add(start);
    while (!queue.isEmpty()) {
      String current = queue.removeFirst();
      if (!visited.add(current)) continue;
      for (String next : graph.getOrDefault(current, List.of())) queue.addLast(next);
    }
    return visited;
  }

  private void validatePosition(Object value) {
    if (value == null) return;
    if (!(value instanceof Map<?, ?> position)) throw new ApiException("节点 position 必须是对象");
    for (String key : List.of("x", "y")) {
      Object coordinate = position.get(key);
      if (coordinate == null) continue;
      if (!(coordinate instanceof Number number)
          || !Double.isFinite(number.doubleValue())
          || Math.abs(number.doubleValue()) > 1_000_000) {
        throw new ApiException("节点 position 坐标无效");
      }
    }
  }

  private List<Map<String, Object>> objectList(Object value, String field) {
    if (value == null) return List.of();
    if (!(value instanceof List<?> list)) throw new ApiException(field + " 必须是数组");
    List<Map<String, Object>> result = new ArrayList<>();
    for (Object item : list) {
      if (!(item instanceof Map<?, ?> map)) throw new ApiException(field + " 包含无效对象");
      result.add(copyMap(map));
    }
    return result;
  }

  private Map<String, Object> copyMap(Map<?, ?> source) {
    Map<String, Object> result = new LinkedHashMap<>();
    source.forEach(
        (key, value) -> {
          if (key != null) result.put(String.valueOf(key), value);
        });
    return result;
  }

  private String text(Object value) {
    if (value == null) return null;
    String result = String.valueOf(value).strip();
    return result.isEmpty() ? null : result;
  }

  private int integer(Object value, int fallback, int min, int max, String message) {
    if (value == null) return fallback;
    try {
      int result =
          value instanceof Number number
              ? number.intValue()
              : Integer.parseInt(String.valueOf(value));
      if (result < min || result > max) throw new NumberFormatException();
      return result;
    } catch (NumberFormatException ex) {
      throw new ApiException(message);
    }
  }

  private Map<String, Object> parseMap(String json) {
    if (json == null || json.isBlank()) return Map.of();
    try {
      return objectMapper.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
    } catch (Exception ignored) {
      return Map.of();
    }
  }

  private Object parse(String json) {
    Map<String, Object> value = parseMap(json);
    return value.isEmpty() ? Map.of() : value;
  }

  private String write(Object value) {
    try {
      return objectMapper.writeValueAsString(value);
    } catch (JsonProcessingException ex) {
      throw new ApiException("工作流保存失败");
    }
  }
}
