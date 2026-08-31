package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
  private static final int MAX_SPEC_BYTES = 512 * 1024;
  private static final int MAX_NODES = 128;
  private static final int MAX_EDGES = 256;
  private static final int MAX_STEPS = 16;
  private static final Pattern NODE_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
  private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
  private static final Set<String> SERVER_METADATA =
      Set.of("workflowId", "scopeId", "revision", "specDigest", "updatedBy", "updatedAt");
  private static final ThreadLocal<WorkflowSnapshot> RUN_SNAPSHOT = new ThreadLocal<>();
  private static final Set<String> RUNTIME_TOOLS =
      Set.of(
          "retrieve_project_context",
          "nmap_service_scan",
          "tcp_ports",
          "http_headers",
          "http_security_check",
          "tls_config",
          "nuclei_scan",
          "afrog_scan",
          "xray_scan",
          "fscan_scan");
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
  private final ProjectAuthorizationService authorization;

  public AgentWorkflowSpecService(
      AgentWorkflowSpecRepository repository,
      ObjectMapper objectMapper,
      ProjectAuthorizationService authorization) {
    this.repository = repository;
    this.objectMapper = objectMapper;
    this.authorization = authorization;
  }

  /** Returns the latest immutable revision for one project without creating a default. */
  @Transactional(readOnly = true)
  public Map<String, Object> read(Long scopeId) {
    requireScope(scopeId, false);
    return repository
        .findFirstByScopeIdOrderByRevisionDesc(scopeId)
        .map(this::toSnapshot)
        .map(WorkflowSnapshot::response)
        .orElseGet(Map::of);
  }

  /** Appends a revision; an existing revision is never overwritten. */
  @Transactional
  public synchronized Map<String, Object> save(Long scopeId, Map<String, Object> body) {
    requireScope(scopeId, true);
    return appendSnapshot(scopeId, body).snapshot().response();
  }

  /**
   * Resolves the exact revision used by a turn. Supplying no identity freezes the latest revision;
   * for a new project, a project-bound default revision is persisted first.
   */
  @Transactional
  public synchronized WorkflowSnapshot freezeSnapshot(
      Long scopeId, String workflowId, Long revision, String specDigest) {
    requireScope(scopeId, false);
    boolean identityAbsent = blank(workflowId) && revision == null && blank(specDigest);
    if (!identityAbsent && (blank(workflowId) || revision == null || blank(specDigest))) {
      throw new ApiException("工作流快照标识必须同时包含 workflowId、revision 和 specDigest");
    }
    AgentWorkflowSpec stored;
    if (identityAbsent) {
      stored =
          repository
              .findFirstByScopeIdOrderByRevisionDesc(scopeId)
              .orElseGet(() -> appendSnapshot(scopeId, defaultSpec()).stored());
    } else {
      if (revision <= 0 || !DIGEST.matcher(specDigest).matches()) {
        throw new ApiException("工作流快照版本或摘要格式无效");
      }
      stored =
          repository
              .findByWorkflowIdAndRevision(workflowId, revision)
              .filter(candidate -> scopeId.equals(candidate.getScopeId()))
              .orElseThrow(() -> new ApiException("工作流快照不存在或不属于当前项目"));
      if (!specDigest.equals(stored.getSpecDigest())) {
        throw new ApiException("工作流摘要不一致，已拒绝使用漂移后的配置");
      }
    }
    return toSnapshot(stored);
  }

  public WorkflowSnapshot freezeSnapshot(Long scopeId) {
    return freezeSnapshot(scopeId, null, null, null);
  }

  /** Keeps the selected immutable revision visible to legacy runtime calls for exactly one turn. */
  public <T> T withSnapshot(WorkflowSnapshot snapshot, Supplier<T> operation) {
    if (snapshot == null || operation == null) throw new ApiException("工作流快照或执行操作不能为空");
    WorkflowSnapshot previous = RUN_SNAPSHOT.get();
    RUN_SNAPSHOT.set(snapshot);
    try {
      return operation.get();
    } finally {
      if (previous == null) RUN_SNAPSHOT.remove();
      else RUN_SNAPSHOT.set(previous);
    }
  }

  public void withSnapshot(WorkflowSnapshot snapshot, Runnable operation) {
    withSnapshot(
        snapshot,
        () -> {
          operation.run();
          return null;
        });
  }

  private SnapshotAndEntity appendSnapshot(Long scopeId, Map<String, Object> body) {
    if (body == null || body.isEmpty()) {
      throw new ApiException("工作流内容不能为空");
    }
    Map<String, Object> copy = copyMap(body);
    SERVER_METADATA.forEach(copy::remove);
    Map<String, Object> normalized = normalize(copy);
    @SuppressWarnings("unchecked")
    Map<String, Object> canonical = (Map<String, Object>) canonicalize(normalized);
    String json = write(canonical);
    if (json.getBytes(StandardCharsets.UTF_8).length > MAX_SPEC_BYTES) {
      throw new ApiException("工作流配置过大");
    }
    Optional<AgentWorkflowSpec> latest = repository.findFirstByScopeIdOrderByRevisionDesc(scopeId);
    AgentWorkflowSpec spec = new AgentWorkflowSpec();
    spec.setWorkflowId(latest.map(AgentWorkflowSpec::getWorkflowId).orElseGet(() -> UUID.randomUUID().toString()));
    spec.setScopeId(scopeId);
    spec.setRevision(latest.map(item -> item.getRevision() + 1).orElse(1L));
    spec.setSpecDigest(digest(json));
    spec.setSpecJson(json);
    spec.setUpdatedBy(authorization.currentUsername());
    spec.setUpdatedAt(Instant.now());
    AgentWorkflowSpec stored = repository.save(spec);
    return new SnapshotAndEntity(toSnapshot(stored), stored);
  }

  /**
   * Returns safe executable steps for the local AI runtime. Invalid old records are treated as an
   * empty workflow instead of preventing the rest of the agent from starting; newly saved records
   * have already passed {@link #normalize(Map)}.
   */
  public List<Map<String, Object>> executableSteps() {
    WorkflowSnapshot snapshot = RUN_SNAPSHOT.get();
    if (snapshot == null) return List.of();
    return snapshot.executableSteps();
  }

  public List<Map<String, Object>> executableSteps(WorkflowSnapshot snapshot) {
    if (snapshot == null) return List.of();
    Map<String, Object> root = mutableCopyMap(snapshot.spec());
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
        normalizeGraphSteps(root.get("steps"), byId, incoming, depth, groupByDepth);
    graph.put("nodes", nodes);
    graph.put("edges", edges);
    root.put("graph", graph);
    root.put("steps", normalizedSteps);
  }

  private List<Map<String, Object>> normalizeGraphSteps(
      Object value,
      Map<String, Map<String, Object>> nodes,
      Map<String, List<String>> incoming,
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
      normalized.put("dependsOnNodeIds", nearestToolDependencies(nodeId, nodes, incoming));
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
    Set<String> nodeIds = new HashSet<>();
    for (int index = 0; index < raw.size(); index++) {
      Map<String, Object> step = raw.get(index);
      String tool = text(step.get("tool"));
      if (tool == null || !RUNTIME_TOOLS.contains(tool)) throw new ApiException("工作流工具不受支持");
      Map<String, Object> normalized = copyMap(step);
      String nodeId = text(step.get("nodeId"));
      if (nodeId == null) nodeId = String.format("legacy-%02d-%s", index + 1, tool);
      if (!NODE_ID.matcher(nodeId).matches() || !nodeIds.add(nodeId)) {
        throw new ApiException("工作流节点 ID 无效或重复");
      }
      normalized.put("nodeId", nodeId);
      normalized.put("group", integer(step.get("group"), 0, 0, 32, "工作流并行组无效"));
      normalized.put(
          "parameters",
          step.get("parameters") instanceof Map<?, ?> ? step.get("parameters") : Map.of());
      result.add(normalized);
    }
    Map<Integer, List<String>> nodesByGroup = new TreeMap<>();
    for (Map<String, Object> step : result) {
      nodesByGroup
          .computeIfAbsent((Integer) step.get("group"), ignored -> new ArrayList<>())
          .add(text(step.get("nodeId")));
    }
    for (Map<String, Object> step : result) {
      int group = (Integer) step.get("group");
      List<String> dependencies =
          nodesByGroup.entrySet().stream()
              .filter(entry -> entry.getKey() < group)
              .reduce((first, second) -> second)
              .map(Map.Entry::getValue)
              .orElse(List.of());
      step.put("dependsOnNodeIds", List.copyOf(dependencies));
    }
    return result;
  }

  private List<String> nearestToolDependencies(
      String nodeId,
      Map<String, Map<String, Object>> nodes,
      Map<String, List<String>> incoming) {
    LinkedHashSet<String> result = new LinkedHashSet<>();
    Deque<String> queue = new ArrayDeque<>(incoming.getOrDefault(nodeId, List.of()));
    Set<String> visited = new HashSet<>();
    while (!queue.isEmpty()) {
      String predecessor = queue.removeFirst();
      if (!visited.add(predecessor)) continue;
      Map<String, Object> node = nodes.get(predecessor);
      if (node != null && text(node.get("tool")) != null) {
        result.add(predecessor);
      } else {
        queue.addAll(incoming.getOrDefault(predecessor, List.of()));
      }
    }
    return List.copyOf(result);
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

  private String write(Object value) {
    try {
      return objectMapper.writeValueAsString(value);
    } catch (JsonProcessingException ex) {
      throw new ApiException("工作流保存失败");
    }
  }

  private void requireScope(Long scopeId, boolean manage) {
    if (scopeId == null || scopeId <= 0) throw new ApiException("缺少有效的工作流项目编号");
    if (manage) authorization.requireManage(scopeId);
    else authorization.requireAccess(scopeId);
  }

  private WorkflowSnapshot toSnapshot(AgentWorkflowSpec stored) {
    if (stored == null
        || stored.getWorkflowId() == null
        || stored.getScopeId() == null
        || stored.getRevision() == null
        || stored.getSpecDigest() == null
        || stored.getUpdatedBy() == null
        || stored.getUpdatedAt() == null) {
      throw new ApiException("工作流快照元数据不完整");
    }
    Map<String, Object> parsed = parseMap(stored.getSpecJson());
    if (parsed.isEmpty()) throw new ApiException("工作流快照内容损坏");
    @SuppressWarnings("unchecked")
    Map<String, Object> canonical = (Map<String, Object>) canonicalize(parsed);
    String canonicalJson = write(canonical);
    if (!DIGEST.matcher(stored.getSpecDigest()).matches()
        || !stored.getSpecDigest().equals(digest(canonicalJson))) {
      throw new ApiException("工作流快照摘要校验失败");
    }
    Map<String, Object> immutableSpec = immutableMap(canonical);
    List<Map<String, Object>> steps = immutableStepList(stepsFromNormalized(canonical));
    return new WorkflowSnapshot(
        stored.getWorkflowId(),
        stored.getScopeId(),
        stored.getRevision(),
        stored.getSpecDigest(),
        stored.getUpdatedBy(),
        stored.getUpdatedAt(),
        immutableSpec,
        steps);
  }

  private String digest(String canonicalJson) {
    try {
      byte[] bytes = MessageDigest.getInstance("SHA-256").digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
      return "sha256:" + HexFormat.of().formatHex(bytes);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 不可用", ex);
    }
  }

  private Object canonicalize(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      map.forEach(
          (key, item) -> {
            if (key != null) sorted.put(String.valueOf(key), canonicalize(item));
          });
      return new LinkedHashMap<>(sorted);
    }
    if (value instanceof List<?> list) {
      return list.stream().map(this::canonicalize).toList();
    }
    return value;
  }

  private Map<String, Object> mutableCopyMap(Map<String, Object> source) {
    @SuppressWarnings("unchecked")
    Map<String, Object> result = (Map<String, Object>) mutableCopy(source);
    return result;
  }

  private Object mutableCopy(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = new LinkedHashMap<>();
      map.forEach(
          (key, item) -> {
            if (key != null) result.put(String.valueOf(key), mutableCopy(item));
          });
      return result;
    }
    if (value instanceof List<?> list) {
      List<Object> result = new ArrayList<>();
      list.forEach(item -> result.add(mutableCopy(item)));
      return result;
    }
    return value;
  }

  private Map<String, Object> immutableMap(Map<String, Object> source) {
    @SuppressWarnings("unchecked")
    Map<String, Object> result = (Map<String, Object>) immutableValue(source);
    return result;
  }

  private Object immutableValue(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = new LinkedHashMap<>();
      map.forEach(
          (key, item) -> {
            if (key != null) result.put(String.valueOf(key), immutableValue(item));
          });
      return Collections.unmodifiableMap(result);
    }
    if (value instanceof List<?> list) {
      return Collections.unmodifiableList(list.stream().map(this::immutableValue).toList());
    }
    return value;
  }

  private List<Map<String, Object>> immutableStepList(List<Map<String, Object>> steps) {
    return Collections.unmodifiableList(steps.stream().map(this::immutableMap).toList());
  }

  private Map<String, Object> defaultSpec() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("version", 1);
    value.put("preset", "runtime-default");
    value.put(
        "steps",
        List.of(
            defaultStep("context", "retrieve_project_context", 0, "SAFE", false),
            defaultStep("service-scan", "nmap_service_scan", 1, "SAFE", false),
            defaultStep("headers", "http_headers", 1, "SAFE", false),
            defaultStep("tls", "tls_config", 1, "SAFE", false),
            defaultStep("http-security", "http_security_check", 2, "SAFE", false),
            defaultStep("nuclei", "nuclei_scan", 3, "CAUTION", true),
            defaultStep("afrog", "afrog_scan", 4, "CAUTION", true),
            defaultStep("xray", "xray_scan", 5, "CAUTION", true)));
    return value;
  }

  private Map<String, Object> defaultStep(
      String nodeId, String tool, int group, String risk, boolean requiresApproval) {
    Map<String, Object> step = new LinkedHashMap<>();
    step.put("nodeId", nodeId);
    step.put("tool", tool);
    step.put(
        "parameters",
        Set.of("afrog_scan", "xray_scan").contains(tool)
            ? Map.of("allPocs", true)
            : Map.of());
    step.put("risk", risk);
    step.put("requiresApproval", requiresApproval);
    step.put("group", group);
    return step;
  }

  private boolean blank(String value) {
    return value == null || value.isBlank();
  }

  public record WorkflowSnapshot(
      String workflowId,
      Long scopeId,
      Long revision,
      String specDigest,
      String updatedBy,
      Instant updatedAt,
      Map<String, Object> spec,
      List<Map<String, Object>> executableSteps) {
    public Map<String, Object> response() {
      Map<String, Object> response = new LinkedHashMap<>(spec);
      response.put("workflowId", workflowId);
      response.put("scopeId", scopeId);
      response.put("revision", revision);
      response.put("specDigest", specDigest);
      response.put("updatedBy", updatedBy);
      response.put("updatedAt", updatedAt);
      return Collections.unmodifiableMap(response);
    }
  }

  private record SnapshotAndEntity(WorkflowSnapshot snapshot, AgentWorkflowSpec stored) {}
}
