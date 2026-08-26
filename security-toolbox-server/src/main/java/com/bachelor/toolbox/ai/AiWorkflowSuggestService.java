package com.bachelor.toolbox.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class AiWorkflowSuggestService {
  private static final int MAX_SUGGESTIONS = 8;
  private static final int MAX_MODEL_SUGGESTIONS = 5;
  private static final String LOCAL_SOURCE = "本地规则";
  private static final Set<String> KNOWN_TOOLS =
      Set.of(
          "retrieve_project_context",
          "tcp_ports",
          "nmap_service_scan",
          "http_headers",
          "http_security_check",
          "tls_config",
          "nuclei_scan",
          "afrog_scan",
          "xray_scan");
  private static final Set<String> SCANNER_TOOLS =
      Set.of("nuclei_scan", "afrog_scan", "xray_scan");

  private final AiModelClient modelClient;
  private final ObjectMapper objectMapper;

  public AiWorkflowSuggestService(AiModelClient modelClient, ObjectMapper objectMapper) {
    this.modelClient = modelClient;
    this.objectMapper = objectMapper;
  }

  /** One-shot aggregate used by non-stream clients and tests. */
  public Map<String, Object> suggest(Map<String, Object> body) {
    List<Map<String, Object>> events = new ArrayList<>();
    stream(body == null ? Map.of() : body, events::add);
    return aggregate(events);
  }

  public void stream(Map<String, Object> body, Consumer<Map<String, Object>> sink) {
    Consumer<Map<String, Object>> emit = sink == null ? ignored -> {} : sink;
    WorkflowInput input = parseInput(body);

    emit.accept(statusEvent("start", "正在分析当前工作流拓扑", Map.of("modelEnabled", modelClient.enabled())));

    SuggestionEmitter suggestions = new SuggestionEmitter(emit);
    suggestions.emitAll(structuralSuggestions(input), "local");

    String source = LOCAL_SOURCE;
    String note = modelClient.enabled() ? "" : "未启用大模型，仅提供结构建议；在设置中配置 API 后可获得实时编排建议";
    String modelName = LOCAL_SOURCE;

    if (modelClient.enabled() && suggestions.hasCapacity()) {
      emit.accept(statusEvent("llm", "大模型正在审阅拓扑并生成编排建议"));
      try {
        int modelCount = suggestions.emitAll(modelSuggestions(input), "llm");
        source = modelCount > 0 ? "大模型+本地规则" : LOCAL_SOURCE;
        modelName = modelClient.model();
        if (modelCount == 0) {
          note = "大模型未给出额外建议，已保留结构建议";
        }
      } catch (Exception ignored) {
        note = "大模型暂时不可用，已提供结构建议";
        source = LOCAL_SOURCE;
        emit.accept(statusEvent("llm_fallback", note));
      }
    }

    emit.accept(doneEvent(source, modelName, note, suggestions.count()));
  }

  private Map<String, Object> aggregate(List<Map<String, Object>> events) {
    List<Map<String, Object>> suggestions = new ArrayList<>();
    String source = LOCAL_SOURCE;
    String note = "";
    String model = modelClient.enabled() ? modelClient.model() : LOCAL_SOURCE;

    for (Map<String, Object> event : events) {
      String type = Objects.toString(event.get("type"), "");
      if ("suggestion".equals(type)) {
        addAggregatedSuggestion(event, suggestions);
      } else if ("done".equals(type)) {
        source = Objects.toString(event.get("source"), source);
        note = Objects.toString(event.get("note"), note);
        model = Objects.toString(event.get("model"), model);
      }
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("source", source);
    result.put("model", model);
    result.put("note", note);
    result.put("suggestions", suggestions);
    result.put("generatedAt", Instant.now().toString());
    return result;
  }

  @SuppressWarnings("unchecked")
  private void addAggregatedSuggestion(
      Map<String, Object> event, List<Map<String, Object>> suggestions) {
    if (event.get("suggestion") instanceof Map<?, ?> suggestion) {
      suggestions.add((Map<String, Object>) suggestion);
    }
  }

  @SuppressWarnings("unchecked")
  private WorkflowInput parseInput(Map<String, Object> body) {
    Map<String, Object> safeBody = body == null ? Map.of() : body;
    Map<String, Object> graph =
        safeBody.get("graph") instanceof Map<?, ?> value ? (Map<String, Object>) value : Map.of();
    return new WorkflowInput(
        asMapList(graph.get("nodes")),
        asMapList(graph.get("edges")),
        stringValue(safeBody.get("preset")),
        stringValue(safeBody.get("selectedNodeId")),
        stringValue(safeBody.get("focus")));
  }

  private Map<String, Object> statusEvent(String phase, String message) {
    return statusEvent(phase, message, Map.of());
  }

  private Map<String, Object> statusEvent(
      String phase, String message, Map<String, Object> details) {
    Map<String, Object> event = new LinkedHashMap<>();
    event.put("type", "status");
    event.put("phase", phase);
    event.put("message", message);
    event.putAll(details);
    return event;
  }

  private Map<String, Object> doneEvent(String source, String model, String note, int count) {
    Map<String, Object> event = new LinkedHashMap<>();
    event.put("type", "done");
    event.put("source", source);
    event.put("model", model);
    event.put("note", note);
    event.put("count", count);
    event.put("generatedAt", Instant.now().toString());
    return event;
  }

  private List<Map<String, Object>> structuralSuggestions(WorkflowInput input) {
    WorkflowTopology topology = inspectTopology(input.nodes(), input.edges());
    List<Map<String, Object>> suggestions = new ArrayList<>();

    addProjectContextSuggestion(suggestions, topology.tools());
    addScanOrderSuggestion(suggestions, topology.tools());
    addServiceCoverageSuggestion(suggestions, topology.tools());
    addRiskConfirmationSuggestion(suggestions, topology.tools());
    addEmptyWorkflowSuggestion(suggestions, topology.toolCount());
    addParallelBranchSuggestion(suggestions, input.edges(), topology.toolCount());
    addOrphanNodeSuggestion(suggestions, input.nodes(), topology.connectedNodeIds());
    addPresetSuggestion(suggestions, input.preset(), topology.tools());
    addSelectedNodeSuggestion(suggestions, input.selectedNodeId(), topology.nodeKinds());
    return suggestions;
  }

  private WorkflowTopology inspectTopology(
      List<Map<String, Object>> nodes, List<Map<String, Object>> edges) {
    Set<String> tools = new LinkedHashSet<>();
    Map<String, String> nodeKinds = new LinkedHashMap<>();
    long toolCount = 0;

    for (Map<String, Object> node : nodes) {
      String id = stringValue(node.get("id"));
      String type = stringValue(node.get("type"));
      String tool = stringValue(node.get("tool"));
      nodeKinds.put(id, type);
      if ("tool".equals(type)) {
        toolCount++;
        if (!tool.isBlank()) {
          tools.add(tool);
        }
      }
    }

    Set<String> connectedNodeIds = new LinkedHashSet<>();
    for (Map<String, Object> edge : edges) {
      connectedNodeIds.add(stringValue(edge.get("source")));
      connectedNodeIds.add(stringValue(edge.get("target")));
    }
    return new WorkflowTopology(tools, nodeKinds, connectedNodeIds, toolCount);
  }

  private void addProjectContextSuggestion(
      List<Map<String, Object>> suggestions, Set<String> tools) {
    if (tools.contains("retrieve_project_context")) {
      return;
    }
    suggestions.add(
        tip(
            "gap",
            "info",
            "补上项目情报检索",
            "被动侦察阶段建议先读取项目资料与历史证据，减少盲目探测。",
            actionAddTool("retrieve_project_context", "recon")));
  }

  private void addScanOrderSuggestion(List<Map<String, Object>> suggestions, Set<String> tools) {
    boolean hasDiscovery =
        tools.contains("nmap_service_scan")
            || tools.contains("tcp_ports")
            || tools.contains("http_headers");
    if (tools.stream().noneMatch(SCANNER_TOOLS::contains) || hasDiscovery) {
      return;
    }
    suggestions.add(
        tip(
            "order",
            "warning",
            "漏洞扫描前先做资产发现",
            "当前有漏洞扫描器节点，但缺少端口/服务/Web 基础采集。建议先完成 mapping 再验证。",
            actionAddTool("nmap_service_scan", "mapping")));
  }

  private void addServiceCoverageSuggestion(
      List<Map<String, Object>> suggestions, Set<String> tools) {
    boolean hasWebCheck =
        tools.contains("http_headers")
            || tools.contains("http_security_check")
            || tools.contains("tls_config");
    boolean hasPortDiscovery = tools.contains("nmap_service_scan") || tools.contains("tcp_ports");
    if (!hasWebCheck || hasPortDiscovery) {
      return;
    }
    suggestions.add(
        tip(
            "coverage",
            "info",
            "可补充端口与服务识别",
            "Web/TLS 检查已存在。若目标授权了端口范围，可增加服务识别以完善资产画像。",
            actionAddTool("nmap_service_scan", "mapping")));
  }

  private void addRiskConfirmationSuggestion(
      List<Map<String, Object>> suggestions, Set<String> tools) {
    if (tools.stream().noneMatch(SCANNER_TOOLS::contains)) {
      return;
    }
    suggestions.add(
        tip("risk", "warning", "漏洞扫描器需人工确认", "Nuclei、Afrog 和 Xray 扫描器会在执行前要求确认；AI 派发时仍会二次校验授权。", null));
  }

  private void addEmptyWorkflowSuggestion(List<Map<String, Object>> suggestions, long toolCount) {
    if (toolCount != 0) {
      return;
    }
    suggestions.add(
        tip(
            "empty",
            "warning",
            "还没有受控能力节点",
            "从右侧能力卡添加至少一个工具节点，AI 才能按图中依赖生成受控任务。",
            actionAddTool("retrieve_project_context", "recon")));
  }

  private void addParallelBranchSuggestion(
      List<Map<String, Object>> suggestions, List<Map<String, Object>> edges, long toolCount) {
    if (toolCount < 2 || hasParallelBranch(edges)) {
      return;
    }
    suggestions.add(
        tip("parallel", "info", "可以尝试并行分支", "同层互不依赖的能力可从同一阶段分叉以缩短时间；汇合节点会等待上游完成。", null));
  }

  private boolean hasParallelBranch(List<Map<String, Object>> edges) {
    return edges.stream()
        .map(edge -> stringValue(edge.get("source")))
        .filter(id -> !id.isBlank())
        .collect(Collectors.groupingBy(source -> source, Collectors.counting()))
        .values()
        .stream()
        .anyMatch(count -> count > 1);
  }

  private void addOrphanNodeSuggestion(
      List<Map<String, Object>> suggestions,
      List<Map<String, Object>> nodes,
      Set<String> connectedNodeIds) {
    for (Map<String, Object> node : nodes) {
      if (!"tool".equals(stringValue(node.get("type")))) {
        continue;
      }
      String id = stringValue(node.get("id"));
      if (id.isBlank() || connectedNodeIds.contains(id)) {
        continue;
      }
      suggestions.add(
          tip(
              "orphan",
              "warning",
              "存在未连线的能力节点",
              "请将未接入主路径的能力节点连到上游，或删除不用的节点。",
              Map.of("type", "focus_node", "nodeId", id)));
      return;
    }
  }

  private void addPresetSuggestion(
      List<Map<String, Object>> suggestions, String preset, Set<String> tools) {
    boolean needsSecurityCheck =
        "quick-web".equals(preset)
            && !tools.contains("http_security_check")
            && tools.contains("http_headers");
    if (!needsSecurityCheck) {
      return;
    }
    suggestions.add(
        tip(
            "preset",
            "info",
            "快速 Web 评估可加安全配置检查",
            "建议在漏洞发现阶段加入 HTTP 安全配置检查。",
            actionAddTool("http_security_check", "discovery")));
  }

  private void addSelectedNodeSuggestion(
      List<Map<String, Object>> suggestions, String selectedNodeId, Map<String, String> nodeKinds) {
    if (selectedNodeId.isBlank() || !"tool".equals(nodeKinds.get(selectedNodeId))) {
      return;
    }
    suggestions.add(
        tip(
            "focus",
            "info",
            "已选中能力节点",
            "可继续向下游连线，或在右侧更换所属阶段。AI 执行时按拓扑分组调度。",
            Map.of("type", "focus_node", "nodeId", selectedNodeId)));
  }

  private List<Map<String, Object>> modelSuggestions(WorkflowInput input) throws Exception {
    String raw = modelClient.complete(modelSystemPrompt(), modelUserPrompt(input));
    JsonNode root = objectMapper.readTree(stripFence(raw));
    return normalizeModelSuggestions(root);
  }

  private String modelSystemPrompt() {
    return "你是授权红队工作流编排顾问。根据当前可视化工作流图给出简洁可执行的编排建议。只输出JSON数组。"
        + " item:{kind,severity,title,detail,action}."
        + " action null or {type:add_tool,tool,phase}."
        + " tools:retrieve_project_context,tcp_ports,nmap_service_scan,http_headers,"
        + "http_security_check,tls_config,nuclei_scan,afrog_scan,xray_scan. max 5.";
  }

  private String modelUserPrompt(WorkflowInput input) throws Exception {
    return "preset="
        + input.preset()
        + " selectedNodeId="
        + input.selectedNodeId()
        + " focus="
        + input.focus()
        + " nodes="
        + objectMapper.writeValueAsString(input.nodes())
        + " edges="
        + objectMapper.writeValueAsString(input.edges());
  }

  private List<Map<String, Object>> normalizeModelSuggestions(JsonNode root) {
    if (root == null || !root.isArray()) {
      return List.of();
    }
    List<Map<String, Object>> suggestions = new ArrayList<>();
    for (JsonNode item : root) {
      Map<String, Object> suggestion = normalizeModelSuggestion(item);
      if (suggestion != null) {
        suggestions.add(suggestion);
      }
      if (suggestions.size() >= MAX_MODEL_SUGGESTIONS) {
        break;
      }
    }
    return suggestions;
  }

  private Map<String, Object> normalizeModelSuggestion(JsonNode item) {
    if (!item.isObject()) {
      return null;
    }
    String title = item.path("title").asText("").strip();
    String detail = item.path("detail").asText("").strip();
    if (title.isBlank() || detail.isBlank()) {
      return null;
    }
    return tip(
        item.path("kind").asText("coverage"),
        item.path("severity").asText("info"),
        title,
        detail,
        normalizeModelAction(item.get("action")));
  }

  private Map<String, Object> normalizeModelAction(JsonNode actionNode) {
    if (actionNode == null
        || !actionNode.isObject()
        || !"add_tool".equals(actionNode.path("type").asText(""))) {
      return null;
    }
    String tool = actionNode.path("tool").asText("");
    if (!KNOWN_TOOLS.contains(tool)) {
      return null;
    }
    return actionAddTool(tool, actionNode.path("phase").asText("mapping"));
  }

  private Map<String, Object> tip(
      String kind, String severity, String title, String detail, Map<String, Object> action) {
    Map<String, Object> suggestion = new LinkedHashMap<>();
    suggestion.put("id", kind + "-" + Integer.toHexString(Objects.hash(title, detail)));
    suggestion.put("kind", kind);
    suggestion.put("severity", severity);
    suggestion.put("title", title);
    suggestion.put("detail", detail);
    if (action != null) {
      suggestion.put("action", action);
    }
    return suggestion;
  }

  private Map<String, Object> actionAddTool(String tool, String phase) {
    Map<String, Object> action = new LinkedHashMap<>();
    action.put("type", "add_tool");
    action.put("tool", tool);
    action.put("phase", phase);
    return action;
  }

  private String stripFence(String content) {
    String value = content == null ? "" : content.strip();
    if (value.startsWith("```")) {
      int firstLine = value.indexOf('\n');
      int closingFence = value.lastIndexOf("```");
      if (firstLine >= 0 && closingFence > firstLine) {
        value = value.substring(firstLine + 1, closingFence).strip();
      }
    }
    int arrayStart = value.indexOf('[');
    int arrayEnd = value.lastIndexOf(']');
    if (arrayStart >= 0 && arrayEnd > arrayStart) {
      value = value.substring(arrayStart, arrayEnd + 1);
    }
    return value;
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> asMapList(Object raw) {
    if (!(raw instanceof List<?> list)) {
      return List.of();
    }
    List<Map<String, Object>> maps = new ArrayList<>();
    for (Object item : list) {
      if (item instanceof Map<?, ?> map) {
        maps.add((Map<String, Object>) map);
      }
    }
    return maps;
  }

  private String stringValue(Object value) {
    return value == null ? "" : String.valueOf(value).trim();
  }

  private record WorkflowInput(
      List<Map<String, Object>> nodes,
      List<Map<String, Object>> edges,
      String preset,
      String selectedNodeId,
      String focus) {}

  private record WorkflowTopology(
      Set<String> tools,
      Map<String, String> nodeKinds,
      Set<String> connectedNodeIds,
      long toolCount) {}

  private static final class SuggestionEmitter {
    private final Consumer<Map<String, Object>> sink;
    private final Set<String> seen = new LinkedHashSet<>();
    private int count;

    private SuggestionEmitter(Consumer<Map<String, Object>> sink) {
      this.sink = sink;
    }

    private int emitAll(List<Map<String, Object>> suggestions, String origin) {
      int emitted = 0;
      for (Map<String, Object> suggestion : suggestions) {
        if (!hasCapacity()) {
          break;
        }
        String key =
            Objects.toString(suggestion.get("title"), "")
                + "|"
                + Objects.toString(suggestion.get("kind"), "");
        if (key.isBlank() || !seen.add(key)) {
          continue;
        }
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("type", "suggestion");
        event.put("suggestion", suggestion);
        event.put("index", count);
        event.put("origin", origin);
        sink.accept(event);
        count++;
        emitted++;
      }
      return emitted;
    }

    private boolean hasCapacity() {
      return count < MAX_SUGGESTIONS;
    }

    private int count() {
      return count;
    }
  }
}
