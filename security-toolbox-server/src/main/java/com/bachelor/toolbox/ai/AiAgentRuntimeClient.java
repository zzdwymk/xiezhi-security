package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Optional loopback adapter for the packaged Python LangGraph runtime. */
@Component
public class AiAgentRuntimeClient {
  private static final List<String> ALLOWED_RUNTIME_TOOLS =
      List.of(
          "retrieve_project_context",
          "nmap_service_scan",
          "tcp_ports",
          "http_headers",
          "http_security_check",
          "tls_config",
          "nuclei_scan");
  private static final List<String> ACTIVE_TASK_STATUSES = List.of("PENDING", "RUNNING");

  private final boolean enabled;
  private final String token;
  private final RestClient restClient;
  private final ObjectMapper objectMapper;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final SecurityTaskRepository tasks;
  private final AgentWorkflowSpecService workflowSpecs;
  private final int maxActions;

  public AiAgentRuntimeClient(
      ObjectMapper objectMapper,
      AssessmentProjectService projects,
      TargetService targets,
      SecurityTaskRepository tasks,
      AgentWorkflowSpecService workflowSpecs,
      @Value("${toolbox.ai.agent.runtime-enabled:true}") boolean enabled,
      @Value("${toolbox.ai.agent.runtime-base-url:}") String configuredBaseUrl,
      @Value("${toolbox.ai.agent.runtime-port:8090}") int port,
      @Value("${toolbox.ai.agent.runtime-token:}") String token,
      @Value("${toolbox.ai.agent.runtime-timeout-seconds:120}") int timeoutSeconds,
      @Value("${toolbox.ai.agent.max-active-tasks-per-project:20}") int maxActions) {
    this.objectMapper = objectMapper;
    this.projects = projects;
    this.targets = targets;
    this.tasks = tasks;
    this.workflowSpecs = workflowSpecs;
    this.enabled = enabled;
    this.token = token == null ? "" : token.strip();
    this.maxActions = Math.max(1, maxActions);
    String baseUrl =
        configuredBaseUrl == null || configuredBaseUrl.isBlank()
            ? "http://127.0.0.1:" + Math.max(1, Math.min(port, 65535))
            : configuredBaseUrl.strip();
    if (!baseUrl.matches("https?://(127\\.0\\.0\\.1|localhost|\\[::1])(?::\\d+)?/?")) {
      throw new IllegalArgumentException("AI Runtime 仅允许连接本机回环地址");
    }
    SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
    requestFactory.setConnectTimeout(Duration.ofSeconds(2));
    requestFactory.setReadTimeout(Duration.ofSeconds(Math.max(10, timeoutSeconds)));
    this.restClient =
        RestClient.builder()
            .baseUrl(stripTrailingSlash(baseUrl))
            .requestFactory(requestFactory)
            .build();
  }

  public boolean enabled() {
    return enabled;
  }

  /**
   * Workflow topology for the visual editor: the real LangGraph structure when the runtime is up,
   * otherwise a static mirror so the view always renders.
   */
  public Object graph() {
    if (enabled) {
      try {
        JsonNode node =
            restClient
                .get()
                .uri("/agent/graph")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(JsonNode.class);
        if (node != null && node.has("nodes")) return node;
      } catch (Exception ignored) {
        // fall through to the static mirror below
      }
    }
    return staticGraph();
  }

  private Map<String, Object> staticGraph() {
    List<Map<String, Object>> nodes =
        List.of(
            graphNode("engage", "任务启动与范围确认", "engagement", "绑定项目、目标、授权时间窗、停止条件和资源配额", false),
            graphNode("recon", "侦察与情报整理", "recon", "优先复用项目资料和公开情报，减少不必要探测", false),
            graphNode("map", "资产与服务发现", "mapping", "识别授权资产、端口、服务、版本和基础指纹", false),
            graphNode("validate", "漏洞验证与受控利用", "validation", "以最小影响方式验证风险并保留可复核证据", false),
            graphNode("impact", "权限与影响评估", "impact", "评估攻击路径和业务影响；高风险动作在此等待人工审批", false),
            graphNode("retest", "清理与复测", "retest", "清理测试痕迹、复测修复结果并记录扫描 Diff", false),
            graphNode("report", "报告交付", "report", "汇总证据链、整改建议和审计记录", false),
            graphNode("finish", "任务结束", "finish", "归档本轮状态并明确后续动作", false));
    List<Map<String, Object>> edges =
        List.of(
            graphEdge("__start__", "engage", false),
            graphEdge("engage", "recon", false),
            graphEdge("recon", "map", false),
            graphEdge("map", "validate", false),
            graphEdge("validate", "impact", false),
            graphEdge("impact", "retest", false),
            graphEdge("retest", "report", false),
            graphEdge("report", "finish", false),
            graphEdge("finish", "__end__", false));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("version", 2);
    result.put("preset", "red-team-lifecycle");
    result.put("nodes", nodes);
    result.put("edges", edges);
    result.put("compiled", null);
    result.put("source", "static");
    result.put(
        "legacyNodeAliases",
        Map.of(
            "planner", "engage",
            "authorization_guard", "engage",
            "executor", "validate",
            "approval_required", "impact",
            "retry", "retest",
            "reviewer", "report"));
    return result;
  }

  private Map<String, Object> graphNode(
      String id, String label, String kind, String desc, boolean removable) {
    Map<String, Object> node = new LinkedHashMap<>();
    node.put("id", id);
    node.put("label", label);
    node.put("kind", kind);
    node.put("desc", desc);
    node.put("removable", removable);
    return node;
  }

  private Map<String, Object> graphEdge(String source, String target, boolean conditional) {
    Map<String, Object> edge = new LinkedHashMap<>();
    edge.put("source", source);
    edge.put("target", target);
    edge.put("conditional", conditional);
    return edge;
  }

  /** Replaces the runtime's project index. Only caller-provided text is accepted. */
  public void indexProject(Long projectId, List<IndexDocument> documents) {
    if (!enabled) throw new RuntimeUnavailableException("AI Runtime 未启用");
    if (projectId == null || documents == null || documents.isEmpty()) return;
    List<Map<String, Object>> safeDocuments =
        documents.stream()
            .filter(Objects::nonNull)
            .limit(200)
            .map(
                document ->
                    Map.<String, Object>of(
                        "title", truncate(document.title(), 300),
                        "text", truncate(document.text(), 20_000),
                        "source", truncate(document.source(), 200),
                        "metadata", document.metadata() == null ? Map.of() : document.metadata()))
            .toList();
    if (safeDocuments.isEmpty()) return;
    try {
      RestClient.RequestBodySpec spec =
          restClient
              .post()
              .uri("/index/project")
              .contentType(MediaType.APPLICATION_JSON)
              .accept(MediaType.APPLICATION_JSON);
      if (!token.isBlank()) spec.header("X-AI-Runtime-Token", token);
      spec.body(
              Map.of(
                  "projectId", projectId,
                  "replace", true,
                  "documents", safeDocuments))
          .retrieve()
          .toBodilessEntity();
    } catch (Exception ex) {
      throw new RuntimeUnavailableException("AI Runtime 项目索引暂时不可用", ex);
    }
  }

  /** Append a conversation summary to the project's LlamaIndex store (best-effort). */
  public void appendMemory(
      long projectId,
      String docId,
      String title,
      String summary,
      String conversationId,
      String createdAt) {
    if (!enabled) return;
    try {
      Map<String, Object> metadata = new LinkedHashMap<>();
      metadata.put("conversationId", conversationId == null ? "" : conversationId);
      metadata.put("createdAt", createdAt == null ? "" : createdAt);
      Map<String, Object> document = new LinkedHashMap<>();
      document.put("id", docId);
      document.put("title", truncate(title, 300));
      document.put("text", truncate(summary, 20_000));
      document.put("source", "conversation");
      document.put("metadata", metadata);
      RestClient.RequestBodySpec spec =
          restClient
              .post()
              .uri("/index/project/{p}/documents", projectId)
              .contentType(MediaType.APPLICATION_JSON)
              .accept(MediaType.APPLICATION_JSON);
      if (!token.isBlank()) spec.header("X-AI-Runtime-Token", token);
      spec.body(Map.of("documents", List.of(document))).retrieve().toBodilessEntity();
    } catch (Exception ignored) {
      // memory is best-effort; never fail the conversation because of it
    }
  }

  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> listMemories(long projectId) {
    if (!enabled) return List.of();
    try {
      RestClient.RequestHeadersSpec<?> spec =
          restClient
              .get()
              .uri(
                  builder ->
                      builder
                          .path("/index/project/{p}/documents")
                          .queryParam("source", "conversation")
                          .build(projectId))
              .accept(MediaType.APPLICATION_JSON);
      if (!token.isBlank()) spec.header("X-AI-Runtime-Token", token);
      JsonNode root = spec.retrieve().body(JsonNode.class);
      List<Map<String, Object>> out = new ArrayList<>();
      if (root != null && root.path("documents").isArray()) {
        for (JsonNode doc : root.path("documents"))
          out.add(objectMapper.convertValue(doc, Map.class));
      }
      return out;
    } catch (Exception ex) {
      return List.of();
    }
  }

  public boolean deleteMemory(long projectId, String docId) {
    if (!enabled) return false;
    try {
      RestClient.RequestHeadersSpec<?> spec =
          restClient
              .delete()
              .uri("/index/project/{p}/documents/{d}", projectId, docId)
              .accept(MediaType.APPLICATION_JSON);
      if (!token.isBlank()) spec.header("X-AI-Runtime-Token", token);
      spec.retrieve().toBodilessEntity();
      return true;
    } catch (Exception ex) {
      return false;
    }
  }

  public int clearMemories(long projectId) {
    if (!enabled) return 0;
    // Prefer bulk clear when the runtime supports DELETE /documents?source=
    try {
      RestClient.RequestHeadersSpec<?> bulk =
          restClient
              .delete()
              .uri(
                  builder ->
                      builder
                          .path("/index/project/{p}/documents")
                          .queryParam("source", "conversation")
                          .build(projectId))
              .accept(MediaType.APPLICATION_JSON);
      if (!token.isBlank()) bulk.header("X-AI-Runtime-Token", token);
      JsonNode root = bulk.retrieve().body(JsonNode.class);
      if (root != null && root.path("deleted").isNumber()) {
        return Math.max(0, root.path("deleted").asInt(0));
      }
    } catch (Exception ignored) {
      /* fall through to per-document delete for older runtimes */
    }
    List<Map<String, Object>> docs = listMemories(projectId);
    int deleted = 0;
    for (Map<String, Object> doc : docs) {
      Object id = doc.get("id");
      if (id == null) continue;
      if (deleteMemory(projectId, String.valueOf(id))) deleted++;
    }
    return deleted;
  }

  public RuntimePlanResult plan(
      AiAgentRequest request, String prompt, Consumer<RuntimeEvent> eventSink) {
    if (!enabled) throw new RuntimeUnavailableException("AI Runtime 未启用");
    Consumer<RuntimeEvent> sink = eventSink == null ? ignored -> {} : eventSink;
    AssessmentProject project = projects.get(request.projectId());
    AuthorizedTarget target = targets.getCurrentlyAuthorized(request.targetId());
    long usedActions = tasks.countByProjectIdAndStatusIn(request.projectId(), ACTIVE_TASK_STATUSES);

    Map<String, Object> authorization = new LinkedHashMap<>();
    authorization.put("status", project.getStatus());
    authorization.put("targetIds", List.of(target.getId()));
    authorization.put("allowedTools", ALLOWED_RUNTIME_TOOLS);
    authorization.put("allowedPorts", target.getAllowedPorts());
    authorization.put("approved", request.executionRequested());
    authorization.put("validFrom", project.getAuthorizationValidFrom());
    authorization.put("expiresAt", project.getAuthorizationExpiresAt());
    authorization.put(
        "quota",
        Map.of("maxActions", maxActions, "usedActions", Math.min(usedActions, maxActions)));

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("projectId", request.projectId());
    body.put("conversationId", request.sessionId());
    body.put("targetId", request.targetId());
    body.put(
        "mode",
        Objects.requireNonNullElse(
            request.mode(), request.executionRequested() ? "execute" : "plan"));
    body.put("maxRetries", 0);
    body.put("messages", buildPlannerMessages(request, prompt, scopeContext(target, project)));
    body.put("authorization", authorization);

    List<Map<String, Object>> workflowSteps = loadWorkflowSteps();
    if (!workflowSteps.isEmpty()) body.put("workflow", workflowSteps);

    Holder holder = new Holder();
    try {
      RestClient.RequestBodySpec spec =
          restClient
              .post()
              .uri("/agent/stream")
              .contentType(MediaType.APPLICATION_JSON)
              .accept(MediaType.TEXT_EVENT_STREAM);
      if (!token.isBlank()) spec.header("X-AI-Runtime-Token", token);
      spec.body(body)
          .exchange(
              (httpRequest, response) -> {
                if (response.getStatusCode().isError()) {
                  throw new RuntimeUnavailableException(
                      "AI Runtime 请求失败（HTTP " + response.getStatusCode().value() + "）");
                }
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(response.getBody(), StandardCharsets.UTF_8))) {
                  readSse(
                      reader,
                      event -> {
                        sink.accept(event);
                        holder.accept(event);
                      });
                }
                return null;
              });
    } catch (RuntimeUnavailableException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new RuntimeUnavailableException("AI Runtime 当前不可用", ex);
    }

    if (holder.error) throw new RuntimeUnavailableException("AI Runtime 返回失败状态");
    AiPlanResponse plan = toPlan(holder.plan, holder.answer);
    if (plan == null) throw new RuntimeUnavailableException("AI Runtime 未返回有效计划");
    return new RuntimePlanResult(plan, holder.answer, holder.finishStatus);
  }

  private List<Map<String, Object>> buildPlannerMessages(
      AiAgentRequest request, String prompt, String scopeContext) {
    List<Map<String, Object>> messages = new ArrayList<>();
    messages.add(
        Map.of(
            "role",
            "system",
            "content",
            "You are the intent-understanding and action-planning component of an authorized"
                + " security testing platform. Understand natural language (including colloquial"
                + " short confirms and dialogue context); do not rely on keyword tables. If the"
                + " user wants execution/scan/probe/check, propose low-risk whitelist tools; if"
                + " they want Q&A, answer only. Never emit shell/exploit commands; Java"
                + " re-validates every tool proposal. "
                + scopeContext));
    String userContent =
        prompt == null || prompt.isBlank() ? Objects.toString(request.prompt(), "") : prompt;
    String currentMarker = "当前请求：";
    if (request.prompt() != null
        && !request.prompt().isBlank()
        && !userContent.contains(currentMarker)) {
      userContent = userContent + "\n\n" + currentMarker + request.prompt();
    }
    messages.add(Map.of("role", "user", "content", userContent));
    return messages;
  }

  private String scopeContext(AuthorizedTarget target, AssessmentProject project) {
    return "projectStatus="
        + project.getStatus()
        + "; target="
        + target.getTargetValue()
        + "; allowedPorts="
        + target.getAllowedPorts()
        + ".";
  }

  private List<Map<String, Object>> loadWorkflowSteps() {
    List<Map<String, Object>> result = new ArrayList<>();
    for (Map<String, Object> step : workflowSpecs.executableSteps()) {
      String tool = Objects.toString(step.get("tool"), "");
      if (!ALLOWED_RUNTIME_TOOLS.contains(tool)) continue;
      Map<String, Object> item = new LinkedHashMap<>();
      item.put("tool", tool);
      item.put(
          "parameters",
          step.get("parameters") instanceof Map<?, ?> ? step.get("parameters") : Map.of());
      item.put("risk", Objects.toString(step.get("risk"), "SAFE"));
      item.put("requiresApproval", Boolean.TRUE.equals(step.get("requiresApproval")));
      Object rawGroup = step.get("group");
      int group = rawGroup instanceof Number number ? number.intValue() : 0;
      item.put("group", Math.max(0, Math.min(group, 32)));
      if (step.get("nodeId") != null) item.put("nodeId", Objects.toString(step.get("nodeId")));
      result.add(item);
    }
    return result;
  }

  private void readSse(BufferedReader reader, Consumer<RuntimeEvent> sink) throws IOException {
    StringBuilder data = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
      if (line.isBlank()) {
        flushEvent(data, sink);
      } else if (line.startsWith("data:")) {
        if (!data.isEmpty()) data.append('\n');
        data.append(line.substring(5).stripLeading());
      } else if (line.startsWith("{")) {
        // Development runtime may be placed behind an NDJSON adapter.
        flushEvent(new StringBuilder(line), sink);
      }
    }
    flushEvent(data, sink);
  }

  private void flushEvent(StringBuilder data, Consumer<RuntimeEvent> sink) throws IOException {
    if (data.isEmpty()) return;
    JsonNode root = objectMapper.readTree(data.toString());
    data.setLength(0);
    String type = root.path("type").asText("message");
    JsonNode rawData = root.path("data");
    @SuppressWarnings("unchecked")
    Map<String, Object> eventData =
        rawData.isObject() ? objectMapper.convertValue(rawData, Map.class) : Map.of();
    sink.accept(
        new RuntimeEvent(
            root.path("eventId").asText(""),
            type,
            root.path("node").asText(type),
            root.path("message").asText(""),
            root.path("timestamp").asText(""),
            eventData,
            rawData));
  }

  private AiPlanResponse toPlan(JsonNode planNode, String answer) {
    if (planNode == null || !planNode.isObject()) {
      if (answer == null || answer.isBlank()) return null;
      return new AiPlanResponse("langgraph-runtime", "runtime", answer, false, List.of());
    }
    List<AiPlanResponse.PlanStep> steps = new ArrayList<>();
    JsonNode actions = planNode.path("actions");
    if (!actions.isArray()) actions = planNode.path("steps");
    for (JsonNode action : actions) {
      String toolCode = action.path("tool").asText(action.path("toolCode").asText(""));
      if (toolCode.isBlank() || "retrieve_project_context".equals(toolCode)) continue;
      if (!ALLOWED_RUNTIME_TOOLS.contains(toolCode)) continue;
      Map<String, Object> parameters = normalizedParameters(toolCode, action.path("parameters"));
      steps.add(
          new AiPlanResponse.PlanStep(
              toolCode, titleOf(toolCode), "本地 AI Runtime 根据项目上下文提出", parameters));
    }
    String summary = planNode.path("summary").asText("");
    if (summary.isBlank())
      summary = answer == null || answer.isBlank() ? "本地 AI Runtime 已生成项目级计划" : answer;
    return new AiPlanResponse(
        "langgraph-runtime", "runtime", summary, !steps.isEmpty(), List.copyOf(steps));
  }

  private Map<String, Object> normalizedParameters(String toolCode, JsonNode raw) {
    Map<String, Object> source =
        raw != null && raw.isObject() ? objectMapper.convertValue(raw, Map.class) : Map.of();
    Map<String, Object> result = new LinkedHashMap<>();
    switch (toolCode) {
      case "tcp_ports" -> copyIfPresent(source, result, "ports");
      case "nmap_service_scan" -> {
        copyIfPresent(source, result, "ports");
        copyIfPresent(source, result, "mode");
      }
      case "http_security_check" -> copyIfPresent(source, result, "check");
      case "nuclei_scan", "http_headers", "tls_config" -> {}
      default -> result.putAll(source); // Java's immutable allow-list rejects unknown tools.
    }
    return Map.copyOf(result);
  }

  private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
    if (source.containsKey(key) && source.get(key) != null) target.put(key, source.get(key));
  }

  private String titleOf(String code) {
    return switch (code) {
      case "nmap_service_scan" -> "Nmap 服务识别";
      case "nuclei_scan" -> "Nuclei 安全模板检测";
      case "tcp_ports" -> "授权端口探测";
      case "http_headers" -> "HTTP 安全响应头检查";
      case "http_security_check" -> "HTTP 常见安全检查";
      case "tls_config" -> "TLS 基础配置检查";
      default -> code;
    };
  }

  private String stripTrailingSlash(String value) {
    return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
  }

  private String truncate(String value, int max) {
    if (value == null) return "";
    String clean = value.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= max ? clean : clean.substring(0, max);
  }

  public record IndexDocument(
      String title, String text, String source, Map<String, String> metadata) {}

  public record RuntimeEvent(
      String eventId,
      String type,
      String node,
      String message,
      String timestamp,
      Map<String, Object> data,
      JsonNode rawData) {}

  public record RuntimePlanResult(AiPlanResponse plan, String answer, String status) {}

  public static final class RuntimeUnavailableException extends RuntimeException {
    public RuntimeUnavailableException(String message) {
      super(message);
    }

    public RuntimeUnavailableException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private static final class Holder {
    private JsonNode plan;
    private String answer = "";
    private String finishStatus = "";
    private boolean error;

    private void accept(RuntimeEvent event) {
      if ("error".equals(event.type())) error = true;
      // Capture the plan as soon as the planner emits it so the UI checklist
      // does not depend only on the terminal finish event.
      if ("plan".equals(event.type())) {
        JsonNode candidate = event.rawData().path("plan");
        if (!candidate.isObject()) candidate = event.rawData();
        if (candidate.isObject()
            && (candidate.path("actions").isArray()
                || candidate.path("steps").isArray()
                || candidate.path("actionCount").isNumber()
                || candidate.path("summary").isTextual())) {
          plan = candidate;
        }
      }
      if ("finish".equals(event.type())) {
        finishStatus = event.rawData().path("status").asText("");
        answer = event.rawData().path("answer").asText("");
        JsonNode candidate = event.rawData().path("plan");
        if (candidate.isObject()) plan = candidate;
      }
    }
  }
}
