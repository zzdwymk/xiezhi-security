package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Optional loopback adapter for the packaged Python LangGraph runtime. */
@Component
public class AiAgentRuntimeClient {
  static final int CONTRACT_VERSION = 3;
  private static final String RUNTIME_LEDGER_GENESIS_DIGEST = "sha256:" + "0".repeat(64);
  private static final int MAX_EVIDENCE_EVENT_BYTES = 64 * 1024;
  private static final int MAX_EVIDENCE_ITEMS = 10;
  private static final int MAX_TURN_EVIDENCE_IDS = 20;
  private static final String SHA256_PATTERN = "sha256:[0-9a-f]{64}";
  private static final String SAFE_ID_PATTERN = "[A-Za-z0-9][A-Za-z0-9_.:-]*";
  private static final List<String> ALLOWED_RUNTIME_TOOLS =
      List.of(
          "retrieve_project_context",
          "nmap_service_scan",
          "tcp_ports",
          "http_headers",
          "http_security_check",
          "tls_config",
          "nuclei_scan",
          "afrog_scan",
          "xray_scan",
          "zap_scan");
  private static final List<String> ACTIVE_TASK_STATUSES = List.of("BLOCKED", "PENDING", "RUNNING");
  private static final List<String> PROJECT_INDEX_SOURCES =
      List.of("project", "target", "task", "finding", "recon", "probe", "conversation");
  static final String POLICY_REVISION = "java-authoritative-v1";
  private static final Set<String> RUNTIME_EVENT_TYPES =
      Set.of(
          "plan",
          "route",
          "evidence",
          "rewrite",
          "authorization_guard",
          "stage",
          "tool",
          "approval_required",
          "retry",
          "review",
          "finish",
          "error");

  private final boolean enabled;
  private final String token;
  private final String projectSigningSecret;
  private final RestClient restClient;
  private final ObjectMapper objectMapper;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final SecurityTaskRepository tasks;
  private final AgentWorkflowSpecService workflowSpecs;
  private final AgentLedgerService ledger;
  private final ObjectMapper canonicalMapper;
  private final int maxActions;

  @Autowired
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
      @Value("${toolbox.ai.agent.runtime-project-signing-secret:}")
          String projectSigningSecret,
      @Value("${toolbox.ai.agent.runtime-timeout-seconds:120}") int timeoutSeconds,
      @Value("${toolbox.ai.agent.max-active-tasks-per-project:20}") int maxActions,
      AgentLedgerService ledger) {
    this.objectMapper = objectMapper;
    this.projects = projects;
    this.targets = targets;
    this.tasks = tasks;
    this.workflowSpecs = workflowSpecs;
    this.ledger = ledger;
    this.canonicalMapper = objectMapper.copy();
    this.canonicalMapper.enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    this.token = token == null ? "" : token.strip();
    this.projectSigningSecret =
        projectSigningSecret == null ? "" : projectSigningSecret.strip();
    this.enabled =
        enabled && !this.token.isBlank() && !this.projectSigningSecret.isBlank();
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

  public AiAgentRuntimeClient(
      ObjectMapper objectMapper,
      AssessmentProjectService projects,
      TargetService targets,
      SecurityTaskRepository tasks,
      AgentWorkflowSpecService workflowSpecs,
      boolean enabled,
      String configuredBaseUrl,
      int port,
      String token,
      String projectSigningSecret,
      int timeoutSeconds,
      int maxActions) {
    this(
        objectMapper,
        projects,
        targets,
        tasks,
        workflowSpecs,
        enabled,
        configuredBaseUrl,
        port,
        token,
        projectSigningSecret,
        timeoutSeconds,
        maxActions,
        null);
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
      authorizeProject(spec, projectId, "index-write");
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
      long targetId,
      String docId,
      String title,
      String summary,
      String conversationId,
      String createdAt) {
    if (!enabled) return;
    try {
      Map<String, Object> metadata = new LinkedHashMap<>();
      metadata.put("conversationId", conversationId == null ? "" : conversationId);
      metadata.put("targetId", String.valueOf(targetId));
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
      authorizeProject(spec, projectId, "index-write");
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
      authorizeProject(spec, projectId, "index-read");
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
              .uri(
                  builder ->
                      builder
                          .path("/index/project/{p}/documents/{d}")
                          .queryParam("source", "conversation")
                          .build(projectId, docId))
              .accept(MediaType.APPLICATION_JSON);
      authorizeProject(spec, projectId, "index-write");
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
      authorizeProject(bulk, projectId, "index-write");
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

  /**
   * Removes every document source written by {@link AiProjectIndexService} for one project.
   *
   * <p>Unlike conversation-memory cleanup, this operation is strict: an enabled runtime must
   * acknowledge every source deletion so a database reset cannot leave retrievable project data.
   */
  public int clearProjectIndex(long projectId) {
    if (!enabled) return 0;
    int deleted = 0;
    for (String source : PROJECT_INDEX_SOURCES) {
      try {
        RestClient.RequestHeadersSpec<?> request =
            restClient
                .delete()
                .uri(
                    builder ->
                        builder
                            .path("/index/project/{p}/documents")
                            .queryParam("source", source)
                            .build(projectId))
                .accept(MediaType.APPLICATION_JSON);
        authorizeProject(request, projectId, "index-write");
        JsonNode root = request.retrieve().body(JsonNode.class);
        JsonNode deletedNode = root == null ? null : root.get("deleted");
        if (deletedNode == null
            || !deletedNode.isIntegralNumber()
            || !deletedNode.canConvertToInt()
            || deletedNode.intValue() < 0) {
          throw new RuntimeProtocolException("AI Runtime 项目索引清理回执无效");
        }
        deleted += deletedNode.intValue();
      } catch (Exception ex) {
        throw new RuntimeUnavailableException("AI Runtime 项目索引清理失败", ex);
      }
    }
    return deleted;
  }

  public RuntimePlanResult plan(
      AiAgentRequest request, String prompt, Consumer<RuntimeEvent> eventSink) {
    if (!enabled) throw new RuntimeUnavailableException("AI Runtime 未启用");
    validateWorkflowContext(request);
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
    authorization.put("policyRevision", POLICY_REVISION);

    Map<String, Object> body = new LinkedHashMap<>();
    String runId = UUID.randomUUID().toString();
    body.put("runId", runId);
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
    body.put("workflowId", request.workflowId());
    body.put("workflowRevision", request.workflowRevision());
    body.put("workflowDigest", request.workflowDigest());
    body.put("outerNodeId", request.outerNodeId());
    body.put("nodeRunId", request.nodeRunId());
    body.put(
        "budget",
        Map.of("maxRetrievalRounds", 2, "maxLlmCalls", 4, "timeoutSeconds", 90));

    List<Map<String, Object>> workflowSteps = loadWorkflowSteps();
    if (!workflowSteps.isEmpty()) body.put("workflow", workflowSteps);

    Holder holder = new Holder(runId, POLICY_REVISION, request);
    try {
      RestClient.RequestBodySpec spec =
          restClient
              .post()
              .uri("/agent/stream")
              .contentType(MediaType.APPLICATION_JSON)
              .accept(MediaType.TEXT_EVENT_STREAM);
      authorizeProject(spec, request.projectId(), "agent");
      spec.body(body)
          .exchange(
              (httpRequest, response) -> {
                if (response.getStatusCode().isError()) {
                  if (response.getStatusCode().is4xxClientError()) {
                    throw new RuntimeProtocolException(
                        "AI Runtime 拒绝了 Harness 请求（HTTP "
                            + response.getStatusCode().value()
                            + "）");
                  }
                  throw new RuntimeUnavailableException(
                      "AI Runtime 请求失败（HTTP " + response.getStatusCode().value() + "）");
                }
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(response.getBody(), StandardCharsets.UTF_8))) {
                  readSse(reader, holder::accept);
                }
                return null;
              });
    } catch (RuntimeProtocolException ex) {
      throw ex;
    } catch (RuntimeUnavailableException ex) {
      throw ex;
    } catch (Exception ex) {
      RuntimeProtocolException protocolException = findProtocolException(ex);
      if (protocolException != null) throw protocolException;
      throw new RuntimeUnavailableException("AI Runtime 当前不可用", ex);
    }

    if (!holder.finished) throw new RuntimeProtocolException("AI Runtime 流在终态前中断");
    holder.persistLedger();
    if (holder.error) {
      throw new RuntimeProtocolException(
          "AI Runtime 返回失败终态：" + (holder.errorCode.isBlank() ? "UNKNOWN" : holder.errorCode));
    }
    AiPlanResponse plan = holder.plan;
    if (plan == null) throw new RuntimeProtocolException("AI Runtime 未返回有效计划");
    if (Set.of("DENIED", "FAILED").contains(holder.finishStatus)) {
      String reason = holder.terminationReason;
      throw new RuntimeProtocolException(
          reason == null || reason.isBlank()
              ? "AI Runtime Harness 拒绝了本轮计划"
              : "AI Runtime 本轮未完成：" + reason);
    }
    if ("APPROVAL_REQUIRED".equals(holder.finishStatus)
        && request.executionRequested()
        && !plan.steps().isEmpty()) {
      throw new RuntimeProtocolException("AI Runtime 未授权执行本轮计划");
    }
    holder.publishTo(sink);
    return new RuntimePlanResult(
        plan,
        holder.answer,
        holder.finishStatus,
        runId,
        POLICY_REVISION,
        holder.stateVersion,
       holder.provenance());
 }

  /**
   * Package-visible entry point for fixture tests: parse a NDJSON/SSE stream without a live HTTP
   * runtime, exercising the full v3 protocol validation, candidate digest chain, and ledger
   * finalization path. The {@code runId} must match the events in the stream.
   */
  RuntimePlanResult consumeStream(
      String runId, String ndjson, AiAgentRequest request, Consumer<RuntimeEvent> eventSink) {
    validateWorkflowContext(request);
    Consumer<RuntimeEvent> sink = eventSink == null ? ignored -> {} : eventSink;
    Holder holder = new Holder(runId, POLICY_REVISION, request);
    try (BufferedReader reader =
        new BufferedReader(new java.io.StringReader(ndjson))) {
      readSse(reader, holder::accept);
    } catch (RuntimeProtocolException ex) {
      throw ex;
    } catch (RuntimeUnavailableException ex) {
      throw ex;
    } catch (Exception ex) {
      RuntimeProtocolException protocolException = findProtocolException(ex);
      if (protocolException != null) throw protocolException;
      throw new RuntimeUnavailableException("AI Runtime 当前不可用", ex);
    }
    if (!holder.finished) throw new RuntimeProtocolException("AI Runtime 流在终态前中断");
    holder.persistLedger();
    if (holder.error) {
      throw new RuntimeProtocolException(
          "AI Runtime 返回失败终态：" + (holder.errorCode.isBlank() ? "UNKNOWN" : holder.errorCode));
    }
    AiPlanResponse plan = holder.plan;
    if (plan == null) throw new RuntimeProtocolException("AI Runtime 未返回有效计划");
    if (Set.of("DENIED", "FAILED").contains(holder.finishStatus)) {
      String reason = holder.terminationReason;
      throw new RuntimeProtocolException(
          reason == null || reason.isBlank()
              ? "AI Runtime Harness 拒绝了本轮计划"
              : "AI Runtime 本轮未完成：" + reason);
    }
    if ("APPROVAL_REQUIRED".equals(holder.finishStatus)
        && request.executionRequested()
        && !plan.steps().isEmpty()) {
      throw new RuntimeProtocolException("AI Runtime 未授权执行本轮计划");
    }
    holder.publishTo(sink);
    return new RuntimePlanResult(
        plan,
        holder.answer,
        holder.finishStatus,
        runId,
        POLICY_REVISION,
        holder.stateVersion,
        holder.provenance());
  }

  /** Persist a bounded continuation tombstone in the local runtime after Java creates tasks. */
  public void checkpointContinuation(Map<String, Object> body, long projectId) {
    if (!enabled) return;
    try {
      RestClient.RequestBodySpec request =
          restClient
              .post()
              .uri("/agent/checkpoint")
              .contentType(MediaType.APPLICATION_JSON)
              .accept(MediaType.APPLICATION_JSON);
      authorizeProject(request, projectId, "agent-resume");
      request.body(body).retrieve().toBodilessEntity();
    } catch (Exception ex) {
      throw new RuntimeUnavailableException("AI Runtime 续接检查点写入失败", ex);
    }
  }

  /** Delivers terminal task summaries to the runtime; duplicate callback IDs are idempotent. */
  @SuppressWarnings("unchecked")
  public Map<String, Object> resumeContinuation(Map<String, Object> body, long projectId) {
    if (!enabled) return Map.of("status", "RUNTIME_DISABLED");
    try {
      RestClient.RequestBodySpec request =
          restClient
              .post()
              .uri("/agent/resume")
              .contentType(MediaType.APPLICATION_JSON)
              .accept(MediaType.APPLICATION_JSON);
      authorizeProject(request, projectId, "agent-resume");
      JsonNode result = request.body(body).retrieve().body(JsonNode.class);
      if (result == null || !result.isObject()) {
        throw new RuntimeProtocolException("AI Runtime 续接响应格式无效");
      }
      return objectMapper.convertValue(result, Map.class);
    } catch (RuntimeProtocolException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new RuntimeUnavailableException("AI Runtime 续接请求失败", ex);
    }
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
      item.put(
          "dependsOnNodeIds",
          step.get("dependsOnNodeIds") instanceof List<?> dependencies
              ? dependencies
              : List.of());
      if (step.get("summary") != null) item.put("summary", Objects.toString(step.get("summary")));
      result.add(item);
    }
    return result;
  }

  void readSse(BufferedReader reader, Consumer<RuntimeEvent> sink) throws IOException {
    StringBuilder data = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
      if (line.isBlank()) {
        flushEvent(data, sink);
      } else if (line.startsWith("data:")) {
        if (!data.isEmpty()) data.append('\n');
        data.append(line.substring(5).stripLeading());
        if (data.length() > 1_000_000) {
          throw new RuntimeProtocolException("AI Runtime 事件超过大小限制");
        }
      } else if (line.startsWith("{")) {
        // Development runtime may be placed behind an NDJSON adapter.
        if (!data.isEmpty())
          throw new RuntimeProtocolException("AI Runtime 混合了不完整的 SSE 与 NDJSON 事件");
        flushEvent(new StringBuilder(line), sink);
      } else if (!line.startsWith(":")
          && !line.startsWith("event:")
          && !line.startsWith("id:")) {
        throw new RuntimeProtocolException("AI Runtime 返回了未知流字段");
      }
    }
    flushEvent(data, sink);
  }

  private void flushEvent(StringBuilder data, Consumer<RuntimeEvent> sink) {
    if (data.isEmpty()) return;
    JsonNode root;
    try {
      root = objectMapper.readTree(data.toString());
    } catch (IOException ex) {
      throw new RuntimeProtocolException("AI Runtime 事件不是合法 JSON", ex);
    }
    data.setLength(0);
    if (root == null || !root.isObject())
      throw new RuntimeProtocolException("AI Runtime 事件必须是 JSON 对象");
    Set<String> allowedFields =
        Set.of(
            "eventId",
            "type",
            "node",
            "message",
            "timestamp",
            "data",
            "contractVersion",
            "runId",
            "workflowDigest",
            "outerNodeId",
            "nodeRunId",
            "innerStep",
            "stateVersion",
            "ledgerSequence",
            "ledgerEntryDigest",
            "policyRevision");
    java.util.Iterator<String> fields = root.fieldNames();
    while (fields.hasNext()) {
      if (!allowedFields.contains(fields.next())) {
        throw new RuntimeProtocolException("AI Runtime 事件包含未知字段");
      }
    }
    String type = strictText(root, "type", 64);
    if (!RUNTIME_EVENT_TYPES.contains(type))
      throw new RuntimeProtocolException("AI Runtime 返回未知事件类型");
    String eventId = strictText(root, "eventId", 36);
    try {
      UUID.fromString(eventId);
      Instant.parse(strictText(root, "timestamp", 64));
    } catch (RuntimeException ex) {
      throw new RuntimeProtocolException("AI Runtime 事件标识或时间格式无效", ex);
    }
    JsonNode rawData = root.path("data");
    if (!rawData.isObject())
      throw new RuntimeProtocolException("AI Runtime 事件 data 必须是对象");
    if (!root.path("contractVersion").isInt()
        || root.path("contractVersion").asInt() != CONTRACT_VERSION
        || !root.path("stateVersion").canConvertToInt()
        || root.path("stateVersion").asInt() <= 0) {
      throw new RuntimeProtocolException("AI Runtime 事件协议版本无效");
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> eventData =
        rawData.isObject() ? objectMapper.convertValue(rawData, Map.class) : Map.of();
    String innerStep = safeProtocolIdentifier(root, "innerStep", 64);
    String node = safeProtocolIdentifier(root, "node", 64);
    if (!node.equals(innerStep)) {
      throw new RuntimeProtocolException("AI Runtime innerStep 与 node 不一致");
    }
    if (!root.path("ledgerSequence").isIntegralNumber()
        || !root.path("ledgerSequence").canConvertToLong()
        || root.path("ledgerSequence").longValue() <= 0) {
      throw new RuntimeProtocolException("AI Runtime ledgerSequence 无效");
    }
    String workflowDigest = strictText(root, "workflowDigest", 71);
    String ledgerEntryDigest = strictText(root, "ledgerEntryDigest", 71);
    if (!workflowDigest.matches(SHA256_PATTERN)
        || !ledgerEntryDigest.matches(SHA256_PATTERN)) {
      throw new RuntimeProtocolException("AI Runtime Workflow 或 Ledger 摘要格式无效");
    }
    String terminationReason = "";
    JsonNode termination = rawData.get("terminationReason");
    if (termination != null && !termination.isNull()) {
      if (!termination.isTextual()
          || termination.textValue().isBlank()
          || termination.textValue().length() > 64
          || !termination.textValue().matches(SAFE_ID_PATTERN)) {
        throw new RuntimeProtocolException("AI Runtime terminationReason 无效");
      }
      terminationReason = termination.textValue();
    }
    sink.accept(
        new RuntimeEvent(
            eventId,
            type,
            node,
            strictText(root, "message", 1200),
            strictText(root, "timestamp", 64),
            eventData,
            rawData,
            strictText(root, "runId", 80),
            root.path("stateVersion").asInt(),
            strictText(root, "policyRevision", 80),
            CONTRACT_VERSION,
            workflowDigest,
            safeProtocolIdentifier(root, "outerNodeId", 64),
            safeProtocolIdentifier(root, "nodeRunId", 80),
            innerStep,
            root.path("ledgerSequence").longValue(),
            ledgerEntryDigest,
            terminationReason));
  }

  private void validateWorkflowContext(AiAgentRequest request) {
    if (request == null
        || request.workflowId() == null
        || !request.workflowId().matches(SAFE_ID_PATTERN)
        || request.workflowRevision() == null
        || request.workflowRevision() <= 0
        || request.workflowDigest() == null
        || !request.workflowDigest().matches(SHA256_PATTERN)
        || request.outerNodeId() == null
        || !request.outerNodeId().matches(SAFE_ID_PATTERN)
        || request.nodeRunId() == null
        || !request.nodeRunId().matches(SAFE_ID_PATTERN)) {
      throw new RuntimeProtocolException("AI Runtime 请求缺少完整的 Workflow 节点上下文");
    }
  }

  private ParsedPlan toPlan(
      JsonNode planNode, Set<String> activeEvidenceIds, boolean ragDisabledLegacy) {
    if (planNode == null || !planNode.isObject()) {
      throw new RuntimeProtocolException("AI Runtime 计划不是 JSON 对象");
    }
    requireFields(
        planNode,
        Set.of(
            "summary",
            "answer",
            "intent",
            "actions",
            "source",
            "modelWarning",
            "knowledgeMode",
            "evidenceRefs"),
        ragDisabledLegacy
            ? Set.of("summary", "answer", "intent", "actions", "source")
            : Set.of(
                "summary",
                "answer",
                "intent",
                "actions",
                "source",
                "knowledgeMode",
                "evidenceRefs"),
        "计划");
    String summary = strictText(planNode, "summary", 1000);
    String planAnswer = strictText(planNode, "answer", 20_000);
    String source = safeProtocolIdentifier(planNode, "source", 64);
    String intent = strictText(planNode, "intent", 20);
    if (!Set.of("answer", "plan", "clarify").contains(intent)) {
      throw new RuntimeProtocolException("AI Runtime 计划 intent 无效");
    }
    JsonNode knowledgeModeNode = planNode.get("knowledgeMode");
    String knowledgeMode =
        ragDisabledLegacy && (knowledgeModeNode == null || knowledgeModeNode.isNull())
            ? "GENERAL"
            : strictText(planNode, "knowledgeMode", 32);
    if (!Set.of("GENERAL", "PROJECT_EVIDENCE", "INSUFFICIENT_EVIDENCE")
        .contains(knowledgeMode)) {
      throw new RuntimeProtocolException("AI Runtime knowledgeMode 无效");
    }
    JsonNode evidenceRefsNode = planNode.get("evidenceRefs");
    List<String> evidenceRefs =
        ragDisabledLegacy && (evidenceRefsNode == null || evidenceRefsNode.isNull())
            ? List.of()
            : strictReferenceList(evidenceRefsNode, 10, "计划 evidenceRefs");
    Set<String> declaredEvidence = Set.copyOf(evidenceRefs);
    if (!activeEvidenceIds.containsAll(declaredEvidence)) {
      throw new RuntimeProtocolException("AI Runtime 计划引用了当前 EvidenceBundle 之外的证据");
    }
    List<AiPlanResponse.PlanStep> steps = new ArrayList<>();
    JsonNode actions = planNode.get("actions");
    if (actions == null || !actions.isArray() || actions.size() > 8) {
      throw new RuntimeProtocolException("AI Runtime actions 格式无效");
    }
    Set<String> actionKeys = new java.util.HashSet<>();
    for (JsonNode action : actions) {
      requireFields(
          action,
          Set.of(
              "actionId",
              "workflowNodeId",
              "tool",
              "parameters",
              "risk",
              "requiresApproval",
              "group",
              "dependsOnNodeIds",
              "evidenceRefs"),
          ragDisabledLegacy
              ? Set.of(
                  "actionId",
                  "workflowNodeId",
                  "tool",
                  "parameters",
                  "risk",
                  "requiresApproval",
                  "group",
                  "dependsOnNodeIds")
              : Set.of(
                  "actionId",
                  "workflowNodeId",
                  "tool",
                  "parameters",
                  "risk",
                  "requiresApproval",
                  "group",
                  "dependsOnNodeIds",
                  "evidenceRefs"),
          "action");
      String actionId = strictText(action, "actionId", 64);
      if (!actionId.matches("[0-9a-f]{32}")) {
        throw new RuntimeProtocolException("AI Runtime actionId 无效");
      }
      String toolCode = strictText(action, "tool", 64);
      String workflowNodeId = strictText(action, "workflowNodeId", 128);
      if (!ALLOWED_RUNTIME_TOOLS.contains(toolCode)) {
        throw new RuntimeProtocolException("AI Runtime 计划包含未知工具");
      }
      String risk = strictText(action, "risk", 16);
      if (!Set.of("SAFE", "CAUTION").contains(risk)
          || !action.path("requiresApproval").isBoolean()
          || !action.path("group").canConvertToInt()
          || action.path("group").asInt() < 0
          || action.path("group").asInt() > 32) {
        throw new RuntimeProtocolException("AI Runtime action 风险或分组无效");
      }
      JsonNode actionEvidenceNode = action.get("evidenceRefs");
      List<String> actionEvidence =
          ragDisabledLegacy && (actionEvidenceNode == null || actionEvidenceNode.isNull())
              ? List.of()
              : strictReferenceList(actionEvidenceNode, 10, "action evidenceRefs");
      if (!declaredEvidence.containsAll(actionEvidence)) {
        throw new RuntimeProtocolException("AI Runtime action 引用了未声明证据");
      }
      if ("PROJECT_EVIDENCE".equals(knowledgeMode) && actionEvidence.isEmpty()) {
        throw new RuntimeProtocolException("项目证据行动必须声明 evidenceRefs");
      }
      Map<String, Object> parameters = strictParameters(toolCode, action.get("parameters"));
      List<String> dependsOnNodeIds =
          strictReferenceList(action.get("dependsOnNodeIds"), 16, "action dependsOnNodeIds");
      if (!actionKeys.add(workflowNodeId)) {
        throw new RuntimeProtocolException("AI Runtime 计划包含重复工作流节点");
      }
      if ("retrieve_project_context".equals(toolCode)) continue;
      steps.add(
          new AiPlanResponse.PlanStep(
              toolCode,
              titleOf(toolCode),
              "本地 AI Runtime 根据项目上下文提出",
              parameters,
              workflowNodeId,
              action.path("group").asInt(),
              dependsOnNodeIds,
              risk,
              action.path("requiresApproval").booleanValue(),
              actionEvidence));
    }
    if ((actions.isEmpty() && "plan".equals(intent))
        || (!actions.isEmpty() && !"plan".equals(intent))) {
      throw new RuntimeProtocolException("AI Runtime plan intent 与 actions 不一致");
    }
    if (ragDisabledLegacy
        && (!"GENERAL".equals(knowledgeMode) || !evidenceRefs.isEmpty())) {
      throw new RuntimeProtocolException("RAG_DISABLED 兼容计划不得声明项目证据");
    }
    switch (knowledgeMode) {
      case "GENERAL" -> {
        if (!evidenceRefs.isEmpty())
          throw new RuntimeProtocolException("GENERAL 计划不得引用项目证据");
      }
      case "PROJECT_EVIDENCE" -> {
        if (evidenceRefs.isEmpty())
          throw new RuntimeProtocolException("PROJECT_EVIDENCE 计划缺少证据引用");
      }
      case "INSUFFICIENT_EVIDENCE" -> {
        if (!"clarify".equals(intent) || !actions.isEmpty() || !evidenceRefs.isEmpty()) {
          throw new RuntimeProtocolException("INSUFFICIENT_EVIDENCE 只能返回无行动澄清");
        }
      }
      default -> throw new RuntimeProtocolException("AI Runtime knowledgeMode 无效");
    }
    return new ParsedPlan(
        new AiPlanResponse(
            "langgraph-runtime", "runtime", summary, !steps.isEmpty(), List.copyOf(steps)),
        source,
        List.copyOf(evidenceRefs),
        planAnswer,
        intent,
        knowledgeMode,
        !actions.isEmpty());
  }

  private List<String> strictReferenceList(JsonNode value, int maxItems, String label) {
    if (value == null || !value.isArray() || value.size() > maxItems) {
      throw new RuntimeProtocolException("AI Runtime " + label + " 格式无效");
    }
    List<String> result = new ArrayList<>();
    Set<String> unique = new java.util.LinkedHashSet<>();
    for (JsonNode item : value) {
      if (!item.isTextual()
          || item.textValue().isBlank()
          || item.textValue().length() > 128
          || !item.textValue().matches(SAFE_ID_PATTERN)
          || !unique.add(item.textValue())) {
        throw new RuntimeProtocolException("AI Runtime " + label + " 包含无效或重复 ID");
      }
      result.add(item.textValue());
    }
    return List.copyOf(result);
  }

  private Map<String, Object> strictParameters(String toolCode, JsonNode raw) {
    if (raw == null || !raw.isObject()) {
      throw new RuntimeProtocolException("AI Runtime 工具参数必须是对象");
    }
    Set<String> allowed =
        switch (toolCode) {
          case "retrieve_project_context" -> Set.of("query");
          case "tcp_ports" -> Set.of("ports");
          case "nmap_service_scan" -> Set.of("ports", "mode");
          case "http_security_check" -> Set.of("check");
          case "afrog_scan", "xray_scan" -> Set.of("pocCodes", "allPocs");
          case "zap_scan" -> Set.of("spider", "strength");
          case "nuclei_scan", "http_headers", "tls_config" -> Set.of();
          default -> throw new RuntimeProtocolException("AI Runtime 工具不在白名单");
        };
    requireFields(raw, allowed, Set.of(), "parameters");
    Map<String, Object> result = new LinkedHashMap<>();
    switch (toolCode) {
      case "retrieve_project_context" ->
          result.put("query", strictText(raw, "query", 2000));
      case "tcp_ports" -> copyStrictText(raw, result, "ports", 200);
      case "nmap_service_scan" -> {
        copyStrictText(raw, result, "ports", 200);
        copyStrictText(raw, result, "mode", 20);
        if (result.containsKey("mode")
            && !Set.of("quick", "service").contains(result.get("mode"))) {
          throw new RuntimeProtocolException("AI Runtime Nmap mode 无效");
        }
      }
      case "http_security_check" -> {
        String check = strictText(raw, "check", 20);
        if (!Set.of("cookies", "cors", "methods", "disclosure").contains(check)) {
          throw new RuntimeProtocolException("AI Runtime HTTP check 无效");
        }
        result.put("check", check);
      }
      case "afrog_scan", "xray_scan" -> result.putAll(strictPocSelection(raw));
      case "zap_scan" -> {
        if (raw.has("spider")) {
          if (!raw.path("spider").isBoolean()) {
            throw new RuntimeProtocolException("AI Runtime zap_scan spider 参数无效");
          }
          result.put("spider", raw.path("spider").booleanValue());
        }
        if (raw.has("strength")) {
          String strength = strictText(raw, "strength", 20);
          if (!Set.of("LOW", "MEDIUM", "HIGH", "INSANE").contains(strength)) {
            throw new RuntimeProtocolException("AI Runtime zap_scan strength 无效");
          }
          result.put("strength", strength);
        }
      }
      case "nuclei_scan", "http_headers", "tls_config" -> {}
      default -> throw new RuntimeProtocolException("AI Runtime 工具不在白名单");
    }
    return Map.copyOf(result);
  }

  private Map<String, Object> strictPocSelection(JsonNode raw) {
    boolean hasCodes = raw.has("pocCodes");
    boolean hasAll = raw.has("allPocs");
    if (hasCodes == hasAll) {
      throw new RuntimeProtocolException("AI Runtime PoC 选择必须指定具体 PoC 或全部 PoC");
    }
    if (hasAll) {
      if (!raw.path("allPocs").isBoolean() || !raw.path("allPocs").booleanValue()) {
        throw new RuntimeProtocolException("AI Runtime 全部 PoC 参数无效");
      }
      return Map.of("allPocs", true);
    }
    JsonNode codes = raw.path("pocCodes");
    if (!codes.isArray() || codes.isEmpty() || codes.size() > 50) {
      throw new RuntimeProtocolException("AI Runtime PoC 数量无效");
    }
    List<String> result = new ArrayList<>();
    Set<String> unique = new java.util.LinkedHashSet<>();
    for (JsonNode code : codes) {
      if (!code.isTextual()
          || !code.textValue().matches("[A-Z]{2}-[A-F0-9]{24}")
          || !unique.add(code.textValue())) {
        throw new RuntimeProtocolException("AI Runtime PoC 编号无效或重复");
      }
      result.add(code.textValue());
    }
    return Map.of("pocCodes", List.copyOf(result));
  }

  private void copyStrictText(
      JsonNode source, Map<String, Object> target, String key, int maxLength) {
    if (source.has(key)) target.put(key, strictText(source, key, maxLength));
  }

  private String strictText(JsonNode node, String field, int maxLength) {
    JsonNode value = node.get(field);
    if (value == null
        || !value.isTextual()
        || value.textValue().isBlank()
        || value.textValue().length() > maxLength
        || containsForbiddenControl(value.textValue())) {
      throw new RuntimeProtocolException("AI Runtime 字段 " + field + " 格式无效");
    }
    return value.textValue();
  }

  private String safeProtocolIdentifier(JsonNode node, String field, int maxLength) {
    String value = strictText(node, field, maxLength);
    if (!value.matches(SAFE_ID_PATTERN)) {
      throw new RuntimeProtocolException("AI Runtime 字段 " + field + " 标识格式无效");
    }
    return value;
  }

  private boolean containsForbiddenControl(String value) {
    return value.codePoints()
        .anyMatch(
            character ->
                Character.isISOControl(character)
                    && character != '\n'
                    && character != '\r'
                    && character != '\t');
  }

  private void requireFields(
      JsonNode node, Set<String> allowed, Set<String> required, String label) {
    if (node == null || !node.isObject()) {
      throw new RuntimeProtocolException("AI Runtime " + label + " 必须是对象");
    }
    java.util.Iterator<String> names = node.fieldNames();
    while (names.hasNext()) {
      if (!allowed.contains(names.next())) {
        throw new RuntimeProtocolException("AI Runtime " + label + " 包含未知字段");
      }
    }
    for (String field : required) {
      if (!node.has(field)) {
        throw new RuntimeProtocolException("AI Runtime " + label + " 缺少字段 " + field);
      }
    }
  }

  private String titleOf(String code) {
    return switch (code) {
      case "nmap_service_scan" -> "Nmap 服务识别";
      case "nuclei_scan" -> "Nuclei 安全模板检测";
      case "afrog_scan" -> "Afrog PoC 漏洞扫描";
      case "xray_scan" -> "Xray PoC 漏洞扫描";
      case "zap_scan" -> "OWASP ZAP 主动扫描";
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

  private RuntimeProtocolException findProtocolException(Throwable error) {
    Throwable current = error;
    while (current != null) {
      if (current instanceof RuntimeProtocolException protocolException) {
        return protocolException;
      }
      current = current.getCause();
    }
    return null;
  }

  public int clearConversationMemories(long projectId, String conversationId) {
    if (!enabled || conversationId == null || conversationId.isBlank()) return 0;
    try {
      RestClient.RequestHeadersSpec<?> request =
          restClient
              .delete()
              .uri(
                  builder ->
                      builder
                          .path("/index/project/{p}/documents")
                          .queryParam("source", "conversation")
                          .queryParam("conversationId", conversationId)
                          .build(projectId))
              .accept(MediaType.APPLICATION_JSON);
      authorizeProject(request, projectId, "index-write");
      JsonNode root = request.retrieve().body(JsonNode.class);
      return root != null ? Math.max(0, root.path("deleted").asInt(0)) : 0;
    } catch (Exception ignored) {
      return 0;
    }
  }

  private void authorizeProject(
      RestClient.RequestHeadersSpec<?> request, long projectId, String scope) {
    if (token.isBlank() || projectSigningSecret.isBlank()) {
      throw new RuntimeUnavailableException("AI Runtime 访问令牌或项目签名密钥未配置");
    }
    long expiresAt = Instant.now().getEpochSecond() + 60;
    String message = "v1:" + projectId + ":" + scope + ":" + expiresAt;
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(
          new SecretKeySpec(
              projectSigningSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      String signature = HexFormat.of().formatHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
      request.header("X-AI-Runtime-Token", token);
      request.header("X-AI-Project-Authorization", message + ":" + signature);
    } catch (java.security.GeneralSecurityException ex) {
      throw new IllegalStateException("无法生成 AI Runtime 项目授权凭据", ex);
    }
  }

  private String runtimeEventDigest(RuntimeEvent event, String previousDigest) {
    Map<String, Object> publicEvent = new LinkedHashMap<>();
    publicEvent.put("eventId", event.eventId());
    publicEvent.put("type", event.type());
    publicEvent.put("node", event.node());
    publicEvent.put("innerStep", event.innerStep());
    publicEvent.put("message", event.message());
    publicEvent.put("timestamp", event.timestamp());
    publicEvent.put("data", event.data());
    publicEvent.put("contractVersion", event.contractVersion());
    publicEvent.put("runId", event.runId());
    publicEvent.put("workflowDigest", event.workflowDigest());
    publicEvent.put("outerNodeId", event.outerNodeId());
    publicEvent.put("nodeRunId", event.nodeRunId());
    publicEvent.put("stateVersion", event.stateVersion());
    publicEvent.put("ledgerSequence", event.ledgerSequence());
    publicEvent.put("policyRevision", event.policyRevision());
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("previousLedgerEntryDigest", previousDigest);
    payload.put("event", publicEvent);
    try {
      byte[] canonical = canonicalMapper.writeValueAsBytes(payload);
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical);
      return "sha256:" + HexFormat.of().formatHex(digest);
    } catch (Exception ex) {
      throw new IllegalStateException("无法验证 Runtime Ledger 摘要", ex);
    }
  }

  private List<String> eventReferences(JsonNode root, Set<String> fieldNames) {
    java.util.LinkedHashSet<String> references = new java.util.LinkedHashSet<>();
    collectEventReferences(root, fieldNames, references, 0);
    return List.copyOf(references);
  }

  private void collectEventReferences(
      JsonNode node, Set<String> fieldNames, java.util.LinkedHashSet<String> references, int depth) {
    if (node == null || node.isNull()) return;
    if (depth > 12 || references.size() > 40) {
      throw new RuntimeProtocolException("AI Runtime Ledger 引用超过限制");
    }
    if (node.isArray()) {
      for (JsonNode item : node) collectEventReferences(item, fieldNames, references, depth + 1);
      return;
    }
    if (!node.isObject()) return;
    node.fields()
        .forEachRemaining(
            field -> {
              JsonNode value = field.getValue();
              if (fieldNames.contains(field.getKey())) {
                if (value.isTextual()) {
                  addEventReference(value.textValue(), references);
                } else if (value.isArray()) {
                  for (JsonNode item : value) {
                    if (item.isTextual()) addEventReference(item.textValue(), references);
                  }
                }
              }
              collectEventReferences(value, fieldNames, references, depth + 1);
            });
  }

  private void addEventReference(
      String value, java.util.LinkedHashSet<String> references) {
    if (value == null
        || value.isBlank()
        || value.length() > 128
        || !value.matches(SAFE_ID_PATTERN)) {
      throw new RuntimeProtocolException("AI Runtime Ledger 引用格式无效");
    }
    references.add(value);
    if (references.size() > 40) {
      throw new RuntimeProtocolException("AI Runtime Ledger 引用超过限制");
    }
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
      JsonNode rawData,
      String runId,
      int stateVersion,
      String policyRevision,
      int contractVersion,
      String workflowDigest,
      String outerNodeId,
      String nodeRunId,
      String innerStep,
      long ledgerSequence,
      String ledgerEntryDigest,
      String terminationReason) {
    public RuntimeEvent(
        String eventId,
        String type,
        String node,
        String message,
        String timestamp,
        Map<String, Object> data,
        JsonNode rawData,
        String runId,
        int stateVersion,
        String policyRevision,
        int contractVersion) {
      this(
          eventId,
          type,
          node,
          message,
          timestamp,
          data,
          rawData,
          runId,
          stateVersion,
          policyRevision,
          contractVersion,
          "",
          "",
          "",
          node,
          stateVersion,
          "",
          "");
    }

    private RuntimeEvent withAuthoritativeLedgerDigest(String digest) {
      return new RuntimeEvent(
          eventId,
          type,
          node,
          message,
          timestamp,
          data,
          rawData,
          runId,
          stateVersion,
          policyRevision,
          contractVersion,
          workflowDigest,
          outerNodeId,
          nodeRunId,
          innerStep,
          ledgerSequence,
          digest,
          terminationReason);
    }
  }

  public record RuntimeProvenance(
      int retrievalRoundCount,
      List<String> evidenceIds,
      String indexRevision,
      String plannerSource,
      String terminationReason) {
    public RuntimeProvenance {
      evidenceIds = evidenceIds == null ? List.of() : List.copyOf(evidenceIds);
      indexRevision = indexRevision == null ? "" : indexRevision;
      plannerSource = plannerSource == null ? "" : plannerSource;
      terminationReason = terminationReason == null ? "" : terminationReason;
    }
  }

  public record RuntimePlanResult(
      AiPlanResponse plan,
      String answer,
      String status,
      String runId,
      String policyRevision,
      int stateVersion,
      RuntimeProvenance provenance) {}

  public static class RuntimeUnavailableException extends RuntimeException {
    public RuntimeUnavailableException(String message) {
      super(message);
    }

    public RuntimeUnavailableException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /** A response was received, but it violated the versioned Harness contract. */
  public static final class RuntimeProtocolException extends RuntimeUnavailableException {
    public RuntimeProtocolException(String message) {
      super(message);
    }

    public RuntimeProtocolException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private record ParsedPlan(
      AiPlanResponse plan,
      String plannerSource,
      List<String> evidenceIds,
      String answer,
      String intent,
      String knowledgeMode,
      boolean actionable) {}

  private final class Holder {
    private static final int MAX_BUFFERED_EVENTS = 64;
    private static final List<String> LIFECYCLE_STAGES =
        List.of("recon", "map", "validate", "impact", "retest", "report");
    private final String expectedRunId;
    private final String expectedPolicyRevision;
    private final AiAgentRequest request;
    private final Set<String> eventIds = new java.util.HashSet<>();
    private final Set<String> retrievalActionIds = new java.util.HashSet<>();
    private final List<RuntimeEvent> bufferedEvents = new ArrayList<>();
    private AiPlanResponse plan;
    private JsonNode planEventData;
    private String answer = "";
    private String finishStatus = "";
    private String authorizationStatus = "";
    private String plannerSource = "";
    private String terminationReason = "";
    private String indexRevision = "";
    private List<String> finishEvidenceIds = List.of();
    private Set<String> activeEvidenceIds = Set.of();
    private String routeQuery = "";
    private String routeStatus = "";
    private String routeIntent = "";
    private String lastEvidenceQuery = "";
    private String rewrittenQuery = "";
    private String lastEvidenceStatus = "";
    private boolean routeNeedsRetrieval;
    private boolean routeSeen;
    private boolean rewriteSeen;
    private boolean rewriteApplied;
    private boolean planSeen;
    private boolean authorizationGuardSeen;
    private boolean reviewSeen;
    private boolean lifecycleFailed;
    private boolean error;
    private String errorCode = "";
    private boolean finished;
    private int stateVersion;
    private int retrievalRoundCount;
    private int plannedActionCount;
    private int lifecyclePosition = -1;
    private String previousRuntimeLedgerDigest = RUNTIME_LEDGER_GENESIS_DIGEST;

    private Holder(
        String expectedRunId, String expectedPolicyRevision, AiAgentRequest request) {
      this.expectedRunId = expectedRunId;
      this.expectedPolicyRevision = expectedPolicyRevision;
      this.request = request;
    }

    private void accept(RuntimeEvent event) {
      if (bufferedEvents.size() >= MAX_BUFFERED_EVENTS) {
        throw new RuntimeProtocolException("AI Runtime 事件数量超过限制");
      }
      if (finished) {
        if ("finish".equals(event.type()) && !error) {
          throw new RuntimeProtocolException("AI Runtime 重复发送 finish 终态");
        }
        throw new RuntimeProtocolException("AI Runtime 在终态后继续发送事件");
      }
      if (!expectedRunId.equals(event.runId())
          || !expectedPolicyRevision.equals(event.policyRevision())
          || event.contractVersion() != CONTRACT_VERSION
          || event.stateVersion() != stateVersion + 1
          || event.ledgerSequence() != stateVersion + 1L
          || !request.workflowDigest().equals(event.workflowDigest())
          || !request.outerNodeId().equals(event.outerNodeId())
          || !request.nodeRunId().equals(event.nodeRunId())
          || !event.node().equals(event.innerStep())) {
        throw new RuntimeProtocolException("AI Runtime 运行标识或状态版本不连续");
      }
      String expectedRuntimeDigest = runtimeEventDigest(event, previousRuntimeLedgerDigest);
      if (!MessageDigest.isEqual(
          expectedRuntimeDigest.getBytes(StandardCharsets.US_ASCII),
          event.ledgerEntryDigest().getBytes(StandardCharsets.US_ASCII))) {
        throw new RuntimeProtocolException("AI Runtime 候选 Ledger 摘要链无效");
      }
      if (!eventIds.add(event.eventId())) {
        throw new RuntimeProtocolException("AI Runtime 重复使用 eventId");
      }
      previousRuntimeLedgerDigest = expectedRuntimeDigest;
      stateVersion = event.stateVersion();
      switch (event.type()) {
        case "route" -> acceptRoute(event.rawData());
        case "evidence" -> acceptEvidence(event.rawData());
        case "rewrite" -> acceptRewrite(event.rawData());
        case "plan" -> acceptPlanEvent(event);
        case "authorization_guard" -> acceptAuthorizationGuard(event);
        case "stage" -> acceptStage(event);
        case "tool" -> acceptTool(event);
        case "approval_required" -> acceptApprovalRequired(event);
        case "retry" ->
            throw new RuntimeProtocolException("AI Runtime 在 maxRetries=0 时发送 retry 事件");
        case "review" -> acceptReview(event);
        case "finish" -> acceptFinish(event.rawData());
        case "error" -> acceptError(event.rawData());
        default -> throw new RuntimeProtocolException("AI Runtime 返回未知事件类型");
      }
      bufferedEvents.add(event);
    }

    private void publishTo(Consumer<RuntimeEvent> sink) {
      bufferedEvents.forEach(sink);
    }

    private void persistLedger() {
      if (ledger == null) return;
      List<AgentLedgerService.AppendRequest> entries = new ArrayList<>();
      String previousDigest = RUNTIME_LEDGER_GENESIS_DIGEST;
      String runIndexRevision = indexRevision.isBlank() ? "none" : indexRevision;
      for (RuntimeEvent event : bufferedEvents) {
        entries.add(
            new AgentLedgerService.AppendRequest(
                event.runId(),
                request.workflowId(),
                request.workflowRevision(),
                event.workflowDigest(),
                event.outerNodeId(),
                event.nodeRunId(),
                event.ledgerSequence(),
                event.innerStep(),
                event.type(),
                ledgerStatus(event),
                previousDigest,
                event.ledgerEntryDigest(),
                eventReferences(event.rawData(), Set.of("evidenceId", "evidenceIds", "evidenceRefs")),
                eventReferences(event.rawData(), Set.of("actionId", "actionIds")),
                event.policyRevision(),
                runIndexRevision,
                request.projectId(),
                request.targetId()));
        previousDigest = event.ledgerEntryDigest();
      }
      List<AgentLedgerRecord> persisted = ledger.appendBatch(entries);
      if (persisted.size() != bufferedEvents.size()) {
        throw new RuntimeProtocolException("Java Ledger 未完整持久化 Runtime 事件流");
      }
      for (int index = 0; index < persisted.size(); index++) {
        AgentLedgerRecord record = persisted.get(index);
        RuntimeEvent event = bufferedEvents.get(index);
        if (record.getSequence() != event.ledgerSequence()
            || !event.runId().equals(record.getRunId())
            || !event.nodeRunId().equals(record.getNodeRunId())) {
          throw new RuntimeProtocolException("Java Ledger 持久化回执与 Runtime 事件不一致");
        }
        bufferedEvents.set(index, event.withAuthoritativeLedgerDigest(record.getEntryDigest()));
      }
    }

    private String ledgerStatus(RuntimeEvent event) {
      if ("error".equals(event.type())) return "FAILED";
      if (!"finish".equals(event.type())) return "IN_PROGRESS";
      String status = strictText(event.rawData(), "status", 32);
      JsonNode finalPlan = event.rawData().path("plan");
      if ("COMPLETED".equals(status) && "clarify".equals(finalPlan.path("intent").asText())) {
        return "CLARIFY";
      }
      return status;
    }

    private void acceptRoute(JsonNode data) {
      if (routeSeen || planSeen || retrievalRoundCount > 0 || rewriteSeen) {
        throw new RuntimeProtocolException("AI Runtime route 事件顺序无效");
      }
      requireFields(
          data,
          Set.of("status", "intent", "needsRetrieval", "retrievalQuery", "publicReasonCode"),
          Set.of("status", "intent", "needsRetrieval", "publicReasonCode"),
          "route data");
      String status = strictText(data, "status", 16);
      if (!Set.of("ROUTED", "RAG_DISABLED", "FAILED").contains(status)) {
        throw new RuntimeProtocolException("AI Runtime route status 无效");
      }
      String intent = strictText(data, "intent", 32);
      String reason = strictText(data, "publicReasonCode", 64);
      if (!data.path("needsRetrieval").isBoolean()) {
        throw new RuntimeProtocolException("AI Runtime route needsRetrieval 必须是布尔值");
      }
      boolean needsRetrieval = data.path("needsRetrieval").booleanValue();
      Map<String, String> expectedReasons =
          Map.of(
              "GENERAL_QA", "GENERAL_KNOWLEDGE",
              "PROJECT_QA", "PROJECT_CONTEXT_REQUIRED",
              "ACTION_PLAN", "AUTHORIZED_ACTION_REQUEST",
              "CLARIFY", "AMBIGUOUS_REQUEST");
      if (!expectedReasons.containsKey(intent) || !expectedReasons.get(intent).equals(reason)) {
        throw new RuntimeProtocolException("AI Runtime route intent 与 reason 不一致");
      }
      boolean expectedRetrieval = Set.of("PROJECT_QA", "ACTION_PLAN").contains(intent);
      if (needsRetrieval != expectedRetrieval) {
        throw new RuntimeProtocolException("AI Runtime route 检索决策与 intent 不一致");
      }
      JsonNode query = data.get("retrievalQuery");
      if (needsRetrieval && "ROUTED".equals(status)) {
        routeQuery = strictText(data, "retrievalQuery", 2000);
      } else if (needsRetrieval && query != null && !query.isNull()) {
        routeQuery = strictText(data, "retrievalQuery", 2000);
      } else if (query != null && !query.isNull()) {
        throw new RuntimeProtocolException("无需检索的 route 不得包含 retrievalQuery");
      }
      routeNeedsRetrieval = needsRetrieval;
      routeStatus = status;
      routeIntent = intent;
      routeSeen = true;
    }

    private void acceptEvidence(JsonNode data) {
      if (!routeSeen
          || !routeNeedsRetrieval
          || !"ROUTED".equals(routeStatus)
          || planSeen
          || Set.of("DENIED", "FAILED").contains(lastEvidenceStatus)
          || retrievalRoundCount >= 2) {
        throw new RuntimeProtocolException("AI Runtime evidence 事件顺序无效");
      }
      if (data.toString().getBytes(StandardCharsets.UTF_8).length > MAX_EVIDENCE_EVENT_BYTES) {
        throw new RuntimeProtocolException("AI Runtime Evidence 元数据超过大小限制");
      }
      requireFields(
          data,
          Set.of(
              "projectId",
              "targetId",
              "conversationId",
              "query",
              "round",
              "retrievalMethod",
              "indexRevision",
              "retrievalActionId",
              "status",
              "items"),
          Set.of(
              "projectId",
              "targetId",
              "conversationId",
              "query",
              "round",
              "retrievalMethod",
              "indexRevision",
              "retrievalActionId",
              "status",
              "items"),
          "evidence data");
      if (strictPositiveLong(data, "projectId") != request.projectId()
          || strictPositiveLong(data, "targetId") != request.targetId()) {
        throw new RuntimeProtocolException("AI Runtime Evidence 超出当前项目或目标 scope");
      }
      JsonNode conversation = data.get("conversationId");
      String expectedConversation = request.sessionId();
      if (expectedConversation == null) {
        if (conversation != null && !conversation.isNull())
          throw new RuntimeProtocolException("AI Runtime Evidence 会话 scope 无效");
      } else if (conversation == null
          || !conversation.isTextual()
          || !expectedConversation.equals(conversation.textValue())) {
        throw new RuntimeProtocolException("AI Runtime Evidence 会话 scope 无效");
      }
      int round = strictBoundedInt(data, "round", 0, 1);
      if (round != retrievalRoundCount || (round == 1 && !rewriteApplied)) {
        throw new RuntimeProtocolException("AI Runtime Evidence retrieval round 不连续");
      }
      String query = strictText(data, "query", 2000);
      String expectedQuery = round == 0 ? routeQuery : rewrittenQuery;
      if (!normalizeQuery(query).equals(normalizeQuery(expectedQuery))) {
        throw new RuntimeProtocolException("AI Runtime Evidence 查询与 route/rewrite 不一致");
      }
      String method = strictText(data, "retrievalMethod", 32);
      if (!Set.of("bm25", "real_embedding").contains(method)) {
        throw new RuntimeProtocolException("AI Runtime Evidence retrievalMethod 无效");
      }
      String actionId = safeProtocolIdentifier(data, "retrievalActionId", 64);
      if (!retrievalActionIds.add(actionId)) {
        throw new RuntimeProtocolException("AI Runtime 重复使用 retrievalActionId");
      }
      String status = strictText(data, "status", 16);
      if (!Set.of("READY", "EMPTY", "DENIED", "FAILED").contains(status)) {
        throw new RuntimeProtocolException("AI Runtime Evidence status 无效");
      }
      JsonNode revisionNode = data.get("indexRevision");
      String revision = "";
      if (revisionNode != null && !revisionNode.isNull()) {
        if (!revisionNode.isTextual() || !revisionNode.textValue().matches(SHA256_PATTERN)) {
          throw new RuntimeProtocolException("AI Runtime Evidence indexRevision 无效");
        }
        revision = revisionNode.textValue();
      }
      if (Set.of("READY", "EMPTY").contains(status) && revision.isBlank()) {
        throw new RuntimeProtocolException("成功检索必须声明 indexRevision");
      }
      if (!revision.isBlank()) {
        if (!indexRevision.isBlank() && !indexRevision.equals(revision)) {
          throw new RuntimeProtocolException("AI Runtime 在同一轮次链路中混用了索引版本");
        }
        indexRevision = revision;
      }
      JsonNode items = data.get("items");
      if (items == null || !items.isArray() || items.size() > MAX_EVIDENCE_ITEMS) {
        throw new RuntimeProtocolException("AI Runtime Evidence items 格式无效");
      }
      if (("READY".equals(status) && items.isEmpty())
          || (!"READY".equals(status) && !items.isEmpty())) {
        throw new RuntimeProtocolException("AI Runtime Evidence status 与 items 不一致");
      }
      Set<String> ids = new java.util.LinkedHashSet<>();
      for (JsonNode item : items) validateEvidenceItem(item, ids);
      activeEvidenceIds = Set.copyOf(ids);
      lastEvidenceStatus = status;
      lastEvidenceQuery = query;
      if (!"DENIED".equals(status)) retrievalRoundCount++;
    }

    private void validateEvidenceItem(JsonNode item, Set<String> ids) {
      requireFields(
          item,
          Set.of(
              "evidenceId",
              "documentId",
              "source",
              "title",
              "score",
              "targetId",
              "contentDigest"),
          Set.of(
              "evidenceId",
              "documentId",
              "source",
              "title",
              "score",
              "targetId",
              "contentDigest"),
          "evidence item");
      String evidenceId = safeProtocolIdentifier(item, "evidenceId", 128);
      if (!ids.add(evidenceId)) {
        throw new RuntimeProtocolException("AI Runtime Evidence 包含重复 evidenceId");
      }
      safeProtocolIdentifier(item, "documentId", 128);
      String source = safeProtocolIdentifier(item, "source", 64);
      strictText(item, "title", 300);
      JsonNode score = item.get("score");
      if (score == null
          || !score.isNumber()
          || !Double.isFinite(score.doubleValue())
          || score.doubleValue() < 0) {
        throw new RuntimeProtocolException("AI Runtime Evidence score 无效");
      }
      JsonNode targetId = item.get("targetId");
      if (targetId == null
          || (targetId.isNull() && !"project".equals(source))
          || (!targetId.isNull() && strictPositiveLong(item, "targetId") != request.targetId())) {
        throw new RuntimeProtocolException("AI Runtime Evidence item 超出当前目标 scope");
      }
      String digest = strictText(item, "contentDigest", 71);
      if (!digest.matches(SHA256_PATTERN)) {
        throw new RuntimeProtocolException("AI Runtime Evidence contentDigest 无效");
      }
    }

    private void acceptRewrite(JsonNode data) {
      if (!routeSeen
          || !routeNeedsRetrieval
          || rewriteSeen
          || planSeen
          || retrievalRoundCount != 1
          || !Set.of("READY", "EMPTY").contains(lastEvidenceStatus)) {
        throw new RuntimeProtocolException("AI Runtime rewrite 事件顺序或前置状态无效");
      }
      requireFields(
          data,
          Set.of(
              "status",
              "decision",
              "reasonCodes",
              "evidenceRefs",
              "rewrittenQuery",
              "fromRound",
              "toRound"),
          Set.of(
              "status",
              "decision",
              "reasonCodes",
              "evidenceRefs",
              "rewrittenQuery",
              "fromRound",
              "toRound"),
          "rewrite data");
      String status = strictText(data, "status", 16);
      if (!Set.of("APPLIED", "REJECTED").contains(status)) {
        throw new RuntimeProtocolException("AI Runtime rewrite status 无效");
      }
      if (!"REWRITE_QUERY".equals(strictText(data, "decision", 32))) {
        throw new RuntimeProtocolException("AI Runtime rewrite 缺少明确 REWRITE_QUERY 决策");
      }
      JsonNode reasonCodes = data.get("reasonCodes");
      if (reasonCodes == null
          || !reasonCodes.isArray()
          || reasonCodes.isEmpty()
          || reasonCodes.size() > 4) {
        throw new RuntimeProtocolException("AI Runtime rewrite reasonCodes 格式无效");
      }
      Set<String> allowedReasons =
          Set.of(
              "DIRECT_SUPPORT",
              "PARTIAL_SUPPORT",
              "NO_RELEVANT_EVIDENCE",
              "CONFLICTING_EVIDENCE",
              "SCOPE_MISMATCH",
              "QUERY_TOO_BROAD");
      Set<String> seenReasons = new java.util.HashSet<>();
      for (JsonNode reason : reasonCodes) {
        if (!reason.isTextual()
            || !allowedReasons.contains(reason.textValue())
            || !seenReasons.add(reason.textValue())) {
          throw new RuntimeProtocolException("AI Runtime rewrite reasonCodes 无效或重复");
        }
      }
      if (!strictReferenceList(data.get("evidenceRefs"), 10, "rewrite evidenceRefs").isEmpty()) {
        throw new RuntimeProtocolException("REWRITE_QUERY 不得声明 evidenceRefs");
      }
      JsonNode queryNode = data.get("rewrittenQuery");
      if (queryNode == null
          || !queryNode.isTextual()
          || queryNode.textValue().length() > 2000
          || containsForbiddenControl(queryNode.textValue())) {
        throw new RuntimeProtocolException("AI Runtime rewrittenQuery 格式无效");
      }
      String candidate = queryNode.textValue();
      int fromRound = strictBoundedInt(data, "fromRound", 0, 1);
      int toRound = strictBoundedInt(data, "toRound", 0, 1);
      if ("APPLIED".equals(status)) {
        if (fromRound != 0
            || toRound != 1
            || candidate.isBlank()
            || normalizeQuery(candidate).equals(normalizeQuery(lastEvidenceQuery))) {
          throw new RuntimeProtocolException("AI Runtime APPLIED rewrite 未形成合法 0 到 1 改写");
        }
        rewrittenQuery = candidate;
        rewriteApplied = true;
      } else if (fromRound != 0 || toRound != 0) {
        throw new RuntimeProtocolException("AI Runtime REJECTED rewrite 必须终止在 round 0");
      }
      rewriteSeen = true;
    }

    private void acceptPlanEvent(RuntimeEvent event) {
      validateRetrievalPathReadyForPlan();
      if (planSeen || authorizationGuardSeen || lifecyclePosition >= 0 || reviewSeen) {
        throw new RuntimeProtocolException("AI Runtime plan 事件顺序无效或重复");
      }
      JsonNode data = event.rawData();
      requireFields(
          data,
          Set.of(
              "summary",
              "answer",
              "intent",
              "knowledgeMode",
              "evidenceRefs",
              "actionCount",
              "source",
              "warning",
              "actions",
              "steps",
              "stage",
              "legacyNode"),
          Set.of(
              "summary",
              "answer",
              "intent",
              "knowledgeMode",
              "evidenceRefs",
              "actionCount",
              "source",
              "warning",
              "actions",
              "steps",
              "stage",
              "legacyNode"),
          "plan event data");
      requireEventLocation(event, "engage", "engage", "planner");

      ObjectNode eventPlanNode = objectMapper.createObjectNode();
      for (String field :
          List.of("summary", "answer", "intent", "knowledgeMode", "evidenceRefs", "actions", "source")) {
        eventPlanNode.set(field, data.get(field));
      }
      JsonNode warning = data.get("warning");
      if (warning != null && !warning.isNull()) {
        if (!warning.isTextual()
            || warning.textValue().length() > 1000
            || containsForbiddenControl(warning.textValue())) {
          throw new RuntimeProtocolException("AI Runtime plan warning 格式无效");
        }
        eventPlanNode.set("modelWarning", warning);
      }
      boolean ragDisabledLegacy = "RAG_DISABLED".equals(routeStatus);
      ParsedPlan parsed = toPlan(eventPlanNode, activeEvidenceIds, ragDisabledLegacy);
      plannedActionCount = strictBoundedInt(data, "actionCount", 0, 8);
      if (plannedActionCount != data.path("actions").size()) {
        throw new RuntimeProtocolException("AI Runtime plan actionCount 与 actions 不一致");
      }
      validatePlanSteps(data.get("steps"), data.get("actions"));
      if (parsed.actionable() != (plannedActionCount > 0)) {
        throw new RuntimeProtocolException("AI Runtime plan actionable 状态不一致");
      }
      planEventData = data.deepCopy();
      planSeen = true;
    }

    private void validatePlanSteps(JsonNode steps, JsonNode actions) {
      if (steps == null || !steps.isArray() || steps.size() != actions.size()) {
        throw new RuntimeProtocolException("AI Runtime plan steps 与 actions 数量不一致");
      }
      for (int index = 0; index < steps.size(); index++) {
        JsonNode step = steps.get(index);
        JsonNode action = actions.get(index);
        requireFields(
            step,
            Set.of(
                "toolCode",
                "tool",
                "title",
                "reason",
                "risk",
                "requiresApproval",
                "workflowNodeId",
                "group",
                "dependsOnNodeIds",
                "parameters",
                "status"),
            Set.of(
                "toolCode",
                "tool",
                "title",
                "reason",
                "risk",
                "requiresApproval",
                "workflowNodeId",
                "group",
                "dependsOnNodeIds",
                "parameters",
                "status"),
            "plan step");
        String tool = strictText(step, "tool", 64);
        if (!tool.equals(strictText(step, "toolCode", 64))
            || !tool.equals(strictText(action, "tool", 64))
            || !ALLOWED_RUNTIME_TOOLS.contains(tool)) {
          throw new RuntimeProtocolException("AI Runtime plan step 工具映射无效");
        }
        strictText(step, "title", 300);
        strictText(step, "reason", 1000);
        if (!strictText(action, "risk", 16).equals(strictText(step, "risk", 16))
            || !strictText(action, "workflowNodeId", 128)
                .equals(strictText(step, "workflowNodeId", 128))
            || !step.path("group").canConvertToInt()
            || step.path("group").asInt() != action.path("group").asInt()
            || !step.path("dependsOnNodeIds").equals(action.path("dependsOnNodeIds"))
            || !step.path("requiresApproval").isBoolean()
            || step.path("requiresApproval").booleanValue()
                != action.path("requiresApproval").booleanValue()
            || !"pending".equals(strictText(step, "status", 16))) {
          throw new RuntimeProtocolException("AI Runtime plan step 风险或状态无效");
        }
        strictParameters(tool, step.get("parameters"));
        if (!step.get("parameters").equals(action.get("parameters"))) {
          throw new RuntimeProtocolException("AI Runtime plan step parameters 与 action 不一致");
        }
      }
    }

    private void acceptAuthorizationGuard(RuntimeEvent event) {
      if (!planSeen || authorizationGuardSeen || lifecyclePosition >= 0 || reviewSeen) {
        throw new RuntimeProtocolException("AI Runtime authorization_guard 事件顺序无效或重复");
      }
      JsonNode data = event.rawData();
      requireFields(
          data,
          Set.of(
              "status",
              "executionRequired",
              "checks",
              "violations",
              "approvalCount",
              "retryCount",
              "stage",
              "legacyNode"),
          Set.of("status", "stage", "legacyNode"),
          "authorization_guard data");
      requireEventLocation(event, "engage", "engage", "authorization_guard");
      String status = strictText(data, "status", 32);
      if ("NOT_APPLICABLE".equals(status)) {
        requireFields(
            data,
            Set.of("status", "executionRequired", "stage", "legacyNode"),
            Set.of("status", "executionRequired", "stage", "legacyNode"),
            "authorization_guard data");
        if (!data.path("executionRequired").isBoolean()
            || data.path("executionRequired").booleanValue()
            || plannedActionCount != 0) {
          throw new RuntimeProtocolException("AI Runtime NOT_APPLICABLE 授权守卫与计划不一致");
        }
      } else {
        requireFields(
            data,
            Set.of(
                "status",
                "checks",
                "violations",
                "approvalCount",
                "retryCount",
                "stage",
                "legacyNode"),
            Set.of(
                "status",
                "checks",
                "violations",
                "approvalCount",
                "retryCount",
                "stage",
                "legacyNode"),
            "authorization_guard data");
        if (!Set.of("AUTHORIZED", "DENIED", "APPROVAL_REQUIRED").contains(status)
            || plannedActionCount == 0) {
          throw new RuntimeProtocolException("AI Runtime authorization_guard status 与计划不一致");
        }
        JsonNode checks = data.get("checks");
        Set<String> checkNames =
            Set.of("project", "status", "timeWindow", "target", "ports", "tools", "approval", "quota");
        requireFields(checks, checkNames, checkNames, "authorization_guard checks");
        int failedChecks = 0;
        for (String name : checkNames) {
          if (!checks.path(name).isBoolean()) {
            throw new RuntimeProtocolException("AI Runtime authorization_guard check 必须是布尔值");
          }
          if (!checks.path(name).booleanValue()) failedChecks++;
        }
        List<String> violations = strictTextList(data.get("violations"), 32, 1000, "guard violations");
        int approvalCount = strictBoundedInt(data, "approvalCount", 0, 8);
        int retryCount = strictBoundedInt(data, "retryCount", 0, 0);
        if (retryCount != 0
            || ("AUTHORIZED".equals(status)
                && (failedChecks != 0 || !violations.isEmpty() || approvalCount != 0))
            || ("DENIED".equals(status) && (failedChecks == 0 || violations.isEmpty()))
            || ("APPROVAL_REQUIRED".equals(status)
                && (failedChecks != 1
                    || checks.path("approval").booleanValue()
                    || !violations.isEmpty()
                    || approvalCount == 0))) {
          throw new RuntimeProtocolException("AI Runtime authorization_guard 决策明细不一致");
        }
      }
      authorizationStatus = status;
      authorizationGuardSeen = true;
    }

    private void acceptStage(RuntimeEvent event) {
      requireLifecycleReady("stage");
      JsonNode data = event.rawData();
      requireFields(
          data,
          Set.of("stage", "status", "legacyNode", "actionCount", "retryCount"),
          Set.of("stage", "status", "legacyNode"),
          "stage data");
      String stage = strictText(data, "stage", 16);
      String status = strictText(data, "status", 16);
      if (!Set.of("SKIPPED", "FAILED", "COMPLETED").contains(status)) {
        throw new RuntimeProtocolException("AI Runtime stage status 无效");
      }
      String expectedLegacy = "retest".equals(stage) ? "retry" : "executor";
      String actualLegacy = strictText(data, "legacyNode", 32);
      if ("impact".equals(stage) && "approval_required".equals(actualLegacy)) {
        expectedLegacy = actualLegacy;
      }
      requireEventLocation(event, stage, stage, expectedLegacy);
      if (data.has("actionCount")) strictBoundedInt(data, "actionCount", 0, 8);
      if (data.has("retryCount")) strictBoundedInt(data, "retryCount", 0, 0);
      advanceLifecycle(stage);
      if ("FAILED".equals(status)) lifecycleFailed = true;
    }

    private void acceptTool(RuntimeEvent event) {
      requireLifecycleReady("tool");
      JsonNode data = event.rawData();
      String stage = strictText(data, "stage", 16);
      if ("retest".equals(stage)) {
        throw new RuntimeProtocolException("AI Runtime 在 maxRetries=0 时发送 retest tool 事件");
      }
      if (!"AUTHORIZED".equals(authorizationStatus) || plannedActionCount == 0) {
        throw new RuntimeProtocolException("AI Runtime 未获授权却发送 tool 事件");
      }
      requireEventLocation(event, stage, stage, "executor");
      if (data.has("status")) {
        requireFields(
            data,
            Set.of("stage", "legacyNode", "status"),
            Set.of("stage", "legacyNode", "status"),
            "tool data");
        if (!"FAILED".equals(strictText(data, "status", 16))) {
          throw new RuntimeProtocolException("AI Runtime tool status 无效");
        }
        lifecycleFailed = true;
      } else {
        Set<String> fields =
            Set.of(
                "stage",
                "legacyNode",
                "resultCount",
                "failedCount",
                "totalResultCount",
                "localExecutions",
                "javaProposals",
                "levels",
                "parallel");
        requireFields(data, fields, fields, "tool data");
        int results = strictBoundedInt(data, "resultCount", 0, 8);
        int failed = strictBoundedInt(data, "failedCount", 0, 8);
        int total = strictBoundedInt(data, "totalResultCount", 0, 8);
        int local = strictBoundedInt(data, "localExecutions", 0, 8);
        int proposals = strictBoundedInt(data, "javaProposals", 0, 8);
        int levels = strictBoundedInt(data, "levels", 1, 8);
        if (!data.path("parallel").isBoolean()
            || results + failed > plannedActionCount
            || total < results
            || local + proposals != results
            || levels > plannedActionCount) {
          throw new RuntimeProtocolException("AI Runtime tool 计数或并行标志无效");
        }
        if (failed > 0) lifecycleFailed = true;
      }
      advanceLifecycle(stage);
    }

    private void acceptApprovalRequired(RuntimeEvent event) {
      requireLifecycleReady("approval_required");
      JsonNode data = event.rawData();
      requireFields(
          data,
          Set.of("actions", "executed", "stage", "legacyNode"),
          Set.of("actions", "executed", "stage", "legacyNode"),
          "approval_required data");
      requireEventLocation(event, "impact", "impact", "approval_required");
      if (!"APPROVAL_REQUIRED".equals(authorizationStatus)
          || !data.path("executed").isBoolean()
          || data.path("executed").booleanValue()) {
        throw new RuntimeProtocolException("AI Runtime approval_required 与授权决策不一致");
      }
      JsonNode actions = data.get("actions");
      if (actions == null || !actions.isArray() || actions.isEmpty() || actions.size() > 8) {
        throw new RuntimeProtocolException("AI Runtime approval_required actions 无效");
      }
      for (JsonNode action : actions) {
        requireFields(
            action,
            Set.of("tool", "risk", "targetId"),
            Set.of("tool", "risk", "targetId"),
            "approval action");
        if (!ALLOWED_RUNTIME_TOOLS.contains(strictText(action, "tool", 64))
            || !Set.of("SAFE", "CAUTION", "HIGH").contains(strictText(action, "risk", 16))
            || !action.path("targetId").isIntegralNumber()
            || action.path("targetId").longValue() != request.targetId()) {
          throw new RuntimeProtocolException("AI Runtime approval action 越出请求范围");
        }
      }
      advanceLifecycle("impact");
    }

    private void acceptReview(RuntimeEvent event) {
      requireLifecycleReady("review");
      if (reviewSeen) throw new RuntimeProtocolException("AI Runtime 重复发送 review 事件");
      JsonNode data = event.rawData();
      Set<String> fields =
          Set.of("status", "referenceCount", "proposalCount", "stage", "legacyNode");
      requireFields(data, fields, fields, "review data");
      requireEventLocation(event, "report", "report", "reviewer");
      String status = strictText(data, "status", 16);
      if (!Set.of("REVIEWED", "FAILED").contains(status)) {
        throw new RuntimeProtocolException("AI Runtime review status 无效");
      }
      strictBoundedInt(data, "referenceCount", 0, 1000);
      strictBoundedInt(data, "proposalCount", 0, 8);
      advanceLifecycle("report");
      reviewSeen = true;
      if ("FAILED".equals(status)) lifecycleFailed = true;
    }

    private void requireLifecycleReady(String type) {
      if (!planSeen || !authorizationGuardSeen || reviewSeen) {
        throw new RuntimeProtocolException("AI Runtime " + type + " 事件顺序无效");
      }
    }

    private void advanceLifecycle(String stage) {
      int position = LIFECYCLE_STAGES.indexOf(stage);
      if (position < 0 || position <= lifecyclePosition) {
        throw new RuntimeProtocolException("AI Runtime 生命周期阶段顺序无效");
      }
      lifecyclePosition = position;
    }

    private void requireEventLocation(
        RuntimeEvent event, String expectedNode, String expectedStage, String expectedLegacyNode) {
      if (!expectedNode.equals(event.node())
          || !expectedStage.equals(strictText(event.rawData(), "stage", 16))
          || !expectedLegacyNode.equals(strictText(event.rawData(), "legacyNode", 32))) {
        throw new RuntimeProtocolException("AI Runtime 事件 node/stage/legacyNode 映射无效");
      }
    }

    private List<String> strictTextList(
        JsonNode value, int maxItems, int maxLength, String label) {
      if (value == null || !value.isArray() || value.size() > maxItems) {
        throw new RuntimeProtocolException("AI Runtime " + label + " 格式无效");
      }
      List<String> result = new ArrayList<>();
      for (JsonNode item : value) {
        if (!item.isTextual()
            || item.textValue().isBlank()
            || item.textValue().length() > maxLength
            || containsForbiddenControl(item.textValue())) {
          throw new RuntimeProtocolException("AI Runtime " + label + " 包含无效文本");
        }
        result.add(item.textValue());
      }
      return List.copyOf(result);
    }

    private void acceptFinish(JsonNode data) {
      validateRetrievalPathReadyForPlan();
      if (!planSeen) throw new RuntimeProtocolException("AI Runtime 在 plan 之前发送 finish");
      if (!authorizationGuardSeen) {
        throw new RuntimeProtocolException("AI Runtime 在 authorization_guard 之前发送 finish");
      }
      if (lifecyclePosition >= 0 && !reviewSeen) {
        throw new RuntimeProtocolException("AI Runtime 生命周期在 review 前提前结束");
      }
      requireFields(
          data,
          Set.of(
              "status",
              "answer",
              "plan",
              "review",
              "violations",
              "retrievalRoundCount",
              "evidenceIds",
              "indexRevision",
              "plannerSource",
              "terminationReason"),
          Set.of(
              "status",
              "answer",
              "plan",
              "review",
              "violations",
              "retrievalRoundCount",
              "evidenceIds",
              "indexRevision",
              "plannerSource",
              "terminationReason"),
          "finish data");
      finishStatus = strictText(data, "status", 32);
      if (!Set.of("COMPLETED", "DENIED", "APPROVAL_REQUIRED", "FAILED")
          .contains(finishStatus)) {
        throw new RuntimeProtocolException("AI Runtime 终态无效");
      }
      if (("DENIED".equals(lastEvidenceStatus) && !"DENIED".equals(finishStatus))
          || ("FAILED".equals(lastEvidenceStatus) && !"FAILED".equals(finishStatus))) {
        throw new RuntimeProtocolException("AI Runtime Evidence 失败状态未传播到终态");
      }
      if (("DENIED".equals(authorizationStatus) && !"DENIED".equals(finishStatus))
          || ("APPROVAL_REQUIRED".equals(authorizationStatus)
              && !"APPROVAL_REQUIRED".equals(finishStatus))
          || (lifecycleFailed && !"FAILED".equals(finishStatus))
          || ("COMPLETED".equals(finishStatus)
              && Set.of("DENIED", "APPROVAL_REQUIRED").contains(authorizationStatus))) {
        throw new RuntimeProtocolException("AI Runtime Harness 中间状态未正确传播到终态");
      }
      answer = strictText(data, "answer", 20_000);
      int rounds = strictBoundedInt(data, "retrievalRoundCount", 0, 2);
      if (rounds != retrievalRoundCount) {
        throw new RuntimeProtocolException("AI Runtime finish retrievalRoundCount 与事件流不一致");
      }
      List<String> reportedEvidence =
          strictReferenceList(data.get("evidenceIds"), MAX_TURN_EVIDENCE_IDS, "finish evidenceIds");
      JsonNode finishRevision = data.get("indexRevision");
      if (indexRevision.isBlank()) {
        if (finishRevision != null && !finishRevision.isNull()) {
          throw new RuntimeProtocolException("无索引快照的终态不得声明 indexRevision");
        }
      } else if (finishRevision == null
          || !finishRevision.isTextual()
          || !indexRevision.equals(finishRevision.textValue())) {
        throw new RuntimeProtocolException("AI Runtime finish indexRevision 与 Evidence 不一致");
      }
      plannerSource = safeProtocolIdentifier(data, "plannerSource", 64);
      JsonNode termination = data.get("terminationReason");
      if (termination != null && !termination.isNull()) {
        if (!termination.isTextual()
            || termination.textValue().isBlank()
            || termination.textValue().length() > 64
            || !termination.textValue().matches(SAFE_ID_PATTERN)) {
          throw new RuntimeProtocolException("AI Runtime terminationReason 无效");
        }
        terminationReason = termination.textValue();
      }
      JsonNode review = data.get("review");
      JsonNode violations = data.get("violations");
      if (review == null
          || !review.isObject()
          || violations == null
          || !violations.isArray()
          || violations.size() > 32) {
        throw new RuntimeProtocolException("AI Runtime finish review 或 violations 格式无效");
      }
      boolean ragDisabledLegacy = "RAG_DISABLED".equals(routeStatus);
      validateFinishMatchesPlanEvent(data.get("plan"));
      ParsedPlan parsed = toPlan(data.get("plan"), activeEvidenceIds, ragDisabledLegacy);
      if (!answer.equals(parsed.answer())) {
        throw new RuntimeProtocolException(
            "AI Runtime finish answer 与最终计划 answer 不一致");
      }
      if (!plannerSource.equals(parsed.plannerSource())
          || !Set.copyOf(reportedEvidence).equals(Set.copyOf(parsed.evidenceIds()))) {
        throw new RuntimeProtocolException("AI Runtime finish provenance 与最终计划不一致");
      }
      if (ragDisabledLegacy
          && (!reportedEvidence.isEmpty()
              || plannerSource.toLowerCase(java.util.Locale.ROOT).contains("grounded"))) {
        throw new RuntimeProtocolException("RAG_DISABLED 终态不得宣称 grounded planner 来源");
      }
      if ("FAILED".equals(routeStatus) && !"FAILED".equals(finishStatus)) {
        throw new RuntimeProtocolException("失败的 route 必须传播 FAILED 终态");
      }
      validateRoutePlanSemantics(parsed, ragDisabledLegacy);
      plan = parsed.plan();
      finishEvidenceIds = List.copyOf(reportedEvidence);
      finished = true;
    }

    private void validateFinishMatchesPlanEvent(JsonNode finalPlan) {
      if (planEventData == null || finalPlan == null || !finalPlan.isObject()) {
        throw new RuntimeProtocolException("AI Runtime 缺少可复核的 plan 事件数据");
      }
      for (String field : List.of("summary", "answer", "intent", "actions", "source")) {
        if (!Objects.equals(planEventData.get(field), finalPlan.get(field))) {
          throw new RuntimeProtocolException("AI Runtime plan 事件与终态计划不一致");
        }
      }
      for (String field : List.of("knowledgeMode", "evidenceRefs")) {
        if (finalPlan.has(field) && !Objects.equals(planEventData.get(field), finalPlan.get(field))) {
          throw new RuntimeProtocolException("AI Runtime plan 事件与终态 provenance 不一致");
        }
      }
    }

    private void validateRoutePlanSemantics(ParsedPlan parsed, boolean ragDisabledLegacy) {
      boolean noActions = !parsed.actionable();
      boolean noEvidence = parsed.evidenceIds().isEmpty();
      boolean insufficientClarification =
          "clarify".equals(parsed.intent())
              && "INSUFFICIENT_EVIDENCE".equals(parsed.knowledgeMode())
              && noActions
              && noEvidence;
      boolean matches;
      if (ragDisabledLegacy) {
        matches =
            switch (routeIntent) {
              case "GENERAL_QA" ->
                  "answer".equals(parsed.intent())
                      && "GENERAL".equals(parsed.knowledgeMode())
                      && noActions
                      && noEvidence;
              case "CLARIFY" ->
                  "clarify".equals(parsed.intent())
                      && "GENERAL".equals(parsed.knowledgeMode())
                      && noActions
                      && noEvidence;
              case "ACTION_PLAN" ->
                  "plan".equals(parsed.intent())
                      && "GENERAL".equals(parsed.knowledgeMode())
                      && parsed.actionable()
                      && noEvidence;
              default -> false;
            };
      } else {
        matches =
            switch (routeIntent) {
              case "GENERAL_QA" ->
                  ("answer".equals(parsed.intent())
                          && "GENERAL".equals(parsed.knowledgeMode())
                          && noActions
                          && noEvidence)
                      || ("clarify".equals(parsed.intent())
                          && "GENERAL".equals(parsed.knowledgeMode())
                          && noActions
                          && noEvidence)
                      || ("FAILED".equals(finishStatus) && insufficientClarification);
              case "CLARIFY" -> insufficientClarification;
              case "PROJECT_QA" ->
                  ("answer".equals(parsed.intent())
                          && "PROJECT_EVIDENCE".equals(parsed.knowledgeMode())
                          && noActions
                          && !noEvidence)
                      || insufficientClarification;
              case "ACTION_PLAN" ->
                  ("plan".equals(parsed.intent())
                          && "PROJECT_EVIDENCE".equals(parsed.knowledgeMode())
                          && parsed.actionable()
                          && !noEvidence)
                      || insufficientClarification;
              default -> false;
            };
      }
      if (!matches) {
        throw new RuntimeProtocolException(
            "AI Runtime route intent 与最终计划语义不一致");
      }
    }

    private void acceptError(JsonNode data) {
      requireFields(
          data,
          Set.of("status", "errorCode"),
          Set.of("status", "errorCode"),
          "error data");
      if (!"FAILED".equals(strictText(data, "status", 16))) {
        throw new RuntimeProtocolException("AI Runtime error 终态 status 无效");
      }
      safeProtocolIdentifier(data, "errorCode", 64);
      errorCode = strictText(data, "errorCode", 64);
      error = true;
      finished = true;
    }

    private void validateRetrievalPathReadyForPlan() {
      if (!routeSeen) throw new RuntimeProtocolException("AI Runtime 缺少 route 事件");
      if (routeNeedsRetrieval && "ROUTED".equals(routeStatus)) {
        boolean terminalEvidence = Set.of("DENIED", "FAILED").contains(lastEvidenceStatus);
        if ((!terminalEvidence && retrievalRoundCount == 0)
            || (!terminalEvidence && rewriteApplied && retrievalRoundCount != 2)) {
          throw new RuntimeProtocolException("AI Runtime 检索链路在完成前进入 plan/finish");
        }
      } else if (retrievalRoundCount != 0 || rewriteSeen) {
        throw new RuntimeProtocolException("无需检索的 route 不得产生 Evidence/ReAct 事件");
      }
    }

    private long strictPositiveLong(JsonNode node, String field) {
      JsonNode value = node.get(field);
      if (value == null || !value.isIntegralNumber() || !value.canConvertToLong() || value.longValue() <= 0) {
        throw new RuntimeProtocolException("AI Runtime 字段 " + field + " 必须是正整数");
      }
      return value.longValue();
    }

    private int strictBoundedInt(JsonNode node, String field, int min, int max) {
      JsonNode value = node.get(field);
      if (value == null
          || !value.isInt()
          || value.intValue() < min
          || value.intValue() > max) {
        throw new RuntimeProtocolException("AI Runtime 字段 " + field + " 超出范围");
      }
      return value.intValue();
    }

    private String normalizeQuery(String value) {
      return value == null
          ? ""
          : value.strip().replaceAll("\\s+", " ").toLowerCase(java.util.Locale.ROOT);
    }

    private RuntimeProvenance provenance() {
      return new RuntimeProvenance(
          retrievalRoundCount,
          finishEvidenceIds,
          indexRevision,
          plannerSource,
          terminationReason);
    }
  }
}
