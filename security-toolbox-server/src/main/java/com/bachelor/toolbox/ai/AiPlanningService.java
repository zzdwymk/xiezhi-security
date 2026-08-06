package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AiPlanningService {
  private static final String MODEL_PROVIDER = "openai-compatible";
  private static final String FALLBACK_PROVIDER = "local-rule-fallback";
  private static final String MODEL_STEP_REASON = "大模型根据用户需求和授权范围选择";
  private static final Pattern MARKDOWN_CODE_FENCE =
      Pattern.compile("```[\\t ]*(?:json)?[\\t ]*\\R([\\s\\S]*?)```", Pattern.CASE_INSENSITIVE);

  private final TargetService targetService;
  private final AssessmentProjectService projectService;
  private final AuditService auditService;
  private final ObjectMapper objectMapper;
  private final AiModelClient modelClient;
  private final AiContextService contextService;

  @Autowired
  public AiPlanningService(
      TargetService targetService,
      AuditService auditService,
      ObjectMapper objectMapper,
      AiModelClient modelClient,
      AiContextService contextService,
      AssessmentProjectService projectService) {
    this.targetService = targetService;
    this.projectService = projectService;
    this.auditService = auditService;
    this.objectMapper = objectMapper;
    this.modelClient = modelClient;
    this.contextService = contextService;
  }

  public AiPlanningService(
      TargetService targetService,
      AuditService auditService,
      ObjectMapper objectMapper,
      AiModelClient modelClient,
      AiContextService contextService) {
    this(targetService, auditService, objectMapper, modelClient, contextService, null);
  }

  public AiPlanningService(
      TargetService targetService,
      AuditService auditService,
      ObjectMapper objectMapper,
      AiModelClient modelClient) {
    this(targetService, auditService, objectMapper, modelClient, null, null);
  }

  public AiPlanResponse plan(AiPlanRequest request) {
    AuthorizedTarget target = validatePlanningScope(request);
    String prompt = enrichedPrompt(request);
    AiPlanResponse response;
    if (!modelClient.enabled()) {
      response = fallbackPlan(target, prompt);
    } else {
      try {
        response = callModel(target, prompt);
      } catch (Exception ex) {
        response = fallbackPlan(target, prompt);
      }
    }
    response = enforceIntentBoundary(response, prompt);
    auditService.record("AI_CREATE_PLAN", "TARGET", target.getId(), request.prompt(), "SUCCESS");
    return response;
  }

  public AiPlanResponse planStreaming(
      AiPlanRequest request, Consumer<AiModelClient.AiModelStreamEvent> listener) {
    AuthorizedTarget target = validatePlanningScope(request);
    String prompt = enrichedPrompt(request);
    Consumer<AiModelClient.AiModelStreamEvent> safeListener =
        listener == null ? ignored -> {} : listener;
    AiPlanResponse response;
    if (!modelClient.enabled()) {
      safeListener.accept(
          new AiModelClient.AiModelStreamEvent("activity", "AI API 未启用，正在使用本地安全规则生成计划"));
      response = fallbackPlan(target, prompt);
    } else if (!modelClient.responsesMode()) {
      safeListener.accept(new AiModelClient.AiModelStreamEvent("activity", "当前接口不提供推理摘要，正在生成检测计划"));
      response = plan(request);
      return response;
    } else {
      try {
        response = callResponsesModel(target, prompt, safeListener);
      } catch (Exception ex) {
        safeListener.accept(
            new AiModelClient.AiModelStreamEvent("activity", "AI 服务未完成计划，已切换本地安全规则"));
        response = fallbackPlan(target, prompt);
      }
    }
    response = enforceIntentBoundary(response, prompt);
    auditService.record("AI_CREATE_PLAN", "TARGET", target.getId(), request.prompt(), "SUCCESS");
    return response;
  }

  private AuthorizedTarget validatePlanningScope(AiPlanRequest request) {
    AuthorizedTarget target = targetService.getCurrentlyAuthorized(request.targetId());
    if (request.projectId() == null) {
      return target;
    }
    if (projectService == null) {
      throw new ApiException("无法校验目标所属的评估项目");
    }
    projectService.validateProjectTargetMembership(request.projectId(), request.targetId());
    return target;
  }

  private String enrichedPrompt(AiPlanRequest request) {
    String context =
        contextService == null
            ? ""
            : contextService.resolve(
                request.projectId(), request.targetId(), request.contextRefs(), request.refs());    return request.prompt() + context;
  }

  private AiPlanResponse callModel(AuthorizedTarget target, String prompt) throws Exception {
    if (modelClient.responsesMode()) {
      return callResponsesModel(target, prompt);
    }
    JsonNode root = modelClient.chat(chatRequest(target, prompt));
    return normalizeChatResponse(root);
  }

  private Map<String, Object> chatRequest(AuthorizedTarget target, String prompt) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("model", modelClient.model());
    body.put(
        "messages",
        List.of(
            Map.of("role", "system", "content", chatSystemPrompt(target)),
            Map.of("role", "user", "content", prompt)));
    body.put("tools", chatTools());
    body.put("tool_choice", "auto");
    return body;
  }

  private List<Map<String, Object>> chatTools() {
    return List.of(
        function(
            "nuclei_scan",
            "Authorized Nuclei vulnerability template scan",
            Map.of("type", "object", "properties", Map.of(), "additionalProperties", false)),
        function(
            "nmap_service_scan",
            "Authorized Nmap TCP and lightweight service scan; never select together with"
                + " tcp_ports",
            Map.of(
                "type",
                "object",
                "properties",
                Map.of(
                    "ports",
                        Map.of(
                            "type", "string",
                            "description", "Comma-separated authorized port subset"),
                    "mode", Map.of("type", "string", "enum", List.of("quick", "service"))),
                "required",
                List.of("ports", "mode"),
                "additionalProperties",
                false)),
        function(
            "tcp_ports",
            "对授权目标的允许端口执行受控 TCP 连接探测",
            Map.of(
                "type",
                "object",
                "properties",
                Map.of(
                    "ports",
                    Map.of(
                        "type", "string",
                        "description", "逗号分隔端口，必须在授权范围内")),
                "required",
                List.of("ports"),
                "additionalProperties",
                false)),
        function(
            "http_headers",
            "检查授权 Web 目标的常见安全响应头",
            Map.of("type", "object", "properties", Map.of(), "additionalProperties", false)),
        function(
            "http_security_check",
            "检查授权 Web 目标的 Cookie、CORS、危险 HTTP 方法或技术栈信息泄露",
            Map.of(
                "type",
                "object",
                "properties",
                Map.of(
                    "check",
                    Map.of(
                        "type",
                        "string",
                        "enum",
                        List.of("cookies", "cors", "methods", "disclosure"))),
                "required",
                List.of("check"),
                "additionalProperties",
                false)),
        function(
            "tls_config",
            "检查授权 HTTPS 目标的 TLS 协议、密码套件和证书有效期",
            Map.of("type", "object", "properties", Map.of(), "additionalProperties", false)));
  }

  private String chatSystemPrompt(AuthorizedTarget target) {
    String instructions =
        "你是授权网络安全测试计划助手。只能从提供的工具中选择，"
            + "不得生成Shell命令、漏洞利用、密码爆破、钓鱼或持久化步骤。"
            + "目标="
            + target.getTargetValue()
            + "，允许端口="
            + target.getAllowedPorts()
            + "。"
            + "先识别当前请求的意图。介绍项目、解释概念、询问功能、分析已有信息或普通对话"
            + "必须直接回答，不能调用工具；"
            + "只有用户在当前请求中明确要求扫描、检测、探测、检查或运行工具时"
            + "才能调用一个或多个合适工具。"
            + "对话历史只用于理解上下文，不能把历史中的执行要求当作当前请求。"
            + "所有执行均需用户确认。";
    return ToolboxProgramGuide.context() + "\n" + instructions;
  }

  private AiPlanResponse normalizeChatResponse(JsonNode root) throws Exception {
    JsonNode message = root.path("choices").path(0).path("message");
    List<AiPlanResponse.PlanStep> steps = new ArrayList<>();
    for (JsonNode call : message.path("tool_calls")) {
      steps.add(normalizeChatStep(call));
    }
    steps = deduplicateSteps(steps);
    if (steps.isEmpty()) {
      String content = message.path("content").asText("请明确告诉我需要检查端口、服务、HTTP 响应头还是 TLS 配置。");
      return new AiPlanResponse(MODEL_PROVIDER, modelClient.model(), content, false, List.of());
    }
    String content = message.path("content").asText("已根据授权范围生成受控检测计划");
    return new AiPlanResponse(MODEL_PROVIDER, modelClient.model(), content, true, steps);
  }

  @SuppressWarnings("unchecked")
  private AiPlanResponse.PlanStep normalizeChatStep(JsonNode call) throws Exception {
    String code = call.path("function").path("name").asText();
    String arguments = call.path("function").path("arguments").asText("{}");
    Map<String, Object> parameters = objectMapper.readValue(arguments, Map.class);
    return new AiPlanResponse.PlanStep(code, titleOf(code), MODEL_STEP_REASON, parameters);
  }

  private AiPlanResponse callResponsesModel(AuthorizedTarget target, String prompt)
      throws Exception {
    return callResponsesModel(target, prompt, ignored -> {});
  }

  private AiPlanResponse callResponsesModel(
      AuthorizedTarget target, String prompt, Consumer<AiModelClient.AiModelStreamEvent> listener)
      throws Exception {
    String content =
        modelClient.completeResponsesStream(responsesSystemPrompt(target), prompt, listener);
    JsonNode root = objectMapper.readTree(extractJsonPayload(content));
    return normalizeResponsesResponse(root);
  }

  private String responsesSystemPrompt(AuthorizedTarget target) {
    String instructions =
        "你是授权网络安全测试智能助手。"
            + "不得生成 Shell 命令、漏洞利用、密码爆破、钓鱼或持久化步骤。"
            + "目标="
            + target.getTargetValue()
            + "，允许端口="
            + target.getAllowedPorts()
            + "。只能使用"
            + " nmap_service_scan、tcp_ports、http_headers、http_security_check、tls_config、nuclei_scan。请理解用户自然语言意图，不要依赖关键词表。口语化的漏扫/扫描啊/扫端口/授权了/能扫的都扫都要正确理解。问答解释找页面看结果：返回空"
            + " steps 并在 summary 回答；执行意图：生成合适"
            + " steps。结合历史理解短确认，但以当前请求为主；含糊时先澄清，不要把明确执行请求当成咨询。漏洞扫描/Nuclei 用"
            + " nuclei_scan；Cookie/CORS/方法/信息泄露用 http_security_check。只输出严格 JSON，不要 Markdown。格式："
            + "{\"summary\":\"简短说明\",\"steps\":[{\"toolCode\":\"工具名\",\"title\":\"标题\",\"reason\":\"原因\",\"parameters\":{}}]}。nmap_service_scan"
            + " parameters 必须包含 ports 和 mode(quick或service)；tcp_ports 必须包含"
            + " ports；http_security_check parameters 必须只包含 check，值为 cookies、cors、methods、disclosure"
            + " 之一；nuclei_scan parameters 必须为空对象；http_headers 与 tls_config parameters 必须为空对象。不要同时选择"
            + " nmap_service_scan 和 tcp_ports。";
    return ToolboxProgramGuide.context() + "\n" + instructions;
  }

  private AiPlanResponse normalizeResponsesResponse(JsonNode root) {
    List<AiPlanResponse.PlanStep> steps = new ArrayList<>();
    for (JsonNode item : root.path("steps")) {
      steps.add(normalizeResponsesStep(item));
    }
    steps = deduplicateSteps(steps);
    return new AiPlanResponse(
        MODEL_PROVIDER,
        modelClient.model(),
        root.path("summary").asText("请告诉我你希望了解或检测什么。"),
        !steps.isEmpty(),
        steps);
  }

  @SuppressWarnings("unchecked")
  private AiPlanResponse.PlanStep normalizeResponsesStep(JsonNode item) {
    String code = item.path("toolCode").asText("");
    Map<String, Object> parameters = objectMapper.convertValue(item.path("parameters"), Map.class);
    return new AiPlanResponse.PlanStep(
        code,
        item.path("title").asText(titleOf(code)),
        item.path("reason").asText(MODEL_STEP_REASON),
        parameters == null ? Map.of() : parameters);
  }

  private List<AiPlanResponse.PlanStep> deduplicateSteps(List<AiPlanResponse.PlanStep> steps) {
    boolean hasNmap =
        steps.stream()
            .filter(Objects::nonNull)
            .anyMatch(step -> "nmap_service_scan".equals(step.toolCode()));
    Set<String> seen = new LinkedHashSet<>();
    List<AiPlanResponse.PlanStep> result = new ArrayList<>();
    for (AiPlanResponse.PlanStep step : steps) {
      if (step == null || (hasNmap && "tcp_ports".equals(step.toolCode()))) {
        continue;
      }
      if (seen.add(stepKey(step))) {
        result.add(step);
      }
    }
    return result;
  }

  private String stepKey(AiPlanResponse.PlanStep step) {
    String toolCode = Objects.toString(step.toolCode(), "");
    if (!"http_security_check".equals(toolCode)) {
      return toolCode;
    }
    Object check = step.parameters() == null ? null : step.parameters().get("check");
    return toolCode + ":" + Objects.toString(check, "");
  }

  private String extractJsonPayload(String content) {
    String value = content == null ? "" : content.strip();
    Matcher fence = MARKDOWN_CODE_FENCE.matcher(value);
    while (fence.find()) {
      String candidate = fence.group(1).strip();
      if (candidate.startsWith("{") && candidate.endsWith("}")) {
        return candidate;
      }
    }
    int objectStart = value.indexOf('{');
    int objectEnd = value.lastIndexOf('}');
    if (objectStart >= 0 && objectEnd > objectStart) {
      return value.substring(objectStart, objectEnd + 1);
    }
    return value;
  }

  private Map<String, Object> function(
      String name, String description, Map<String, Object> parameters) {
    return Map.of(
        "type",
        "function",
        "function",
        Map.of(
            "name", name,
            "description", description,
            "parameters", parameters,
            "strict", true));
  }

  private AiPlanResponse fallbackPlan(AuthorizedTarget target, String prompt) {
    String currentRequest = currentUserRequest(prompt);
    String lower = currentRequest.toLowerCase(Locale.ROOT);
    String programHelp = programHelp(lower);
    if (programHelp != null) {
      return fallbackResponse(programHelp, false, List.of());
    }
    if (isProjectIntroductionRequest(lower)) {
      return fallbackResponse(projectIntroduction(prompt), false, List.of());
    }

    // 名词本身不代表执行授权，只有明确动作请求才能进入本地计划生成。
    if (!explicitlyRequestsExecution(prompt)) {
      String reply =
          containsAny(lower, "你好", "您好", "hello", "hi", "嗨")
              ? "你好！我是安全助手。你可以直接问我项目、程序功能或安全概念；只有你明确要求执行检测时，我才会生成任务计划。"
              : "这是一个咨询或说明请求，我不会创建检测任务。你可以继续询问项目情况、程序功能或安全问题；" + "如需实际检测，请明确说明要扫描或检查的内容。";
      return fallbackResponse(reply, false, List.of());
    }

    List<AiPlanResponse.PlanStep> steps =
        buildLocalPlanSteps(target, localPlanIntent(target, lower));
    if (steps.isEmpty()) {
      String reply =
          "我识别到你希望执行检测，但还不能确定需要使用哪一类安全工具。" + "请明确说明要扫描端口、识别服务、检查 HTTP 响应头、TLS 配置还是执行通用漏洞扫描。";
      return fallbackResponse(reply, false, List.of());
    }
    return fallbackResponse("未配置或未成功调用 AI API，已根据关键词和授权范围生成可执行计划。", true, steps);
  }

  private AiPlanResponse fallbackResponse(
      String summary, boolean requiresConfirmation, List<AiPlanResponse.PlanStep> steps) {
    return new AiPlanResponse(
        FALLBACK_PROVIDER, modelClient.model(), summary, requiresConfirmation, steps);
  }

  private LocalPlanIntent localPlanIntent(AuthorizedTarget target, String request) {
    String targetValue = target.getTargetValue().toLowerCase(Locale.ROOT);
    boolean webTarget =
        targetValue.startsWith("http://")
            || targetValue.startsWith("https://")
            || "URL".equalsIgnoreCase(target.getTargetType());
    boolean broadAssessment =
        containsAny(
            request,
            "漏洞",
            "风险",
            "安全检查",
            "安全检测",
            "安全评估",
            "全面",
            "全部",
            "综合",
            "扫描一下",
            "扫描啊",
            "漏扫",
            "有什么功能就扫描",
            "能扫的都扫",
            "vulnerability",
            "security scan",
            "assessment");
    boolean wantsFullPortScan =
        containsAny(
            request,
            "全端口",
            "全部端口",
            "所有端口",
            "全量端口",
            "完整端口",
            "1-65535",
            "1到65535",
            "1 到 65535",
            "full port",
            "all port",
            "entire port range",
            "-p-");
    boolean wantsServiceIdentification =
        containsAny(
            request, "服务识别", "服务扫描", "版本识别", "service scan", "fingerprint", "version detection");
    boolean fullAuthorization = "1-65535".equals(target.getAllowedPorts());
    boolean wantsPortAssessment =
        broadAssessment || containsAny(request, "端口", "port", "服务", "资产", "基础");
    boolean wantsNmap =
        wantsFullPortScan
            || containsAny(request, "nmap")
            || wantsServiceIdentification
            || (fullAuthorization && wantsPortAssessment);
    boolean wantsNuclei =
        containsAny(
            request, "nuclei", "漏洞扫描", "漏扫", "漏洞检测", "通用漏洞", "漏洞模板", "扫漏洞", "vulnerability scan");
    if (wantsNuclei && !containsAny(request, "端口", "nmap", "服务识别")) {
      wantsNmap = false;
    }
    return new LocalPlanIntent(
        request,
        webTarget,
        targetValue.startsWith("https"),
        broadAssessment,
        wantsFullPortScan,
        wantsServiceIdentification,
        fullAuthorization,
        wantsPortAssessment,
        wantsNmap,
        wantsNuclei);
  }

  private List<AiPlanResponse.PlanStep> buildLocalPlanSteps(
      AuthorizedTarget target, LocalPlanIntent intent) {
    List<AiPlanResponse.PlanStep> steps = new ArrayList<>();
    addNucleiStep(steps, intent);
    addPortStep(steps, target, intent);
    addHttpHeaderStep(steps, intent);
    addHttpSecurityStep(steps, intent);
    addTlsStep(steps, intent);
    return steps;
  }

  private void addNucleiStep(List<AiPlanResponse.PlanStep> steps, LocalPlanIntent intent) {
    if (intent.wantsNuclei()) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "nuclei_scan", "Nuclei 通用漏洞扫描", "使用非破坏性模板检查授权目标上的已知安全问题", Map.of()));
    }
  }

  private void addPortStep(
      List<AiPlanResponse.PlanStep> steps, AuthorizedTarget target, LocalPlanIntent intent) {
    if (intent.wantsNmap()) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "nmap_service_scan",
              intent.wantsFullPortScan() || intent.fullAuthorization()
                  ? "Nmap 授权全端口扫描"
                  : "Nmap 服务识别",
              intent.wantsServiceIdentification() && !intent.fullAuthorization()
                  ? "识别授权端口状态和轻量服务版本"
                  : "快速扫描全部授权端口",
              Map.of(
                  "ports",
                  target.getAllowedPorts(),
                  "mode",
                  intent.wantsServiceIdentification() && !intent.fullAuthorization()
                      ? "service"
                      : "quick")));
    } else if (intent.wantsPortAssessment()) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "tcp_ports", "授权端口探测", "识别授权范围内可访问的网络服务", Map.of("ports", target.getAllowedPorts())));
    }
  }

  private void addHttpHeaderStep(List<AiPlanResponse.PlanStep> steps, LocalPlanIntent intent) {
    boolean requested =
        intent.broadAssessment()
            || containsAny(intent.request(), "web", "http", "响应头", "安全头", "基础");
    if (intent.webTarget() && requested) {
      steps.add(
          new AiPlanResponse.PlanStep("http_headers", "HTTP 安全响应头检查", "评估浏览器侧常见安全基线", Map.of()));
    }
  }

  private void addHttpSecurityStep(List<AiPlanResponse.PlanStep> steps, LocalPlanIntent intent) {
    if (!intent.webTarget()) {
      return;
    }
    String request = intent.request();
    if (containsAny(request, "cookie", "会话 cookie", "认证 cookie")) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "http_security_check",
              "敏感 Cookie 安全属性检查",
              "检查会话 Cookie 的 Secure、HttpOnly 和 SameSite 属性",
              Map.of("check", "cookies")));
    } else if (containsAny(request, "cors", "跨域", "origin")) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "http_security_check", "CORS 跨域策略检查", "检查非可信来源是否被错误允许", Map.of("check", "cors")));
    } else if (containsAny(request, "http 方法", "危险方法", "trace", "track", "connect 方法")) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "http_security_check",
              "危险 HTTP 方法检查",
              "检查端点是否声明支持危险 HTTP 方法",
              Map.of("check", "methods")));
    } else if (containsAny(request, "信息泄露", "技术栈", "server 头", "x-powered-by", "版本泄露")) {
      steps.add(
          new AiPlanResponse.PlanStep(
              "http_security_check",
              "HTTP 技术栈信息泄露检查",
              "检查响应头中的服务器和框架披露信息",
              Map.of("check", "disclosure")));
    }
  }

  private void addTlsStep(List<AiPlanResponse.PlanStep> steps, LocalPlanIntent intent) {
    boolean requested =
        intent.broadAssessment() || containsAny(intent.request(), "tls", "https", "证书", "基础");
    if (intent.secureWebTarget() && requested) {
      steps.add(
          new AiPlanResponse.PlanStep("tls_config", "TLS 基础配置检查", "检查协议、密码套件和证书有效期", Map.of()));
    }
  }

  private boolean containsAny(String text, String... words) {
    return Arrays.stream(words).anyMatch(text::contains);
  }

  /** 模型结果负责在线意图路由；确定性拦截只约束本地回退，避免咨询问题被历史上下文误转为扫描。 */
  private AiPlanResponse enforceIntentBoundary(AiPlanResponse response, String fullPrompt) {
    if (response == null) {
      return null;
    }
    String provider = response.provider() == null ? "" : response.provider();
    boolean localFallback = provider.contains("local-rule");
    if (!localFallback) {
      return response;
    }
    if (!isClearlyInformational(fullPrompt)) {
      return response;
    }
    if (response.steps() == null || response.steps().isEmpty()) {
      return response;
    }
    String answer = response.summary();
    if (answer == null || answer.isBlank()) {
      answer = "这是一个说明或咨询请求，我不会创建检测任务。需要执行时请直接说明要扫描或检查的内容。";
    }
    return new AiPlanResponse(response.provider(), response.model(), answer, false, List.of());
  }

  private boolean isClearlyInformational(String prompt) {
    if (prompt == null || prompt.isBlank()) {
      return true;
    }
    if (explicitlyRequestsExecution(prompt)) {
      return false;
    }
    String lower = currentUserRequest(prompt.toLowerCase(Locale.ROOT));
    return containsAny(
        lower, "什么是", "是什么意思", "为什么", "介绍", "解释", "区别", "原理", "算漏洞吗", "是否算", "有哪些功能", "能做什么",
        "怎么使用", "如何使用", "怎么扫描", "如何扫描", "怎么检测", "如何检测", "可以扫描吗", "可以检测吗", "你好", "您好", "谢谢");
  }

  private boolean explicitlyRequestsExecution(String prompt) {
    if (prompt == null || prompt.isBlank()) {
      return false;
    }
    String lower = prompt.toLowerCase(Locale.ROOT);
    String current = currentUserRequest(lower);
    String history = lower.contains("当前请求：") ? lower.substring(0, lower.lastIndexOf("当前请求：")) : "";

    // “如何扫描”等纯咨询即使包含动作词，也不代表用户授权执行。
    boolean pureQuestion =
        containsAny(
                current, "什么是", "是什么意思", "为什么", "介绍", "解释", "区别", "原理", "算漏洞吗", "是否算", "怎么使用",
                "如何使用", "怎么扫描", "如何扫描", "怎么检测", "如何检测", "怎么检查", "如何检查", "可以扫描吗", "可以检测吗", "在哪里",
                "怎么用")
            && !containsAny(
                current, "请扫描", "帮我扫描", "开始扫描", "执行扫描", "立即扫描", "扫描一下", "扫一下", "请检测", "帮我检测",
                "漏扫一下", "进行漏扫", "授权了", "确认执行");
    if (pureQuestion) {
      return false;
    }

    if (containsAny(
        current,
        "请扫描",
        "帮我扫描",
        "开始扫描",
        "执行扫描",
        "立即扫描",
        "重新扫描",
        "扫描一下",
        "扫一下",
        "进行扫描",
        "进行漏扫",
        "漏扫一下",
        "做个扫描",
        "发起扫描",
        "启动扫描",
        "请检测",
        "帮我检测",
        "开始检测",
        "执行检测",
        "重新检测",
        "检测一下",
        "测一下",
        "请检查",
        "帮我检查",
        "开始检查",
        "执行检查",
        "检查一下",
        "查一下",
        "请探测",
        "帮我探测",
        "开始探测",
        "执行探测",
        "探测一下",
        "运行工具",
        "执行工具",
        "运行扫描",
        "执行任务",
        "扫描端口",
        "端口扫描",
        "漏洞扫描",
        "漏扫",
        "服务扫描",
        "全端口",
        "探测端口",
        "探测服务",
        "识别服务",
        "服务版本",
        "端口和服务",
        "进行后渗透",
        "提权验证",
        "扫端口",
        "扫服务",
        "扫漏洞",
        "扫描啊",
        "扫吧",
        "有什么功能就扫描",
        "有什么就扫",
        "能扫的都扫",
        "全部扫描",
        "全面扫描",
        "都扫一遍",
        "综合扫描",
        "全面检查",
        "全面检测",
        "nuclei",
        "nmap",
        "scan ",
        "run scan",
        "start scan",
        "execute scan")) {
      return true;
    }

    // 动作词作为当前请求主体时，按执行意图处理。
    if (containsAny(current, "扫描", "漏扫", "探测", "检测", "检查", "审计", "scan", "probe", "audit")
        && !containsAny(current, "有哪些功能", "能做什么", "程序功能")) {
      return true;
    }

    // 扫描上下文之后的简短确认可以延续执行意图。
    String compact = current.replaceAll("\\s+", "");
    boolean affirmation =
        containsAny(compact, "授权了", "已授权", "确认执行", "开始吧", "执行吧", "扫吧", "扫描啊", "好的", "继续", "可以");
    if (affirmation
        && (containsAny(history, "扫描", "漏扫", "探测", "检测", "端口", "nmap", "nuclei")
            || containsAny(compact, "授权了", "已授权", "确认执行", "执行吧"))) {
      return true;
    }

    boolean englishAction =
        containsAny(current, "check ", "check\n", "audit ", "inspect ", "probe ", "test ");
    boolean securitySubject =
        containsAny(
            current,
            "http",
            "https",
            "header",
            "cookie",
            "cors",
            "tls",
            "certificate",
            "port",
            "service",
            "asset",
            "security",
            "vulnerability",
            "nmap",
            "nuclei");
    return englishAction && securitySubject;
  }

  private boolean isProjectIntroductionRequest(String prompt) {
    return containsAny(prompt, "介绍一下项目", "介绍项目", "当前项目", "项目情况", "项目概况", "这个项目")
        && !explicitlyRequestsExecution(prompt);
  }

  private String projectIntroduction(String fullPrompt) {
    String marker = "服务端授权上下文：";
    int index = fullPrompt == null ? -1 : fullPrompt.lastIndexOf(marker);
    if (index >= 0) {
      String scope = fullPrompt.substring(index + marker.length()).strip();
      int end = scope.indexOf("\n以下是服务端");
      if (end >= 0) {
        scope = scope.substring(0, end).strip();
      }
      if (!scope.isBlank()) {
        return "这是“獬豸（Xiezhi）授权安全测试平台”中的一个授权安全评估项目。当前对话绑定的是："
            + scope
            + "。你可以继续询问项目范围、已有任务、漏洞结果和报告；只有明确要求执行检测时，我才会创建任务。";
      }
    }
    return "这是“獬豸（Xiezhi）授权安全测试平台”中的安全评估项目。一个项目集中管理授权范围、多个目标、多次检测任务、漏洞与复测记录、审批审计记录和项目总结报告。普通项目问答不会创建扫描任务。";
  }

  private String currentUserRequest(String prompt) {
    if (prompt == null) {
      return "";
    }
    String value = prompt.strip();
    int current = value.lastIndexOf("当前请求：");
    if (current >= 0) {
      value = value.substring(current + "当前请求：".length()).strip();
    }
    for (String marker : List.of("\n\n服务端授权上下文：", "\n以下是服务端重新查询", "\n[功能引用：")) {
      int markerIndex = value.indexOf(marker);
      if (markerIndex >= 0) {
        value = value.substring(0, markerIndex).strip();
      }
    }
    return value;
  }

  private String programHelp(String prompt) {
    // 帮助回答只处理咨询；明确执行请求仍交给授权边界决定是否生成步骤。
    if (explicitlyRequestsExecution(prompt)) {
      return null;
    }
    if (containsAny(prompt, "新建项目", "创建项目", "评估项目在哪里", "项目管理", "项目怎么建", "安全评估项目")) {
      return "请打开左侧“评估项目”页面，点击“新建评估项目”。创建后进入项目详情，在“授权目标”中登记目标；项目详情还包含信息收集、探测服务、检测任务、漏洞/复测记录、审计和“项目报告”页签。";
    }
    if (containsAny(prompt, "新增目标", "添加目标", "授权目标怎么", "目标在哪里")) {
      return "请打开左侧“授权目标”页面，点击新增目标，填写名称、目标类型、目标地址、允许端口和授权说明后保存；需要全端口授权时填写 1-65535。";
    }
    if (containsAny(
        prompt, "信息收集在哪里", "信息收集功能", "信息收集怎么", "子域名在哪里", "域名收集", "备案查询", "真实ip怎么查", "真实 IP 怎么查")) {
      return "请打开左侧“信息收集”页面，先选择安全评估项目，再进入项目详情的“信息收集”页签。结果会按项目保存域名、子域名、DNS、IP、HTTP、TLS、备案和网络证据；公开资产证据不会自动判定为漏洞。";
    }
    if (containsAny(prompt, "指纹识别在哪里", "waf识别", "waf 识别", "探测服务在哪里", "服务探测在哪里", "网站指纹")) {
      return "请进入“评估项目”→对应项目详情→“探测服务”页签，可执行网站指纹、WAF 和服务识别并查看证据；也可以从项目联动工作流启动这一步。";
    }
    if (containsAny(prompt, "项目报告", "总结报告", "pdf报告", "pdf 报告", "报告怎么导出", "报告在哪里")) {
      return "请进入“评估项目”→对应项目详情→“项目报告”页签。这里可生成项目级"
          + " PDF，总结项目授权目标、任务、漏洞、复测、探测、审批和审计记录；单任务报告在“检测任务”或“结果中心”下载。";
    }
    if (containsAny(prompt, "工作流怎么用", "红队工作流", "联动工作流", "并行执行", "手动连线", "工作流连线")) {
      return "请打开左侧“红队工作流”。从“开始”节点出发拖动节点调整布局，在节点连接点手动连线；同一层分支可并行，汇合节点会等待上游完成，右键连线可删除。项目详情也提供一键联动工作流。";
    }
    if (containsAny(prompt, "取消任务", "重试任务", "并发数量", "队列限制", "任务超时", "终止原因", "任务控制中心")) {
      return "请打开左侧“检测任务”（任务控制中心）。这里会实时显示状态、真实进度和执行命令日志；运行中的任务可取消，失败/超时/取消任务可重试，并按项目和目标的并发、队列与资源配额执行。";
    }
    if (containsAny(prompt, "漏洞库在哪里", "漏洞知识库", "漏洞库更新", "每页十条", "nuclei模板")) {
      return "请打开“漏洞库与主动检测”页面。漏洞知识库每页固定显示 10 条，程序启动时会用内容哈希检查本地漏洞库/模板是否有更新；更新后再从页面同步。";
    }
    if (containsAny(prompt, "审计日志在哪里", "授权快照", "审批记录")) {
      return "请打开左侧“审计日志”，或进入“评估项目”→项目详情查看项目级审批、授权快照和审计记录。任务创建时会保存授权目标、端口、声明有效期、工具/规则版本及 Nuclei"
          + " 模板哈希快照。";
    }
    if (containsAny(prompt, "ccs", "api key", "api怎么", "配置ai", "配置 ai", "模型设置")) {
      return "请打开“系统设置”→“AI 模型服务”。填写兼容 API 地址和模型；直连服务填写 API Key，使用 CCS 时启用本地代理模式，然后先测试连接再保存。";
    }
    if (containsAny(prompt, "依赖", "安装nmap", "安装 nuclei", "安装httpx", "工具目录")) {
      return "请打开“系统设置”→“依赖检测与工具安装”。桌面启动时也会进入该页面；便携工具默认安装到程序可执行文件旁的 tools 目录。";
    }
    if (containsAny(prompt, "怎么看任务", "任务进度", "扫描结果在哪", "检测结果在哪")) {
      return "请在“检测任务”查看执行状态、进度和详细结果；在“结果中心”查看风险、证据和修复建议，成功任务还可以下载报告。";
    }
    if (containsAny(prompt, "你会什么", "能做什么", "有哪些功能", "怎么使用", "如何使用", "程序功能")) {
      return "我可以指导你使用评估项目、授权目标、信息收集、探测服务、红队工作流、主动检测、"
          + "任务控制中心、结果中心、漏洞复测/扫描 Diff、项目 PDF 报告、流量分析、审计日志、"
          + "依赖安装和 AI 设置；你明确提出检测要求时，我也能在授权范围内派发 Nmap、TCP、"
          + "HTTP 响应头、Cookie、CORS、危险方法、信息泄露或 TLS 检查。";
    }
    return null;
  }

  private record LocalPlanIntent(
      String request,
      boolean webTarget,
      boolean secureWebTarget,
      boolean broadAssessment,
      boolean wantsFullPortScan,
      boolean wantsServiceIdentification,
      boolean fullAuthorization,
      boolean wantsPortAssessment,
      boolean wantsNmap,
      boolean wantsNuclei) {}

  private String titleOf(String code) {
    return switch (code) {
      case "nmap_service_scan" -> "Nmap 服务识别";
      case "nuclei_scan" -> "Nuclei 通用漏洞扫描";
      case "tcp_ports" -> "授权端口探测";
      case "http_headers" -> "HTTP 安全响应头检查";
      case "http_security_check" -> "HTTP 常见漏洞检查";
      case "tls_config" -> "TLS 基础配置检查";
      default -> code;
    };
  }
}
