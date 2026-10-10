package com.bachelor.toolbox.postscan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiDispatchResponse;
import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.ai.AiPlanResponse;
import com.bachelor.toolbox.ai.AiAgentRequest;
import com.bachelor.toolbox.ai.SecurityAgentTools;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.HttpHeaderTool;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

class PostScanPathServiceTests {
  private static final long PROJECT = 1L;
  private final PostScanPathRepository pathRepository = mock(PostScanPathRepository.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final TargetService targetService = mock(TargetService.class);  private final FindingRepository findingRepository = mock(FindingRepository.class);
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final VulnerabilityDefinitionRepository vulnerabilityRepository =
      mock(VulnerabilityDefinitionRepository.class);
  private final AiModelClient modelClient = mock(AiModelClient.class);
  private final SecurityAgentTools agentTools = mock(SecurityAgentTools.class);
  private final AuditService auditService = mock(AuditService.class);
  private final AtomicReference<PostScanPath> savedPath = new AtomicReference<>();
  private PostScanPathService service;
  private AuthorizedTarget target;
  private Finding finding;
  private SecurityTask sourceTask;

  @BeforeEach
  void setUp() throws Exception {
    service =
        new PostScanPathService(
            pathRepository,
            authorization,
            projectService,
            targetService,
            findingRepository,
            taskRepository,
            vulnerabilityRepository,
            modelClient,
            agentTools,
            auditService,
            new ObjectMapper());    target = new AuthorizedTarget();
    target.setId(7L);
    target.setName("local web");
    target.setTargetType("URL");
    target.setTargetValue("https://127.0.0.1:8443");
    target.setAllowedPorts("8443");
    target.setEnabled(true);
    finding = new Finding();
    finding.setId(11L);
    finding.setTaskId(21L);
    finding.setTargetId(7L);
    finding.setTitle("敏感 Cookie 缺少安全属性: JSESSIONID");
    finding.setSeverity("HIGH");
    finding.setStatus("OPEN");
    finding.setSourceTool("http_security_check");
    finding.setVulnerabilityCode("STB-WEB-002");
    finding.setEvidence("cookie=JSESSIONID; missing=Secure,HttpOnly");
    sourceTask = new SecurityTask();
    sourceTask.setId(21L);
    sourceTask.setProjectId(PROJECT);
    sourceTask.setTargetId(7L);
    sourceTask.setToolCode("http_security_check");
    sourceTask.setStatus("SUCCESS");    when(targetService.get(7L)).thenReturn(target);
    when(findingRepository.findAllById(any())).thenReturn(List.of(finding));
    when(taskRepository.findAllById(any())).thenReturn(List.of(sourceTask));
    when(taskRepository.existsByTargetIdAndStatusIn(7L, List.of("PENDING", "RUNNING")))
        .thenReturn(false);
    when(vulnerabilityRepository.findByVulnerabilityCode(any())).thenReturn(Optional.empty());
    when(modelClient.enabled()).thenReturn(true);
    when(modelClient.model()).thenReturn("test-model");
    when(modelClient.complete(any(), any())).thenReturn("模型结合扫描证据完善的路径分析。");
    when(pathRepository.save(any(PostScanPath.class)))
        .thenAnswer(
            invocation -> {
              PostScanPath value = invocation.getArgument(0);
              if (value.getId() == null) value.setId(31L);
              savedPath.set(value);
              return value;
            });
    when(pathRepository.findById(31L)).thenAnswer(ignored -> Optional.ofNullable(savedPath.get()));
  }

  @Test
  void planCreatesNoTaskAndConfirmedSafeStepsDispatchOnce() throws Exception {
    PostScanPathResponse planned =
        service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L), "生成后续授权验证路径"));
    assertThat(planned.status()).isEqualTo("DRAFT");
    assertThat(planned.steps())
        .anyMatch(step -> step.automated() && "SAFE".equals(step.riskLevel()));
    assertThat(planned.steps())
        .anyMatch(step -> !step.automated() && "CAUTION".equals(step.riskLevel()));
    verify(agentTools, never())
        .executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class));

    AiPlanResponse executedPlan = new AiPlanResponse("local", "test", "ok", false, List.of());
    when(agentTools.executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class)))
        .thenReturn(new AiDispatchResponse(7L, executedPlan, 2, List.of(101L, 102L)));
    List<String> selected =
        planned.steps().stream()
            .filter(PostScanPathResponse.RecommendedStep::automated)
            .map(PostScanPathResponse.RecommendedStep::id)
            .toList();
    PostScanPathResponse first = service.confirm(31L, new PostScanConfirmRequest(true, selected));
    PostScanPathResponse replay = service.confirm(31L, new PostScanConfirmRequest(true, selected));

    assertThat(first.status()).isEqualTo("DISPATCHED");
    assertThat(first.taskIds()).containsExactly(101L, 102L);
    assertThat(replay.taskIds()).containsExactly(101L, 102L);
    verify(agentTools, times(1))
        .executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class));
  }

  @Test
  void rejectsFindingFromAnotherTargetBeforePlanning() throws Exception {
    finding.setTargetId(8L);

    assertThatThrownBy(() -> service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L), "follow up")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不属于当前授权目标");    verify(pathRepository, never()).save(any());
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @ParameterizedTest
  @ValueSource(strings = {"TIMEOUT", "SKIPPED"})
  void permitsDraftFollowUpForExistingFindingsFromTerminalTasks(String status) throws Exception {
    sourceTask.setStatus(status);

    PostScanPathResponse response = service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L), "规划后续验证"));

    assertThat(response.status()).isEqualTo("DRAFT");
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void actualReferrerPolicyFindingWithoutCatalogCodeGetsOneConfirmedHeaderCheck() throws Exception {
    AtomicInteger requests = new AtomicInteger();
    HttpServer fixture = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    fixture.createContext("/original-page", exchange -> {
      requests.incrementAndGet();
      exchange.getResponseHeaders().add("Content-Security-Policy", "default-src 'self'");
      exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
      exchange.getResponseHeaders().add("X-Frame-Options", "DENY");
      exchange.getResponseHeaders().add("Permissions-Policy", "camera=()");
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    fixture.start();
    try {
      target.setTargetValue("http://127.0.0.1:" + fixture.getAddress().getPort());
      target.setAllowedPorts(String.valueOf(fixture.getAddress().getPort()));
      TargetPolicyService policy = mock(TargetPolicyService.class);
      when(policy.validatedHttpUri(target, "/original-page"))
          .thenReturn(URI.create(target.getTargetValue() + "/original-page"));
      List<FindingDraft> actualFindings = new HttpHeaderTool(policy)
          .execute(target, Map.of("path", "/original-page")).findings();
      assertThat(actualFindings).hasSize(1);
      FindingDraft actual = actualFindings.get(0);
      assertThat(actual.title()).isEqualTo("缺少安全响应头: referrer-policy");
      assertThat(actual.vulnerabilityCode()).isNull();
      finding.setTitle(actual.title());
      finding.setSeverity(actual.severity());
      finding.setEvidence(actual.evidence());
      finding.setVulnerabilityCode(actual.vulnerabilityCode());
      finding.setSourceTool("http_headers");
      sourceTask.setToolCode("http_headers");
      sourceTask.setRequestJson("{\"path\":\"/original-page\"}");

      PostScanPathResponse planned = plan();

      assertThat(planned.steps()).hasSize(1);
      PostScanPathResponse.RecommendedStep step = planned.steps().get(0);
      assertThat(step.automated()).isTrue();
      assertThat(step.toolCode()).isEqualTo("http_headers");
      assertThat(step.parameters()).isEmpty();
      assertThat(step.expectedEvidence()).contains("默认入口", "不保证与源发现路径相同");
      assertThat(planned.analysis()).isEqualTo("模型结合扫描证据完善的路径分析。");
      assertThat(modelContext().path("localAnalysisTemplate").asText())
          .contains("规则生成", "确认后", "尚未执行").doesNotContain("[LOW]");
      assertThat(requests).hasValue(1);
      verify(agentTools, never()).executeAuthorizedPlan(any(), any());
      assertThatThrownBy(() -> service.confirm(31L, new PostScanConfirmRequest(false, List.of())))
          .isInstanceOf(ApiException.class).hasMessageContaining("必须确认");
      verify(agentTools, never()).executeAuthorizedPlan(any(), any());

      stubDispatch();
      PostScanPathResponse confirmed = service.confirm(31L, new PostScanConfirmRequest(true, List.of(step.id())));
      PostScanPathResponse repeated = service.confirm(31L, new PostScanConfirmRequest(true, List.of(step.id())));
      ArgumentCaptor<AiPlanResponse> dispatched = ArgumentCaptor.forClass(AiPlanResponse.class);
      ArgumentCaptor<AiAgentRequest> dispatchedRequest = ArgumentCaptor.forClass(AiAgentRequest.class);
      verify(agentTools, times(1)).executeAuthorizedPlan(dispatchedRequest.capture(), dispatched.capture());
      assertThat(dispatched.getValue().steps()).hasSize(1);
      assertThat(dispatched.getValue().steps().get(0).toolCode()).isEqualTo("http_headers");
      assertThat(dispatched.getValue().steps().get(0).parameters()).isEmpty();
      assertThat(dispatchedRequest.getValue().projectId()).isEqualTo(PROJECT);
      assertThat(dispatchedRequest.getValue().targetId()).isEqualTo(7L);
      assertThat(confirmed.taskIds()).containsExactly(101L);
      assertThat(repeated.taskIds()).containsExactly(101L);
    } finally {
      fixture.stop(0);
    }
  }

  @ParameterizedTest
  @CsvSource({
      "cookies, Cookie 安全属性", "cors, 跨域允许来源及凭据策略",
      "methods, OPTIONS 声明的 HTTP 方法", "disclosure, 服务器与应用技术栈响应头"
  })
  void uncataloguedHttpChecksRepeatTheActualSourceCheckAndUseChineseEvidence(String check, String label)
      throws Exception {
    directFinding("http_security_check", "{\"check\":\"" + check + "\"}");
    PostScanPathResponse planned = plan();
    assertThat(planned.steps()).hasSize(1);
    PostScanPathResponse.RecommendedStep step = planned.steps().get(0);
    assertThat(step.toolCode()).isEqualTo("http_security_check");
    assertThat(step.parameters()).containsExactlyEntriesOf(Map.of("check", check));
    assertThat(step.expectedEvidence()).contains(label).doesNotContain(check);

    stubDispatch();
    service.confirm(31L, new PostScanConfirmRequest(true, List.of(step.id())));
    ArgumentCaptor<AiPlanResponse> dispatched = ArgumentCaptor.forClass(AiPlanResponse.class);
    verify(agentTools).executeAuthorizedPlan(any(), dispatched.capture());
    assertThat(dispatched.getValue().steps()).hasSize(1);
    assertThat(dispatched.getValue().steps().get(0).toolCode()).isEqualTo("http_security_check");
    assertThat(dispatched.getValue().steps().get(0).parameters()).containsExactlyEntriesOf(Map.of("check", check));
  }

  @ParameterizedTest
  @CsvSource({
      "RULE-WEB-HEADERS,http_headers,1", "RULE-WEB-COOKIES,http_security_check,2",
      "RULE-WEB-CORS,http_security_check,2", "RULE-WEB-METHODS,http_security_check,2",
      "RULE-WEB-DISCLOSURE,http_security_check,2"
  })
  void registeredSourceRulesRecoverCatalogPathsWithoutChangingFindingCodes(String rule, String tool, int size)
      throws Exception {
    directFinding(tool, "{}");
    sourceTask.setRuleCode(rule);
    PostScanPathResponse fromTaskRule = plan();
    sourceTask.setRuleCode(null);
    finding.setRuleCode(rule);
    PostScanPathResponse fromFindingRule = plan();

    assertThat(fromTaskRule.steps()).hasSize(size);
    assertThat(fromFindingRule.steps()).isEqualTo(fromTaskRule.steps());
    assertThat(fromTaskRule.steps()).anyMatch(step -> "http_headers".equals(step.toolCode()));
    assertThat(finding.getVulnerabilityCode()).isNull();
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @ParameterizedTest
  @ValueSource(strings = {"{}", "null", "[]", "{", "{\"check\":\"unknown\"}",
      "{\"check\":42}", "{\"check\":[\"cookies\"]}", "{\"check\":\"cookies\"} {}"})
  void unknownOrMalformedSourceCheckDoesNotInventAutomatedSteps(String requestJson) throws Exception {
    directFinding("http_security_check", requestJson);
    when(modelClient.enabled()).thenReturn(true);

    PostScanPathResponse planned = plan();

    assertThat(planned.steps()).isEmpty();
    assertThat(planned.provider()).isEqualTo("openai-compatible");
    assertThat(planned.analysis()).isEqualTo("模型结合扫描证据完善的路径分析。");
    assertThat(modelContext().path("localAnalysisTemplate").asText())
        .contains("没有可自动执行的步骤", "仅提供人工核查建议", "尚未执行");
    assertThatThrownBy(() -> service.confirm(31L, new PostScanConfirmRequest(true, List.of())))
        .isInstanceOf(ApiException.class).hasMessageContaining("没有选择可自动执行");
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void unknownHighSeverityHttpsFindingRetainsManualReviewWithoutTlsOrModelInventedExecution() throws Exception {
    finding.setVulnerabilityCode("CUSTOM-UNKNOWN");
    finding.setSourceTool("custom_tool");
    sourceTask.setToolCode("custom_tool");
    when(modelClient.enabled()).thenReturn(true);

    PostScanPathResponse planned = plan();

    assertThat(planned.steps()).hasSize(1).allMatch(step -> !step.automated());
    assertThat(planned.analysis()).isEqualTo("模型结合扫描证据完善的路径分析。");
    assertThat(modelContext().path("localAnalysisTemplate").asText())
        .contains("[高危]", "没有可自动执行的步骤").doesNotContain("[HIGH]");
    assertThatThrownBy(() -> service.confirm(31L, new PostScanConfirmRequest(true, List.of(planned.steps().get(0).id()))))
        .isInstanceOf(ApiException.class).hasMessageContaining("不能自动执行");
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void mismatchedFindingAndTaskToolsCannotRecoverHttpStepsFromRulesOrParameters() throws Exception {
    directFinding("http_security_check", "{\"check\":\"cookies\"}");
    sourceTask.setToolCode("http_headers");
    sourceTask.setRuleCode("RULE-WEB-COOKIES");
    assertThat(plan().steps()).isEmpty();
  }

  @ParameterizedTest
  @CsvSource({"custom_tool,custom_tool,false", "tcp_ports,custom_tool,false", "tcp_ports,tcp_ports,true"})
  void openPortTitleRequiresMatchingTcpScanProvenance(String findingTool, String taskTool, boolean recognized)
      throws Exception {
    directFinding(findingTool, "{\"ports\":\"8443\"}");
    sourceTask.setToolCode(taskTool);
    finding.setTitle("开放 TCP 端口 8443");
    when(modelClient.enabled()).thenReturn(true);
    PostScanPathResponse planned = plan();
    if (recognized) {
      assertThat(planned.steps()).hasSize(1);
      assertThat(planned.steps().get(0).toolCode()).isEqualTo("nmap_service_scan");
      assertThat(planned.steps().get(0).parameters())
          .containsExactlyInAnyOrderEntriesOf(Map.of("ports", "8443", "mode", "service"));
    } else {
      assertThat(planned.steps()).isEmpty();
      verify(modelClient).complete(any(), any());
    }
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void eachFindingUsesItsOwnTaskAndDuplicateChecksAreMerged() throws Exception {
    directFinding("http_security_check", "{\"check\":\"cookies\"}");
    Finding second = directFindingCopy(12L, 22L);
    Finding third = directFindingCopy(13L, 21L);
    SecurityTask secondTask = new SecurityTask();
    secondTask.setId(22L);
    secondTask.setTargetId(7L);
    secondTask.setProjectId(PROJECT);
    secondTask.setToolCode("http_security_check");
    secondTask.setStatus("SUCCESS");
    secondTask.setRequestJson("{\"check\":\"cors\"}");
    when(taskRepository.findAllById(any())).thenReturn(List.of(secondTask, sourceTask));
    when(findingRepository.findAllById(any())).thenReturn(List.of(third, second, finding));

    PostScanPathResponse planned = service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L, 12L, 13L), "核查"));

    assertThat(planned.steps()).extracting(PostScanPathResponse.RecommendedStep::id)
        .containsExactly("cookies-11", "cors-12");
    assertThat(planned.steps()).extracting(PostScanPathResponse.RecommendedStep::parameters)
        .containsExactly(Map.of("check", "cookies"), Map.of("check", "cors"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"parameters", "taskRule", "findingRule", "sourceTool", "title", "severity", "evidence"})
  void changedPlanningInputsInvalidateTheDraftBeforeDispatch(String changed) throws Exception {
    directFinding("http_security_check", "{\"check\":\"cookies\"}");
    plan();
    switch (changed) {
      case "parameters" -> sourceTask.setRequestJson("{\"check\":\"cors\"}");
      case "taskRule" -> sourceTask.setRuleCode("RULE-WEB-CORS");
      case "findingRule" -> finding.setRuleCode("RULE-WEB-COOKIES");
      case "sourceTool" -> finding.setSourceTool("http_headers");
      case "title" -> finding.setTitle("另一条发现");
      case "severity" -> finding.setSeverity("HIGH");
      case "evidence" -> finding.setEvidence("已更新的检测证据");
      default -> throw new AssertionError(changed);
    }
    assertThatThrownBy(() -> service.confirm(31L, new PostScanConfirmRequest(true, List.of())))
        .isInstanceOf(ApiException.class).hasMessageContaining("已经变化");
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void modelOnlyExplainsTheServerAuthoredStepsAndCannotModifyDispatch() throws Exception {
    directFinding("http_headers", "{}");
    when(modelClient.enabled()).thenReturn(true);
    when(modelClient.complete(any(), any())).thenReturn("建议先检查响应头缺失的适用条件。自动步骤需确认后执行。");
    PostScanPathResponse planned = plan();
    assertThat(planned.provider()).isEqualTo("openai-compatible");
    assertThat(planned.analysis()).isEqualTo("建议先检查响应头缺失的适用条件。自动步骤需确认后执行。");
    assertThat(planned.steps()).hasSize(1);
    ArgumentCaptor<String> context = ArgumentCaptor.forClass(String.class);
    verify(modelClient).complete(any(), context.capture());
    assertThat(new ObjectMapper().readTree(context.getValue()).get("serverAuthoredSteps").get(0).get("id").asText())
        .isEqualTo(planned.steps().get(0).id());
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void missingModelFailsBeforeSavingAPlan() throws Exception {
    when(modelClient.enabled()).thenReturn(false);
    assertThatThrownBy(this::plan).isInstanceOf(ApiException.class)
        .hasMessageContaining("尚未配置或启用 AI 模型");
    verify(modelClient, never()).complete(any(), any());
    verify(pathRepository, never()).save(any());
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @Test
  void failedModelDoesNotSaveALocalPlanOrExposeProviderDetails() throws Exception {
    when(modelClient.complete(any(), any())).thenThrow(new IllegalStateException("secret-provider-detail"));
    assertThatThrownBy(this::plan).isInstanceOf(ApiException.class)
        .hasMessageContaining("未能完成扫描后路径分析").hasMessageNotContaining("secret-provider-detail");
    verify(pathRepository, never()).save(any());
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  @ParameterizedTest
  @org.junit.jupiter.params.provider.NullAndEmptySource
  @ValueSource(strings = {" ", "```shell\nanything\n```"})
  void invalidModelAnswerDoesNotSaveOrDispatchAPlan(String answer) throws Exception {
    when(modelClient.complete(any(), any())).thenReturn(answer);
    assertThatThrownBy(this::plan).isInstanceOf(ApiException.class)
        .hasMessageContaining("未能完成扫描后路径分析");
    verify(pathRepository, never()).save(any());
    verify(agentTools, never()).executeAuthorizedPlan(any(), any());
  }

  private com.fasterxml.jackson.databind.JsonNode modelContext() throws Exception {
    ArgumentCaptor<String> context = ArgumentCaptor.forClass(String.class);
    verify(modelClient).complete(any(), context.capture());
    return new ObjectMapper().readTree(context.getValue());
  }

  private PostScanPathResponse plan() throws Exception {
    return service.plan(new PostScanPathRequest(PROJECT, 7L, List.of(11L), "核查当前发现"));
  }

  private void directFinding(String toolCode, String requestJson) {
    finding.setVulnerabilityCode(null);
    finding.setSourceTool(toolCode);
    finding.setSeverity("LOW");
    sourceTask.setToolCode(toolCode);
    sourceTask.setRequestJson(requestJson);
  }

  private Finding directFindingCopy(long id, long taskId) {
    Finding copy = new Finding();
    copy.setId(id);
    copy.setTaskId(taskId);
    copy.setTargetId(7L);
    copy.setTitle("配置证据");
    copy.setEvidence("来自对应源任务的证据");
    copy.setSeverity("LOW");
    copy.setStatus("OPEN");
    copy.setSourceTool("http_security_check");
    return copy;
  }

  private void stubDispatch() throws Exception {
    when(agentTools.executeAuthorizedPlan(any(AiAgentRequest.class), any(AiPlanResponse.class)))
        .thenReturn(new AiDispatchResponse(7L, new AiPlanResponse("local", "test", "ok", false, List.of()), 1, List.of(101L)));
  }
}
