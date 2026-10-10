package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

class AiAnswerServiceTests {
  private static final long PROJECT = 1L;
  private final TargetService targetService = mock(TargetService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final FindingRepository findingRepository = mock(FindingRepository.class);
  private final AuditService auditService = mock(AuditService.class);
  private final AiModelClient client = mock(AiModelClient.class);
  private AiAnswerService service;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() throws Exception {
    when(client.enabled()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.complete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
        .thenReturn("模型结合证据生成的回答。");
    service =
        new AiAnswerService(
            targetService,
            projectService,
            taskRepository,
            findingRepository,
            auditService,
            new ObjectMapper(),
            client);
    target = new AuthorizedTarget();
    target.setId(7L);    target.setName("本地靶场");
    target.setTargetValue("http://127.0.0.1:8080");
    when(targetService.get(7L)).thenReturn(target);
  }

  @Test
  void modelReceivesChineseStatusGuidanceWhileTaskStatusAndToolCodeStayIntact() throws Exception {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(true);
    when(client.model()).thenReturn("test-model");
    when(client.complete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
        .thenReturn("检测执行成功。");
    service = new AiAnswerService(targetService, projectService, taskRepository, findingRepository,
        auditService, new ObjectMapper(), client);
    when(taskRepository.findAllById(List.of(11L)))
        .thenReturn(List.of(task(11L, 7L, "http_headers", "SUCCESS")));
    when(findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(List.of(11L))).thenReturn(List.of());

    AiAnswerResponse response = service.answer(new AiAnswerRequest(PROJECT, 7L, "检查结果怎么样？", List.of(11L)));

    org.mockito.ArgumentCaptor<String> system = org.mockito.ArgumentCaptor.forClass(String.class);
    org.mockito.ArgumentCaptor<String> user = org.mockito.ArgumentCaptor.forClass(String.class);
    verify(client).complete(system.capture(), user.capture());
    assertThat(system.getValue()).contains(AiUserFacingLanguage.PROMPT);
    assertThat(user.getValue()).contains("\"status\":\"SUCCESS\"", "http_headers");
    assertThat(response.provider()).isEqualTo("openai-compatible");
  }

  @Test
  void providesChineseStatisticsAsModelReferenceAndReturnsTheModelAnswer() throws Exception {
    SecurityTask success = task(11L, 7L, "http_headers", "SUCCESS");
    success.setResultJson("{\"summary\":\"HTTP 响应头检查完成\"}");
    SecurityTask failed = task(12L, 7L, "tls_config", "FAILED");
    failed.setErrorMessage("目标不是 HTTPS");
    Finding finding = finding(11L, 7L, "缺少 Content-Security-Policy", "MEDIUM");
    finding.setRemediation("配置严格的 Content-Security-Policy 响应头");
    when(taskRepository.findAllById(List.of(11L, 12L))).thenReturn(List.of(success, failed));
    when(findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(List.of(11L, 12L)))
        .thenReturn(List.of(finding));

    AiAnswerResponse response =
        service.answer(new AiAnswerRequest(PROJECT, 7L, "检查结果怎么样？", List.of(11L, 12L)));
    assertThat(response.provider()).isEqualTo("openai-compatible");
    assertThat(response.taskCount()).isEqualTo(2);
    assertThat(response.successCount()).isEqualTo(1);
    assertThat(response.failedCount()).isEqualTo(1);
    assertThat(response.findingCount()).isEqualTo(1);
    assertThat(response.severityCounts()).containsEntry("MEDIUM", 1L);
    assertThat(response.answer()).isEqualTo("模型结合证据生成的回答。");
    assertThat(localSummaryTemplate())
        .contains("HTTP 响应头检查完成")
        .contains("缺少 Content-Security-Policy")
        .contains("目标不是 HTTPS")
        .contains("对应检查范围不能据此下结论", "执行失败", "中危", "TLS 基础配置检查")
        .doesNotContain("FAILED", "MEDIUM", "http_headers", "tls_config");
    assertThat(failed.getStatus()).isEqualTo("FAILED");
    assertThat(finding.getSeverity()).isEqualTo("MEDIUM");
    verify(auditService)
        .record(
            org.mockito.ArgumentMatchers.eq("AI_ANSWER_TASK_RESULTS"),
            org.mockito.ArgumentMatchers.eq("TARGET"),
            org.mockito.ArgumentMatchers.eq(7L),
            org.mockito.ArgumentMatchers.contains("provider=openai-compatible"),
            org.mockito.ArgumentMatchers.eq("SUCCESS"));
  }

  @Test
  void priorityTemplateStartsWithHighestSeverityFindingForTheModelToReview() throws Exception {
    SecurityTask success = task(13L, 7L, "http_headers", "SUCCESS");
    Finding low = finding(13L, 7L, "缺少 Referrer-Policy", "LOW");
    low.setRemediation("设置 Referrer-Policy");
    Finding medium = finding(13L, 7L, "缺少 Content-Security-Policy", "MEDIUM");
    medium.setRemediation("配置严格的 Content-Security-Policy 响应头");
    when(taskRepository.findAllById(List.of(13L))).thenReturn(List.of(success));
    when(findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(List.of(13L)))
        .thenReturn(List.of(low, medium));

    AiAnswerResponse response =
        service.answer(new AiAnswerRequest(PROJECT, 7L, "哪个问题最严重，应该先修什么？", List.of(13L)));
    assertThat(response.answer()).isEqualTo("模型结合证据生成的回答。");
    assertThat(localSummaryTemplate())
        .startsWith(
            "最需要优先处理的是 [中危] 缺少 Content-Security-Policy。建议先配置严格的 Content-Security-Policy 响应头");
  }

  @ParameterizedTest
  @ValueSource(strings = {"TIMEOUT", "SKIPPED", "CANCELLED", "REJECTED"})
  void summarizesTimeoutAndSkippedTasksAsTerminalResults(String status) throws Exception {
    SecurityTask completed = task(41L, 7L, "http_headers", status);
    completed.setErrorMessage("检测未能完成");
    when(taskRepository.findAllById(List.of(41L))).thenReturn(List.of(completed));
    when(findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(List.of(41L)))
        .thenReturn(List.of());

    AiAnswerResponse response = service.answer(new AiAnswerRequest(PROJECT, 7L, "解释未完成的检测", List.of(41L)));

    assertThat(response.taskCount()).isEqualTo(1);
    assertThat(response.successCount()).isZero();
    assertThat(localSummaryTemplate()).contains("检测未能完成", "对应检查范围不能据此下结论")
        .doesNotContain(status, "http_headers");
    assertThat(completed.getStatus()).isEqualTo(status);
  }

  @ParameterizedTest
  @CsvSource({"CRITICAL,严重", "HIGH,高危", "MEDIUM,中危", "LOW,低危", "INFO,提示", "INTERNAL_UNKNOWN,等级未知"})
  void localSummaryUsesSeverityLabelsWithoutChangingResponseMetadata(String code, String label) throws Exception {
    SecurityTask completed = task(42L, 7L, "unknown_internal_tool", "SUCCESS");
    Finding found = finding(42L, 7L, "待确认发现", code);
    when(taskRepository.findAllById(List.of(42L))).thenReturn(List.of(completed));
    when(findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(List.of(42L))).thenReturn(List.of(found));
    AiAnswerResponse response = service.answer(new AiAnswerRequest(PROJECT, 7L, "优先处理什么", List.of(42L)));
    assertThat(localSummaryTemplate()).contains("[" + label + "]", "安全检测工具")
        .doesNotContain(code, "unknown_internal_tool");
    assertThat(response.severityCounts()).containsEntry(code, 1L);
    assertThat(found.getSeverity()).isEqualTo(code);
    assertThat(completed.getToolCode()).isEqualTo("unknown_internal_tool");
  }

  @Test
  void rejectsTaskFromAnotherTargetWithoutLoadingFindings() {
    SecurityTask foreignTask = task(21L, 8L, "tcp_ports", "SUCCESS");
    when(taskRepository.findAllById(List.of(21L))).thenReturn(List.of(foreignTask));

    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "结果", List.of(21L))))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不属于当前授权目标");    verify(auditService)
        .record(
            org.mockito.ArgumentMatchers.eq("AI_ANSWER_TASK_RESULTS"),
            org.mockito.ArgumentMatchers.eq("TARGET"),
            org.mockito.ArgumentMatchers.eq(7L),
            org.mockito.ArgumentMatchers.contains("error="),
            org.mockito.ArgumentMatchers.eq("FAILED"));
  }

  @Test
  void rejectsTasksThatHaveNotReachedTerminalState() {
    SecurityTask running = task(31L, 7L, "nmap_service_scan", "RUNNING");
    when(taskRepository.findAllById(List.of(31L))).thenReturn(List.of(running));

    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "扫描完成了吗", List.of(31L))))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("31（执行中）")
        .hasMessageNotContaining("RUNNING");  }

  @Test
  void rejectsDuplicateAndOversizedTaskLists() {
    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "结果", List.of(1L, 1L))))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("重复");
    List<Long> ids = new ArrayList<>();
    for (long id = 1; id <= 21; id++) {
      ids.add(id);
    }
    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "结果", ids)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("20");  }

  @Test
  void editedFormattingRequestIsPassedToTheModelAndItsAnswerIsReturned() throws Exception {
    prepareCompletedTask();
    when(client.complete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.contains("只回答 1111")))
        .thenReturn("1111");

    AiAnswerResponse response = service.answer(new AiAnswerRequest(PROJECT, 7L, "只回答 1111", List.of(11L)));

    assertThat(response.answer()).isEqualTo("1111");
    verify(client).complete(org.mockito.ArgumentMatchers.contains("最新问题"),
        org.mockito.ArgumentMatchers.contains("用户问题：只回答 1111"));
  }

  @Test
  void disabledModelFailsInsteadOfReturningTheStatisticsTemplate() {
    prepareCompletedTask();
    when(client.enabled()).thenReturn(false);
    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "总结", List.of(11L))))
        .isInstanceOf(ApiException.class).hasMessageContaining("尚未配置或启用 AI 模型");
  }

  @Test
  void failedModelDoesNotSilentlyReturnStatisticsOrProviderDetails() throws Exception {
    prepareCompletedTask();
    when(client.complete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
        .thenThrow(new IllegalStateException("secret-provider-detail"));
    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "总结", List.of(11L))))
        .isInstanceOf(ApiException.class).hasMessageContaining("未能生成检测结果回答")
        .hasMessageNotContaining("secret-provider-detail");
    verify(auditService).record(org.mockito.ArgumentMatchers.eq("AI_ANSWER_TASK_RESULTS"),
        org.mockito.ArgumentMatchers.eq("TARGET"), org.mockito.ArgumentMatchers.eq(7L),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq("FAILED"));
  }

  @Test
  void emptyModelAnswerFails() throws Exception {
    prepareCompletedTask();
    when(client.complete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
        .thenReturn(" ");
    assertThatThrownBy(() -> service.answer(new AiAnswerRequest(PROJECT, 7L, "总结", List.of(11L))))
        .isInstanceOf(ApiException.class).hasMessageContaining("未能生成检测结果回答");
  }

  private void prepareCompletedTask() {
    when(taskRepository.findAllById(List.of(11L)))
        .thenReturn(List.of(task(11L, 7L, "http_headers", "SUCCESS")));
    when(findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(List.of(11L))).thenReturn(List.of());
  }

  private String localSummaryTemplate() throws Exception {
    org.mockito.ArgumentCaptor<String> user = org.mockito.ArgumentCaptor.forClass(String.class);
    verify(client).complete(org.mockito.ArgumentMatchers.anyString(), user.capture());
    String prefix = "检测结果(JSON)：";
    return new ObjectMapper().readTree(user.getValue().substring(user.getValue().indexOf(prefix) + prefix.length()))
        .path("localSummaryTemplate").asText();
  }

  private SecurityTask task(long id, long targetId, String toolCode, String status) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setProjectId(PROJECT);
    task.setTargetId(targetId);
    task.setToolCode(toolCode);
    task.setStatus(status);
    return task;
  }
  private Finding finding(long taskId, long targetId, String title, String severity) {
    Finding finding = new Finding();
    finding.setTaskId(taskId);
    finding.setTargetId(targetId);
    finding.setTitle(title);
    finding.setSeverity(severity);
    finding.setStatus("OPEN");
    return finding;
  }
}
