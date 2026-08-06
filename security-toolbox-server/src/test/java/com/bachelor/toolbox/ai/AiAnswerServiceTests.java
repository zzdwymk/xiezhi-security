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

class AiAnswerServiceTests {
  private static final long PROJECT = 1L;
  private final TargetService targetService = mock(TargetService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final FindingRepository findingRepository = mock(FindingRepository.class);
  private final AuditService auditService = mock(AuditService.class);
  private AiAnswerService service;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() {
    AiModelClient client = mock(AiModelClient.class);
    when(client.enabled()).thenReturn(false);
    when(client.model()).thenReturn("test-model");
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
  void returnsLocalChineseSummaryForCompletedTasksAndFindings() {
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
    assertThat(response.provider()).isEqualTo("local-rule-fallback");
    assertThat(response.taskCount()).isEqualTo(2);
    assertThat(response.successCount()).isEqualTo(1);
    assertThat(response.failedCount()).isEqualTo(1);
    assertThat(response.findingCount()).isEqualTo(1);
    assertThat(response.severityCounts()).containsEntry("MEDIUM", 1L);
    assertThat(response.answer())
        .contains("HTTP 响应头检查完成")
        .contains("缺少 Content-Security-Policy")
        .contains("目标不是 HTTPS")
        .contains("对应检查范围不能据此下结论");
    verify(auditService)
        .record(
            org.mockito.ArgumentMatchers.eq("AI_ANSWER_TASK_RESULTS"),
            org.mockito.ArgumentMatchers.eq("TARGET"),
            org.mockito.ArgumentMatchers.eq(7L),
            org.mockito.ArgumentMatchers.contains("provider=local-rule-fallback"),
            org.mockito.ArgumentMatchers.eq("SUCCESS"));
  }

  @Test
  void answersPriorityFollowUpWithHighestSeverityFindingFirst() {
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
    assertThat(response.answer())
        .startsWith(
            "最需要优先处理的是 [MEDIUM] 缺少 Content-Security-Policy。建议先配置严格的 Content-Security-Policy 响应头");
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
        .hasMessageContaining("31(RUNNING)");  }

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
