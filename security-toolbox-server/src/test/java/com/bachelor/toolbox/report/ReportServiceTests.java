package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiAnswerService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReportServiceTests {
  private TaskService taskService;
  private AuthorizedTargetRepository targetRepository;
  private FindingRepository findingRepository;
  private AiAnswerService aiAnswerService;
  private ReportService service;

  @BeforeEach
  void setUp() {
    taskService = mock(TaskService.class);
    targetRepository = mock(AuthorizedTargetRepository.class);
    findingRepository = mock(FindingRepository.class);
    aiAnswerService = mock(AiAnswerService.class);
    service = new ReportService(taskService, targetRepository, findingRepository, aiAnswerService);
  }

  @Test
  void reportsMissingTaskWithFixedChineseMessage() {
    when(taskService.get(11L)).thenThrow(new ApiException("任务不存在"));

    assertThatThrownBy(() -> service.generateTaskReport(11L))
        .isInstanceOf(ApiException.class)
        .hasMessage("任务不存在");
    verifyNoInteractions(targetRepository, findingRepository, aiAnswerService);
  }

  @Test
  void hidesAiFailureDetailsAndKeepsReportAvailable() {
    SecurityTask task = new SecurityTask();
    task.setId(11L);
    task.setTargetId(7L);
    task.setStatus("SUCCESS");
    String internalMessage = "模型调用失败：api_key=secret";

    when(taskService.get(11L)).thenReturn(task);
    when(targetRepository.findById(7L)).thenReturn(Optional.empty());
    when(findingRepository.findAllByTaskIdOrderByCreatedAtAsc(11L)).thenReturn(List.of());
    when(aiAnswerService.answer(any())).thenThrow(new IllegalStateException(internalMessage));

    String html = service.generateTaskReport(11L);

    assertThat(html)
        .contains("AI 综合研判暂不可用")
        .doesNotContain(internalMessage)
        .doesNotContain("api_key=secret");
  }

  @Test
  void hidesStoredLegacyFailureDetailsFromTaskReport() {
    SecurityTask task = new SecurityTask();
    task.setId(11L);
    task.setTargetId(7L);
    task.setStatus("FAILED");
    task.setTerminationReason("FAILED");
    task.setErrorMessage("数据库连接失败：jdbc:postgresql://internal?password=secret");

    when(taskService.get(11L)).thenReturn(task);
    when(targetRepository.findById(7L)).thenReturn(Optional.empty());
    when(findingRepository.findAllByTaskIdOrderByCreatedAtAsc(11L)).thenReturn(List.of());

    String html = service.generateTaskReport(11L);

    assertThat(html)
        .contains("任务执行失败，请稍后重试")
        .doesNotContain("jdbc:postgresql")
        .doesNotContain("password=secret");
  }
}
