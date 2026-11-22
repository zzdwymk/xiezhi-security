package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 第315轮：任务列表不得携带完整执行结果。
 *
 * <p>{@code GET /api/tasks} 实测 23.4 MB（366 条任务），根因是每条任务都把完整 {@code resultJson}
 * 一起返回。列表页只需要结果里的摘要文本，因此列表接口应把 resultJson 压缩成 {@code {"summary": ...}}；
 * 完整结果仍由 {@code GET /api/tasks/{id}} 提供。
 */
class TaskListResultCompactionTests {

  @Test
  void listCompactsResultJsonToSummaryOnly() throws Exception {
    SecurityTaskRepository repository = mock(SecurityTaskRepository.class);
    TargetService targetService = mock(TargetService.class);
    SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
    TaskExecutionService executionService = mock(TaskExecutionService.class);
    AuditService auditService = mock(AuditService.class);
    TaskSnapshotService snapshotService = mock(TaskSnapshotService.class);
    TaskExecutionControlService executionControl = mock(TaskExecutionControlService.class);
    AssessmentProjectService projectService = mock(AssessmentProjectService.class);
    TaskProgressEventService progressEvents = mock(TaskProgressEventService.class);

    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    when(projectService.list()).thenReturn(List.of(project));

    String hugeDetail = "x".repeat(200_000);
    SecurityTask task = new SecurityTask();
    task.setId(10L);
    task.setProjectId(1L);
    task.setToolCode("http_headers");
    task.setStatus("SUCCESS");
    task.setCreatedAt(Instant.now());
    task.setResultJson("{\"summary\":\"检查完成\",\"raw\":\"" + hugeDetail + "\"}");
    when(repository.findAllByProjectIdIn(any(), any())).thenReturn(List.of(task));

    TaskService service =
        new TaskService(
            repository,
            targetService,
            registry,
            executionService,
            auditService,
            new ObjectMapper(),
            snapshotService,
            executionControl,
            projectService,
            progressEvents);

    List<SecurityTask> listed = service.list();

    assertThat(listed).hasSize(1);
    assertThat(listed.get(0).getResultJson())
        .as("列表返回的结果 JSON 必须压缩到摘要级别，不能携带完整执行明细")
        .hasSizeLessThan(1_000)
        .contains("检查完成");
  }
}

