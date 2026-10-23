package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.ProjectBatchTaskRequest;
import com.bachelor.toolbox.task.ProjectBatchTaskResult;
import com.bachelor.toolbox.task.TaskService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/** AI 对话入口的“按项目批量执行”必须绑定项目范围并复用批量任务服务。 */
class AiControllerProjectBatchTests {
  private ProjectAuthorizationService authorization;
  private TaskService taskService;
  private AiController controller;

  @BeforeEach
  void setUp() {
    authorization = mock(ProjectAuthorizationService.class);
    taskService = mock(TaskService.class);
    controller =
        new AiController(
            mock(AiPlanningService.class),
            mock(AiAnswerService.class),
            mock(AgentOrchestrator.class),
            mock(AiAgentRuntimeClient.class),
            mock(AgentWorkflowSpecService.class),
            mock(AiWorkflowSuggestService.class),
            new ObjectMapper(),
            authorization,
            mock(AssessmentProjectService.class));
    controller.setTaskService(taskService);
  }

  @Test
  void batchExecuteRequiresProjectAccessAndForwardsProjectScope() {
    ProjectBatchTaskResult expected =
        new ProjectBatchTaskResult(5L, "tcp_ports", 2, 2, 0, List.of());
    when(taskService.createBatchForProject(org.mockito.ArgumentMatchers.any()))
        .thenReturn(expected);

    ProjectBatchTaskResult result =
        controller.batchExecuteForProject(
            5L, new ProjectBatchTaskRequest(5L, "tcp_ports", Map.of("ports", "80"), null));

    assertEquals(expected, result);
    verify(authorization).requireAccess(5L);
    ArgumentCaptor<ProjectBatchTaskRequest> captor =
        ArgumentCaptor.forClass(ProjectBatchTaskRequest.class);
    verify(taskService).createBatchForProject(captor.capture());
    assertEquals(5L, captor.getValue().projectId());
    assertEquals("tcp_ports", captor.getValue().toolCode());
  }

  @Test
  void batchExecuteRejectsMismatchedProjectId() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                controller.batchExecuteForProject(
                    5L, new ProjectBatchTaskRequest(6L, "tcp_ports", Map.of(), null)));

    assertEquals("路径项目 ID 与请求体项目 ID 不一致", error.getMessage());
    verifyNoInteractions(taskService);
  }
}
