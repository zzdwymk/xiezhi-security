package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.ai.AiAgentRuntimeClient;
import com.bachelor.toolbox.ai.AiProjectIndexService;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.ProjectContextRetrievalTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TaskProjectRetrievalTests {
  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void persistsRealEvidenceIncludingAnHonestEmptyResult(boolean match) throws Exception {
    Fixture f = new Fixture();
    Map<String,Object> bundle = Map.of("query", "响应头", "projectId", 1L, "targetId", 7L,
        "items", match ? List.of(Map.of("title", "已有响应头记录", "snippet", "发现缺少响应头")) : List.of());
    when(f.runtime.retrieveProjectEvidence(1L, 7L, "响应头")).thenReturn(bundle);
    f.execute();
    assertThat(f.task.getStatus()).isEqualTo("SUCCESS");
    assertThat(f.mapper.readTree(f.task.getResultJson()).get("data"))
        .isEqualTo(f.mapper.readTree(f.mapper.writeValueAsString(bundle)));
    assertThat(f.task.getResultJson()).contains(match ? "找到 1 条" : "不代表目标不存在风险");
    var order = inOrder(f.projects, f.index, f.runtime);
    order.verify(f.projects).validateProjectTarget(1L, 7L);
    order.verify(f.projects).validateProjectTargetMembership(1L, 7L);
    order.verify(f.index).refreshBestEffort(1L);
    order.verify(f.runtime).retrieveProjectEvidence(1L, 7L, "响应头");
    verifyNoInteractions(f.findings);
  }

  @Test void failedIndexRefreshCannotReturnStaleEvidenceAsSuccess() throws Exception {
    Fixture f = new Fixture();
    when(f.index.refreshBestEffort(1L)).thenReturn(false);
    f.execute();
    assertThat(f.task.getStatus()).isEqualTo("FAILED");
    assertThat(f.task.getResultJson()).isNull();
    verifyNoInteractions(f.runtime, f.findings);
  }

  @Test void failedRuntimeQueryIsNotAnEmptySuccessfulResult() throws Exception {
    Fixture f = new Fixture();
    when(f.runtime.retrieveProjectEvidence(1L, 7L, "响应头")).thenThrow(new ApiException("检索服务不可用"));
    f.execute();
    assertThat(f.task.getStatus()).isEqualTo("FAILED");
    assertThat(f.task.getResultJson()).isNull();
  }

  @Test void changedAuthorizationPreventsIndexingAndReading() throws Exception {
    Fixture f = new Fixture();
    doThrow(new ApiException("项目归属变化")).when(f.projects).validateProjectTarget(1L, 7L);
    f.execute();
    assertThat(f.task.getTerminationReason()).isEqualTo("AUTHORIZATION_CHANGED");
    verifyNoInteractions(f.index, f.runtime);
  }

  @Test void callerCannotInjectTheProjectThroughToolParameters() throws Exception {
    Fixture f = new Fixture();
    f.task.setRequestJson("{\"query\":\"响应头\",\"projectId\":999}");
    f.execute();
    assertThat(f.task.getStatus()).isEqualTo("FAILED");
    verifyNoInteractions(f.index, f.runtime);
    assertThatThrownBy(() -> f.tool.execute(f.target, Map.of("projectId",1)))
        .isInstanceOf(ApiException.class).hasMessageContaining("项目归属");
  }

  @Test void cancelAfterIndexRefreshStopsBeforeQueryAndNeverPublishesSuccess() throws Exception {
    Fixture f = new Fixture();
    when(f.index.refreshBestEffort(1L)).thenAnswer(invocation -> { f.control.requestCancellation(42L); return true; });
    f.execute();
    assertThat(f.task.getStatus()).isEqualTo("CANCELLED");
    assertThat(f.task.getResultJson()).isNull();
    verifyNoInteractions(f.runtime);
  }

  private static class Fixture {
    final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    final FindingRepository findings = mock(FindingRepository.class);
    final TargetService targets = mock(TargetService.class);
    final AssessmentProjectService projects = mock(AssessmentProjectService.class);
    final AiProjectIndexService index = mock(AiProjectIndexService.class);
    final AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    final AuditService audit = mock(AuditService.class);
    final TaskSnapshotService snapshots = mock(TaskSnapshotService.class);
    final TaskProgressEventService progress = mock(TaskProgressEventService.class);
    final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    final TaskExecutionControlService control = new TaskExecutionControlService(1, 1);
    final ObjectMapper mapper = new ObjectMapper();
    final ProjectContextRetrievalTool tool = new ProjectContextRetrievalTool(projects, index, runtime);
    final SecurityTask task = new SecurityTask();
    final AuthorizedTarget target = new AuthorizedTarget();
    Fixture() throws Exception {
      task.setId(42L); task.setProjectId(1L); task.setTargetId(7L);
      task.setToolCode("retrieve_project_context"); task.setStatus("PENDING");
      task.setRequestJson("{\"query\":\"响应头\"}"); task.setAuthorizationSnapshotHash("test-hash");
      target.setId(7L); target.setTargetValue("http://127.0.0.1:18888");
      when(authorization.callWithSystemAccess(any(Callable.class)))
          .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());
      when(tasks.findById(42L)).thenReturn(Optional.of(task));
      when(targets.getCurrentlyAuthorized(7L)).thenReturn(target);
      when(index.refreshBestEffort(1L)).thenReturn(true);
    }
    void execute() {
      new TaskExecutionService(tasks, findings, targets, projects, new SecurityToolRegistry(List.of(tool)),
          audit, mapper, snapshots, control, progress, authorization).executeAsync(42L);
    }
  }
}
