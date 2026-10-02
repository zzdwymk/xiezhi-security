package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.probe.ProbeResultRepository;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.recon.ReconResultRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiProjectIndexServiceTests {
  private final AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
  private final AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final ReconResultRepository recon = mock(ReconResultRepository.class);
  private final ProbeResultRepository probes = mock(ProbeResultRepository.class);
  private AiProjectIndexService service;

  @BeforeEach
  void setUp() {
    service =
        new AiProjectIndexService(
            runtime, projects, projectTargets, targets, tasks, findings, recon, probes);
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setName("Example assessment");
    project.setStatus("ACTIVE");
    project.setOwner("admin");
    project.setAuthorizationStatement("Authorized security assessment");
    project.setAuthorizationValidFrom(Instant.parse("2026-07-22T00:00:00Z"));
    project.setAuthorizationExpiresAt(Instant.parse("2026-07-30T00:00:00Z"));
    when(projects.get(1L)).thenReturn(project);
    when(projectTargets.findByProjectId(1L)).thenReturn(List.of());
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of());
    when(recon.findByProjectIdOrderByCollectedAtDesc(1L)).thenReturn(List.of());
    when(probes.findByProjectIdOrderByDetectedAtDesc(1L)).thenReturn(List.of());
    when(runtime.enabled()).thenReturn(true);
  }

  @Test
  void indexesRecordedTaskEventWithoutStageWeightedPercentage() {
    SecurityTask task = new SecurityTask();
    task.setId(10L); task.setProjectId(1L); task.setTargetId(9L);
    task.setStatus("TIMEOUT"); task.setProgress(57);
    task.setProgressMessage("任务执行超时");
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of(task));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L))).thenReturn(List.of());
    assertTrue(service.refreshBestEffort(1L));
    verify(runtime).indexProject(eq(1L), argThat(documents -> documents.stream().anyMatch(d ->
        d.source().equals("task") && d.text().contains("最近执行事件：任务执行超时")
            && !d.text().contains("57%"))));
  }

  @Test
  void indexesBoundedProjectAuthorizationDocument() {
    assertTrue(service.refreshBestEffort(1L));
    verify(runtime)
        .indexProject(
            eq(1L),
            argThat(
                documents ->
                    documents.size() == 1
                        && documents.get(0).text().contains("Authorized security assessment")));
  }

  @Test
  void runtimeFailureDoesNotBlockAgentTurn() {
    doThrow(new AiAgentRuntimeClient.RuntimeUnavailableException("offline"))
        .when(runtime)
        .indexProject(eq(1L), argThat(documents -> true));
    assertFalse(service.refreshBestEffort(1L));
  }

  @Test
  void selectedRecordPrecedesSnapshotDocuments() {
    var reference = new AiAgentRuntimeClient.IndexDocument("本轮引用", "任务 #1 的已脱敏证据", "reference", java.util.Map.of("targetId", "9"));
    assertTrue(service.refreshBestEffort(1L, reference));
    verify(runtime).indexProject(eq(1L), argThat(documents ->
        documents.size() == 2 && documents.get(0).equals(reference)));
  }

  @Test
  void projectOverviewIncludesRecordsBeyondSelectedTarget() {
    var first = new com.bachelor.toolbox.task.SecurityTask();
    first.setId(10L); first.setTargetId(9L); first.setStatus("SUCCESS");
    var second = new com.bachelor.toolbox.task.SecurityTask();
    second.setId(11L); second.setTargetId(20L); second.setStatus("FAILED");
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of(first, second));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L, 11L))).thenReturn(List.of());
    assertTrue(service.refreshBestEffort(1L));
    verify(runtime).indexProject(eq(1L), argThat(documents -> documents.stream().anyMatch(d ->
        d.source().equals("project") && "project-overview".equals(d.metadata().get("kind"))
            && !d.metadata().containsKey("targetId") && d.text().contains("检测任务总数：2")
            && d.text().contains("FAILED=1") && d.text().contains("SUCCESS=1"))));
  }

  @Test
  void taskSnapshotRedactsResultsErrorsAndLogsWithoutLosingEvidence() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    String nested = mapper.writeValueAsString(Map.of("api_key", "encoded-key-secret", "open", true));
    SecurityTask task = new SecurityTask();
    task.setId(10L);
    task.setProjectId(1L);
    task.setTargetId(9L);
    task.setStatus("SUCCESS");
    task.setResultJson(mapper.writeValueAsString(Map.of(
        "password", "prefix\"escaped-tail-secret", "body", nested, "port", 80)));
    task.setExecutionLog("received: " + mapper.writeValueAsString(Map.of(
        "response", nested, "token", "log-token-secret", "elapsedMs", 12)) + "; scan finished");
    task.setErrorMessage("diagnostic; password=\"first\\\"error-tail-secret\"; HTTP 200");
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of(task));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L))).thenReturn(List.of());

    var document = service.collect(1L).stream().filter(d -> d.source().equals("task"))
        .findFirst().orElseThrow();

    assertThat(document.text()).contains("port", "80", "open", "true", "elapsedMs", "12",
            "scan finished", "HTTP 200", "执行日志摘要", "[REDACTED]")
        .doesNotContain("encoded-key-secret", "escaped-tail-secret", "log-token-secret", "error-tail-secret");
    assertThat(document.metadata()).containsEntry("targetId", "9").containsEntry("taskId", "10");
  }
}
