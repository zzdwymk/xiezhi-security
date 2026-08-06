package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import java.time.Instant;
import java.util.List;
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
}
