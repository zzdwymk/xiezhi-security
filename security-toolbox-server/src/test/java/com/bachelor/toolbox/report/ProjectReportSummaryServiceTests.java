package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.probe.ProbeResult;
import com.bachelor.toolbox.probe.ProbeResultRepository;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalRepository;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.recon.ReconResult;
import com.bachelor.toolbox.recon.ReconResultRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import java.util.List;
import java.util.function.IntFunction;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

class ProjectReportSummaryServiceTests {
  private static final Long PROJECT_ID = 1L;

  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final ReconResultRepository recon = mock(ReconResultRepository.class);
  private final ProbeResultRepository probes = mock(ProbeResultRepository.class);
  private final ProjectApprovalRepository approvals = mock(ProjectApprovalRepository.class);

  private ProjectReportSummaryService service;

  @BeforeEach
  void setUp() {
    service =
        new ProjectReportSummaryService(
            projects, projectTargets, tasks, findings, recon, probes, approvals);

    AssessmentProject project = new AssessmentProject();
    project.setId(PROJECT_ID);
    when(projects.get(PROJECT_ID)).thenReturn(project);
    when(projectTargets.findByProjectId(eq(PROJECT_ID), any(Pageable.class))).thenReturn(List.of());
    when(tasks.findAllByProjectId(eq(PROJECT_ID), any(Pageable.class))).thenReturn(List.of());
    when(findings.findAllByTaskIdIn(any(), any(Pageable.class))).thenReturn(List.of());
    when(recon.findByProjectIdOrderByCollectedAtDescIdDesc(eq(PROJECT_ID), any(Pageable.class)))
        .thenReturn(List.of());
    when(probes.findByProjectIdOrderByDetectedAtDescIdDesc(eq(PROJECT_ID), any(Pageable.class)))
        .thenReturn(List.of());
    when(approvals.findByProjectId(eq(PROJECT_ID), any(Pageable.class))).thenReturn(List.of());
  }

  @Test
  void loadsEveryReportCollectionInFixedBatchesWithoutTruncation() {
    List<ProjectTarget> targetRows = rows(501, this::projectTarget);
    List<SecurityTask> taskRows = List.of(task(900L, Instant.parse("2026-01-01T00:00:00Z")));
    List<Finding> findingRows =
        rows(
            501,
            index ->
                finding(
                    (long) index + 1,
                    900L,
                    Instant.parse("2026-01-01T00:00:00Z").plusSeconds(index)));
    List<ReconResult> reconRows = rows(501, this::reconResult);
    List<ProbeResult> probeRows = rows(501, this::probeResult);
    List<ProjectApproval> approvalRows = rows(501, this::approval);

    when(projectTargets.findByProjectId(eq(PROJECT_ID), any(Pageable.class)))
        .thenAnswer(pages(targetRows));
    when(tasks.findAllByProjectId(eq(PROJECT_ID), any(Pageable.class))).thenAnswer(pages(taskRows));
    when(findings.findAllByTaskIdIn(any(), any(Pageable.class))).thenAnswer(pages(findingRows));
    when(recon.findByProjectIdOrderByCollectedAtDescIdDesc(eq(PROJECT_ID), any(Pageable.class)))
        .thenAnswer(pages(reconRows));
    when(probes.findByProjectIdOrderByDetectedAtDescIdDesc(eq(PROJECT_ID), any(Pageable.class)))
        .thenAnswer(pages(probeRows));
    when(approvals.findByProjectId(eq(PROJECT_ID), any(Pageable.class)))
        .thenAnswer(pages(approvalRows));

    ProjectReportSummaryService.Summary summary = service.load(PROJECT_ID);

    assertThat(summary.targets()).hasSize(501);
    assertThat(summary.vulnerabilityDiscovery()).hasSize(1);
    assertThat(summary.findings()).hasSize(501);
    assertThat(summary.informationCollection()).hasSize(501);
    assertThat(summary.fingerprintAndWafEvidence()).hasSize(501);
    assertThat(summary.approvals()).hasSize(501);
    assertThat(summary.approvalAndAudit().approved()).isEqualTo(501);

    assertTwoFixedPagesForTargets();
    assertOneFixedPageForTasks();
    assertTwoFixedPagesForFindings();
    assertTwoFixedPagesForRecon();
    assertTwoFixedPagesForProbes();
    assertTwoFixedPagesForApprovals();

    verify(projectTargets, never()).findByProjectId(PROJECT_ID);
    verify(tasks, never()).findAllByProjectIdOrderByCreatedAtAsc(PROJECT_ID);
    verify(findings, never()).findAllByTaskIdInOrderByCreatedAtAsc(any());
    verify(recon, never()).findByProjectIdOrderByCollectedAtDesc(PROJECT_ID);
    verify(probes, never()).findByProjectIdOrderByDetectedAtDesc(PROJECT_ID);
    verify(approvals, never()).findByProjectIdOrderByCreatedAtDesc(PROJECT_ID);
  }

  @Test
  void batchesTaskIdsAndRestoresGlobalFindingOrderAcrossChunks() {
    List<SecurityTask> taskRows =
        rows(
            501,
            index ->
                task((long) index + 1, Instant.parse("2026-01-01T00:00:00Z").plusSeconds(index)));
    Finding later = finding(2L, 1L, Instant.parse("2026-02-02T00:00:00Z"));
    Finding earlier = finding(1L, 501L, Instant.parse("2026-02-01T00:00:00Z"));

    when(tasks.findAllByProjectId(eq(PROJECT_ID), any(Pageable.class))).thenAnswer(pages(taskRows));
    when(findings.findAllByTaskIdIn(any(), any(Pageable.class)))
        .thenAnswer(
            invocation -> {
              List<Long> ids = invocation.getArgument(0);
              return ids.size() == ProjectReportSummaryService.REPORT_BATCH_SIZE
                  ? List.of(later)
                  : List.of(earlier);
            });

    ProjectReportSummaryService.Summary summary = service.load(PROJECT_ID);

    assertThat(summary.vulnerabilityDiscovery()).hasSize(501);
    assertThat(summary.findings()).containsExactly(earlier, later);

    ArgumentCaptor<Pageable> taskPages = ArgumentCaptor.forClass(Pageable.class);
    verify(tasks, times(2)).findAllByProjectId(eq(PROJECT_ID), taskPages.capture());
    assertPageNumbersAndSizes(taskPages.getAllValues(), 0, 1);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<Long>> taskIdBatches = ArgumentCaptor.forClass(List.class);
    ArgumentCaptor<Pageable> findingPages = ArgumentCaptor.forClass(Pageable.class);
    verify(findings, times(2)).findAllByTaskIdIn(taskIdBatches.capture(), findingPages.capture());
    assertThat(taskIdBatches.getAllValues().get(0)).hasSize(500).startsWith(1L).endsWith(500L);
    assertThat(taskIdBatches.getAllValues().get(1)).containsExactly(501L);
    assertThat(findingPages.getAllValues())
        .allSatisfy(
            page -> {
              assertThat(page.getPageNumber()).isZero();
              assertThat(page.getPageSize()).isEqualTo(500);
            });
  }

  private void assertTwoFixedPagesForTargets() {
    ArgumentCaptor<Pageable> pages = ArgumentCaptor.forClass(Pageable.class);
    verify(projectTargets, times(2)).findByProjectId(eq(PROJECT_ID), pages.capture());
    assertPageNumbersAndSizes(pages.getAllValues(), 0, 1);
    assertSort(
        pages.getAllValues().get(0), "addedAt", Sort.Direction.ASC, "id", Sort.Direction.ASC);
  }

  private void assertOneFixedPageForTasks() {
    ArgumentCaptor<Pageable> pages = ArgumentCaptor.forClass(Pageable.class);
    verify(tasks).findAllByProjectId(eq(PROJECT_ID), pages.capture());
    assertPageNumbersAndSizes(pages.getAllValues(), 0);
    assertSort(pages.getValue(), "createdAt", Sort.Direction.ASC, "id", Sort.Direction.ASC);
  }

  private void assertTwoFixedPagesForFindings() {
    ArgumentCaptor<Pageable> pages = ArgumentCaptor.forClass(Pageable.class);
    verify(findings, times(2)).findAllByTaskIdIn(any(), pages.capture());
    assertPageNumbersAndSizes(pages.getAllValues(), 0, 1);
    assertSort(
        pages.getAllValues().get(0), "createdAt", Sort.Direction.ASC, "id", Sort.Direction.ASC);
  }

  private void assertTwoFixedPagesForRecon() {
    ArgumentCaptor<Pageable> pages = ArgumentCaptor.forClass(Pageable.class);
    verify(recon, times(2))
        .findByProjectIdOrderByCollectedAtDescIdDesc(eq(PROJECT_ID), pages.capture());
    assertPageNumbersAndSizes(pages.getAllValues(), 0, 1);
    assertThat(pages.getAllValues().get(0).getSort()).isEmpty();
  }

  private void assertTwoFixedPagesForProbes() {
    ArgumentCaptor<Pageable> pages = ArgumentCaptor.forClass(Pageable.class);
    verify(probes, times(2))
        .findByProjectIdOrderByDetectedAtDescIdDesc(eq(PROJECT_ID), pages.capture());
    assertPageNumbersAndSizes(pages.getAllValues(), 0, 1);
    assertThat(pages.getAllValues().get(0).getSort()).isEmpty();
  }
  private void assertTwoFixedPagesForApprovals() {
    ArgumentCaptor<Pageable> pages = ArgumentCaptor.forClass(Pageable.class);
    verify(approvals, times(2)).findByProjectId(eq(PROJECT_ID), pages.capture());
    assertPageNumbersAndSizes(pages.getAllValues(), 0, 1);
    assertSort(
        pages.getAllValues().get(0), "createdAt", Sort.Direction.DESC, "id", Sort.Direction.DESC);
  }

  private void assertPageNumbersAndSizes(List<Pageable> pages, int... expectedNumbers) {
    assertThat(pages).hasSize(expectedNumbers.length);
    for (int index = 0; index < expectedNumbers.length; index++) {
      assertThat(pages.get(index).getPageNumber()).isEqualTo(expectedNumbers[index]);
      assertThat(pages.get(index).getPageSize())
          .isEqualTo(ProjectReportSummaryService.REPORT_BATCH_SIZE);
    }
  }

  private void assertSort(
      Pageable page,
      String firstProperty,
      Sort.Direction firstDirection,
      String secondProperty,
      Sort.Direction secondDirection) {
    assertSortOrder(page, firstProperty, firstDirection);
    assertSortOrder(page, secondProperty, secondDirection);
  }

  private void assertSortOrder(Pageable page, String property, Sort.Direction direction) {
    assertThat(page.getSort().getOrderFor(property)).isNotNull();
    assertThat(page.getSort().getOrderFor(property).getDirection()).isEqualTo(direction);
  }

  private ProjectTarget projectTarget(int index) {
    ProjectTarget target = new ProjectTarget();
    target.setId((long) index + 1);
    target.setProjectId(PROJECT_ID);
    return target;
  }

  private SecurityTask task(Long id, Instant createdAt) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setProjectId(PROJECT_ID);
    task.setCreatedAt(createdAt);
    return task;
  }

  private Finding finding(Long id, Long taskId, Instant createdAt) {
    Finding finding = new Finding();
    finding.setId(id);
    finding.setTaskId(taskId);
    finding.setCreatedAt(createdAt);
    finding.setSeverity("LOW");
    finding.setStatus("OPEN");
    return finding;
  }

  private ReconResult reconResult(int index) {
    ReconResult result = new ReconResult();
    result.setId((long) index + 1);
    return result;
  }

  private ProbeResult probeResult(int index) {
    ProbeResult result = new ProbeResult();
    result.setId((long) index + 1);
    return result;
  }

  private ProjectApproval approval(int index) {
    ProjectApproval approval = new ProjectApproval();
    approval.setId((long) index + 1);
    approval.setProjectId(PROJECT_ID);
    approval.setStatus("APPROVED");
    return approval;
  }

  private static <T> List<T> rows(int count, IntFunction<T> factory) {
    return IntStream.range(0, count).mapToObj(factory).toList();
  }

  private static <T> Answer<List<T>> pages(List<T> values) {
    return invocation -> {
      Pageable pageable = invocation.getArgument(invocation.getArguments().length - 1);
      int from = Math.toIntExact(pageable.getOffset());
      if (from >= values.size()) {
        return List.of();
      }
      int to = Math.min(from + pageable.getPageSize(), values.size());
      return List.copyOf(values.subList(from, to));
    };
  }
}
