package com.bachelor.toolbox.report;

import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingClassification;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.probe.ProbeResultRepository;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalRepository;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.recon.ReconResultRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

/** Structured, project-scoped source data used by both the UI and final report generation. */
@Service
public class ProjectReportSummaryService {
  static final int REPORT_BATCH_SIZE = 500;
  private static final Sort CREATED_ASC_ID_ASC =
      Sort.by(Sort.Order.asc("createdAt"), Sort.Order.asc("id"));
  private static final Sort CREATED_DESC_ID_DESC =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final Sort ADDED_ASC_ID_ASC =
      Sort.by(Sort.Order.asc("addedAt"), Sort.Order.asc("id"));
  private static final Comparator<Finding> FINDING_ORDER =
      Comparator.comparing(Finding::getCreatedAt, Comparator.nullsLast(Comparator.naturalOrder()))
          .thenComparing(Finding::getId, Comparator.nullsLast(Comparator.naturalOrder()));

  private final AssessmentProjectService projects;
  private final ProjectTargetRepository projectTargets;
  private final SecurityTaskRepository tasks;
  private final FindingRepository findings;
  private final ReconResultRepository recon;
  private final ProbeResultRepository probes;
  private final ProjectApprovalRepository approvals;

  public ProjectReportSummaryService(
      AssessmentProjectService projects,
      ProjectTargetRepository projectTargets,
      SecurityTaskRepository tasks,
      FindingRepository findings,
      ReconResultRepository recon,
      ProbeResultRepository probes,
      ProjectApprovalRepository approvals) {
    this.projects = projects;
    this.projectTargets = projectTargets;
    this.tasks = tasks;
    this.findings = findings;
    this.recon = recon;
    this.probes = probes;
    this.approvals = approvals;
  }

  public Summary load(Long projectId) {
    AssessmentProject project = projects.get(projectId);
    List<ProjectTarget> links =
        loadAll(pageable -> projectTargets.findByProjectId(projectId, pageable), ADDED_ASC_ID_ASC);
    List<SecurityTask> projectTasks =
        loadAll(pageable -> tasks.findAllByProjectId(projectId, pageable), CREATED_ASC_ID_ASC);
    List<Finding> projectFindings = loadFindings(projectTasks);
    Map<String, Long> severities = new LinkedHashMap<>();
    for (String value : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
      severities.put(value, 0L);
    projectFindings.forEach(
        f ->
            severities.compute(
                f.getSeverity().toUpperCase(Locale.ROOT), (k, v) -> v == null ? 1 : v + 1));
    Set<Long> explicitlyRetestedFindingIds =
        projectTasks.stream()
            .map(SecurityTask::getSourceFindingId)
            .filter(java.util.Objects::nonNull)
            .collect(java.util.stream.Collectors.toSet());
    long retested =
        projectFindings.stream()
            .filter(
                f ->
                    explicitlyRetestedFindingIds.contains(f.getId())
                        || Set.of("VERIFIED", "FIXED", "REOPENED").contains(f.getStatus()))
            .count();
    long controlledPostExploitation =
        projectTasks.stream()
            .filter(
                t ->
                    t.getToolCode() != null
                        && (t.getToolCode().contains("POST") || t.getToolCode().contains("VERIFY")))
            .count();
    List<ProjectApproval> projectApprovals =
        loadAll(pageable -> approvals.findByProjectId(projectId, pageable), CREATED_DESC_ID_DESC);
    return new Summary(
        project,
        links,
        projectTasks,
        projectFindings,
        severities,
        FindingClassification.vulnerabilityCount(projectFindings),
        FindingClassification.informationalCount(projectFindings),
        loadAll(
            pageable -> recon.findByProjectIdOrderByCollectedAtDescIdDesc(projectId, pageable),
            Sort.unsorted()),
        loadAll(
            pageable -> probes.findByProjectIdOrderByDetectedAtDescIdDesc(projectId, pageable),
            Sort.unsorted()),
        projectApprovals,
        new Verification(retested, projectFindings.size() - retested),
        new ControlledActivity(
            controlledPostExploitation, "仅统计经授权任务记录的验证/后渗透活动；高风险操作必须经过审批，不自动执行持久化、提权或凭据导出。"),
        new AuditOverview(
            projectApprovals.size(),
            projectApprovals.stream().filter(a -> "APPROVED".equals(a.getStatus())).count(),
            projectApprovals.stream().filter(a -> "REJECTED".equals(a.getStatus())).count()),
        Instant.now());
  }

  private List<Finding> loadFindings(List<SecurityTask> projectTasks) {
    List<Long> taskIds = projectTasks.stream().map(SecurityTask::getId).toList();
    if (taskIds.isEmpty()) {
      return List.of();
    }

    List<Finding> result = new ArrayList<>();
    for (int from = 0; from < taskIds.size(); from += REPORT_BATCH_SIZE) {
      List<Long> taskIdBatch =
          List.copyOf(taskIds.subList(from, Math.min(from + REPORT_BATCH_SIZE, taskIds.size())));
      result.addAll(
          loadAll(
              pageable -> findings.findAllByTaskIdIn(taskIdBatch, pageable), CREATED_ASC_ID_ASC));
    }
    result.sort(FINDING_ORDER);
    return List.copyOf(result);
  }

  private <T> List<T> loadAll(Function<Pageable, List<T>> pageLoader, Sort sort) {
    List<T> result = new ArrayList<>();
    for (int page = 0; ; page++) {
      Pageable pageable =
          PageRequests.bounded(page, REPORT_BATCH_SIZE, REPORT_BATCH_SIZE, REPORT_BATCH_SIZE, sort);
      List<T> batch = pageLoader.apply(pageable);
      result.addAll(batch);
      if (batch.size() < REPORT_BATCH_SIZE) {
        return List.copyOf(result);
      }
    }
  }

  public record Summary(
      AssessmentProject project,
      List<ProjectTarget> targets,
      List<SecurityTask> vulnerabilityDiscovery,
      List<Finding> findings,
      Map<String, Long> severityCounts,
      long vulnerabilityCount,
      long informationalCount,
      List<?> informationCollection,
      List<?> fingerprintAndWafEvidence,
      List<ProjectApproval> approvals,
      Verification verification,
      ControlledActivity controlledPostExploitation,
      AuditOverview approvalAndAudit,
      Instant generatedAt) {}

  public record Verification(long retestedFindings, long awaitingRetest) {}

  public record ControlledActivity(long recordedTasks, String safetyBoundary) {}

  public record AuditOverview(long totalApprovals, long approved, long rejected) {}
}
