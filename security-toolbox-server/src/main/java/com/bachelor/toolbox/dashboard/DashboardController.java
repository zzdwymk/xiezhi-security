package com.bachelor.toolbox.dashboard;

import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {
  private final AuthorizedTargetRepository targetRepository;
  private final SecurityTaskRepository taskRepository;
  private final FindingRepository findingRepository;
  private final ProjectAuthorizationService authorization;

  public DashboardController(
      AuthorizedTargetRepository targetRepository,
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository,
      ProjectAuthorizationService authorization) {
    this.targetRepository = targetRepository;
    this.taskRepository = taskRepository;
    this.findingRepository = findingRepository;
    this.authorization = authorization;
  }

  @GetMapping("/summary")
  public Map<String, Long> summary() {
    if (authorization.isAdmin()) {
      return Map.of(
          "targets", targetRepository.count(),
          "running", taskRepository.countByStatus("RUNNING"),
          "findings", findingRepository.count(),
          "critical", findingRepository.countBySeverityIn(List.of("HIGH", "CRITICAL")));
    }

    // Round 230：普通用户只能看到自己可访问项目范围内的聚合；原实现直接 count()
    // 会把其它项目/用户的目标、任务与漏洞数量暴露到仪表盘。
    Collection<Long> projectIds = authorization.accessibleProjectIds();
    if (projectIds == null || projectIds.isEmpty()) {
      return Map.of("targets", 0L, "running", 0L, "findings", 0L, "critical", 0L);
    }
    return Map.of(
        "targets", targetRepository.countAccessibleByProjectIds(projectIds),
        "running", taskRepository.countByProjectIdInAndStatusIn(projectIds, List.of("RUNNING")),
        "findings", findingRepository.countByProjectIds(projectIds),
        "critical", findingRepository.countByProjectIdsAndSeverityIn(projectIds, List.of("HIGH", "CRITICAL")));
  }
}
