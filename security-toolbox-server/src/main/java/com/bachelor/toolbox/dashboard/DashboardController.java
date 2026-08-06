package com.bachelor.toolbox.dashboard;

import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
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

  public DashboardController(
      AuthorizedTargetRepository targetRepository,
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository) {
    this.targetRepository = targetRepository;
    this.taskRepository = taskRepository;
    this.findingRepository = findingRepository;
  }

  @GetMapping("/summary")
  public Map<String, Long> summary() {
    return Map.of(
        "targets", targetRepository.count(),
        "running", taskRepository.countByStatus("RUNNING"),
        "findings", findingRepository.count(),
        "critical", findingRepository.countBySeverityIn(List.of("HIGH", "CRITICAL")));
  }
}
